//! The command tree, modelled on lldb's: `noun verb [options] args`, where any unique
//! prefix of a command works (`mem re` is `memory read`).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use procodile::scan::ValueType;

use crate::expr::parse_usize;
use crate::format::Format;

#[derive(Parser, Debug)]
#[command(
    multicall = true,
    infer_subcommands = true,
    disable_help_flag = true,
    help_template = "{subcommands}",
    subcommand_help_heading = "Commands"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Short forms expanded before parsing, like lldb's built-in aliases.
pub const ALIASES: &[(&str, &str)] = &[
    ("x", "memory read"),
    ("attach", "process attach"),
    ("detach", "process detach"),
    ("c", "process continue"),
    ("continue", "process continue"),
    ("ps", "process list"),
    ("p", "struct read"),
    ("q", "quit"),
    ("exit", "quit"),
];

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List, attach to and control processes.
    #[command(subcommand)]
    Process(ProcessCommand),
    /// Read, write, search and inspect memory.
    #[command(subcommand)]
    Memory(MemoryCommand),
    /// Inspect loaded modules (executables and shared libraries).
    #[command(subcommand)]
    Image(ImageCommand),
    /// Find values by scanning, then narrowing down the results.
    #[command(subcommand)]
    Scan(ScanCommand),
    /// Find pointer paths from static memory to an address, which survive restarts.
    #[command(subcommand)]
    Pointer(PointerCommand),
    /// Define structures and view memory through them.
    #[command(subcommand)]
    Struct(StructCommand),
    /// The address table: saved addresses that can be watched, edited and frozen.
    #[command(subcommand)]
    Table(TableCommand),
    /// Open the full-screen interface (q returns here).
    Tui,
    /// Exit procodile.
    Quit,
}

#[derive(Debug, Subcommand)]
pub enum ProcessCommand {
    /// List running processes.
    List {
        /// Only show processes whose name contains this.
        filter: Option<String>,
    },
    /// Attach to a process by pid or name.
    Attach(AttachArgs),
    /// Detach from the current process.
    Detach,
    /// Show the attached process.
    Status,
    /// Suspend all threads of the process.
    Interrupt,
    /// Resume a suspended process.
    Continue,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct AttachArgs {
    #[arg(short, long)]
    pub pid: Option<u32>,
    #[arg(short, long)]
    pub name: Option<String>,
    /// A pid, or a process name.
    pub target: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommand {
    /// Read and display memory (alias: x).
    Read {
        /// Display format.
        #[arg(short, long, value_enum)]
        format: Option<Format>,
        /// Size in bytes of each item.
        #[arg(short, long, value_parser = parse_usize)]
        size: Option<usize>,
        /// Number of items to display.
        #[arg(short, long, value_parser = parse_usize)]
        count: Option<usize>,
        /// Show items as this value type (sets format and size).
        #[arg(short, long)]
        r#type: Option<ValueType>,
        /// Address expression.
        address: String,
    },
    /// Write values to memory.
    Write {
        /// Size in bytes of each value (default 1). Values are hex unless --type is given.
        #[arg(short, long, value_parser = parse_usize, conflicts_with = "type")]
        size: Option<usize>,
        /// Parse the values as this type.
        #[arg(short, long)]
        r#type: Option<ValueType>,
        /// Address expression.
        address: String,
        /// Values to write, one after another.
        #[arg(required = true, allow_negative_numbers = true)]
        values: Vec<String>,
    },
    /// Show the region containing an address, or all regions.
    Region {
        #[arg(short, long, conflicts_with = "address")]
        all: bool,
        #[arg(required_unless_present = "all")]
        address: Option<String>,
    },
    /// Search memory for a value, string or byte pattern.
    Find(FindArgs),
    /// Change the protection of memory pages (Windows only).
    Protect {
        address: String,
        #[arg(value_parser = parse_usize)]
        size: usize,
        /// Permissions such as `rwx`, `r-x` or `rw`.
        permissions: String,
    },
    /// Allocate memory in the process (Windows only).
    Allocate {
        #[arg(value_parser = parse_usize)]
        size: usize,
        #[arg(short, long, default_value = "rw")]
        permissions: String,
    },
    /// Free memory allocated with `memory allocate`.
    Free { address: String },
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("needle").required(true).args(["expression", "string", "pattern"])))]
pub struct FindArgs {
    /// A value, parsed as `--type`.
    #[arg(short, long, allow_negative_numbers = true)]
    pub expression: Option<String>,
    /// A string (UTF-8).
    #[arg(short, long)]
    pub string: Option<String>,
    /// A byte pattern with `??` wildcards, e.g. "48 8b ?? ?? 89".
    #[arg(short, long)]
    pub pattern: Option<String>,
    /// Value type for --expression.
    #[arg(short, long)]
    pub r#type: Option<ValueType>,
    /// Only search this module.
    #[arg(short, long)]
    pub module: Option<String>,
    /// Only search executable memory.
    #[arg(short = 'x', long)]
    pub executable: bool,
    /// Stop after this many matches.
    #[arg(short, long, default_value_t = 32, value_parser = parse_usize)]
    pub count: usize,
}

/// How `image inject` loads the library (mirrors `procodile::LoadMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum InjectMethod {
    /// Use the target's OS loader (LoadLibraryW / dlopen). Default.
    #[default]
    Loader,
    /// Map the image directly without the OS loader.
    Manual,
}

#[derive(Debug, Subcommand)]
pub enum ImageCommand {
    /// List loaded modules.
    List {
        /// Only show modules whose name contains this.
        filter: Option<String>,
    },
    /// Show which module and region an address belongs to.
    Lookup {
        #[arg(short, long)]
        address: String,
    },
    /// Load a shared library (.dll / .so) into the attached process.
    ///
    /// Uses the OS loader by default (`--method loader`). Pass `--method manual` to map
    /// the image directly without the loader — useful when dlopen/LoadLibrary cannot be
    /// used (static/musl targets, stripped symbols, restricted ptrace).
    ///
    /// Example:
    ///   image inject /path/to/library.so
    ///   image inject -m manual /path/to/library.so
    Inject {
        /// How to load the library: `loader` (default) or `manual`.
        #[arg(short = 'm', long = "method", value_enum, default_value_t = InjectMethod::Loader)]
        method: InjectMethod,
        /// Path to the shared library file.
        path: String,
    },
}

#[derive(Debug, Args)]
pub struct ScanSettings {
    /// Value type (i8..i64, u8..u64, f32, f64).
    #[arg(short, long)]
    pub r#type: Option<ValueType>,
    /// Alignment of candidate addresses; default is the type's size.
    #[arg(short, long, value_parser = parse_usize)]
    pub align: Option<usize>,
    /// Also scan read-only memory.
    #[arg(long)]
    pub read_only: bool,
    /// Also scan shared and file mappings.
    #[arg(long)]
    pub mapped: bool,
    /// Only scan this module.
    #[arg(short, long)]
    pub module: Option<String>,
    /// Floats within this distance count as equal; default from the value's precision.
    #[arg(long)]
    pub tolerance: Option<f64>,
}

#[derive(Debug, Subcommand)]
pub enum ScanCommand {
    /// Start a new scan.
    ///
    /// The condition is a value (`100`), or one of: eq, ne, gt, lt, between <a> <b>,
    /// unknown.
    First {
        #[command(flatten)]
        settings: ScanSettings,
        #[arg(
            required = true,
            allow_negative_numbers = true,
            value_name = "CONDITION"
        )]
        condition: Vec<String>,
    },
    /// Narrow the results down.
    ///
    /// The condition is a value (`93`), or one of: eq, ne, gt, lt, between <a> <b>,
    /// changed, unchanged, increased, decreased, inc-by <n>, dec-by <n>.
    Next {
        #[arg(
            required = true,
            allow_negative_numbers = true,
            value_name = "CONDITION"
        )]
        condition: Vec<String>,
    },
    /// Show results with their current values; refer to them as #N.
    List {
        #[arg(short, long, default_value_t = 20, value_parser = parse_usize)]
        count: usize,
        #[arg(short, long, default_value_t = 0, value_parser = parse_usize)]
        start: usize,
    },
    /// Discard the current scan.
    Reset,
}

#[derive(Debug, Subcommand)]
pub enum PointerCommand {
    /// Find paths from module statics to an address; refer to them as @N.
    ///
    /// With a pointer database open, the pointer map built for the scan is saved too.
    Scan {
        /// Address expression, e.g. `#0` or `$1`. Defaults to the map's target with --map.
        #[arg(required_unless_present = "map")]
        address: Option<String>,
        /// Scan a saved pointer map instead of the attached process.
        #[arg(short, long)]
        map: Option<i64>,
        /// Maximum number of dereferences.
        #[arg(short, long, default_value_t = 4, value_parser = parse_usize)]
        depth: usize,
        /// Maximum offset after each dereference.
        #[arg(short = 'o', long, default_value = "0x1000", value_parser = parse_usize)]
        max_offset: usize,
        /// Stop after this many paths.
        #[arg(short, long, default_value_t = 10_000, value_parser = parse_usize)]
        count: usize,
        /// Also look for pointers stored in read-only memory.
        #[arg(long, conflicts_with = "map")]
        read_only: bool,
    },
    /// Show paths with the address each one resolves to now.
    List {
        #[arg(short, long, default_value_t = 20, value_parser = parse_usize)]
        count: usize,
        #[arg(short, long, default_value_t = 0, value_parser = parse_usize)]
        start: usize,
    },
    /// Keep only the paths that resolve to an address in the attached process, e.g. after
    /// restarting the target and finding the value again.
    Filter { address: String },
    /// Keep only the paths that resolve to each saved map's target within that map.
    Intersect {
        #[arg(required = true)]
        maps: Vec<i64>,
    },
    /// Manage saved pointer maps (needs `pointer open`).
    #[command(subcommand)]
    Map(PointerMapCommand),
    /// Open or create a pointer database, which keeps maps and results across sessions.
    Open { path: PathBuf },
    /// Close the pointer database. Results stay loaded.
    Close,
    /// Save the paths to a text file, one per line.
    Save { path: PathBuf },
    /// Load paths saved with `pointer save`.
    Load { path: PathBuf },
    /// Discard the pointer scan results.
    Reset,
}

#[derive(Debug, Subcommand)]
pub enum PointerMapCommand {
    /// Snapshot every pointer in the attached process, recording where the value is now.
    ///
    /// Take one per run of the target, finding the value again each time, then use
    /// `pointer intersect` to keep only the paths that work in every run.
    Save {
        /// Address of the value in this run, e.g. `#0`.
        address: String,
        #[arg(short, long)]
        label: Option<String>,
        /// Also record pointers stored in read-only memory.
        #[arg(long)]
        read_only: bool,
    },
    /// List saved maps.
    List,
    /// Delete a saved map.
    Remove { id: i64 },
}

#[derive(Debug, Subcommand)]
pub enum StructCommand {
    /// Define structures in Rust syntax, e.g.
    /// `struct define 'struct Stats { armor: i32, health: i32 }'`.
    Define {
        /// Definitions; several words are joined with spaces.
        #[arg(required = true, num_args = 1..)]
        source: Vec<String>,
    },
    /// Load definitions from a file (adding to, or replacing, those with the same name).
    Load { path: PathBuf },
    /// Save all definitions to a file.
    Save { path: PathBuf },
    /// List defined structures.
    List,
    /// Show a structure's layout with offsets and sizes.
    Show { name: String },
    /// Read memory as a structure.
    Read {
        name: String,
        /// Address expression.
        address: String,
        /// How many levels of pointers to follow.
        #[arg(short, long, default_value_t = 1, value_parser = parse_usize)]
        depth: usize,
        /// Show field offsets.
        #[arg(short, long)]
        offsets: bool,
    },
    /// Guess the fields of unknown memory.
    Dissect {
        /// Address expression.
        address: String,
        /// Bytes to look at.
        #[arg(short, long, default_value = "0x40", value_parser = parse_usize)]
        size: usize,
        /// Also define the guess as a structure with this name, to refine.
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Forget a structure.
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
pub enum TableCommand {
    /// Add an address (e.g. `#0`, `@2`, `game.exe+0x1c`, `[[base]+8]`); refer to it as $N.
    Add {
        address: String,
        #[arg(short, long)]
        r#type: Option<ValueType>,
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Show entries with their current values.
    List,
    /// Remove an entry.
    Remove {
        #[arg(value_parser = parse_index)]
        index: usize,
    },
    /// Write a value to an entry (updating its frozen value if frozen).
    Write {
        #[arg(value_parser = parse_index)]
        index: usize,
        #[arg(allow_negative_numbers = true)]
        value: String,
    },
    /// Keep an entry at a value (default: its current value).
    Freeze {
        #[arg(value_parser = parse_index)]
        index: usize,
        #[arg(allow_negative_numbers = true)]
        value: Option<String>,
    },
    Unfreeze {
        #[arg(value_parser = parse_index)]
        index: usize,
    },
    /// Save the table to a TOML file.
    Save { path: PathBuf },
    /// Replace the table with one loaded from a TOML file.
    Load { path: PathBuf },
}

/// Accepts `3` or `$3`.
fn parse_index(s: &str) -> Result<usize, String> {
    parse_usize(s.strip_prefix('$').unwrap_or(s))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn prefixes_and_negative_values() {
        let cli = Cli::try_parse_from(["mem", "wr", "-t", "i32", "0x10", "-5"]).unwrap();
        let Command::Memory(MemoryCommand::Write { values, r#type, .. }) = cli.command else {
            panic!()
        };
        assert_eq!(values, ["-5"]);
        assert_eq!(r#type, Some(ValueType::I32));
    }
}
