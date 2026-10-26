# procodile-cli

`procodile`, an interactive memory scanner and editor for Linux and Windows, in the
spirit of Cheat Engine with an lldb-style command line. It has a REPL and a full-screen
TUI that share one session: value scans, pointer scans, an address table with freezing,
and memory viewed through struct definitions.

It is built on the [procodile](https://crates.io/crates/procodile) library.

## Install

```sh
cargo install procodile-cli    # installs the `procodile` binary
```

The `sqlite` feature (on by default) adds pointer databases (`pointer open`). It bundles
SQLite, so it needs a C compiler; install with `--no-default-features` to leave it out.

### Permissions

- **Linux:** attaching to another process needs ptrace permission. Either run as root,
  give the binary `CAP_SYS_PTRACE`, or set `/proc/sys/kernel/yama/ptrace_scope` to `0`.
  The default (`1`) only allows attaching to your own child processes.
- **Windows:** protected processes need an elevated (Administrator) prompt.

## Quick start

The repository includes a toy target with a value behind a pointer chain:

```sh
cargo run -p procodile --example target   # prints its pid; Enter = take damage
```

In another terminal:

```text
$ procodile -n target
Process 4242 (target) attached
(procodile) scan first 100          # find every i32 equal to 100
6 results (0.05s); see `scan list`
                                    # ...take damage in the target...
(procodile) scan next decreased     # or `scan next 93`
1 result (0.05s); see `scan list`
(procodile) table add #0 -d health  # save scan result #0 as table entry $0
(procodile) table freeze $0 999     # keep it at 999
(procodile) x -t i32 $0             # memory read, lldb-style
```

Type `tui` at the prompt (or start with `procodile -o tui`) for the full-screen interface.

## The TUI

The TUI shares its state with the REPL, so scans, the address table, pointer paths and
struct definitions carry over in both directions.

- **Left pane:** value scan results (`1`) or pointer paths (`2`).
- **Right pane:** the address table.
- **Bottom pane:** the selected address, as hex or as a struct.

Press `?` for the full key list. The main keys:

| Key | |
| --- | --- |
| `f` / `n` | first / next value scan |
| `P` | pointer scan options for the selected address: depth, max offset, result limit, read-only memory, or a saved map to scan offline |
| `x` | (pointer paths) keep only paths that lead to an address |
| `s` | edit struct definitions in a popup editor (Ctrl-S saves, Esc discards) |
| `v` | view the selection as a struct |
| `a` / `Enter` | add the selected scan result or pointer path to the table |
| `Space` / `e` | freeze / write the selected table entry |
| `p` | pick a process to attach to |
| `:` | run any REPL command |

## The REPL

Commands follow lldb's `noun verb [options]` shape. Any unique prefix works (`mem re` is
`memory read`), an empty line repeats the previous command, Tab completes, and
`help <command>` describes any command.

| Command | What it does |
| --- | --- |
| `process list/attach/detach/status/interrupt/continue` | find and control processes |
| `memory read/write/region/find/protect/allocate/free` | inspect and change memory |
| `image list/lookup` | loaded modules |
| `scan first/next/list/reset` | value scanning |
| `pointer ...` | pointer scanning (below) |
| `struct define/load/save/list/show/read/dissect/remove` | structures (below) |
| `table add/list/write/freeze/unfreeze/remove/save/load` | the address table |

Aliases: `x` (memory read), `p` (struct read), `attach`, `detach`, `c` (process continue),
`ps`, `q`.

Startup options, as in lldb: `-p <pid>` / `-n <name>` to attach, `-o <command>` to run a
command first (repeatable), `-b` to exit afterwards.

### Address expressions

Anywhere an address is expected:

| Expression | Meaning |
| --- | --- |
| `0x7ffd1000`, `4096` | numbers: hex with `0x`, otherwise decimal |
| `libc.so.6+0x10` | module base plus offset (quote names with other characters: `"ld-linux-x86-64.so.2"`) |
| `[expr]` | the pointer stored at `expr` |
| `$N` | address table entry N |
| `#N` | value scan result N |
| `@N` | pointer scan result N |

## Structures

Define the layout of data in the target with Rust struct syntax, then view memory through
it.

```rust
// game.rs: the target example's types, in memory order
#[repr(C)]
struct Stats {
    health: i32,
    armor: i32,
    mana: i32,
}

struct Player {
    name_cap: u64,
    name: *const c_char,   // [c_char; N] and *const c_char are shown as strings
    name_len: usize,       // usize/isize follow the target's pointer size
    stats: *const Stats,
    level: u32,
    #[offset(0x40)]        // an explicit offset; the gap is padding
    pos: [f32; 3],
}
```

Fields are laid out as with `#[repr(C)]`, in order with natural alignment, for the
target's pointer size. Rust doesn't guarantee the field order of a plain struct, so write
fields in the order they really are in memory.

Supported types:
- **Primitives:** `i8`..`u64`, `f32`, `f64`, `bool`, `usize`, `isize`.
- **Text:** `c_char`, a single byte shown as text. Rust's 4-byte `char` is rejected.
- **C types:** the fixed-size `std::ffi` ones (`c_int`, `c_uint`, ...). `c_long` is rejected because its size differs between Windows and Linux.
- **Raw pointers:** `*const T` and `*mut T`, including `*const c_void`.
- **Arrays:** `[T; N]`.
- **Other structs**, by name.

Paths like `std::ffi::c_char` work. Visibility, `#[repr(C)]` and other attributes are
accepted and ignored, so most `#[repr(C)]` definitions can be pasted directly.

```text
(procodile) struct load game.rs
loaded 2 structs from game.rs
(procodile) struct show Player               # layout with offsets and sizes
/* offset | size */  struct Player {
/*    0x0 |  0x8 */      name_cap: u64,
/*    0x8 |  0x8 */      name: *const c_char,
...
(procodile) p Player [target+0x5e068]        # struct read, following pointers 1 level
(Player) 0x55f7353c4220 = {
  name_cap = 4
  name = 0x55f7353c6fc0 -> "hero"
  name_len = 4
  stats = 0x55f7353c6fe0 -> (Stats) {
    health = 100
    armor = 5
    mana = 50
  }
  level = 1
}
```

`struct read` takes `-d <depth>` (how many levels of pointers to follow; `0` shows
addresses only) and `-o` (show field offsets).
`struct define 'struct Stats { armor: i32, health: i32 }'` defines structures inline, and `struct save <file>` writes all definitions back out.

For memory you don't have a definition for yet, `struct dissect <addr> [-s size]` guesses
the fields: pointers into mapped memory, text, plausible floats, zeros and integers.
`-n <name>` also defines the guess as a structure (with fields named after their offsets)
to save, rename and refine.

In the TUI, press `s` to edit all definitions in a popup editor (parse errors are shown
and the cursor jumps to the line). Select a scan result, pointer path or table entry and
press `v` to view it as a structure
instead of hex. The view updates live; `+`/`-` change the pointer depth and `[`/`]`
scroll. Press `v` and submit an empty name to go back to hex.

## Pointer scanning

A value scan finds where a value is *now*, but heap addresses change every time the
program restarts. A pointer scan finds **pointer paths** from static memory (inside a
module, so stable relative to its base) to the value, like
`[[game.exe+0x5e078]+0x18]+0x8`: read the pointer at `game.exe+0x5e078`, add `0x18`, read
the pointer there, add `0x8`. Paths can be used anywhere an address can, including in the
address table, where they keep working after a restart.

### One run: scan and filter

```text
(procodile) scan first 100
(procodile) scan next 93                  # narrow down until #0 is the value
(procodile) pointer scan #0               # find paths to it
2 pointer paths to 0x560e63f68fe8 (0.05s); see `pointer list`
(procodile) pointer list
@0     [[target+0x5e068]+0x18]+0x0  -> 0x560e63f68fe8
@1     [[target+0x5e068]+0x8]+0x20  -> 0x560e63f68fe8
(procodile) pointer save paths.txt
```

A scan usually finds many paths, and most only work by coincidence (they go through
temporary pointers). To weed them out, restart the target, find the value again, and keep
the paths that still lead to it:

```text
(procodile) pointer load paths.txt
(procodile) scan first 100 ...            # find the value in the new run
(procodile) pointer filter #0
1 of 2 paths resolve to 0x55efb7c11fe8
(procodile) table add @0 -d health        # stores the path itself
```

Options for `pointer scan`:

| Option | Default | |
| --- | --- | --- |
| `-d, --depth` | 4 | maximum number of dereferences |
| `-o, --max-offset` | 0x1000 | maximum offset after each dereference |
| `-c, --count` | 10000 | stop after this many paths |
| `--read-only` | off | also look for pointers stored in read-only memory |

Larger depths and offsets find more paths but take longer and produce more false ones.

### Several runs: pointer maps and a database

The more reliable workflow takes a **pointer map** (a snapshot of every pointer in the
process) on each run, recording where the value was in that run, and compares paths
across them offline. A pointer database keeps the maps and the results between
sessions:

```text
# run 1
(procodile) pointer open game.db          # created if missing
(procodile) scan first 100 ...            # find the value
(procodile) pointer map save #0 -l run1
saved pointer map 1: 1369 pointers, value at 0x560e63f68fe8

# restart the game, run 2
(procodile) pointer open game.db
(procodile) scan first 100 ...            # find it again
(procodile) pointer map save #0 -l run2

# compare, with or without the game running
(procodile) pointer map list
(procodile) pointer scan --map 1          # scan run 1's map offline
(procodile) pointer intersect 2           # keep paths that also work in run 2
map 2 (run2): 2 of 2 paths resolve to 0x560395745fe8
```

Save more maps and intersect with all of them (`pointer intersect 2 3 4`) until only the
reliable paths are left. Results are saved to the database whenever they change and
reloaded by `pointer open`, so a later session can pick up where you left off and
`table add @0` the survivors.

While a database is open, a live `pointer scan` also saves the map it built, so the first
run's map does not need a separate `pointer map save`.

| Command | What it does |
| --- | --- |
| `pointer scan <addr>` / `--map <id> [addr]` | find paths in the attached process / a saved map |
| `pointer list [-c N] [-s start]` | show paths and where they lead now |
| `pointer filter <addr>` | keep paths leading to `addr` in the attached process |
| `pointer intersect <id>...` | keep paths leading to each map's recorded address in that map |
| `pointer map save <addr> [-l label]` / `list` / `remove <id>` | manage saved maps |
| `pointer open <file>` / `close` | open or close a pointer database |
| `pointer save <file>` / `load <file>` | paths as a text file, one per line |
| `pointer reset` | discard the results |

The same scans are available from Rust through the
[procodile](https://docs.rs/procodile) library.

## License

MIT OR Apache-2.0.
