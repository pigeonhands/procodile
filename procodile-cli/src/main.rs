mod cli;
mod commands;
mod completion;
mod expr;
mod format;
mod session;
mod table;

use std::path::PathBuf;
use std::sync::atomic::Ordering;

use clap::Parser;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{Config, Editor};

use cli::{ALIASES, Cli, Command};
use commands::INTERRUPTED;
use completion::CommandCompleter;
use session::Session;

/// An interactive process memory tool, in the style of lldb.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Attach to this pid on startup.
    #[arg(short, long)]
    pid: Option<u32>,
    /// Attach to the process with this name on startup.
    #[arg(short, long, conflicts_with = "pid")]
    name: Option<String>,
    /// Run these commands before the prompt (repeatable), like lldb's -o.
    #[arg(short = 'o', long = "one-line")]
    commands: Vec<String>,
    /// Exit after running the -o commands.
    #[arg(short, long)]
    batch: bool,
}

const PROMPT: &str = "(procodile) ";

fn main() -> rustyline::Result<()> {
    let args = Args::parse();
    let _ = ctrlc::set_handler(|| INTERRUPTED.store(true, Ordering::Relaxed));

    let mut session = Session::new();
    let attach = match (args.pid, &args.name) {
        (Some(pid), _) => Some(format!("process attach -p {pid}")),
        (_, Some(name)) => Some(format!("process attach -n {}", quote(name))),
        _ => None,
    };
    for line in attach.iter().chain(&args.commands) {
        if args.batch || !args.commands.is_empty() {
            println!("{PROMPT}{line}");
        }
        if !execute(&mut session, line) {
            return Ok(());
        }
    }
    if args.batch {
        return Ok(());
    }

    let mut rl: Editor<CommandCompleter, DefaultHistory> =
        Editor::with_config(Config::builder().auto_add_history(false).build())?;
    rl.set_helper(Some(CommandCompleter::new()));
    let history = history_path();
    if let Some(path) = &history {
        let _ = rl.load_history(path);
    }

    let mut last = String::new();
    loop {
        match rl.readline(PROMPT) {
            Ok(line) => {
                // As in lldb, an empty line repeats the previous command.
                let line = if line.trim().is_empty() {
                    last.clone()
                } else {
                    line
                };
                if line.trim().is_empty() {
                    continue;
                }
                if line != last {
                    rl.add_history_entry(line.as_str())?;
                }
                last = line.clone();
                if !execute(&mut session, &line) {
                    break;
                }
            }
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("error: {err}");
                break;
            }
        }
    }

    if let Some(path) = &history {
        let _ = rl.save_history(path);
    }
    Ok(())
}

/// Runs one command line. Returns false when the REPL should exit.
fn execute(session: &mut Session, line: &str) -> bool {
    let Some(mut words) = split_words(line) else {
        eprintln!("error: unbalanced quotes");
        return true;
    };
    if let Some((_, full)) = words
        .first()
        .and_then(|w| ALIASES.iter().find(|(a, _)| a == w))
    {
        words.splice(0..1, full.split(' ').map(String::from));
    }

    INTERRUPTED.store(false, Ordering::Relaxed);
    match Cli::try_parse_from(&words) {
        Ok(Cli {
            command: Command::Quit,
        }) => return false,
        Ok(cli) => {
            if let Err(e) = commands::run(session, cli.command) {
                eprintln!("error: {e}");
            }
        }
        Err(e) => {
            let _ = e.print();
        }
    }
    true
}

/// Splits a command line into words, honouring '...' and "..." quotes and backslash
/// escapes. Unlike a shell, `#` is not a comment (it means a scan result).
fn split_words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut quote = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, c) if c.is_whitespace() => words.extend(word.take()),
            (None, '\'' | '"') => {
                quote = Some(c);
                word.get_or_insert_default();
            }
            (Some(q), c) if c == q => quote = None,
            (Some('\''), c) => word.get_or_insert_default().push(c),
            (_, '\\') => word.get_or_insert_default().push(chars.next()?),
            (_, c) => word.get_or_insert_default().push(c),
        }
    }
    if quote.is_some() {
        return None;
    }
    words.extend(word);
    Some(words)
}

fn history_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".procodile_history"))
}

fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_words() {
        let split = |s| split_words(s).unwrap();
        assert_eq!(
            split("table add #0 -d 'max hp'"),
            ["table", "add", "#0", "-d", "max hp"]
        );
        assert_eq!(split(r#"a "b c" d\ e ''"#), ["a", "b c", "d e", ""]);
        assert_eq!(split("  "), Vec::<String>::new());
        assert!(split_words("'open").is_none());
    }
}
