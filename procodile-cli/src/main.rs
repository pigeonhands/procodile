use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, Result};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    multicall=true,
    infer_subcommands = true // This is the magic line
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    Memory {
        #[command(subcommand)]
        sub: MemoryCommands,
    },
}

#[derive(Debug, clap::Subcommand)]
enum MemoryCommands {
    Read { address: String },
    Write { address: String },
}

fn main() -> Result<()> {
    let mut rl = DefaultEditor::new()?;

    loop {
        let readline = rl.readline("(procodile) ");
        match readline {
            Ok(mut line) => {
                if line.trim().is_empty() {
                    if let Some(last_history) = rl.history().iter().last() {
                        line = last_history.clone();
                    } else {
                        continue;
                    }
                }
                rl.add_history_entry(line.as_str())?;

                // 1. Lex the string into a Vec of tokens
                // Use shlex so that "my argument" stays one token
                let words = shlex::split(&line).ok_or("Invalid quoting").unwrap();

                // 2. Parse with Clap
                // we use try_parse_from so it doesn't crash the whole app on error
                match Cli::try_parse_from(words) {
                    Ok(cli) => {
                        println!("{:?}", cli);
                    }
                    Err(e) => {
                        // This prints help or error messages to the user
                        e.print()?;
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(err) => println!("Error: {:?}", err),
        }
    }
    Ok(())
}
