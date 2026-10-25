use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    multicall = true,
    infer_subcommands = true // This is the magic line
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Process {
        #[command(subcommand)]
        sub: ProcessCommands,
    },
    Attach {
        pid: u32,
    },
    Detach,
    Memory {
        #[command(subcommand)]
        sub: MemoryCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProcessCommands {
    List,
}

#[derive(Debug, Subcommand)]
pub enum MemoryCommands {
    Read {
        address: String,
        #[arg(long, short, default_value_t = 16)]
        size: usize,
    },
    Write {
        address: String,
        value: String,
    },
}
