use procodile::{Access, Address, Process};

use crate::cli::{Commands, MemoryCommands, ProcessCommands};
use crate::parse::{parse_address, parse_bytes};
use crate::session::{AttachedProcess, Session};

pub fn dispatch(session: &mut Session, command: Commands) {
    match command {
        Commands::Process { sub } => dispatch_process(sub),
        Commands::Attach { pid } => dispatch_attach(session, pid),
        Commands::Detach => dispatch_detach(session),
        Commands::Memory { sub } => dispatch_memory(session, sub),
    }
}

fn dispatch_process(sub: ProcessCommands) {
    match sub {
        ProcessCommands::List => {
            let mut processes: Vec<Process> = match procodile::process::processes() {
                Ok(p) => p.collect(),
                Err(e) => {
                    println!("Error: {e}");
                    return;
                }
            };
            processes.sort_by_key(|p| p.pid());
            println!("{:>8}  NAME", "PID");
            for p in processes {
                println!("{:>8}  {}", p.pid(), p.name().to_string_lossy());
            }
        }
    }
}

fn dispatch_attach(session: &mut Session, pid: u32) {
    let process = match Process::by_pid(pid) {
        Ok(p) => p,
        Err(e) => {
            println!("Error: {e}");
            return;
        }
    };
    let handle = match process.open(Access::ReadWrite) {
        Ok(h) => h,
        Err(e) => {
            println!("Error: failed to attach to pid {pid}: {e}");
            return;
        }
    };
    println!(
        "Attached to {} (pid {})",
        process.name().to_string_lossy(),
        process.pid()
    );
    session.attached = Some(AttachedProcess { process, handle });
}

fn dispatch_detach(session: &mut Session) {
    match session.attached.take() {
        Some(a) => println!(
            "Detached from {} (pid {})",
            a.process.name().to_string_lossy(),
            a.process.pid()
        ),
        None => println!("Error: no process attached"),
    }
}

fn dispatch_memory(session: &mut Session, sub: MemoryCommands) {
    let Some(attached) = session.attached.as_ref() else {
        println!("Error: no process attached. Use `attach <pid>` first.");
        return;
    };

    match sub {
        MemoryCommands::Read { address, size } => {
            let addr = match parse_address(&address) {
                Ok(a) => a,
                Err(e) => {
                    println!("Error: {e}");
                    return;
                }
            };
            let mut buffer = vec![0u8; size];
            match attached.handle.read_bytes(addr, &mut buffer) {
                Ok(n) => print_hex_dump(addr, &buffer[..n]),
                Err(e) => println!("Error: {e}"),
            }
        }
        MemoryCommands::Write { address, value } => {
            let addr = match parse_address(&address) {
                Ok(a) => a,
                Err(e) => {
                    println!("Error: {e}");
                    return;
                }
            };
            let bytes = match parse_bytes(&value) {
                Ok(b) => b,
                Err(e) => {
                    println!("Error: {e}");
                    return;
                }
            };
            match attached.handle.write_bytes(addr, &bytes) {
                Ok(n) => println!("Wrote {n} byte(s) to {addr:?}"),
                Err(e) => println!("Error: {e}"),
            }
        }
    }
}

fn print_hex_dump(base: Address, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base.get() + i * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("{addr:#016x}  {:<47}  {ascii}", hex.join(" "));
    }
}
