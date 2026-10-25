use procodile::mem::ProcessAccess;
use procodile::process::Process;

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
            let mut processes: Vec<Process> = Process::iter_processes().collect();
            processes.sort_by_key(|p| p.id());
            println!("{:>8}  NAME", "PID");
            for p in processes {
                println!("{:>8}  {}", p.id(), p.name().to_string_lossy());
            }
        }
    }
}

fn dispatch_attach(session: &mut Session, pid: usize) {
    let process = match Process::by_id(pid) {
        Ok(p) => p,
        Err(e) => {
            println!("Error: {e}");
            return;
        }
    };
    let handle = match process.open_process(ProcessAccess::ReadWrite) {
        Ok(h) => h,
        Err(e) => {
            println!("Error: failed to attach to pid {pid}: {e}");
            return;
        }
    };
    println!(
        "Attached to {} (pid {})",
        process.name().to_string_lossy(),
        process.id()
    );
    session.attached = Some(AttachedProcess { process, handle });
}

fn dispatch_detach(session: &mut Session) {
    match session.attached.take() {
        Some(a) => println!(
            "Detached from {} (pid {})",
            a.process.name().to_string_lossy(),
            a.process.id()
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
            match unsafe { attached.handle.read_memory_to_buffer(addr, &mut buffer) } {
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
            match unsafe { attached.handle.write_memory_to_buffer(addr, &bytes) } {
                Ok(n) => println!("Wrote {n} byte(s) to {addr:?}"),
                Err(e) => println!("Error: {e}"),
            }
        }
    }
}

fn print_hex_dump(base: *const std::ffi::c_void, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let addr = base as usize + i * 16;
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
