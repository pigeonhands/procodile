//! Loads a shared library into a running process and prints the resulting module.
//!
//! Usage:
//!   cargo run -p procodile --example inject -- <pid> <path-to-library> [loader|manual]
//!
//! The optional third argument selects the loading method:
//!   loader  (default) — OS loader (LoadLibraryW / dlopen via ptrace)
//!   manual             — direct ELF/PE mapping without the OS loader
//!                        (requires `--features inject`)

use procodile::{Access, ProcessHandle};

fn main() -> procodile::Result<()> {
    let mut args = std::env::args().skip(1);
    let pid: u32 = args
        .next()
        .expect("usage: inject <pid> <path> [loader|manual]")
        .parse()
        .expect("pid must be a number");
    let path = args
        .next()
        .expect("usage: inject <pid> <path> [loader|manual]");
    let manual = args.next().as_deref() == Some("manual");

    let handle = ProcessHandle::open(pid, Access::ReadWrite)?;

    let module = if manual {
        #[cfg(feature = "inject")]
        {
            println!("Injecting {path:?} into pid {pid} via manual map...");
            handle.inject_file(&path)?
        }
        #[cfg(not(feature = "inject"))]
        {
            eprintln!("manual mapping requires --features inject");
            std::process::exit(1);
        }
    } else {
        println!("Injecting {path:?} into pid {pid} via OS loader...");
        handle.load_library(&path, procodile::LoadMethod::Loader)?
    };

    println!("  Module: {}", module.name.to_string_lossy());
    println!("    Base: {}", module.base);
    println!("    Size: {:#x} ({} bytes)", module.size, module.size);
    if module.path != std::path::PathBuf::new() {
        println!("    Path: {}", module.path.display());
    }

    println!("\nAll modules after injection:");
    for (i, m) in handle.modules()?.iter().enumerate() {
        println!(
            "[{i:>3}] {:?} {:>#10x}  {}",
            m.base,
            m.size,
            m.name.to_string_lossy()
        );
    }

    Ok(())
}
