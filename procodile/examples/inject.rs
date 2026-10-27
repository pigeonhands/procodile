//! Loads a shared library into a running process and prints the resulting module.
//!
//! Usage:
//!   cargo run -p procodile --example inject -- <pid> <path-to-library> [loader|manual]
//!
//! The optional third argument selects the loading method:
//!   loader  (default) — OS loader (LoadLibraryW / dlopen via ptrace)
//!   manual             — direct ELF/PE mapping without the OS loader
//!
//! To build a small marker library for testing, create `examples/injectme/lib.rs`:
//!
//!   // lib.rs
//!   #[no_mangle]
//!   pub extern "C" fn procodile_marker() {}
//!
//!   #[cfg(target_os = "linux")]
//!   #[used]
//!   #[link_section = ".init_array"]
//!   static INIT: extern "C" fn() = init;
//!   extern "C" fn init() {
//!       let _ = std::fs::write("/tmp/procodile_inject_ok", b"ok\n");
//!   }
//!
//! Then: cargo build --example injectme && run this example pointing at the .so.
//! After injection, `/tmp/procodile_inject_ok` will contain "ok" confirming the
//! library loaded and its constructor ran.

use procodile::{Access, LoadMethod, ProcessHandle};

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
    let method = match args.next().as_deref() {
        Some("manual") => LoadMethod::ManualMap,
        _ => LoadMethod::Loader,
    };

    let handle = ProcessHandle::open(pid, Access::ReadWrite)?;

    let method_label = match method {
        LoadMethod::Loader => "loader",
        LoadMethod::ManualMap => "manual",
    };
    println!("Injecting {path:?} into pid {pid} via {method_label}...");

    let module = handle.load_library(&path, method)?;

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
