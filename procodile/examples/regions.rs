//! Lists the memory regions and modules of a process (default: this one).
//!
//! `cargo run -p procodile --example regions [pid]`

use procodile::{Access, ProcessHandle};

fn main() -> procodile::Result<()> {
    let handle = match std::env::args().nth(1) {
        Some(pid) => ProcessHandle::open(pid.parse().expect("pid"), Access::Read)?,
        None => ProcessHandle::open_current()?,
    };

    let regions = handle.regions()?;
    for r in &regions {
        let path = r.path.as_deref().map(|p| p.display().to_string());
        println!(
            "[{:?}-{:?}) {:<5} {:<8?} {}",
            r.base,
            r.end(),
            r.protection,
            r.kind,
            path.unwrap_or_default()
        );
    }
    let total: usize = regions.iter().map(|r| r.size).sum();
    println!("{} regions, {total:#x} bytes\n", regions.len());

    for m in handle.modules()? {
        println!("{:?} {:>#10x} {}", m.base, m.size, m.path.display());
    }
    Ok(())
}
