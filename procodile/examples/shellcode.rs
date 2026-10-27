//! Demonstrates the low-level `inject_bytes` + `execute_remote` primitives.
//!
//! Usage:
//!   cargo run -p procodile --example shellcode -- <pid>
//!
//! Writes a small x86-64 function (`mov eax, 42; ret`) into the target, calls it,
//! and prints the return value.

use procodile::{Access, ProcessHandle};

fn main() -> procodile::Result<()> {
    let pid: u32 = std::env::args()
        .nth(1)
        .expect("usage: shellcode <pid>")
        .parse()
        .expect("pid must be a number");

    let handle = ProcessHandle::open(pid, Access::ReadWrite)?;

    // mov eax, 42; ret
    let code: &[u8] = &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3];

    let addr = handle.inject_bytes(code)?;
    println!("Wrote {} bytes at {addr}", code.len());

    let result = handle.execute_remote(addr, 0)?;
    println!("execute_remote returned: {result}");
    assert_eq!(result, 42);

    Ok(())
}
