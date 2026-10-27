//! Platform backends. This is the only place (besides `os`) that selects on `cfg`.
//!
//! Every backend exposes the same items with the same signatures:
//!
//! - `process::{Process, Processes, Handle, processes, current_pid}`
//! - `impl Handle { suspend, resume }` (in `process`)
//! - `impl Handle { read_at, write_at, regions, protect, allocate, free }` (in `memory`)
//! - `impl Handle { modules }` (in `module`)
//! - `impl Handle { load_library(&Path) -> io::Result<Address> }` (in `inject`)
//!   Loads a shared library via the OS loader (`LoadLibraryW`/`dlopen`), returning the
//!   module's base address. Returns `io::ErrorKind::Unsupported` if the architecture or
//!   environment does not allow loader-based injection.
//! - `impl Handle { map_image(&[u8]) -> io::Result<(Address, usize)> }` (in `inject`)
//!   Maps a shared library image directly into the target without the OS loader, returning
//!   `(base, mapped_size)`. x86-64 only in the first pass.
//! - `fn inject_bytes(&ProcessHandle, &[u8]) -> io::Result<Address>` (in `inject`)
//!   Allocates RWX memory in the target and writes `data` into it.
//! - `fn execute_remote(&ProcessHandle, Address, u64) -> io::Result<u64>` (in `inject`)
//!   Runs code at an address in the target, passing one argument; returns the result.
//!
//! The facades in the crate root wrap these types one-to-one.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::*;
#[cfg(target_os = "linux")]
pub(crate) use linux::inject;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;
#[cfg(windows)]
pub(crate) use windows::inject;

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("procodile only supports Linux and Windows");
