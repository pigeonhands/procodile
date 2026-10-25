//! Platform backends. This is the only place (besides `os`) that selects on `cfg`.
//!
//! Every backend exposes the same items with the same signatures:
//!
//! - `process::{Process, Processes, Handle, processes, current_pid}`
//! - `impl Handle { suspend, resume }` (in `process`)
//! - `impl Handle { read_at, write_at, regions, protect, allocate, free }` (in `memory`)
//!
//! The facades in the crate root wrap these types one-to-one.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("procodile only supports Linux and Windows");
