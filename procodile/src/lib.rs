#![doc = include_str!("../README.md")]

pub mod address;
pub mod error;
pub mod freeze;
pub mod inject;
pub mod memory;
pub mod module;
pub mod os;
pub mod process;
#[cfg(feature = "reflect")]
pub mod reflect;
pub mod scan;
pub mod structs;

mod sys;

pub use address::Address;
pub use error::{Error, Result};
pub use inject::LoadMethod;
pub use memory::{Pod, Protection, Region, RegionKind};
pub use module::Module;
pub use process::{Access, Process, ProcessHandle};

/// Access to the platform implementation behind a facade type, like std's `AsInner`.
pub(crate) trait AsInner<Inner: ?Sized> {
    fn as_inner(&self) -> &Inner;
}
