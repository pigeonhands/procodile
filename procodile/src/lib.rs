//! Cross-platform primitives for inspecting and modifying the memory of other processes.
//!
//! The layout follows the standard library: the public modules (`process`, `memory`, ...)
//! are thin, platform-independent facades over `sys`, which holds one backend per OS.
//! Functionality that only exists on one platform is exposed through extension traits
//! in [`os`].

pub mod address;
pub mod error;
pub mod memory;
pub mod os;
pub mod process;

mod sys;

pub use address::Address;
pub use error::{Error, Result};
pub use memory::{Pod, Protection, Region, RegionKind};
pub use process::{Access, Process, ProcessHandle};

/// Access to the platform implementation behind a facade type, like std's `AsInner`.
pub(crate) trait AsInner<Inner: ?Sized> {
    fn as_inner(&self) -> &Inner;
}
