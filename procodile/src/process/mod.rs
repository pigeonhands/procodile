#[cfg(target_os = "windows")]
pub(crate) mod inner {
    pub mod windows;
    pub use windows::*;

    pub use windows::WindowsProcessHandle as ProcessHandle;
    pub(crate) use windows::WindowsProcessInner as ProcessInner;
}

#[cfg(target_os = "linux")]
pub(crate) mod inner {
    pub mod linux;
    pub use linux::*;

    pub use linux::LinuxProcessHandle as ProcessHandle;
    pub(crate) use linux::LinuxProcessInner as ProcessInner;
}

pub mod error;

use std::ffi::OsString;

//pub use error::{ProcessError, Result};
pub(crate) use inner::ProcessInner;

#[derive(Debug)]
pub struct ProcessHandle(pub(crate) inner::ProcessHandle);

pub struct Process {
    pub(crate) inner: ProcessInner,
}

impl Process {
    pub(crate) fn from_inner(inner: ProcessInner) -> Self {
        Self { inner }
    }

    pub fn name(&self) -> OsString {
        self.inner.name()
    }

    pub fn id(&self) -> usize {
        self.inner.id()
    }
}
