#[cfg(target_os = "windows")]
pub(crate) mod inner {
    pub mod windows;
    pub use windows::*;

    pub use windows::WindowsProcessHandle as ProcessHandle;
    pub(crate) use windows::WindowsProcessInner as ProcessInner;
}

pub mod error;

use std::ffi::OsString;

//pub use error::{ProcessError, Result};
pub(crate) use inner::ProcessInner;
use widestring::U16CStr;

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
        let image_name = self.inner.0.ImageName;
        let wide_str = unsafe { U16CStr::from_ptr(image_name.Buffer, image_name.Length as usize) }
            .unwrap_or_default();
        wide_str.to_os_string()
    }

    pub fn id(&self) -> usize {
        self.inner.0.UniqueProcessId as usize
    }
}
