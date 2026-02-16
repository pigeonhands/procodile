pub mod error;

use std::ffi::OsStr;

use crate::{
    mem::ProcessAccess,
    process::{Process, ProcessHandle, ProcessInner},
};
pub use error::{ProcessBasicError, Result};

pub mod inner {
    #[cfg(target_os = "windows")]
    pub(crate) mod windows;
}

impl Process {
    pub fn iter_processes() -> impl Iterator<Item = Process> {
        ProcessInner::iter_processes().map(Process::from_inner)
    }

    pub fn by_name(name: &OsStr) -> impl Iterator<Item = Process> {
        ProcessInner::iter_processes()
            .filter(|p| p.name_is(name))
            .map(Process::from_inner)
    }

    pub fn open_process(&self, access: ProcessAccess) -> Result<ProcessHandle> {
        self.inner.open_process(access).map(ProcessHandle)
    }
}
