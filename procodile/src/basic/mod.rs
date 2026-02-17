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

    pub fn by_id(id: usize) -> Result<Self> {
        ProcessInner::iter_processes()
            .filter(|p| p.0.UniqueProcessId as usize == id)
            .next()
            .map(Process::from_inner)
            .ok_or_else(|| ProcessBasicError::ProcessNotFound(id))
    }

    pub fn by_name(name: &OsStr) -> impl Iterator<Item = Process> {
        ProcessInner::iter_processes()
            .filter(|p| p.name_is(name))
            .map(Process::from_inner)
    }

    pub fn open_process(&self, access: ProcessAccess) -> Result<ProcessHandle> {
        self.inner.open_process(access).map(ProcessHandle)
    }

    pub fn current_process_id() -> Result<usize> {
        Ok(ProcessInner::current_process_id())
    }
    pub fn open_current_process() -> Result<ProcessHandle> {
        Ok(ProcessHandle(ProcessInner::open_current_process()))
    }
}
