use std::ffi::{OsStr, OsString};
use std::fs::File;

pub(crate) struct LinuxProcessInner {
    pub(crate) pid: i32,
    pub(crate) name: OsString,
}

#[derive(Debug)]
pub struct LinuxProcessHandle {
    pub(crate) pid: i32,
    pub(crate) mem_file: File,
}

impl LinuxProcessInner {
    pub fn name_is(&self, compare: &OsStr) -> bool {
        self.name == compare
    }

    pub fn id(&self) -> usize {
        self.pid as usize
    }

    pub fn name(&self) -> OsString {
        self.name.clone()
    }
}
