//! Linux-specific extensions.

use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

use crate::{AsInner, ProcessHandle};

pub trait ProcessHandleExt {
    /// The open `/proc/<pid>/mem` file backing this handle.
    fn mem_file(&self) -> &File;
}

impl ProcessHandleExt for ProcessHandle {
    fn mem_file(&self) -> &File {
        &self.as_inner().mem
    }
}

impl AsFd for ProcessHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.mem_file().as_fd()
    }
}

impl AsRawFd for ProcessHandle {
    fn as_raw_fd(&self) -> RawFd {
        self.mem_file().as_raw_fd()
    }
}
