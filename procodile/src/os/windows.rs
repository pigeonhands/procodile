//! Windows-specific extensions.

use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, RawHandle};

use crate::{Address, AsInner, Error, ProcessHandle, Protection, Result};

/// A run of contiguous pages in a process's working set (resident in physical memory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentRange {
    pub base: Address,
    pub size: usize,
    pub protection: Protection,
    pub shared: bool,
}

pub trait ProcessHandleExt {
    /// The pages of the process currently resident in memory, from `QueryWorkingSet`.
    ///
    /// Unlike [`ProcessHandle::regions`], this omits committed pages that are paged out.
    fn resident_ranges(&self) -> Result<Vec<ResidentRange>>;
}

impl ProcessHandleExt for ProcessHandle {
    fn resident_ranges(&self) -> Result<Vec<ResidentRange>> {
        self.as_inner()
            .resident_ranges()
            .map_err(Error::query("working set"))
    }
}

impl AsHandle for ProcessHandle {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.as_inner().owned().as_handle()
    }
}

impl AsRawHandle for ProcessHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_inner().raw()
    }
}
