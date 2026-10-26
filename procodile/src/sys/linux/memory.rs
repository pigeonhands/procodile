use std::io;
use std::os::unix::fs::FileExt;

use super::maps::{self, MapsEntry};
use super::process::Handle;
use crate::{Address, Protection, Region};

impl Handle {
    pub fn read_at(&self, address: Address, buf: &mut [u8]) -> io::Result<usize> {
        self.mem.read_at(buf, address.get() as u64)
    }

    pub fn write_at(&self, address: Address, buf: &[u8]) -> io::Result<usize> {
        // /proc/pid/mem writes go through FOLL_FORCE, so they ignore page protection.
        self.mem.write_at(buf, address.get() as u64)
    }

    pub fn regions(&self) -> io::Result<Vec<Region>> {
        Ok(self.maps()?.iter().map(MapsEntry::to_region).collect())
    }

    pub fn protect(&self, _: Address, _: usize, _: Protection) -> io::Result<Protection> {
        Err(io::ErrorKind::Unsupported.into())
    }

    // Remote allocation needs syscall injection through ptrace.
    pub fn allocate(&self, _: usize, _: Protection) -> io::Result<Address> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn free(&self, _: Address) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// The process's mappings, in address order.
    ///
    /// The kernel generates `maps` a page at a time, so if another thread maps or unmaps
    /// memory while it is read, lines can come back repeated or out of order; sort and drop
    /// overlaps so callers always see a consistent list.
    pub(crate) fn maps(&self) -> io::Result<Vec<MapsEntry>> {
        let contents = std::fs::read(format!("/proc/{}/maps", self.pid()))?;
        let mut entries = maps::parse(&contents);
        entries.sort_by_key(|e| e.start);
        let mut end = 0;
        entries.retain(|e| {
            let keep = e.start >= end;
            if keep {
                end = e.end;
            }
            keep
        });
        Ok(entries)
    }
}
