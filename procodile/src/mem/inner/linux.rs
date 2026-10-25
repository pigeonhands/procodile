use std::ffi::c_void;
use std::os::unix::fs::FileExt;
use std::slice;

use crate::mem::error::{MemoryError, Result};
use crate::mem::ActiveMemoryRegion;
use crate::process::inner::LinuxProcessHandle;

pub(crate) struct LinuxMemoryPage {
    base_address: usize,
    size: usize,
    // bit0 = read, bit1 = write, bit2 = execute
    prot: u8,
}

impl LinuxMemoryPage {
    pub fn base_address(&self) -> *const c_void {
        self.base_address as *const c_void
    }

    pub fn region_size(&self) -> usize {
        self.size
    }

    pub fn raw_protection_flags(&self) -> u32 {
        self.prot as u32
    }

    pub fn is_read(&self) -> bool {
        self.is_read_write() || self.is_read_only() || self.is_read_execute()
    }

    pub fn is_read_only(&self) -> bool {
        self.prot == 0b001
    }

    pub fn is_execute(&self) -> bool {
        self.prot == 0b100
    }

    pub fn is_read_write(&self) -> bool {
        self.prot == 0b011
    }

    pub fn is_read_execute(&self) -> bool {
        self.prot == 0b101
    }
}

struct MapsEntry {
    start: usize,
    end: usize,
    read: bool,
    write: bool,
    exec: bool,
}

fn parse_maps(pid: i32) -> Result<Vec<MapsEntry>> {
    let contents =
        std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|_| MemoryError::MemoryPageFail)?;

    Ok(contents.lines().filter_map(parse_maps_line).collect())
}

fn parse_maps_line(line: &str) -> Option<MapsEntry> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;

    let (start_str, end_str) = range.split_once('-')?;
    let start = usize::from_str_radix(start_str, 16).ok()?;
    let end = usize::from_str_radix(end_str, 16).ok()?;

    let mut chars = perms.chars();
    let read = chars.next()? == 'r';
    let write = chars.next()? == 'w';
    let exec = chars.next()? == 'x';

    Some(MapsEntry {
        start,
        end,
        read,
        write,
        exec,
    })
}

fn active_region_flags(read: bool, write: bool, exec: bool) -> u16 {
    match (read, write, exec) {
        (true, false, false) => 1,
        (false, false, true) => 2,
        (true, false, true) => 3,
        (true, true, _) => 4,
        _ => 0,
    }
}

impl LinuxProcessHandle {
    pub unsafe fn read_memory(
        &self,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
    ) -> Result<usize> {
        let buf = unsafe { slice::from_raw_parts_mut(buffer as *mut u8, size) };
        self.mem_file
            .read_at(buf, address as u64)
            .map_err(|_| MemoryError::MemoryReadFail(address))
    }

    pub unsafe fn write_memory(
        &self,
        address: *const c_void,
        buffer: *const c_void,
        size: usize,
    ) -> Result<usize> {
        let buf = unsafe { slice::from_raw_parts(buffer as *const u8, size) };
        self.mem_file
            .write_at(buf, address as u64)
            .map_err(|_| MemoryError::MemoryWriteFail(address))
    }

    pub fn get_memory_regions(
        &self,
        start_address: *const c_void,
        end_address: *const c_void,
    ) -> Result<std::vec::IntoIter<LinuxMemoryPage>> {
        let start_address = start_address as usize;
        let end_address = end_address as usize;

        let pages: Vec<LinuxMemoryPage> = parse_maps(self.pid)?
            .into_iter()
            .filter(|e| e.read || e.write || e.exec)
            .filter_map(|e| {
                let region_start = e.start.max(start_address);
                let region_end = e.end.min(end_address);
                if region_start >= region_end {
                    return None;
                }
                let prot = (e.read as u8) | ((e.write as u8) << 1) | ((e.exec as u8) << 2);
                Some(LinuxMemoryPage {
                    base_address: region_start,
                    size: region_end - region_start,
                    prot,
                })
            })
            .collect();

        Ok(pages.into_iter())
    }

    pub fn get_active_memory_regions(&self) -> Result<std::vec::IntoIter<ActiveMemoryRegion>> {
        let regions: Vec<ActiveMemoryRegion> = parse_maps(self.pid)?
            .into_iter()
            .filter_map(|e| {
                let flags = active_region_flags(e.read, e.write, e.exec);
                if flags == 0 {
                    return None;
                }
                Some(ActiveMemoryRegion {
                    base_address: e.start,
                    memory_size: e.end - e.start,
                    flags,
                })
            })
            .collect();

        Ok(regions.into_iter())
    }
}
