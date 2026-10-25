use std::io;
use std::mem::MaybeUninit;

use windows_sys::Win32::Foundation::{ERROR_BAD_LENGTH, ERROR_PARTIAL_COPY};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_NOCACHE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx,
};
use windows_sys::Win32::System::ProcessStatus::QueryWorkingSet;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use super::cvt;
use super::process::Handle;
use crate::os::windows::ResidentRange;
use crate::{Address, Protection, Region, RegionKind};

impl Handle {
    pub fn read_at(&self, address: Address, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0;
        let result = cvt(unsafe {
            ReadProcessMemory(
                self.raw(),
                address.get() as *const _,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut done,
            )
        });
        partial(result, done)
    }

    pub fn write_at(&self, address: Address, buf: &[u8]) -> io::Result<usize> {
        let mut done = 0;
        let result = cvt(unsafe {
            WriteProcessMemory(
                self.raw(),
                address.get() as *const _,
                buf.as_ptr().cast(),
                buf.len(),
                &mut done,
            )
        });
        partial(result, done)
    }

    pub fn regions(&self) -> io::Result<Vec<Region>> {
        let mut regions = Vec::new();
        let mut address = 0usize;
        loop {
            let mut mbi = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
            let written = unsafe {
                VirtualQueryEx(
                    self.raw(),
                    address as *const _,
                    mbi.as_mut_ptr(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                // ERROR_INVALID_PARAMETER marks the end of the address space.
                let err = io::Error::last_os_error();
                if regions.is_empty() {
                    return Err(err);
                }
                break;
            }
            let mbi = unsafe { mbi.assume_init() };

            if mbi.State == MEM_COMMIT {
                regions.push(Region {
                    base: Address::new(mbi.BaseAddress as usize),
                    size: mbi.RegionSize,
                    protection: protection(mbi.Protect),
                    kind: match mbi.Type {
                        MEM_IMAGE => RegionKind::Image,
                        MEM_MAPPED => RegionKind::Mapped,
                        _ => RegionKind::Private,
                    },
                    path: None,
                });
            }

            match (mbi.BaseAddress as usize).checked_add(mbi.RegionSize) {
                Some(next) if next > address => address = next,
                _ => break,
            }
        }
        Ok(regions)
    }

    pub fn protect(
        &self,
        address: Address,
        size: usize,
        protection: Protection,
    ) -> io::Result<Protection> {
        let mut old = 0;
        cvt(unsafe {
            VirtualProtectEx(
                self.raw(),
                address.get() as *const _,
                size,
                page_protection(protection),
                &mut old,
            )
        })?;
        Ok(self::protection(old))
    }

    pub fn allocate(&self, size: usize, protection: Protection) -> io::Result<Address> {
        let ptr = unsafe {
            VirtualAllocEx(
                self.raw(),
                std::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                page_protection(protection),
            )
        };
        if ptr.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Address::new(ptr as usize))
    }

    pub fn free(&self, address: Address) -> io::Result<()> {
        cvt(unsafe { VirtualFreeEx(self.raw(), address.get() as *mut _, 0, MEM_RELEASE) })
    }

    /// The pages currently in the process's working set, merged into contiguous ranges.
    pub(crate) fn resident_ranges(&self) -> io::Result<Vec<ResidentRange>> {
        let page_size = unsafe {
            let mut info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(info.as_mut_ptr());
            info.assume_init().dwPageSize as usize
        };

        // PSAPI_WORKING_SET_INFORMATION is a usize count followed by one usize per page.
        let mut buf: Vec<usize> = vec![0; 4096];
        loop {
            let result = cvt(unsafe {
                QueryWorkingSet(
                    self.raw(),
                    buf.as_mut_ptr().cast(),
                    (buf.len() * size_of::<usize>()) as u32,
                )
            });
            match result {
                Ok(()) => break,
                Err(e) if e.raw_os_error() == Some(ERROR_BAD_LENGTH as i32) => {
                    // The working set can grow before the next call.
                    let entries = buf[0];
                    buf.resize(1 + entries + entries / 4 + 64, 0);
                }
                Err(e) => return Err(e),
            }
        }

        let entries = buf[0].min(buf.len() - 1);
        let mut blocks = buf[1..=entries].to_vec();
        blocks.sort_unstable_by_key(|flags| flags & !0xfff);

        let mut ranges: Vec<ResidentRange> = Vec::new();
        for flags in blocks {
            let base = Address::new(flags & !0xfff);
            let protection = working_set_protection(flags & 0x1f);
            let shared = flags & 0x100 != 0;
            match ranges.last_mut() {
                Some(last)
                    if last.base + last.size == base
                        && last.protection == protection
                        && last.shared == shared =>
                {
                    last.size += page_size;
                }
                _ => ranges.push(ResidentRange {
                    base,
                    size: page_size,
                    protection,
                    shared,
                }),
            }
        }
        Ok(ranges)
    }
}

/// A failed transfer that still moved some bytes is reported as a short count, like a
/// partial `pread`.
fn partial(result: io::Result<()>, done: usize) -> io::Result<usize> {
    match result {
        Ok(()) => Ok(done),
        Err(e) if done > 0 && e.raw_os_error() == Some(ERROR_PARTIAL_COPY as i32) => Ok(done),
        Err(e) => Err(e),
    }
}

fn protection(protect: PAGE_PROTECTION_FLAGS) -> Protection {
    let mut p = match protect & 0xff {
        PAGE_READONLY => Protection::READ,
        PAGE_READWRITE => Protection::READ_WRITE,
        PAGE_WRITECOPY => Protection::READ_WRITE | Protection::COPY_ON_WRITE,
        PAGE_EXECUTE => Protection::EXECUTE,
        PAGE_EXECUTE_READ => Protection::READ_EXECUTE,
        PAGE_EXECUTE_READWRITE => Protection::READ_WRITE_EXECUTE,
        PAGE_EXECUTE_WRITECOPY => Protection::READ_WRITE_EXECUTE | Protection::COPY_ON_WRITE,
        _ => Protection::NONE,
    };
    if protect & PAGE_GUARD != 0 {
        p |= Protection::GUARD;
    }
    if protect & PAGE_NOCACHE != 0 {
        p |= Protection::NO_CACHE;
    }
    p
}

fn page_protection(p: Protection) -> PAGE_PROTECTION_FLAGS {
    let rwx = (
        p.contains(Protection::READ),
        p.contains(Protection::WRITE),
        p.executable(),
    );
    let cow = p.contains(Protection::COPY_ON_WRITE);
    let mut flags = match rwx {
        (_, true, true) if cow => PAGE_EXECUTE_WRITECOPY,
        (_, true, true) => PAGE_EXECUTE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, false, true) => PAGE_EXECUTE,
        (_, true, false) if cow => PAGE_WRITECOPY,
        (_, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        (false, false, false) => PAGE_NOACCESS,
    };
    if p.contains(Protection::GUARD) {
        flags |= PAGE_GUARD;
    }
    if p.contains(Protection::NO_CACHE) {
        flags |= PAGE_NOCACHE;
    }
    flags
}

/// Decodes the 5-bit memory-manager protection code stored in a working set block.
fn working_set_protection(code: usize) -> Protection {
    let mut p = match code & 0x7 {
        1 => Protection::READ,
        2 => Protection::EXECUTE,
        3 => Protection::READ_EXECUTE,
        4 => Protection::READ_WRITE,
        5 => Protection::READ_WRITE | Protection::COPY_ON_WRITE,
        6 => Protection::READ_WRITE_EXECUTE,
        7 => Protection::READ_WRITE_EXECUTE | Protection::COPY_ON_WRITE,
        _ => Protection::NONE,
    };
    match code >> 3 {
        1 => p |= Protection::NO_CACHE,
        2 => p |= Protection::GUARD,
        _ => {}
    }
    p
}
