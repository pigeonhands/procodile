use std::{ffi::c_void, mem::MaybeUninit};

use crate::{
    mem::{
        ActiveMemoryRegion,
        error::{MemoryError, Result},
    },
    process::inner::WindowsProcessHandle,
};

use windows_sys::Win32::System::{
    Diagnostics::Debug::ReadProcessMemory,
    Memory::{
        MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY,
        PAGE_READWRITE, VirtualQueryEx,
    },
    ProcessStatus::PSAPI_WORKING_SET_BLOCK,
    SystemInformation::GetSystemInfo,
};
use windows_sys::Win32::System::{
    Memory::MEMORY_BASIC_INFORMATION, SystemInformation::SYSTEM_INFO,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BAD_LENGTH, GetLastError},
    System::ProcessStatus::{PSAPI_WORKING_SET_INFORMATION, QueryWorkingSet},
};

pub(crate) struct WindowsMemoryPage(MEMORY_BASIC_INFORMATION);

impl WindowsMemoryPage {
    pub fn base_address(&self) -> *const c_void {
        self.0.BaseAddress
    }

    pub fn region_size(&self) -> usize {
        self.0.RegionSize as usize
    }
    pub fn raw_protection_flags(&self) -> u32 {
        self.0.Protect
    }

    pub fn is_read(&self) -> bool {
        self.is_read_write() || self.is_read_only() || self.is_read_execute()
    }
    pub fn is_read_only(&self) -> bool {
        (self.0.Protect & PAGE_READONLY) != 0
    }

    pub fn is_execute(&self) -> bool {
        (self.0.Protect & PAGE_EXECUTE) != 0
    }

    pub fn is_read_write(&self) -> bool {
        (self.0.Protect & PAGE_READWRITE) != 0
    }

    pub fn is_read_execute(&self) -> bool {
        (self.0.Protect & PAGE_EXECUTE_READ) != 0
    }
}

impl WindowsProcessHandle {
    pub unsafe fn read_memory(
        &self,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
    ) -> Result<usize> {
        let mut bytes_read = 0;
        let result =
            unsafe { ReadProcessMemory(self.0.as_ptr(), address, buffer, size, &mut bytes_read) };
        if result == 0 {
            Err(MemoryError::MemoryReadFail(address))
        } else {
            Ok(bytes_read)
        }
    }

    unsafe fn query_working_set(&self) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> =
            Vec::with_capacity(core::mem::size_of::<PSAPI_WORKING_SET_INFORMATION>());

        loop {
            let resp = unsafe {
                QueryWorkingSet(
                    self.0.as_ptr(),
                    buffer.as_mut_ptr() as *mut _,
                    buffer.capacity() as u32,
                )
            };

            if resp == 0 {
                if unsafe { GetLastError() } != ERROR_BAD_LENGTH {
                    return Err(MemoryError::MemoryPageFail);
                }

                let wsi_ptr = buffer.as_ptr() as *const PSAPI_WORKING_SET_INFORMATION;
                let number_of_entries = unsafe { (*wsi_ptr).NumberOfEntries };

                let bytes_needed = core::mem::size_of::<PSAPI_WORKING_SET_INFORMATION>()
                    + ((number_of_entries + (number_of_entries / 4)) // sometimes the exact size
                                                                     // just isnt enough
                        * core::mem::size_of::<PSAPI_WORKING_SET_BLOCK>());

                let current_cap = buffer.capacity();
                if bytes_needed > current_cap {
                    buffer.reserve(bytes_needed - current_cap);
                }
            } else {
                break;
            }
        }

        Ok(buffer)
    }

    unsafe fn virtual_query(
        &self,
        base_address: *const c_void,
    ) -> Result<MEMORY_BASIC_INFORMATION> {
        let mbi = unsafe {
            let mut buffer = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
            let res = VirtualQueryEx(
                self.0.as_ptr(),
                base_address,
                buffer.as_mut_ptr(),
                core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if res == 0 {
                return Err(MemoryError::MemoryPageQueryFail(base_address as usize));
            }

            buffer.assume_init()
        };

        Ok(mbi)
    }
}

// Higher level impl
impl WindowsProcessHandle {
    unsafe fn get_system_info(&self) -> SYSTEM_INFO {
        unsafe {
            let mut system_info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(system_info.as_mut_ptr());
            system_info.assume_init()
        }
    }

    pub fn get_active_memory_regions(&self) -> Result<WindowsPsApiWorkingSetIterator> {
        let working_set = unsafe { self.query_working_set()? };

        let page_size = unsafe { self.get_system_info() }.dwPageSize as usize;
        Ok(unsafe { WindowsPsApiWorkingSetIterator::new(page_size, working_set) })
    }
    pub fn get_memory_regions<'a>(
        &'a self,
        start_address: *const c_void,
        end_address: *const c_void,
    ) -> Result<WindowsVirtualQueryPageIterator<'a>> {
        Ok(WindowsVirtualQueryPageIterator::new(
            self,
            start_address,
            end_address,
        ))
    }
}

pub(crate) struct WindowsVirtualQueryPageIterator<'a> {
    pub current_address: *const c_void,
    pub start_address: *const c_void,
    pub end_address: *const c_void,
    pub handle: &'a WindowsProcessHandle,
}

impl<'a> WindowsVirtualQueryPageIterator<'a> {
    pub fn new(
        handle: &'a WindowsProcessHandle,
        start_address: *const c_void,
        end_address: *const c_void,
    ) -> Self {
        Self {
            handle,
            current_address: start_address,
            start_address,
            end_address,
        }
    }
}

impl<'a> Iterator for WindowsVirtualQueryPageIterator<'a> {
    type Item = WindowsMemoryPage;

    fn next(&mut self) -> Option<Self::Item> {
        let mut page = None;
        while self.current_address < self.end_address {
            let mut mbi = match unsafe { self.handle.virtual_query(self.current_address) } {
                Ok(mbi) => mbi,
                Err(_) => break,
            };
            self.current_address = unsafe { self.current_address.add(mbi.RegionSize) };

            if mbi.State != MEM_COMMIT {
                continue;
            }

            if ((mbi.Protect & PAGE_GUARD) != 0) || ((mbi.Protect & PAGE_NOACCESS) != 0) {
                continue;
            }

            if mbi.BaseAddress < self.start_address as *mut _ {
                mbi.BaseAddress = self.start_address as *mut _;
            }
            if (mbi.BaseAddress as usize + mbi.RegionSize) > self.end_address as usize {
                mbi.RegionSize = unsafe { self.end_address.sub(mbi.BaseAddress as usize) as usize };
            }

            page = Some(WindowsMemoryPage(mbi));
            break;
        }
        page
    }
}

impl ActiveMemoryRegion {
    fn protection_flags(&self) -> u8 {
        (self.flags & 0b_11111) as u8
    }
    pub fn can_read(&self) -> bool {
        self.is_read_only() || self.is_read_execute() || self.is_read_write()
    }
    pub fn is_read_only(&self) -> bool {
        self.protection_flags() == 1
    }
    pub fn is_execute(&self) -> bool {
        self.protection_flags() == 2
    }
    pub fn is_read_execute(&self) -> bool {
        self.protection_flags() == 3
    }
    pub fn is_read_write(&self) -> bool {
        self.protection_flags() == 4
    }
}

pub struct WindowsPsApiWorkingSetIterator {
    wapi_working_set: Vec<u8>,
    index: usize,
    page_size: usize,
}

impl WindowsPsApiWorkingSetIterator {
    // `wapi_working_set` needs to be a buffer pointing to
    // a valid `PSAPI_WORKING_SET_INFORMATION`
    pub unsafe fn new(page_size: usize, wapi_working_set: Vec<u8>) -> Self {
        Self {
            wapi_working_set,
            index: 0,
            page_size,
        }
    }
}

impl Iterator for WindowsPsApiWorkingSetIterator {
    type Item = ActiveMemoryRegion;

    fn next(&mut self) -> Option<Self::Item> {
        let wsi: *const PSAPI_WORKING_SET_INFORMATION = self.wapi_working_set.as_ptr().cast();

        let wapi_blocks: &[PSAPI_WORKING_SET_BLOCK] = unsafe {
            core::slice::from_raw_parts(
                (*wsi).WorkingSetInfo.as_ptr().cast(),
                (*wsi).NumberOfEntries,
            )
        };

        let mut current_region: Option<ActiveMemoryRegion> = None;

        while self.index < wapi_blocks.len() {
            let current_block = &wapi_blocks[self.index];

            let flags = unsafe { current_block.Flags };
            let base_address = flags & 0xfffffffffffff000;
            let flags = (flags & 0xfff) as u16;

            if let Some(current_region) = &mut current_region {
                if current_region.flags == flags
                    && (current_region.base_address + current_region.memory_size) == base_address
                {
                    current_region.memory_size += self.page_size;
                } else {
                    // break without incrementing index so next call
                    // will use the current block that is a start
                    // of a new region.
                    break;
                }
            } else {
                current_region = Some(ActiveMemoryRegion {
                    base_address,
                    memory_size: self.page_size,
                    flags,
                });
            }

            self.index += 1;
        }
        current_region
    }
}
