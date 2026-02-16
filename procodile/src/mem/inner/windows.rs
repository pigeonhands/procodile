use std::{ffi::c_void, mem::MaybeUninit};

use crate::{
    mem::{
        MemoryRegion,
        error::{MemoryError, Result},
    },
    process::inner::WindowsProcessHandle,
};

use windows_sys::Win32::System::SystemInformation::SYSTEM_INFO;
use windows_sys::Win32::System::{
    Diagnostics::Debug::ReadProcessMemory, ProcessStatus::PSAPI_WORKING_SET_BLOCK,
    SystemInformation::GetSystemInfo,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BAD_LENGTH, GetLastError},
    System::ProcessStatus::{PSAPI_WORKING_SET_INFORMATION, QueryWorkingSet},
};

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
                    + (number_of_entries * core::mem::size_of::<PSAPI_WORKING_SET_BLOCK>());

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

    pub fn get_memory_regions(&self) -> Result<WindowsMemoryRegionIterator> {
        let working_set = unsafe { self.query_working_set()? };

        let page_size = unsafe { self.get_system_info() }.dwPageSize as usize;
        Ok(WindowsMemoryRegionIterator::new(page_size, working_set))
    }
}

pub struct WindowsMemoryRegionIterator {
    current_region: Option<MemoryRegion>,
    wapi_working_set: Vec<u8>,
    index: usize,
    page_size: usize,
}

impl WindowsMemoryRegionIterator {
    pub fn new(page_size: usize, wapi_working_set: Vec<u8>) -> Self {
        Self {
            wapi_working_set,
            current_region: None,
            index: 0,
            page_size,
        }
    }
}

impl Iterator for WindowsMemoryRegionIterator {
    type Item = MemoryRegion;

    fn next(&mut self) -> Option<Self::Item> {
        let wsi: *const PSAPI_WORKING_SET_INFORMATION = self.wapi_working_set.as_ptr().cast();

        let wapi_blocks: &[PSAPI_WORKING_SET_BLOCK] = unsafe {
            core::slice::from_raw_parts(
                (*wsi).WorkingSetInfo.as_ptr().cast(),
                (*wsi).NumberOfEntries,
            )
        };

        let mut current_region: Option<MemoryRegion> = None;

        while self.index < wapi_blocks.len() {
            let current_block = &wapi_blocks[self.index];

            let flags = unsafe { current_block.Flags };
            let base_address = flags & 0xfffffffffffff000;
            let protection_flags = (flags & 0xfff) as u16;

            if let Some(current_region) = &mut current_region {
                if current_region.protection_flags == protection_flags
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
                current_region = Some(MemoryRegion {
                    base_address,
                    memory_size: self.page_size,
                    protection_flags: protection_flags,
                });
            }

            self.index += 1;
        }
        current_region
    }
}
