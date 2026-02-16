pub mod inner {
    #[cfg(target_os = "windows")]
    mod windows;
}

pub mod error;
use std::{ffi::c_void, mem::MaybeUninit};

use error::Result;

use crate::process::ProcessHandle;

#[derive(Debug, Clone, Copy)]
pub enum ProcessAccess {
    AllAccess,
    Read,
    Write,
    ReadWrite,
    Other(usize),
}

#[derive(Debug)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub memory_size: usize,
    pub protection_flags: u16,
}

impl ProcessHandle {
    pub unsafe fn read_memory_raw(
        &self,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
    ) -> Result<usize> {
        unsafe { self.0.read_memory(address, buffer, size) }
    }
    pub unsafe fn read_memory_to_buffer(
        &self,
        address: *const c_void,
        buffer: &mut [u8],
    ) -> Result<usize> {
        unsafe { self.read_memory_raw(address, buffer.as_mut_ptr() as *mut _, buffer.len()) }
    }
    pub fn read_memory<T: Sized>(&self, address: *const c_void) -> Result<T> {
        unsafe {
            let mut buffer = MaybeUninit::<T>::uninit();
            let bytes_read = self.read_memory_raw(
                address,
                buffer.as_mut_ptr() as *mut _,
                core::mem::size_of::<T>(),
            )?;
            if bytes_read != core::mem::size_of::<T>() {
                return Err(error::MemoryError::MemoryReadFail(address));
            }
            Ok(buffer.assume_init())
        }
    }

    pub fn memory_regions(&self) -> Result<impl Iterator<Item = MemoryRegion>> {
        self.0.get_memory_regions()
    }
}
