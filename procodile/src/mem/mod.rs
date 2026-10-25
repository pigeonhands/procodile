pub mod inner {
    #[cfg(target_os = "windows")]
    mod windows;
    #[cfg(target_os = "windows")]
    pub(crate) use windows::WindowsMemoryPage as MemoryRegion;

    #[cfg(target_os = "linux")]
    mod linux;
    #[cfg(target_os = "linux")]
    pub(crate) use linux::LinuxMemoryPage as MemoryRegion;
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
pub struct ActiveMemoryRegion {
    pub base_address: usize,
    pub memory_size: usize,
    pub flags: u16,
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

pub struct MemoryRegion(inner::MemoryRegion);

impl MemoryRegion {
    pub fn base_address(&self) -> *const c_void {
        self.0.base_address()
    }

    pub fn region_size(&self) -> usize {
        self.0.region_size()
    }
    pub fn raw_protection_flags(&self) -> usize {
        self.0.raw_protection_flags() as usize
    }

    pub fn is_read(&self) -> bool {
        self.0.is_read()
    }
    pub fn is_read_only(&self) -> bool {
        self.0.is_read_only()
    }

    pub fn is_execute(&self) -> bool {
        self.0.is_execute()
    }

    pub fn is_read_write(&self) -> bool {
        self.0.is_read_write()
    }

    pub fn is_read_execute(&self) -> bool {
        self.0.is_read_execute()
    }
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

    pub unsafe fn write_memory_raw(
        &self,
        address: *const c_void,
        buffer: *const c_void,
        size: usize,
    ) -> Result<usize> {
        unsafe { self.0.write_memory(address, buffer, size) }
    }
    pub unsafe fn write_memory_to_buffer(
        &self,
        address: *const c_void,
        buffer: &[u8],
    ) -> Result<usize> {
        unsafe { self.write_memory_raw(address, buffer.as_ptr() as *const _, buffer.len()) }
    }
    pub fn write_memory<T: Sized>(&self, address: *const c_void, value: &T) -> Result<()> {
        unsafe {
            let bytes_written = self.write_memory_raw(
                address,
                value as *const T as *const _,
                core::mem::size_of::<T>(),
            )?;
            if bytes_written != core::mem::size_of::<T>() {
                return Err(error::MemoryError::MemoryWriteFail(address));
            }
            Ok(())
        }
    }

    pub fn active_memory_regions(&self) -> Result<impl Iterator<Item = ActiveMemoryRegion>> {
        self.0.get_active_memory_regions()
    }

    pub fn memory_regions(
        &self,
        start_address: *const c_void,
        end_address: *const c_void,
    ) -> Result<impl Iterator<Item = MemoryRegion>> {
        Ok(self
            .0
            .get_memory_regions(start_address, end_address)?
            .into_iter()
            .map(MemoryRegion))
    }
}
