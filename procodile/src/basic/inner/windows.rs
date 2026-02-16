use std::ptr::NonNull;

use super::super::{ProcessBasicError, Result};
use crate::mem::ProcessAccess;
use crate::process::inner::{WindowsProcessHandle, WindowsProcessInner};

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Win32::Foundation::STATUS_SUCCESS;
use windows_sys::Win32::System::{
    Threading::{OpenProcess, PROCESS_ALL_ACCESS, PROCESS_VM_READ, PROCESS_VM_WRITE},
    WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
};

impl WindowsProcessInner {
    pub fn open_process(&self, access: ProcessAccess) -> Result<WindowsProcessHandle> {
        let access = match access {
            ProcessAccess::AllAccess => PROCESS_ALL_ACCESS,
            ProcessAccess::Read => PROCESS_VM_READ,
            ProcessAccess::Write => PROCESS_VM_WRITE,
            ProcessAccess::ReadWrite => PROCESS_VM_READ | PROCESS_VM_WRITE,
            ProcessAccess::Other(c) => c as u32,
        };
        let handle = NonNull::new(unsafe { OpenProcess(access, 0, self.0.UniqueProcessId as u32) });

        handle
            .ok_or_else(|| ProcessBasicError::OpenProcessFail(self.0.UniqueProcessId as usize))
            .map(WindowsProcessHandle)
    }

    pub fn iter_processes() -> WindowsProcessIterator {
        let proc_buffer = unsafe {
            let mut buffer: Vec<u8> = Vec::new();
            let mut size: u32 = 0;

            for _ in 0..5 {
                let status = NtQuerySystemInformation(
                    SystemProcessInformation,
                    buffer.as_mut_ptr() as *mut _,
                    size,
                    &mut size,
                );
                if status == STATUS_SUCCESS {
                    buffer.set_len(size as usize);
                    break;
                }
                if buffer.capacity() < size as usize {
                    buffer.reserve(size as usize - buffer.capacity());
                }
            }
            buffer
        };

        WindowsProcessIterator::new(proc_buffer)
    }
}

pub(crate) struct WindowsProcessIterator {
    offset: u32,
    buffer: Vec<u8>,
    done: bool,
}

impl WindowsProcessIterator {
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            done: buffer.is_empty(),
            buffer,
            offset: 0,
        }
    }
}

impl Iterator for WindowsProcessIterator {
    type Item = WindowsProcessInner;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let current_item: SYSTEM_PROCESS_INFORMATION =
            unsafe { *self.buffer.as_ptr().add(self.offset as usize).cast() };

        if current_item.NextEntryOffset == 0 {
            self.done = true;
        } else {
            self.offset += current_item.NextEntryOffset;
        }

        Some(WindowsProcessInner(current_item))
    }
}
