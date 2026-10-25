use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

use super::cvt;
use super::process::Handle;
use crate::Address;
use crate::module::Module;

impl Handle {
    pub fn modules(&self) -> io::Result<Vec<Module>> {
        let snapshot = loop {
            let raw = unsafe {
                CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid())
            };
            if raw != INVALID_HANDLE_VALUE {
                break unsafe { OwnedHandle::from_raw_handle(raw) };
            }
            let err = io::Error::last_os_error();
            // Documented as transient while the target is loading or unloading modules.
            if err.raw_os_error() != Some(ERROR_BAD_LENGTH as i32) {
                return Err(err);
            }
        };

        let mut modules = Vec::new();
        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        let mut result = cvt(unsafe { Module32FirstW(snapshot.as_raw_handle(), &mut entry) });
        while result.is_ok() {
            modules.push(Module {
                name: from_wide_nul(&entry.szModule),
                path: PathBuf::from(from_wide_nul(&entry.szExePath)),
                base: Address::new(entry.modBaseAddr as usize),
                size: entry.modBaseSize as usize,
            });
            result = cvt(unsafe { Module32NextW(snapshot.as_raw_handle(), &mut entry) });
        }
        match result {
            Err(e) if e.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) => Err(e),
            _ => Ok(modules),
        }
    }
}

fn from_wide_nul(buf: &[u16]) -> OsString {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
}
