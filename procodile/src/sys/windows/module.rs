use std::ffi::OsString;
use std::io;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_BAD_LENGTH, ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, VirtualQueryEx,
};
use windows_sys::Win32::System::ProcessStatus::GetMappedFileNameW;

use super::process::Handle;
use super::cvt;
use crate::Address;
use crate::module::Module;

const PE_MAGIC: [u8; 2] = *b"MZ";

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

    /// All file-backed images in the address space, including memory-mapped
    /// PE files not in the OS module list (e.g. .NET assemblies loaded by
    /// CoreCLR). Merges OS-loaded modules with images found by scanning
    /// committed `MEM_IMAGE` and `MEM_MAPPED` regions for PE headers.
    pub fn mapped_images(&self) -> io::Result<Vec<Module>> {
        let mut modules = self.modules()?;
        let known_bases: Vec<usize> = modules.iter().map(|m| m.base.get()).collect();

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
                break;
            }
            let mbi = unsafe { mbi.assume_init() };
            let base = mbi.BaseAddress as usize;

            if mbi.State == MEM_COMMIT
                && (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)
                && mbi.AllocationBase as usize == base
                && !known_bases.contains(&base)
            {
                if self.starts_with_pe_header(base) {
                    if let Some(path) = self.mapped_file_name(base) {
                        let size = self.image_span(base, &mbi);
                        modules.push(Module {
                            name: path
                                .file_name()
                                .unwrap_or_default()
                                .to_owned(),
                            base: Address::new(base),
                            size,
                            path,
                        });
                    }
                }
            }

            match base.checked_add(mbi.RegionSize) {
                Some(next) if next > address => address = next,
                _ => break,
            }
        }
        Ok(modules)
    }

    fn starts_with_pe_header(&self, address: usize) -> bool {
        let mut magic = [0u8; 2];
        matches!(self.read_at(Address::new(address), &mut magic), Ok(2)) && magic == PE_MAGIC
    }

    /// Resolves the device path for a memory-mapped region to a DOS path.
    fn mapped_file_name(&self, address: usize) -> Option<PathBuf> {
        let mut buf = [0u16; 512];
        let len = unsafe {
            GetMappedFileNameW(self.raw(), address as *const _, buf.as_mut_ptr(), buf.len() as u32)
        };
        if len == 0 {
            return None;
        }
        let device_path = &buf[..len as usize];
        device_path_to_dos(device_path)
    }

    /// Walks forward from `base` through contiguous committed regions of the
    /// same allocation to compute the full image span.
    fn image_span(&self, base: usize, first: &MEMORY_BASIC_INFORMATION) -> usize {
        let mut end = base + first.RegionSize;
        loop {
            let mut mbi = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
            let written = unsafe {
                VirtualQueryEx(
                    self.raw(),
                    end as *const _,
                    mbi.as_mut_ptr(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                break;
            }
            let mbi = unsafe { mbi.assume_init() };
            if mbi.AllocationBase as usize != base || mbi.State != MEM_COMMIT {
                break;
            }
            end += mbi.RegionSize;
        }
        end - base
    }
}

/// Converts an NT device path (`\Device\HarddiskVolume1\...`) to a DOS
/// path (`C:\...`) by probing drive letters with `QueryDosDeviceW`.
fn device_path_to_dos(device_path: &[u16]) -> Option<PathBuf> {
    for letter in b'A'..=b'Z' {
        let drive = [letter as u16, b':' as u16, 0];
        let mut target = [0u16; 260];
        let len =
            unsafe { QueryDosDeviceW(drive.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
        if len == 0 {
            continue;
        }
        // The buffer has double-nul terminated strings; take the first.
        let target_len = target[..len as usize]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(len as usize);
        let prefix = &target[..target_len];
        if device_path.len() > prefix.len() && device_path.starts_with(prefix) {
            let mut result = vec![letter as u16, b':' as u16];
            result.extend_from_slice(&device_path[prefix.len()..]);
            return Some(PathBuf::from(OsString::from_wide(&result)));
        }
    }
    // Fall back to the raw device path if no drive letter matches.
    Some(PathBuf::from(OsString::from_wide(device_path)))
}

fn from_wide_nul(buf: &[u16]) -> OsString {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
}
