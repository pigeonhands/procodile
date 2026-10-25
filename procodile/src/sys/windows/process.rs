use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, HANDLE, NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS,
    STILL_ACTIVE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetExitCodeProcess, IsWow64Process, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_ALL_ACCESS, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, QueryFullProcessImageNameW,
};
use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

use super::cvt;
use crate::Access;

// Undocumented but stable since XP; not exposed by windows-sys.
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(process: HANDLE) -> NTSTATUS;
    fn NtResumeProcess(process: HANDLE) -> NTSTATUS;
}

fn nt_result(what: &str, status: NTSTATUS) -> io::Result<()> {
    if status < 0 {
        return Err(io::Error::other(format!(
            "{what} failed with NTSTATUS {status:#x}"
        )));
    }
    Ok(())
}

pub(crate) struct Process {
    pid: u32,
    parent_pid: Option<u32>,
    name: OsString,
}

impl Process {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn parent_pid(&self) -> Option<u32> {
        self.parent_pid
    }

    pub fn name(&self) -> &OsStr {
        &self.name
    }

    pub fn exe_path(&self) -> io::Result<PathBuf> {
        let handle = Handle::open_raw(self.pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let mut buf = vec![0u16; 32 * 1024];
        let mut len = buf.len() as u32;
        cvt(unsafe {
            QueryFullProcessImageNameW(handle.raw(), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        })?;
        Ok(OsString::from_wide(&buf[..len as usize]).into())
    }
}

/// The process list is copied out of the `NtQuerySystemInformation` buffer up front, so no
/// `Process` borrows from it.
pub(crate) struct Processes(std::vec::IntoIter<Process>);

impl Iterator for Processes {
    type Item = Process;

    fn next(&mut self) -> Option<Process> {
        self.0.next()
    }
}

pub(crate) fn processes() -> io::Result<Processes> {
    // u64 elements keep the buffer suitably aligned for SYSTEM_PROCESS_INFORMATION.
    let mut buf: Vec<u64> = vec![0; 64 * 1024];
    loop {
        let byte_len = (buf.len() * size_of::<u64>()) as u32;
        let mut needed = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buf.as_mut_ptr().cast(),
                byte_len,
                &mut needed,
            )
        };
        match status {
            STATUS_SUCCESS => break,
            // The process list can grow between calls, so leave some slack.
            STATUS_INFO_LENGTH_MISMATCH => {
                buf.resize((needed as usize + 64 * 1024).div_ceil(size_of::<u64>()), 0)
            }
            _ => nt_result("NtQuerySystemInformation", status)?,
        }
    }

    let base = buf.as_ptr().cast::<u8>();
    let mut list = Vec::new();
    let mut offset = 0usize;
    loop {
        // SAFETY: the kernel filled the buffer with a chain of SYSTEM_PROCESS_INFORMATION
        // entries linked by NextEntryOffset.
        let info = unsafe { &*base.add(offset).cast::<SYSTEM_PROCESS_INFORMATION>() };
        list.push(Process {
            pid: info.UniqueProcessId as u32,
            // Reserved2 is InheritedFromUniqueProcessId.
            parent_pid: Some(info.Reserved2 as u32).filter(|&p| p != 0),
            name: image_name(info),
        });
        if info.NextEntryOffset == 0 {
            break;
        }
        offset += info.NextEntryOffset as usize;
    }
    Ok(Processes(list.into_iter()))
}

fn image_name(info: &SYSTEM_PROCESS_INFORMATION) -> OsString {
    let name = info.ImageName;
    if name.Buffer.is_null() {
        // Only the idle process (pid 0) has no image name.
        return OsString::from("System Idle Process");
    }
    // Length is in bytes, not UTF-16 units.
    let units = unsafe { std::slice::from_raw_parts(name.Buffer, name.Length as usize / 2) };
    OsString::from_wide(units)
}

pub(crate) fn current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

pub(crate) struct Handle {
    pid: u32,
    handle: OwnedHandle,
}

impl Handle {
    pub fn open(pid: u32, access: Access) -> io::Result<Handle> {
        let query = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION;
        let rights = match access {
            Access::Read => query | PROCESS_VM_READ,
            Access::ReadWrite => {
                query
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_SUSPEND_RESUME
            }
            Access::All => PROCESS_ALL_ACCESS,
        };
        Self::open_raw(pid, rights)
    }

    /// Opens a real handle rather than using the `GetCurrentProcess` pseudo-handle, so
    /// every `Handle` can be closed the same way.
    pub fn open_current() -> io::Result<Handle> {
        Self::open(current_pid(), Access::All)
    }

    pub(crate) fn open_raw(pid: u32, rights: PROCESS_ACCESS_RIGHTS) -> io::Result<Handle> {
        let raw = unsafe { OpenProcess(rights, 0, pid) };
        if raw.is_null() {
            let err = io::Error::last_os_error();
            return Err(
                if err.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                    io::Error::new(io::ErrorKind::NotFound, err)
                } else {
                    err
                },
            );
        }
        // SAFETY: OpenProcess returned a fresh handle that we now own.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        Ok(Handle { pid, handle })
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    pub(crate) fn owned(&self) -> &OwnedHandle {
        &self.handle
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_alive(&self) -> bool {
        let mut code = 0;
        cvt(unsafe { GetExitCodeProcess(self.raw(), &mut code) }).is_ok()
            && code == STILL_ACTIVE as u32
    }

    pub fn suspend(&self) -> io::Result<()> {
        nt_result("NtSuspendProcess", unsafe { NtSuspendProcess(self.raw()) })
    }

    pub fn resume(&self) -> io::Result<()> {
        nt_result("NtResumeProcess", unsafe { NtResumeProcess(self.raw()) })
    }

    pub fn pointer_width(&self) -> io::Result<usize> {
        let mut wow64 = 0;
        cvt(unsafe { IsWow64Process(self.raw(), &mut wow64) })?;
        Ok(if wow64 != 0 { 4 } else { size_of::<usize>() })
    }
}
