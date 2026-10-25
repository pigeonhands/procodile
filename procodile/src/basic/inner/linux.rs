use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use super::super::{ProcessBasicError, Result};
use crate::mem::ProcessAccess;
use crate::process::inner::{LinuxProcessHandle, LinuxProcessInner};

impl LinuxProcessInner {
    pub fn open_process(&self, access: ProcessAccess) -> Result<LinuxProcessHandle> {
        let writable = matches!(
            access,
            ProcessAccess::Write
                | ProcessAccess::ReadWrite
                | ProcessAccess::AllAccess
                | ProcessAccess::Other(_)
        );
        let mem_file = OpenOptions::new()
            .read(true)
            .write(writable)
            .open(format!("/proc/{}/mem", self.pid))
            .map_err(|_| ProcessBasicError::OpenProcessFail(self.pid as usize))?;

        Ok(LinuxProcessHandle {
            pid: self.pid,
            mem_file,
        })
    }

    pub fn iter_processes() -> LinuxProcessIterator {
        LinuxProcessIterator {
            entries: fs::read_dir("/proc").ok(),
        }
    }

    pub fn current_process_id() -> usize {
        std::process::id() as usize
    }

    pub fn open_current_process() -> Result<LinuxProcessHandle> {
        let pid = std::process::id() as i32;
        let mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/self/mem")
            .map_err(|_| ProcessBasicError::OpenProcessFail(pid as usize))?;

        Ok(LinuxProcessHandle { pid, mem_file })
    }
}

pub(crate) struct LinuxProcessIterator {
    entries: Option<fs::ReadDir>,
}

impl Iterator for LinuxProcessIterator {
    type Item = LinuxProcessInner;

    fn next(&mut self) -> Option<Self::Item> {
        let entries = self.entries.as_mut()?;
        loop {
            let entry = entries.next()?.ok();
            let Some(entry) = entry else {
                continue;
            };
            let file_name = entry.file_name();
            let Some(pid_str) = file_name.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<i32>() else {
                continue;
            };
            if let Some(name) = read_process_name(pid) {
                return Some(LinuxProcessInner { pid, name });
            }
            // Process vanished mid-scan, or is unreadable (permissions); skip it.
        }
    }
}

fn read_process_name(pid: i32) -> Option<OsString> {
    read_cmdline_name(pid).or_else(|| read_comm_name(pid))
}

fn read_cmdline_name(pid: i32) -> Option<OsString> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let first_arg = bytes.split(|&b| b == 0).next()?;
    if first_arg.is_empty() {
        return None;
    }
    let path = PathBuf::from(OsStr::from_bytes(first_arg));
    path.file_name().map(|n| n.to_os_string())
}

fn read_comm_name(pid: i32) -> Option<OsString> {
    let contents = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(OsString::from(contents.trim_end().to_string()))
}
