use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::Access;

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
        fs::read_link(format!("/proc/{}/exe", self.pid))
    }
}

pub(crate) struct Processes(fs::ReadDir);

pub(crate) fn processes() -> io::Result<Processes> {
    fs::read_dir("/proc").map(Processes)
}

impl Iterator for Processes {
    type Item = Process;

    fn next(&mut self) -> Option<Process> {
        loop {
            let Ok(entry) = self.0.next()? else {
                continue;
            };
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) else {
                continue;
            };
            // The process may have exited mid-scan; skip it.
            if let Some(name) = read_name(pid) {
                return Some(Process {
                    pid,
                    parent_pid: read_parent_pid(pid),
                    name,
                });
            }
        }
    }
}

pub(crate) fn current_pid() -> u32 {
    std::process::id()
}

/// Prefers argv[0]'s file name, since `comm` is truncated to 15 bytes.
fn read_name(pid: u32) -> Option<OsString> {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv0 = cmdline.split(|&b| b == 0).next().unwrap_or_default();
    if let Some(name) = Path::new(OsStr::from_bytes(argv0)).file_name() {
        return Some(name.to_owned());
    }
    // Kernel threads have an empty cmdline.
    let comm = fs::read(format!("/proc/{pid}/comm")).ok()?;
    Some(OsStr::from_bytes(comm.trim_ascii_end()).to_owned())
}

fn read_parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid ...`; comm may itself contain spaces and parentheses.
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

pub(crate) struct Handle {
    pid: u32,
    pub(crate) mem: File,
}

impl Handle {
    pub fn open(pid: u32, access: Access) -> io::Result<Handle> {
        Self::open_path(pid, &format!("/proc/{pid}/mem"), access)
    }

    pub fn open_current() -> io::Result<Handle> {
        Self::open_path(current_pid(), "/proc/self/mem", Access::ReadWrite)
    }

    fn open_path(pid: u32, path: &str, access: Access) -> io::Result<Handle> {
        let mem = OpenOptions::new()
            .read(true)
            .write(access != Access::Read)
            .open(path)?;
        Ok(Handle { pid, mem })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_alive(&self) -> bool {
        // A zombie still has a /proc entry but no address space.
        fs::read_to_string(format!("/proc/{}/stat", self.pid)).is_ok_and(|stat| {
            stat.rfind(')')
                .and_then(|i| stat[i + 1..].split_whitespace().next())
                .is_some_and(|state| state != "Z" && state != "X")
        })
    }

    pub fn suspend(&self) -> io::Result<()> {
        self.signal(libc::SIGSTOP)
    }

    pub fn resume(&self) -> io::Result<()> {
        self.signal(libc::SIGCONT)
    }

    fn signal(&self, signal: libc::c_int) -> io::Result<()> {
        if unsafe { libc::kill(self.pid as libc::pid_t, signal) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn pointer_width(&self) -> io::Result<usize> {
        // EI_CLASS of the ELF header: 1 = 32-bit, 2 = 64-bit.
        let mut ident = [0u8; 5];
        File::open(format!("/proc/{}/exe", self.pid))?.read_exact(&mut ident)?;
        match ident {
            [0x7f, b'E', b'L', b'F', 1] => Ok(4),
            [0x7f, b'E', b'L', b'F', 2] => Ok(8),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not an ELF executable",
            )),
        }
    }
}
