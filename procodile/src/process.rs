use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::sys::process as imp;
use crate::{AsInner, Error, Result};

/// What a [`ProcessHandle`] will be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Access {
    /// Query and read memory.
    Read,
    /// Query, read and write memory.
    #[default]
    ReadWrite,
    /// Everything the OS allows (Windows `PROCESS_ALL_ACCESS`).
    All,
}

/// A snapshot of a running process, as returned by [`processes`].
///
/// Holding a `Process` does not keep the process alive or give access to it; use
/// [`Process::open`] for that.
pub struct Process(imp::Process);

/// Iterator over the processes running on the system.
pub struct Processes(imp::Processes);

/// Lists the processes running on the system.
pub fn processes() -> Result<Processes> {
    imp::processes()
        .map(Processes)
        .map_err(Error::query("list"))
}

impl Iterator for Processes {
    type Item = Process;

    fn next(&mut self) -> Option<Process> {
        self.0.next().map(Process)
    }
}

impl Process {
    pub fn by_pid(pid: u32) -> Result<Process> {
        processes()?
            .find(|p| p.pid() == pid)
            .ok_or(Error::ProcessNotFound(pid))
    }

    pub fn by_name(name: impl AsRef<OsStr>) -> Result<impl Iterator<Item = Process>> {
        let processes = processes()?;
        Ok(processes.filter(move |p| p.name() == name.as_ref()))
    }

    pub fn current_pid() -> u32 {
        imp::current_pid()
    }

    pub fn pid(&self) -> u32 {
        self.0.pid()
    }

    pub fn parent_pid(&self) -> Option<u32> {
        self.0.parent_pid()
    }

    /// The executable's file name, e.g. `game.exe`.
    pub fn name(&self) -> &OsStr {
        self.0.name()
    }

    pub fn exe_path(&self) -> Result<PathBuf> {
        self.0.exe_path().map_err(Error::query("executable path"))
    }

    pub fn open(&self, access: Access) -> Result<ProcessHandle> {
        ProcessHandle::open(self.pid(), access)
    }
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process")
            .field("pid", &self.pid())
            .field("name", &self.name())
            .finish()
    }
}

/// An open handle to a process, through which its memory can be read and written.
///
/// Handles are `Send + Sync`, so one handle can be shared between threads (e.g. a scanner
/// and a value freezer) behind an `Arc`.
pub struct ProcessHandle(pub(crate) imp::Handle);

impl ProcessHandle {
    pub fn open(pid: u32, access: Access) -> Result<ProcessHandle> {
        imp::Handle::open(pid, access)
            .map(ProcessHandle)
            .map_err(|source| match source.kind() {
                io::ErrorKind::NotFound => Error::ProcessNotFound(pid),
                _ => Error::OpenProcess { pid, source },
            })
    }

    pub fn open_current() -> Result<ProcessHandle> {
        let pid = imp::current_pid();
        imp::Handle::open_current()
            .map(ProcessHandle)
            .map_err(|source| Error::OpenProcess { pid, source })
    }

    pub fn pid(&self) -> u32 {
        self.0.pid()
    }

    pub fn is_alive(&self) -> bool {
        self.0.is_alive()
    }

    /// Stops all threads of the process, e.g. to take a consistent snapshot.
    pub fn suspend(&self) -> Result<()> {
        self.0
            .suspend()
            .map_err(Error::operation("suspend process"))
    }

    pub fn resume(&self) -> Result<()> {
        self.0.resume().map_err(Error::operation("resume process"))
    }

    /// Size of a pointer in the target process (4 for 32-bit processes, 8 for 64-bit).
    pub fn pointer_width(&self) -> Result<usize> {
        self.0
            .pointer_width()
            .map_err(Error::query("pointer width"))
    }
}

impl AsInner<imp::Handle> for ProcessHandle {
    fn as_inner(&self) -> &imp::Handle {
        &self.0
    }
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessHandle")
            .field("pid", &self.pid())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_is_listed() {
        let me = Process::by_pid(Process::current_pid()).unwrap();
        assert_eq!(me.pid(), std::process::id());
        assert!(!me.name().is_empty());
        assert!(me.exe_path().unwrap().is_absolute());
    }

    #[test]
    fn missing_process() {
        assert!(matches!(
            ProcessHandle::open(u32::MAX - 1, Access::Read),
            Err(Error::ProcessNotFound(_))
        ));
    }

    /// Run by `suspend_and_resume_child` as a long-lived child process.
    #[test]
    #[ignore]
    fn sleeper() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    #[test]
    fn suspend_and_resume_child() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process::tests::sleeper", "--ignored"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let handle = ProcessHandle::open(child.id(), Access::ReadWrite).unwrap();
        handle.suspend().unwrap();
        handle.resume().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn open_current() {
        let handle = ProcessHandle::open_current().unwrap();
        assert_eq!(handle.pid(), std::process::id());
        assert!(handle.is_alive());
        assert_eq!(handle.pointer_width().unwrap(), size_of::<usize>());
    }
}
