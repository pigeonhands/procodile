use crate::process::{IntoProcess, Process, ProcessInner};

pub trait ProcessIterator {}

impl Process {
    pub fn iter_processes() -> impl Iterator<Item = Self> {
        ProcessInner::iter_processes().map(IntoProcess::into_process)
    }
}
