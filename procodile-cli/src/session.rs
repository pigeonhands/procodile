use procodile::{Process, ProcessHandle};

#[derive(Default)]
pub struct Session {
    pub attached: Option<AttachedProcess>,
}

pub struct AttachedProcess {
    pub process: Process,
    pub handle: ProcessHandle,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }
}
