use thiserror::Error;

pub type Result<T> = std::result::Result<T, ProcessBasicError>;

#[derive(Debug, Error)]
pub enum ProcessBasicError {
    #[error("Failed to open process with pid {0}")]
    OpenProcessFail(usize),
}
