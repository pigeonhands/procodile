use std::ffi::c_void;

use thiserror::Error;

use crate::basic::ProcessBasicError;

pub type Result<T> = std::result::Result<T, MemoryError>;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Error: {0}")]
    BasicError(#[from] ProcessBasicError),

    #[error("Failed to open process with pid {0}")]
    OpenProcessFail(usize),

    #[error("Failed to read memory at {0:?}")]
    MemoryReadFail(*const c_void),

    #[error("Failed to write memory at {0:?}")]
    MemoryWriteFail(*const c_void),

    #[error("Failed to get memory pages")]
    MemoryPageFail,

    #[error("Failed to query memory page at {0:x}")]
    MemoryPageQueryFail(usize),
}
