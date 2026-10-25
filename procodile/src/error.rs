use std::io;

use thiserror::Error;

use crate::Address;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("process {0} not found")]
    ProcessNotFound(u32),

    #[error("failed to open process {pid}: {source}")]
    OpenProcess { pid: u32, source: io::Error },

    #[error("failed to read memory at {address:?}: {source}")]
    Read { address: Address, source: io::Error },

    #[error("failed to write memory at {address:?}: {source}")]
    Write { address: Address, source: io::Error },

    #[error("partial read at {address:?}: got {done} of {expected} bytes")]
    PartialRead {
        address: Address,
        done: usize,
        expected: usize,
    },

    #[error("partial write at {address:?}: wrote {done} of {expected} bytes")]
    PartialWrite {
        address: Address,
        done: usize,
        expected: usize,
    },

    #[error("failed to query process {what}: {source}")]
    Query {
        what: &'static str,
        source: io::Error,
    },

    #[error("failed to {what}: {source}")]
    Operation {
        what: &'static str,
        source: io::Error,
    },

    #[error("invalid scan: {0}")]
    InvalidScan(String),

    #[error("scan cancelled")]
    Cancelled,

    #[error("{0} is not supported on this platform")]
    Unsupported(&'static str),
}

impl Error {
    /// The underlying OS error, if there is one.
    pub fn os_error(&self) -> Option<&io::Error> {
        match self {
            Error::OpenProcess { source, .. }
            | Error::Read { source, .. }
            | Error::Write { source, .. }
            | Error::Query { source, .. }
            | Error::Operation { source, .. } => Some(source),
            _ => None,
        }
    }

    pub fn is_permission_denied(&self) -> bool {
        self.os_error()
            .is_some_and(|e| e.kind() == io::ErrorKind::PermissionDenied)
    }

    pub(crate) fn query(what: &'static str) -> impl FnOnce(io::Error) -> Error {
        move |source| Error::Query { what, source }
    }

    /// For operations a backend may not implement: `io::ErrorKind::Unsupported` becomes
    /// [`Error::Unsupported`].
    pub(crate) fn operation(what: &'static str) -> impl FnOnce(io::Error) -> Error {
        move |source| match source.kind() {
            io::ErrorKind::Unsupported => Error::Unsupported(what),
            _ => Error::Operation { what, source },
        }
    }
}
