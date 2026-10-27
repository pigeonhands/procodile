use std::io;

use windows_sys::core::BOOL;

pub(crate) mod inject;
pub(crate) mod memory;
pub(crate) mod module;
pub(crate) mod process;

/// Turns a Win32 `BOOL` result into an `io::Result`, capturing `GetLastError` on failure.
pub(crate) fn cvt(result: BOOL) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
