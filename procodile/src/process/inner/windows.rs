use std::{
    ffi::{OsStr, c_void},
    os::windows::ffi::OsStrExt,
    ptr::NonNull,
};
use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

pub(crate) struct WindowsProcessInner(pub SYSTEM_PROCESS_INFORMATION);

#[derive(Debug, Clone, Copy)]
pub struct WindowsProcessHandle(pub(crate) NonNull<c_void>);

impl WindowsProcessInner {
    pub fn name_is(&self, compare: &OsStr) -> bool {
        compare.len() == self.0.ImageName.Length as usize
            && unsafe {
                core::slice::from_raw_parts(
                    self.0.ImageName.Buffer,
                    self.0.ImageName.Length as usize,
                )
            }
            .iter()
            .copied()
            .eq(compare.encode_wide())
    }
}
