use std::{
    ffi::{OsStr, OsString, c_void},
    os::windows::ffi::OsStrExt,
    ptr::NonNull,
};
use widestring::U16CStr;
use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

pub(crate) struct WindowsProcessInner(pub SYSTEM_PROCESS_INFORMATION);

#[derive(Debug)]
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

    pub fn id(&self) -> usize {
        self.0.UniqueProcessId as usize
    }

    pub fn name(&self) -> OsString {
        let image_name = self.0.ImageName;
        let wide_str = unsafe { U16CStr::from_ptr(image_name.Buffer, image_name.Length as usize) }
            .unwrap_or_default();
        wide_str.to_os_string()
    }
}
