//! Platform-specific extensions, in the style of `std::os`.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod windows;
