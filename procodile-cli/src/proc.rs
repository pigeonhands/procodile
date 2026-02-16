use core::slice;
use std::ptr;
use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

fn main() {
    unsafe {
        let mut size: u32 = 0;

        // 1. Initial call to determine the required buffer size
        // We expect STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
        NtQuerySystemInformation(SystemProcessInformation, ptr::null_mut(), 0, &mut size);

        // 2. Allocate the buffer based on the returned size
        let mut buffer: Vec<u8> = vec![0; size as usize];

        // 3. The actual call to get the process data
        let status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut size,
        );

        if status == 0 {
            // STATUS_SUCCESS
            let mut current_ptr = buffer.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;

            loop {
                let info = &*current_ptr;

                // Note: ImageName is a UNICODE_STRING. You'd need to convert it to a Rust String.
                let name = if info.ImageName.Buffer.is_null() {
                    ""
                } else {
                    str::from_utf8_unchecked(slice::from_raw_parts(
                        info.ImageName.Buffer as *const u8,
                        info.ImageName.Length as usize / 2,
                    ))
                };
                println!("{} | PID: {:?}", name, info.UniqueProcessId);

                if info.NextEntryOffset == 0 {
                    break;
                }

                // Move the pointer to the next entry in the blob
                current_ptr = (current_ptr as *const u8).add(info.NextEntryOffset as usize)
                    as *const SYSTEM_PROCESS_INFORMATION;
            }
        } else {
            println!(
                "Failed to query system information. NTSTATUS: {:#x}",
                status
            );
        }
    }
}
