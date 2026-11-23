//! Windows library injection.
//!
//! Loader path: `LoadLibraryW` via `CreateRemoteThread`.
//!
//! Manual-mapping path (requires `inject` feature): maps a PE image directly into the
//! target using pewter for parsing, applies base relocations, resolves imports, runs TLS
//! callbacks and the entry point.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, INFINITE, WaitForSingleObject,
};

use crate::memory::Protection;
use crate::{Address, ProcessHandle};

// ─── loader path (always available) ──────────────────────────────────────────

pub(crate) fn load_library(handle: &ProcessHandle, path: &Path) -> io::Result<Address> {
    let target_width = handle.0.pointer_width()?;
    if target_width != size_of::<usize>() {
        return Err(io::ErrorKind::Unsupported.into());
    }

    let wide_path = path_to_wide(path);
    let path_bytes = wide_path.len() * 2;

    let remote_path = handle.0.allocate(path_bytes, Protection::READ_WRITE)?;
    let cleanup = || { let _ = handle.0.free(remote_path); };

    let path_slice = unsafe {
        std::slice::from_raw_parts(wide_path.as_ptr() as *const u8, path_bytes)
    };
    if let Err(e) = handle.0.write_at(remote_path, path_slice).and_then(|n| {
        if n == path_bytes { Ok(()) } else {
            Err(io::Error::new(io::ErrorKind::WriteZero, "short write"))
        }
    }) {
        cleanup();
        return Err(e);
    }

    let kernel32_name: Vec<u16> = OsStr::new("kernel32.dll\0").encode_wide().collect();
    let kernel32 = unsafe { GetModuleHandleW(kernel32_name.as_ptr()) };
    if kernel32.is_null() {
        cleanup();
        return Err(io::Error::last_os_error());
    }
    let loadlib_addr = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr()) };
    let loadlib_addr = match loadlib_addr {
        Some(f) => f as usize,
        None => {
            cleanup();
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "LoadLibraryW not found in kernel32",
            ));
        }
    };

    let thread = unsafe {
        CreateRemoteThread(
            handle.0.raw(),
            std::ptr::null(),
            0,
            Some(std::mem::transmute(loadlib_addr)),
            remote_path.get() as *const _,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        cleanup();
        return Err(io::Error::last_os_error());
    }

    let wait = unsafe { WaitForSingleObject(thread, INFINITE) };
    let mut exit_code: u32 = 0;
    let get_ok = unsafe { GetExitCodeThread(thread, &mut exit_code) };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(thread) };
    cleanup();

    if wait != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error());
    }
    if get_ok == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(Address::new(exit_code as usize))
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    wide
}

// ─── low-level primitives (always available) ─────────────────────────────────

pub(crate) fn inject_bytes(handle: &ProcessHandle, data: &[u8]) -> io::Result<Address> {
    let size = (data.len() + 0xfff) & !0xfff;
    let addr = handle.0.allocate(size, Protection::READ_WRITE)?;
    handle.0.write_at(addr, data).map_err(|e| {
        let _ = handle.0.free(addr);
        e
    })?;
    let _ = handle.0.protect(addr, size, Protection::READ_WRITE | Protection::EXECUTE);
    Ok(addr)
}

pub(crate) fn execute_remote(
    handle: &ProcessHandle,
    entry: Address,
    arg: u64,
) -> io::Result<u64> {
    let thread = unsafe {
        CreateRemoteThread(
            handle.0.raw(),
            std::ptr::null(),
            0,
            Some(std::mem::transmute(entry.get())),
            arg as usize as *const _,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return Err(io::Error::last_os_error());
    }
    let wait = unsafe { WaitForSingleObject(thread, INFINITE) };
    let mut exit_code: u32 = 0;
    let get_ok = unsafe { GetExitCodeThread(thread, &mut exit_code) };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(thread) };
    if wait != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error());
    }
    if get_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(exit_code as u64)
}

pub(crate) fn execute_remote_detached(
    handle: &ProcessHandle,
    entry: Address,
    arg: u64,
) -> io::Result<()> {
    let thread = unsafe {
        CreateRemoteThread(
            handle.0.raw(),
            std::ptr::null(),
            0,
            Some(std::mem::transmute(entry.get())),
            arg as usize as *const _,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return Err(io::Error::last_os_error());
    }
    unsafe { windows_sys::Win32::Foundation::CloseHandle(thread) };
    Ok(())
}

fn call_remote_thread(handle: &ProcessHandle, ep: Address, arg: Address) -> io::Result<()> {
    let thread = unsafe {
        CreateRemoteThread(
            handle.0.raw(),
            std::ptr::null(),
            0,
            Some(std::mem::transmute(ep.get())),
            arg.get() as *const _,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return Err(io::Error::last_os_error());
    }
    unsafe { WaitForSingleObject(thread, INFINITE) };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(thread) };
    Ok(())
}

// ─── manual mapping (requires `inject` feature / pewter) ─────────────────────

#[cfg(feature = "inject")]
pub(crate) fn map_image(
    handle: &ProcessHandle,
    image: &[u8],
    _hint_name: Option<&OsStr>,
) -> io::Result<(Address, usize)> {
    if handle.is_current() {
        return map_image_local(image);
    }
    map_image_remote(handle, image)
}

#[cfg(feature = "inject")]
fn map_image_remote(
    handle: &ProcessHandle,
    image: &[u8],
) -> io::Result<(Address, usize)> {
    use pewter::pe::sections::base_relocation::BaseRelocationType;

    let pe = pewter::PEImageDef::parse(image)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    if !pe.coff_header.machine.is_64_bit() {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only 64-bit PE supported"));
    }

    let image_base = pe.optional_header.windows_specific_fields.image_base();
    let size_of_image = pe.optional_header.windows_specific_fields.size_of_image() as usize;
    let size_of_headers = pe.optional_header.windows_specific_fields.size_of_headers() as usize;
    let ep_rva = pe.optional_header.standard_fields.address_of_entry_point as usize;

    // Allocate in the target.
    let base = handle.0.allocate(size_of_image, Protection::READ_WRITE)?;
    let delta = base.get() as i64 - image_base as i64;

    let free_on_err = |e| { let _ = handle.0.free(base); e };

    // Copy headers.
    handle.0.write_at(base, &image[..size_of_headers.min(image.len())])
        .map_err(free_on_err)?;

    // Copy sections.
    for sec in pe.sections.iter() {
        let raw_size = sec.size_of_raw_data as usize;
        let raw_off = sec.pointer_to_raw_data as usize;
        if raw_size == 0 || raw_off >= image.len() { continue; }
        let src_end = (raw_off + raw_size).min(image.len());
        let dst = Address::new(base.get() + sec.virtual_address as usize);
        handle.0.write_at(dst, &image[raw_off..src_end]).map_err(free_on_err)?;
    }

    // Base relocations.
    if delta != 0 {
        if let Ok(Some(relocs)) = pe.read_base_relocation_table() {
            for block in relocs.relocations.iter() {
                for entry in block.table.iter() {
                    if entry.relocation_type != BaseRelocationType::Dir64 { continue; }
                    let target = Address::new(
                        base.get() + block.base_rva as usize + entry.offset as usize,
                    );
                    let mut val = [0u8; 8];
                    handle.0.read_at(target, &mut val).map_err(free_on_err)?;
                    let patched = (i64::from_le_bytes(val) + delta) as u64;
                    handle.0.write_at(target, &patched.to_le_bytes()).map_err(free_on_err)?;
                }
            }
        }
    }

    // Imports.
    if let Ok(Some(imports)) = pe.read_import_table() {
        let modules = handle.modules().unwrap_or_default();
        for entry in imports.entries.iter() {
            let dll_module = modules.iter().find(|m| {
                m.name.to_string_lossy().eq_ignore_ascii_case(&entry.dll_name)
            });

            let iat_rva = entry.import_directory_table.import_address_table_rva as usize;
            let mut iat_ptr = Address::new(base.get() + iat_rva);

            for row in entry.import_lookup_table.iter() {
                let sym_addr = match row {
                    pewter::pe::sections::idata::ImportTableRow::Ordinal(ord) => {
                        dll_module.and_then(|m| find_export_by_ordinal(handle, m.base, *ord))
                    }
                    pewter::pe::sections::idata::ImportTableRow::HintName { name, .. } => {
                        dll_module.and_then(|m| find_export_by_name(handle, m.base, name))
                    }
                };
                if let Some(addr) = sym_addr {
                    let _ = handle.0.write_at(iat_ptr, &(addr as u64).to_le_bytes());
                }
                iat_ptr = Address::new(iat_ptr.get() + 8);
            }
        }
    }

    // Section protections.
    for sec in pe.sections.iter() {
        let prot = section_flags_to_protection(sec.characteristics);
        let addr = Address::new(base.get() + sec.virtual_address as usize);
        let _ = handle.0.protect(addr, (sec.virtual_size() as usize + 0xfff) & !0xfff, prot);
    }

    // TLS callbacks.
    if let Ok(Some(tls)) = pe.read_tls_directory() {
        let _ = run_tls_callbacks(handle, base, &tls, delta);
    }

    // Entry point.
    if ep_rva != 0 {
        let _ = call_remote_thread(handle, Address::new(base.get() + ep_rva), base);
    }

    Ok((base, size_of_image))
}

/// In-process PE manual mapping — no remote threads, direct memory operations.
#[cfg(feature = "inject")]
fn map_image_local(image: &[u8]) -> io::Result<(Address, usize)> {
    use pewter::pe::sections::base_relocation::BaseRelocationType;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualProtect,
    };

    let pe = pewter::PEImageDef::parse(image)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    if !pe.coff_header.machine.is_64_bit() {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only 64-bit PE supported"));
    }

    let image_base = pe.optional_header.windows_specific_fields.image_base();
    let size_of_image = pe.optional_header.windows_specific_fields.size_of_image() as usize;
    let size_of_headers = pe.optional_header.windows_specific_fields.size_of_headers() as usize;
    let ep_rva = pe.optional_header.standard_fields.address_of_entry_point as usize;

    let base_ptr = unsafe {
        VirtualAlloc(std::ptr::null(), size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if base_ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    let base = base_ptr as usize;
    let delta = base as i64 - image_base as i64;

    // Copy headers.
    let hdr_len = size_of_headers.min(image.len());
    unsafe { std::ptr::copy_nonoverlapping(image.as_ptr(), base as *mut u8, hdr_len) };

    // Copy sections.
    for sec in pe.sections.iter() {
        let raw_size = sec.size_of_raw_data as usize;
        let raw_off = sec.pointer_to_raw_data as usize;
        if raw_size == 0 || raw_off >= image.len() { continue; }
        let src_end = (raw_off + raw_size).min(image.len());
        let dst = (base + sec.virtual_address as usize) as *mut u8;
        unsafe { std::ptr::copy_nonoverlapping(image[raw_off..].as_ptr(), dst, src_end - raw_off) };
    }

    // Base relocations.
    if delta != 0 {
        if let Ok(Some(relocs)) = pe.read_base_relocation_table() {
            for block in relocs.relocations.iter() {
                for entry in block.table.iter() {
                    if entry.relocation_type != BaseRelocationType::Dir64 { continue; }
                    let target = (base + block.base_rva as usize + entry.offset as usize) as *mut u64;
                    unsafe {
                        let val = target.read_unaligned();
                        target.write_unaligned((val as i64 + delta) as u64);
                    };
                }
            }
        }
    }

    // Imports — resolve via GetProcAddress in the current process.
    if let Ok(Some(imports)) = pe.read_import_table() {
        for entry in imports.entries.iter() {
            let dll_name: Vec<u16> = entry.dll_name.encode_utf16().chain(std::iter::once(0)).collect();
            let hmod = unsafe { GetModuleHandleW(dll_name.as_ptr()) };

            let iat_rva = entry.import_directory_table.import_address_table_rva as usize;
            let mut iat_ptr = (base + iat_rva) as *mut u64;

            for row in entry.import_lookup_table.iter() {
                let sym_addr = match row {
                    pewter::pe::sections::idata::ImportTableRow::Ordinal(ord) => {
                        if hmod.is_null() { None } else {
                            let f = unsafe { GetProcAddress(hmod, *ord as usize as *const _) };
                            f.map(|f| f as u64)
                        }
                    }
                    pewter::pe::sections::idata::ImportTableRow::HintName { name, .. } => {
                        if hmod.is_null() { None } else {
                            let cname = std::ffi::CString::new(name.as_bytes()).ok();
                            cname.and_then(|c| {
                                let f = unsafe { GetProcAddress(hmod, c.as_ptr() as *const _) };
                                f.map(|f| f as u64)
                            })
                        }
                    }
                };
                if let Some(addr) = sym_addr {
                    unsafe { iat_ptr.write_unaligned(addr) };
                }
                iat_ptr = unsafe { iat_ptr.add(1) };
            }
        }
    }

    // Section protections.
    for sec in pe.sections.iter() {
        let prot = section_flags_to_win_prot(sec.characteristics);
        let addr = (base + sec.virtual_address as usize) as *mut std::ffi::c_void;
        let size = (sec.virtual_size() as usize + 0xfff) & !0xfff;
        let mut old_prot = 0u32;
        unsafe { VirtualProtect(addr, size, prot, &mut old_prot) };
    }

    // TLS callbacks — call directly.
    if let Ok(Some(tls)) = pe.read_tls_directory() {
        let callbacks_va = (tls.address_of_callbacks as i64 + delta) as usize;
        if callbacks_va != 0 {
            let mut ptr = callbacks_va as *const u64;
            loop {
                let fn_addr = unsafe { ptr.read_unaligned() };
                if fn_addr == 0 { break; }
                type TlsCallback = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut std::ffi::c_void);
                let cb: TlsCallback = unsafe { std::mem::transmute(fn_addr) };
                unsafe { cb(base_ptr, 1 /* DLL_PROCESS_ATTACH */, std::ptr::null_mut()) };
                ptr = unsafe { ptr.add(1) };
            }
        }
    }

    // Entry point — DllMain(hModule, DLL_PROCESS_ATTACH, NULL).
    if ep_rva != 0 {
        type DllMain = unsafe extern "system" fn(*mut std::ffi::c_void, u32, *mut std::ffi::c_void) -> i32;
        let entry: DllMain = unsafe { std::mem::transmute(base + ep_rva) };
        unsafe { entry(base_ptr, 1, std::ptr::null_mut()) };
    }

    Ok((Address::new(base), size_of_image))
}

#[cfg(feature = "inject")]
fn section_flags_to_win_prot(flags: pewter::pe::sections::SectionFlags) -> u32 {
    use pewter::pe::sections::SectionFlags;
    use windows_sys::Win32::System::Memory::*;
    let r = flags.contains(SectionFlags::MEM_READ);
    let w = flags.contains(SectionFlags::MEM_WRITE);
    let x = flags.contains(SectionFlags::MEM_EXECUTE);
    match (r, w, x) {
        (_, _, true) if w => PAGE_EXECUTE_READWRITE,
        (_, _, true) => PAGE_EXECUTE_READ,
        (_, true, _) => PAGE_READWRITE,
        (true, _, _) => PAGE_READONLY,
        _ => PAGE_NOACCESS,
    }
}

#[cfg(feature = "inject")]
fn section_flags_to_protection(flags: pewter::pe::sections::SectionFlags) -> Protection {
    use pewter::pe::sections::SectionFlags;
    let mut p = Protection::NONE;
    if flags.contains(SectionFlags::MEM_READ) { p |= Protection::READ; }
    if flags.contains(SectionFlags::MEM_WRITE) { p |= Protection::WRITE; }
    if flags.contains(SectionFlags::MEM_EXECUTE) { p |= Protection::EXECUTE; }
    p
}

#[cfg(feature = "inject")]
fn run_tls_callbacks(
    handle: &ProcessHandle,
    base: Address,
    tls: &pewter::pe::sections::tls::TlsDirectory,
    delta: i64,
) -> io::Result<()> {
    let callbacks_va = (tls.address_of_callbacks as i64 + delta) as usize;
    if callbacks_va == 0 { return Ok(()); }

    let mut ptr = Address::new(callbacks_va);
    loop {
        let mut fn_va = [0u8; 8];
        handle.0.read_at(ptr, &mut fn_va)?;
        let fn_addr = u64::from_le_bytes(fn_va) as usize;
        if fn_addr == 0 { break; }
        call_remote_thread(handle, Address::new(fn_addr), base)?;
        ptr = Address::new(ptr.get() + 8);
    }
    Ok(())
}

// Export table reading — needed for import resolution, always reads from the
// target process memory since these are already-loaded modules.

#[cfg(feature = "inject")]
fn find_export_by_name(handle: &ProcessHandle, mod_base: Address, sym_name: &str) -> Option<usize> {
    let (names, funcs, ordinals, _, base) = read_export_table(handle, mod_base)?;
    for (i, &name_rva) in names.iter().enumerate() {
        let name = read_target_string(handle, Address::new(base + name_rva as usize))?;
        if name == sym_name {
            let fn_rva = funcs[ordinals[i] as usize] as usize;
            return Some(base + fn_rva);
        }
    }
    None
}

#[cfg(feature = "inject")]
fn find_export_by_ordinal(handle: &ProcessHandle, mod_base: Address, ordinal: u16) -> Option<usize> {
    let (_, funcs, _, ordinal_base, base) = read_export_table(handle, mod_base)?;
    let index = (ordinal as usize).checked_sub(ordinal_base as usize)?;
    let fn_rva = *funcs.get(index)? as usize;
    Some(base + fn_rva)
}

#[cfg(feature = "inject")]
fn read_export_table(
    handle: &ProcessHandle,
    mod_base: Address,
) -> Option<(Vec<u32>, Vec<u32>, Vec<u16>, u32, usize)> {
    let mut hdr = vec![0u8; 0x400];
    handle.0.read_at(mod_base, &mut hdr).ok()?;
    if &hdr[0..2] != b"MZ" { return None; }
    let e_lfanew = u32::from_le_bytes(hdr[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > hdr.len() { return None; }
    let opt_off = e_lfanew + 4 + 20;
    let dd_off = opt_off + 112;
    if dd_off + 8 > hdr.len() { return None; }
    let export_rva = u32::from_le_bytes(hdr[dd_off..dd_off + 4].try_into().ok()?) as usize;
    if export_rva == 0 { return None; }

    let export_dir_addr = Address::new(mod_base.get() + export_rva);
    let mut dir = vec![0u8; 40];
    handle.0.read_at(export_dir_addr, &mut dir).ok()?;

    let ordinal_base = u32::from_le_bytes(dir[16..20].try_into().ok()?);
    let num_funcs = u32::from_le_bytes(dir[20..24].try_into().ok()?) as usize;
    let num_names = u32::from_le_bytes(dir[24..28].try_into().ok()?) as usize;
    let funcs_rva = u32::from_le_bytes(dir[28..32].try_into().ok()?) as usize;
    let names_rva = u32::from_le_bytes(dir[32..36].try_into().ok()?) as usize;
    let ords_rva = u32::from_le_bytes(dir[36..40].try_into().ok()?) as usize;

    let read_rva_array = |rva: usize, count: usize, elem: usize| -> Option<Vec<u8>> {
        let mut v = vec![0u8; count * elem];
        handle.0.read_at(Address::new(mod_base.get() + rva), &mut v).ok()?;
        Some(v)
    };

    let funcs_raw = read_rva_array(funcs_rva, num_funcs, 4)?;
    let names_raw = read_rva_array(names_rva, num_names, 4)?;
    let ords_raw = read_rva_array(ords_rva, num_names, 2)?;

    let funcs: Vec<u32> = (0..num_funcs)
        .map(|i| u32::from_le_bytes(funcs_raw[i * 4..i * 4 + 4].try_into().unwrap()))
        .collect();
    let names: Vec<u32> = (0..num_names)
        .map(|i| u32::from_le_bytes(names_raw[i * 4..i * 4 + 4].try_into().unwrap()))
        .collect();
    let ordinals: Vec<u16> = (0..num_names)
        .map(|i| u16::from_le_bytes(ords_raw[i * 2..i * 2 + 2].try_into().unwrap()))
        .collect();

    Some((names, funcs, ordinals, ordinal_base, mod_base.get()))
}

#[cfg(feature = "inject")]
fn read_target_string(handle: &ProcessHandle, addr: Address) -> Option<String> {
    let mut buf = vec![0u8; 256];
    handle.0.read_at(addr, &mut buf).ok()?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).ok().map(|s| s.to_owned())
}
