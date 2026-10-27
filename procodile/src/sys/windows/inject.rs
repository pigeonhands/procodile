//! Windows library injection.
//!
//! Loader path: `LoadLibraryW` via `CreateRemoteThread` — the textbook, universally
//! documented approach used by Steam, mod loaders, and debuggers.
//!
//! Manual-mapping path: maps a PE image directly into the target, applies base
//! relocations, resolves imports from the target's already-loaded modules, runs TLS
//! callbacks and the entry point. Needed when the loader path cannot be used or when
//! the image only exists in memory.

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

/// Loads a shared library into the target via `LoadLibraryW` / `CreateRemoteThread`.
///
/// Returns the base address of the loaded module.
pub(crate) fn load_library(handle: &ProcessHandle, path: &Path) -> io::Result<Address> {
    // Guard: we only support matching pointer widths.
    let target_width = handle.0.pointer_width()?;
    if target_width != size_of::<usize>() {
        return Err(io::ErrorKind::Unsupported.into());
    }

    let wide_path = path_to_wide(path);
    let path_bytes = wide_path.len() * 2;

    // Allocate memory in the target for the path string.
    let remote_path = handle.0.allocate(path_bytes, Protection::READ_WRITE)?;

    let cleanup = || {
        let _ = handle.0.free(remote_path);
    };

    // Write the wide path into the target.
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

    // Resolve `LoadLibraryW` in our own kernel32 — it lives at the same VA in all processes.
    let kernel32_name: Vec<u16> = OsStr::new("kernel32.dll\0").encode_wide().collect();
    let kernel32 = unsafe { GetModuleHandleW(kernel32_name.as_ptr()) };
    if kernel32.is_null() {
        cleanup();
        return Err(io::Error::last_os_error());
    }
    let loadlib_name = b"LoadLibraryW\0";
    let loadlib_addr = unsafe { GetProcAddress(kernel32, loadlib_name.as_ptr()) };
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

    // Spawn a remote thread that calls LoadLibraryW(remote_path).
    let thread = unsafe {
        CreateRemoteThread(
            handle.0.raw(),
            std::ptr::null(),
            0,
            // SAFETY: LoadLibraryW has the correct signature for LPTHREAD_START_ROUTINE.
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

    // Wait for LoadLibraryW to finish and retrieve its return value.
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

    // exit_code is the low 32 bits of the HMODULE — sufficient for a base address
    // comparison; the facade resolves the full Module via modules() diff.
    Ok(Address::new(exit_code as usize))
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0); // NUL terminator
    wide
}

/// Allocates RWX memory in the target and writes `data` into it.
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

/// Runs code at `entry` in the target, passing `arg` as the first argument.
/// Blocks until the thread finishes. Returns the thread exit code.
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

/// Maps a PE image directly into the target without the OS loader.
///
/// Returns `(base, mapped_size)`.
pub(crate) fn map_image(
    handle: &ProcessHandle,
    image: &[u8],
    _hint_name: Option<&OsStr>,
) -> io::Result<(Address, usize)> {
    parse_and_map_pe(handle, image)
}

fn parse_and_map_pe(handle: &ProcessHandle, data: &[u8]) -> io::Result<(Address, usize)> {
    // ── Validate DOS / PE headers ────────────────────────────────────────────
    if data.len() < 64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "image too small"));
    }
    if &data[0..2] != b"MZ" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a PE file (no MZ)"));
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 24 > data.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PE header offset out of range"));
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "PE signature missing"));
    }

    let coff_off = e_lfanew + 4;
    let machine = u16::from_le_bytes(data[coff_off..coff_off + 2].try_into().unwrap());
    // IMAGE_FILE_MACHINE_AMD64 = 0x8664
    if machine != 0x8664 {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only AMD64 PE supported"));
    }
    let num_sections = u16::from_le_bytes(data[coff_off + 2..coff_off + 4].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(data[coff_off + 16..coff_off + 18].try_into().unwrap()) as usize;
    let opt_off = coff_off + 20;

    // Optional header magic: 0x20b = PE32+
    let magic = u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().unwrap());
    if magic != 0x20b {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only PE32+ (64-bit) supported"));
    }

    let image_base = u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().unwrap());
    let size_of_image = u32::from_le_bytes(data[opt_off + 56..opt_off + 60].try_into().unwrap()) as usize;
    let size_of_headers = u32::from_le_bytes(data[opt_off + 60..opt_off + 64].try_into().unwrap()) as usize;

    // Data directories (starts at opt_off + 112 for PE32+; each entry is 8 bytes).
    // Entry 0 = Export, 1 = Import, 5 = Base Relocation, 9 = TLS.
    let dd_off = opt_off + 112;
    let import_rva = u32::from_le_bytes(data[dd_off + 8..dd_off + 12].try_into().unwrap()) as usize;
    let import_sz = u32::from_le_bytes(data[dd_off + 12..dd_off + 16].try_into().unwrap()) as usize;
    let reloc_rva = u32::from_le_bytes(data[dd_off + 40..dd_off + 44].try_into().unwrap()) as usize;
    let reloc_sz = u32::from_le_bytes(data[dd_off + 44..dd_off + 48].try_into().unwrap()) as usize;
    let tls_rva = u32::from_le_bytes(data[dd_off + 72..dd_off + 76].try_into().unwrap()) as usize;

    // ── Allocate memory in the target ────────────────────────────────────────
    let base = handle.0.allocate(size_of_image, Protection::READ_WRITE)?;
    let delta = base.get() as i64 - image_base as i64;

    // ── Copy headers ─────────────────────────────────────────────────────────
    handle.0.write_at(base, &data[..size_of_headers.min(data.len())])
        .map_err(|e| { let _ = handle.0.free(base); e })?;

    // ── Sections ─────────────────────────────────────────────────────────────
    let sections_off = opt_off + opt_size;
    struct Section {
        virtual_address: usize,
        virtual_size: usize,
        raw_offset: usize,
        raw_size: usize,
        characteristics: u32,
    }
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sections_off + i * 40;
        if s + 40 > data.len() { break; }
        sections.push(Section {
            virtual_address: u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap()) as usize,
            virtual_size: u32::from_le_bytes(data[s + 8..s + 12].try_into().unwrap()) as usize,
            raw_offset: u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap()) as usize,
            raw_size: u32::from_le_bytes(data[s + 16..s + 20].try_into().unwrap()) as usize,
            characteristics: u32::from_le_bytes(data[s + 36..s + 40].try_into().unwrap()),
        });
    }

    for sec in &sections {
        if sec.raw_size == 0 { continue; }
        let src_end = (sec.raw_offset + sec.raw_size).min(data.len());
        if sec.raw_offset >= src_end { continue; }
        let src = &data[sec.raw_offset..src_end];
        let dst = Address::new(base.get() + sec.virtual_address);
        if let Err(e) = handle.0.write_at(dst, src) {
            let _ = handle.0.free(base);
            return Err(e);
        }
    }

    // ── Base relocations ─────────────────────────────────────────────────────
    if reloc_rva != 0 && reloc_sz != 0 && delta != 0 {
        if let Err(e) = apply_base_relocs(handle, data, base, reloc_rva, reloc_sz, delta) {
            let _ = handle.0.free(base);
            return Err(e);
        }
    }

    // ── Import table ─────────────────────────────────────────────────────────
    if import_rva != 0 && import_sz != 0 {
        if let Err(e) = resolve_imports(handle, data, base, import_rva) {
            let _ = handle.0.free(base);
            return Err(e);
        }
    }

    // ── Apply correct section protections via VirtualProtectEx ───────────────
    for sec in &sections {
        let prot = section_characteristics_to_protection(sec.characteristics);
        let addr = Address::new(base.get() + sec.virtual_address);
        let _ = handle.0.protect(addr, (sec.virtual_size + 0xfff) & !0xfff, prot);
    }

    // ── TLS callbacks ─────────────────────────────────────────────────────────
    if tls_rva != 0 {
        let _ = run_tls_callbacks(handle, data, base, tls_rva);
    }

    // ── Entry point ──────────────────────────────────────────────────────────
    let ep_rva = u32::from_le_bytes(data[opt_off + 16..opt_off + 20].try_into().unwrap()) as usize;
    if ep_rva != 0 {
        let ep = Address::new(base.get() + ep_rva);
        let _ = call_entry_point(handle, ep, base);
    }

    Ok((base, size_of_image))
}

fn apply_base_relocs(
    handle: &ProcessHandle,
    data: &[u8],
    base: Address,
    reloc_rva: usize,
    reloc_sz: usize,
    delta: i64,
) -> io::Result<()> {
    let mut off = rva_to_file_offset(data, reloc_rva)?;
    let end = off + reloc_sz;

    while off + 8 <= end && off + 8 <= data.len() {
        let page_rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        let block_sz = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if block_sz < 8 { break; }
        let entries = (block_sz - 8) / 2;
        for i in 0..entries {
            let entry_off = off + 8 + i * 2;
            if entry_off + 2 > data.len() { break; }
            let entry = u16::from_le_bytes(data[entry_off..entry_off + 2].try_into().unwrap());
            let reloc_type = (entry >> 12) as u8;
            let reloc_off = (entry & 0xfff) as usize;
            // IMAGE_REL_BASED_DIR64 = 10
            if reloc_type == 10 {
                let target = Address::new(base.get() + page_rva + reloc_off);
                let mut val = [0u8; 8];
                handle.0.read_at(target, &mut val)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "reloc read failed"))?;
                let patched = (i64::from_le_bytes(val) + delta) as u64;
                handle.0.write_at(target, &patched.to_le_bytes())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "reloc write failed"))?;
            }
        }
        off += block_sz;
    }
    Ok(())
}

fn resolve_imports(
    handle: &ProcessHandle,
    data: &[u8],
    base: Address,
    import_rva: usize,
) -> io::Result<()> {
    let mut desc_off = rva_to_file_offset(data, import_rva)?;
    let modules = handle.modules().unwrap_or_default();

    loop {
        if desc_off + 20 > data.len() { break; }
        let orig_first_thunk = u32::from_le_bytes(data[desc_off..desc_off + 4].try_into().unwrap()) as usize;
        let name_rva = u32::from_le_bytes(data[desc_off + 12..desc_off + 16].try_into().unwrap()) as usize;
        let first_thunk_rva = u32::from_le_bytes(data[desc_off + 16..desc_off + 20].try_into().unwrap()) as usize;
        desc_off += 20;

        if name_rva == 0 && first_thunk_rva == 0 { break; }

        let name_off = rva_to_file_offset(data, name_rva)?;
        let name_end = data[name_off..].iter().position(|&b| b == 0)
            .map(|n| name_off + n)
            .unwrap_or(data.len());
        let dll_name = std::str::from_utf8(&data[name_off..name_end])
            .unwrap_or("");

        let dll_module = modules.iter().find(|m| {
            m.name.to_string_lossy().eq_ignore_ascii_case(dll_name)
        });

        // Walk the import name table (INT / ILT).
        let ilt_rva = if orig_first_thunk != 0 { orig_first_thunk } else { first_thunk_rva };
        let mut ilt_off = rva_to_file_offset(data, ilt_rva)?;
        let mut iat_ptr = Address::new(base.get() + first_thunk_rva);

        loop {
            if ilt_off + 8 > data.len() { break; }
            let entry = u64::from_le_bytes(data[ilt_off..ilt_off + 8].try_into().unwrap());
            ilt_off += 8;
            if entry == 0 { break; }

            // High bit set = ordinal import.
            let sym_addr = if entry & (1 << 63) != 0 {
                let ordinal = (entry & 0xffff) as u16;
                dll_module.and_then(|m| find_export_by_ordinal(handle, m.base, ordinal))
            } else {
                // Hint/Name entry.
                let hint_rva = (entry & 0x7fff_ffff_ffff) as usize;
                let hint_off = rva_to_file_offset(data, hint_rva).ok();
                let name = hint_off.and_then(|o| {
                    let name_start = o + 2; // skip the 2-byte hint
                    let name_end = data[name_start..].iter().position(|&b| b == 0)
                        .map(|n| name_start + n)?;
                    std::str::from_utf8(&data[name_start..name_end]).ok().map(|s| s.to_owned())
                });
                name.and_then(|n| {
                    dll_module.and_then(|m| find_export_by_name(handle, m.base, &n))
                })
            };

            if let Some(addr) = sym_addr {
                handle.0.write_at(iat_ptr, &(addr as u64).to_le_bytes())
                    .ok();
            }
            iat_ptr = Address::new(iat_ptr.get() + 8);
        }
    }
    Ok(())
}

/// Resolve an export by name from a module already loaded in the target.
fn find_export_by_name(handle: &ProcessHandle, mod_base: Address, sym_name: &str) -> Option<usize> {
    let (names, funcs, ordinals, ordinal_base, base) = read_export_table(handle, mod_base)?;
    let _ = ordinal_base;
    for (i, &name_rva) in names.iter().enumerate() {
        let name = read_target_string(handle, Address::new(base + name_rva as usize))?;
        if name == sym_name {
            let ord = ordinals[i] as usize;
            let fn_rva = funcs[ord] as usize;
            return Some(base + fn_rva);
        }
    }
    None
}

fn find_export_by_ordinal(handle: &ProcessHandle, mod_base: Address, ordinal: u16) -> Option<usize> {
    let (_, funcs, _, ordinal_base, base) = read_export_table(handle, mod_base)?;
    let index = (ordinal as usize).checked_sub(ordinal_base as usize)?;
    let fn_rva = *funcs.get(index)? as usize;
    Some(base + fn_rva)
}

fn read_export_table(
    handle: &ProcessHandle,
    mod_base: Address,
) -> Option<(Vec<u32>, Vec<u32>, Vec<u16>, u32, usize)> {
    // Read the PE headers from the target to find the export directory.
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

fn read_target_string(handle: &ProcessHandle, addr: Address) -> Option<String> {
    let mut buf = vec![0u8; 256];
    handle.0.read_at(addr, &mut buf).ok()?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).ok().map(|s| s.to_owned())
}

fn run_tls_callbacks(
    handle: &ProcessHandle,
    data: &[u8],
    base: Address,
    tls_rva: usize,
) -> io::Result<()> {
    // IMAGE_TLS_DIRECTORY64 is 40 bytes; AddressOfCallBacks is at offset 24.
    let tls_addr = Address::new(base.get() + tls_rva);
    let mut tls_dir = vec![0u8; 40];
    handle.0.read_at(tls_addr, &mut tls_dir)?;
    let callbacks_va = u64::from_le_bytes(tls_dir[24..32].try_into().unwrap()) as usize;
    if callbacks_va == 0 { return Ok(()); }

    let mut ptr = Address::new(callbacks_va);
    loop {
        let mut fn_va = [0u8; 8];
        handle.0.read_at(ptr, &mut fn_va)?;
        let fn_addr = u64::from_le_bytes(fn_va) as usize;
        if fn_addr == 0 { break; }
        call_entry_point(handle, Address::new(fn_addr), base)?;
        ptr = Address::new(ptr.get() + 8);
    }
    Ok(())
}

fn call_entry_point(handle: &ProcessHandle, ep: Address, base: Address) -> io::Result<()> {
    // Spawn a remote thread at the entry point.
    let thread = unsafe {
        CreateRemoteThread(
            handle.0.raw(),
            std::ptr::null(),
            0,
            Some(std::mem::transmute(ep.get())),
            base.get() as *const _,
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

fn section_characteristics_to_protection(ch: u32) -> Protection {
    // IMAGE_SCN_MEM_READ = 0x40000000, WRITE = 0x80000000, EXECUTE = 0x20000000
    let mut p = Protection::NONE;
    if ch & 0x40000000 != 0 { p |= Protection::READ; }
    if ch & 0x80000000 != 0 { p |= Protection::WRITE; }
    if ch & 0x20000000 != 0 { p |= Protection::EXECUTE; }
    p
}

/// Convert an RVA to a file offset by walking section headers.
fn rva_to_file_offset(data: &[u8], rva: usize) -> io::Result<usize> {
    if data.len() < 64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "image too small"));
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    let coff_off = e_lfanew + 4;
    let num_sections = u16::from_le_bytes(data[coff_off + 2..coff_off + 4].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(data[coff_off + 16..coff_off + 18].try_into().unwrap()) as usize;
    let sections_off = coff_off + 20 + opt_size;

    // Check if rva falls in the headers (before first section).
    let size_of_headers = u32::from_le_bytes(data[coff_off + 20 + 60..coff_off + 20 + 64].try_into().unwrap_or([0;4])) as usize;
    if rva < size_of_headers {
        return Ok(rva);
    }

    for i in 0..num_sections {
        let s = sections_off + i * 40;
        if s + 40 > data.len() { break; }
        let vaddr = u32::from_le_bytes(data[s + 12..s + 16].try_into().unwrap()) as usize;
        let raw_offset = u32::from_le_bytes(data[s + 20..s + 24].try_into().unwrap()) as usize;
        let raw_size = u32::from_le_bytes(data[s + 16..s + 20].try_into().unwrap()) as usize;
        if rva >= vaddr && rva < vaddr + raw_size {
            return Ok(raw_offset + (rva - vaddr));
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, format!("RVA {rva:#x} not in any section")))
}
