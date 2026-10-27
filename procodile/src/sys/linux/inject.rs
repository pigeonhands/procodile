//! Linux library injection — loader-based (`dlopen` via ptrace) and manual ELF mapping.
//!
//! Both approaches require the caller to have `CAP_SYS_PTRACE` or the same UID as the
//! target, and the kernel's Yama ptrace-scope must be ≤ 1
//! (`/proc/sys/kernel/yama/ptrace_scope`).
//!
//! The ptrace-driven paths are x86-64 only in the current implementation.

#[cfg(feature = "inject")]
use std::ffi::OsStr;
use std::io;
use std::path::Path;

use crate::{Address, ProcessHandle};

/// Loads a shared library into the target via `dlopen` driven by ptrace.
pub(crate) fn load_library(handle: &ProcessHandle, path: &Path) -> io::Result<Address> {
    #[cfg(target_arch = "x86_64")]
    { x86_64::dlopen_inject(handle, path) }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (handle, path); Err(io::ErrorKind::Unsupported.into()) }
}

pub(crate) fn inject_bytes(handle: &ProcessHandle, data: &[u8]) -> io::Result<Address> {
    #[cfg(target_arch = "x86_64")]
    { x86_64::inject_bytes_impl(handle, data) }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (handle, data); Err(io::ErrorKind::Unsupported.into()) }
}

pub(crate) fn execute_remote(
    handle: &ProcessHandle,
    entry: Address,
    arg: u64,
) -> io::Result<u64> {
    #[cfg(target_arch = "x86_64")]
    { x86_64::execute_remote_impl(handle, entry, arg) }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (handle, entry, arg); Err(io::ErrorKind::Unsupported.into()) }
}

pub(crate) fn execute_remote_detached(
    handle: &ProcessHandle,
    entry: Address,
    arg: u64,
) -> io::Result<()> {
    #[cfg(target_arch = "x86_64")]
    { x86_64::execute_remote_detached_impl(handle, entry, arg) }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (handle, entry, arg); Err(io::ErrorKind::Unsupported.into()) }
}

#[cfg(feature = "inject")]
pub(crate) fn map_image(
    handle: &ProcessHandle,
    image: &[u8],
    _hint_name: Option<&OsStr>,
) -> io::Result<(Address, usize)> {
    #[cfg(target_arch = "x86_64")]
    { x86_64::elf_map(handle, image) }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (handle, image); Err(io::ErrorKind::Unsupported.into()) }
}

// ── x86-64 implementation ────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::unix::fs::FileExt;
    use std::path::Path;

    use libc::{
        PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_SETREGS,
        PTRACE_SINGLESTEP, pid_t, ptrace, user_regs_struct, waitpid,
    };

    use crate::{Address, ProcessHandle};
    use crate::AsInner;

    // ─── ptrace helpers ──────────────────────────────────────────────────────

    struct PtraceGuard {
        pid: pid_t,
        detached: bool,
    }

    impl PtraceGuard {
        fn attach(pid: pid_t) -> io::Result<Self> {
            let ret = unsafe { ptrace(PTRACE_ATTACH, pid, 0usize, 0usize) };
            if ret == -1 {
                return Err(io::Error::last_os_error());
            }
            let mut status = 0i32;
            let ret = unsafe { waitpid(pid, &mut status, 0) };
            if ret == -1 {
                unsafe { ptrace(PTRACE_DETACH, pid, 0usize, 0usize) };
                return Err(io::Error::last_os_error());
            }
            Ok(PtraceGuard { pid, detached: false })
        }

        fn detach(&mut self) -> io::Result<()> {
            if !self.detached {
                self.detached = true;
                let ret = unsafe { ptrace(PTRACE_DETACH, self.pid, 0usize, 0usize) };
                if ret == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }

        fn getregs(&self) -> io::Result<user_regs_struct> {
            let mut regs = MaybeUninit::<user_regs_struct>::uninit();
            let ret = unsafe {
                ptrace(PTRACE_GETREGS, self.pid, 0usize, regs.as_mut_ptr() as usize)
            };
            if ret == -1 { return Err(io::Error::last_os_error()); }
            Ok(unsafe { regs.assume_init() })
        }

        fn setregs(&self, regs: &user_regs_struct) -> io::Result<()> {
            let ret = unsafe {
                ptrace(PTRACE_SETREGS, self.pid, 0usize, regs as *const _ as usize)
            };
            if ret == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }

        fn cont(&self) -> io::Result<()> {
            let ret = unsafe { ptrace(PTRACE_CONT, self.pid, 0usize, 0usize) };
            if ret == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }

        fn singlestep(&self) -> io::Result<()> {
            let ret = unsafe { ptrace(PTRACE_SINGLESTEP, self.pid, 0usize, 0usize) };
            if ret == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
        }

        fn cont_and_wait(&self) -> io::Result<i32> {
            self.cont()?;
            self.wait()
        }

        fn wait(&self) -> io::Result<i32> {
            let mut status = 0i32;
            loop {
                let ret = unsafe { waitpid(self.pid, &mut status, 0) };
                if ret == -1 { return Err(io::Error::last_os_error()); }
                if libc::WIFSTOPPED(status) || libc::WIFEXITED(status) {
                    return Ok(status);
                }
            }
        }

        fn singlestep_and_wait(&self) -> io::Result<i32> {
            self.singlestep()?;
            self.wait()
        }
    }

    impl Drop for PtraceGuard {
        fn drop(&mut self) { let _ = self.detach(); }
    }

    // ─── remote syscall injection ────────────────────────────────────────────

    fn remote_mmap(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        size: usize,
        prot: i32,
    ) -> io::Result<u64> {
        let syscall_addr = find_syscall_insn(handle)?;
        let mut regs = *saved;
        regs.rip = syscall_addr;
        regs.rax = libc::SYS_mmap as u64;
        regs.rdi = 0;
        regs.rsi = size as u64;
        regs.rdx = prot as u64;
        regs.r10 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        regs.r8 = u64::MAX; // fd = -1
        regs.r9 = 0;

        tracer.setregs(&regs)?;
        tracer.singlestep_and_wait()?;

        let after = tracer.getregs()?;
        let mapped = after.rax;
        if mapped > u64::MAX - 0x1000 {
            return Err(io::Error::from_raw_os_error(-(mapped as i64) as i32));
        }
        Ok(mapped)
    }

    #[cfg(feature = "inject")]
    fn remote_mprotect(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        addr: u64,
        size: u64,
        elf_flags: u32,
    ) -> io::Result<()> {
        let syscall_addr = find_syscall_insn(handle)?;
        let prot = elf_flags_to_prot(elf_flags);
        let mut regs = *saved;
        regs.rip = syscall_addr;
        regs.rax = libc::SYS_mprotect as u64;
        regs.rdi = addr;
        regs.rsi = size;
        regs.rdx = prot as u64;

        tracer.setregs(&regs)?;
        tracer.singlestep_and_wait()?;
        Ok(())
    }

    fn find_syscall_insn(handle: &ProcessHandle) -> io::Result<u64> {
        let maps = handle.as_inner().maps()?;
        let rx = maps
            .iter()
            .find(|e| {
                e.protection.executable()
                    && e.protection.readable()
                    && e.path().is_some_and(|p| p.to_string_lossy().contains("libc"))
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no libc rx mapping"))?;

        let scan_len = (rx.end - rx.start).min(4 * 1024 * 1024);
        let mut buf = vec![0u8; scan_len];
        handle.as_inner().mem.read_at(&mut buf, rx.start as u64)?;
        for i in 0..buf.len().saturating_sub(1) {
            if buf[i] == 0x0f && buf[i + 1] == 0x05 {
                return Ok(rx.start as u64 + i as u64);
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "syscall insn not found in libc"))
    }

    #[cfg(feature = "inject")]
    fn elf_flags_to_prot(flags: u32) -> i32 {
        let mut p = libc::PROT_NONE;
        if flags & 4 != 0 { p |= libc::PROT_READ; }
        if flags & 2 != 0 { p |= libc::PROT_WRITE; }
        if flags & 1 != 0 { p |= libc::PROT_EXEC; }
        p
    }

    // ─── remote function call ────────────────────────────────────────────────

    fn remote_call(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        scratch: u64,
        fn_addr: u64,
        args: &[u64; 6],
    ) -> io::Result<u64> {
        let ret_addr = scratch + 4096 - 16;
        let trap: [u8; 1] = [0xcc];
        handle.as_inner().mem.write_at(&trap, ret_addr)?;

        let mut regs = *saved;
        regs.rip = fn_addr;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.rcx = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        regs.rsp = ret_addr;
        regs.rsp -= 8;
        handle.as_inner().mem.write_at(&ret_addr.to_le_bytes(), regs.rsp)?;

        tracer.setregs(&regs)?;
        tracer.cont_and_wait()?;

        let after = tracer.getregs()?;
        Ok(after.rax)
    }

    // ─── dlopen symbol resolution ────────────────────────────────────────────

    fn resolve_dlopen(handle: &ProcessHandle) -> io::Result<u64> {
        let target_maps = handle.as_inner().maps()?;
        let target_libc = target_maps
            .iter()
            .find(|e| {
                e.path().is_some_and(|p| {
                    let s = p.to_string_lossy();
                    s.contains("/libc.so") || s.contains("/libc-")
                })
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "libc not found in target maps")
            })?;
        let target_libc_base = target_libc.start as u64;
        let libc_path = target_libc.path().unwrap();

        let offset = resolve_local_sym(&libc_path, "__libc_dlopen_mode")?
            .or_else(|| resolve_local_sym(&libc_path, "dlopen").ok().flatten())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "dlopen symbol not found in libc")
            })?;

        Ok(target_libc_base + offset)
    }

    fn resolve_local_sym(
        lib_path: &std::path::Path,
        sym_name: &str,
    ) -> io::Result<Option<u64>> {
        let data = std::fs::read(lib_path)?;
        if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 {
            return Ok(None);
        }

        let read_u16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off + 2].try_into().unwrap())
        };
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
        };
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
        };

        let shoff = read_u64(0x28) as usize;
        let shentsize = read_u16(0x3a) as usize;
        let shnum = read_u16(0x3c) as usize;
        if shoff == 0 || shnum == 0 { return Ok(None); }

        let mut dynsym_off = 0usize;
        let mut dynsym_size = 0usize;
        let mut dynstr_off = 0usize;

        for i in 0..shnum {
            let base = shoff + i * shentsize;
            if base + shentsize > data.len() { break; }
            if read_u32(base + 0x4) == 11 {
                dynsym_off = read_u64(base + 0x18) as usize;
                dynsym_size = read_u64(base + 0x20) as usize;
                let link = read_u32(base + 0x28) as usize;
                if link < shnum {
                    let sbase = shoff + link * shentsize;
                    dynstr_off = read_u64(sbase + 0x18) as usize;
                }
            }
        }
        if dynsym_off == 0 || dynstr_off == 0 { return Ok(None); }

        let count = dynsym_size / 24;
        for i in 0..count {
            let base = dynsym_off + i * 24;
            if base + 24 > data.len() { break; }
            let st_name = read_u32(base) as usize;
            let st_value = read_u64(base + 0x8);
            if st_value == 0 { continue; }
            let name_off = dynstr_off + st_name;
            let name_end = data[name_off..]
                .iter()
                .position(|&b| b == 0)
                .map(|n| name_off + n)
                .unwrap_or(data.len());
            if &data[name_off..name_end] == sym_name.as_bytes() {
                return Ok(Some(st_value));
            }
        }
        Ok(None)
    }

    // ─── dlopen injection ────────────────────────────────────────────────────

    pub(super) fn dlopen_inject(handle: &ProcessHandle, path: &Path) -> io::Result<Address> {
        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        let path_bytes = {
            let s = path.as_os_str().as_encoded_bytes();
            let mut v = s.to_vec();
            v.push(0);
            v
        };
        let scratch_size = (path_bytes.len() + 4096) & !0xfff;
        let scratch = remote_mmap(
            handle,
            &tracer,
            &saved,
            scratch_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;

        handle.as_inner().mem.write_at(&path_bytes, scratch)?;
        let dlopen_addr = resolve_dlopen(handle)?;
        let args = [scratch, libc::RTLD_NOW as u64, 0, 0, 0, 0];
        let result = remote_call(handle, &tracer, &saved, scratch, dlopen_addr, &args)?;

        tracer.setregs(&saved)?;
        tracer.detach()?;

        if result == 0 {
            return Err(io::Error::other(
                "dlopen returned NULL — library not found or symbol resolution failed",
            ));
        }

        let after_maps = handle.as_inner().maps()?;
        let lib_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        let base = after_maps
            .iter()
            .filter(|e| {
                e.path().is_some_and(|p| {
                    std::fs::canonicalize(&p).ok().as_deref() == Some(lib_path.as_path())
                })
            })
            .map(|e| e.start)
            .min()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "new module not found in maps after dlopen")
            })?;

        Ok(Address::new(base))
    }

    // ─── low-level primitives ────────────────────────────────────────────────

    pub(super) fn inject_bytes_impl(
        handle: &ProcessHandle,
        data: &[u8],
    ) -> io::Result<Address> {
        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        let size = (data.len() + 0xfff) & !0xfff;
        let addr = remote_mmap(
            handle, &tracer, &saved, size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;
        handle.as_inner().mem.write_at(data, addr)?;

        tracer.setregs(&saved)?;
        tracer.detach()?;
        Ok(Address::new(addr as usize))
    }

    pub(super) fn execute_remote_impl(
        handle: &ProcessHandle,
        entry: Address,
        arg: u64,
    ) -> io::Result<u64> {
        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        let scratch = remote_mmap(
            handle, &tracer, &saved, 4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;
        let args = [arg, 0, 0, 0, 0, 0];
        let result = remote_call(handle, &tracer, &saved, scratch, entry.get() as u64, &args)?;

        tracer.setregs(&saved)?;
        tracer.detach()?;
        Ok(result)
    }

    pub(super) fn execute_remote_detached_impl(
        handle: &ProcessHandle,
        entry: Address,
        arg: u64,
    ) -> io::Result<()> {
        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        // Two pages: first holds the pthread_t, second is remote_call scratch.
        let alloc = remote_mmap(
            handle, &tracer, &saved, 8192,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;
        let tid_slot = alloc;
        let scratch = alloc + 4096;

        let pthread_create = resolve_pthread_sym(handle, "pthread_create")?;
        let pthread_detach = resolve_pthread_sym(handle, "pthread_detach")?;

        // pthread_create(&tid, NULL, start_routine, arg)
        let args = [tid_slot, 0, entry.get() as u64, arg, 0, 0];
        let ret = remote_call(handle, &tracer, &saved, scratch, pthread_create, &args)?;
        if ret != 0 {
            tracer.setregs(&saved)?;
            tracer.detach()?;
            return Err(io::Error::from_raw_os_error(ret as i32));
        }

        // Read back the pthread_t and detach the thread so its resources are
        // freed on exit.
        let mut tid_bytes = [0u8; 8];
        handle.as_inner().mem.read_at(&mut tid_bytes, tid_slot)?;
        let tid = u64::from_le_bytes(tid_bytes);

        let args = [tid, 0, 0, 0, 0, 0];
        remote_call(handle, &tracer, &saved, scratch, pthread_detach, &args)?;

        tracer.setregs(&saved)?;
        tracer.detach()?;
        Ok(())
    }

    fn resolve_pthread_sym(handle: &ProcessHandle, name: &str) -> io::Result<u64> {
        let target_maps = handle.as_inner().maps()?;
        let candidates = ["/libpthread", "/libc.so", "/libc-"];
        for pattern in &candidates {
            if let Some(entry) = target_maps.iter().find(|e| {
                e.path().is_some_and(|p| p.to_string_lossy().contains(pattern))
            }) {
                let base = entry.start as u64;
                let path = entry.path().unwrap();
                if let Ok(Some(offset)) = resolve_local_sym(&path, name) {
                    return Ok(base + offset);
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} not found in target"),
        ))
    }

    // ─── ELF manual mapping (requires `inject` feature / pewter) ─────────────

    #[cfg(feature = "inject")]
    pub(super) fn elf_map(
        handle: &ProcessHandle,
        image: &[u8],
    ) -> io::Result<(Address, usize)> {
        use pewter::elf::{ElfFile, SegmentType};

        let elf = ElfFile::parse(image)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        if !elf.is_64() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "32-bit ELF not supported"));
        }

        let load_segs: Vec<_> = elf.program_headers.iter()
            .filter(|p| p.segment_type == SegmentType::Load)
            .collect();
        if load_segs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no PT_LOAD segments"));
        }

        let dyn_seg = elf.program_headers.iter()
            .find(|p| p.segment_type == SegmentType::Dynamic);

        let base_vaddr = load_segs.iter().map(|s| s.vaddr).min().unwrap();
        let top_vaddr = load_segs.iter().map(|s| s.vaddr + s.memory_size).max().unwrap();
        let total_size = (top_vaddr - base_vaddr) as usize;
        let aligned_size = (total_size + 0xfff) & !0xfff;

        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        let mapped_base = remote_mmap(
            handle, &tracer, &saved, aligned_size,
            libc::PROT_READ | libc::PROT_WRITE,
        )?;
        let delta = mapped_base - base_vaddr;

        // Write each PT_LOAD segment's file-backed portion.
        for seg in &load_segs {
            let off = seg.offset as usize;
            let fsz = seg.file_size as usize;
            if fsz > 0 && off + fsz <= image.len() {
                handle.as_inner().mem.write_at(&image[off..off + fsz], seg.vaddr + delta)?;
            }
        }

        // Relocations via pewter.
        let relative_type = elf.header.machine.relative_relocation_type();
        let absolute_types = elf.header.machine.absolute_relocation_types();
        if let Ok(relocations) = elf.relocations() {
            for r in &relocations {
                let addend = r.addend.unwrap_or(0) as u64;
                if Some(r.relocation_type) == relative_type {
                    // R_X86_64_RELATIVE: value = base + addend
                    let val = (mapped_base as i64 + addend as i64) as u64;
                    handle.as_inner().mem.write_at(&val.to_le_bytes(), r.offset + delta)?;
                } else if absolute_types.contains(&r.relocation_type) {
                    // GLOB_DAT / JUMP_SLOT — resolve from target's loaded modules.
                    let symbols = elf.symbols()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    let dynsyms: Vec<_> = symbols.iter().filter(|s| s.dynamic).collect();
                    if let Some(sym) = dynsyms.get(r.symbol as usize)
                        && let Some(addr) = find_export_in_target(handle, sym.name)
                    {
                        handle.as_inner().mem.write_at(&addr.to_le_bytes(), r.offset + delta)?;
                    }
                }
            }
        }

        // Segment protections.
        for seg in &load_segs {
            let addr = seg.vaddr + delta;
            let size = ((seg.memory_size as usize + 0xfff) & !0xfff) as u64;
            let _ = remote_mprotect(handle, &tracer, &saved, addr, size, seg.flags.bits());
        }

        // Scratch page for init calls.
        let scratch = remote_mmap(
            handle, &tracer, &saved, 4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;

        // Call DT_INIT and DT_INIT_ARRAY.
        if let Some(dyn_ph) = dyn_seg {
            call_init(handle, &tracer, &saved, image, &elf, delta, dyn_ph.vaddr, scratch)?;
        }

        tracer.setregs(&saved)?;
        tracer.detach()?;

        Ok((Address::new(mapped_base as usize), aligned_size))
    }

    /// Look up an exported symbol in the target's loaded modules using pewter.
    #[cfg(feature = "inject")]
    fn find_export_in_target(handle: &ProcessHandle, sym_name: &str) -> Option<u64> {
        use pewter::elf::{ElfFile, SegmentType, SymbolBinding, SymbolType};

        let maps = handle.as_inner().maps().ok()?;
        let mut seen_paths: std::collections::HashSet<String> = Default::default();
        for entry in &maps {
            let path = entry.path()?;
            let path_s = path.to_string_lossy().into_owned();
            if !seen_paths.insert(path_s.clone()) { continue; }
            if path_s.starts_with('[') { continue; }

            let Ok(data) = std::fs::read(&path) else { continue };
            if !ElfFile::is_elf(&data) { continue; }
            let Ok(elf) = ElfFile::parse(&data) else { continue };

            let Ok(symbols) = elf.symbols() else { continue };
            for sym in &symbols {
                if !sym.dynamic || sym.name != sym_name || sym.value == 0 { continue; }
                if !sym.is_defined() { continue; }
                if !matches!(sym.binding(), Some(SymbolBinding::Global | SymbolBinding::Weak)) {
                    continue;
                }
                if !matches!(sym.symbol_type(), Some(SymbolType::Func | SymbolType::Object)) {
                    continue;
                }

                let runtime_base = entry.start as u64;
                let file_base_vaddr = elf.program_headers.iter()
                    .filter(|p| p.segment_type == SegmentType::Load)
                    .map(|p| p.vaddr)
                    .min()
                    .unwrap_or(0);
                return Some(sym.value + runtime_base - file_base_vaddr);
            }
        }
        None
    }

    // ─── init functions ──────────────────────────────────────────────────────

    #[cfg(feature = "inject")]
    #[allow(clippy::too_many_arguments)]
    fn call_init(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        data: &[u8],
        elf: &pewter::elf::ElfFile<'_>,
        delta: u64,
        dyn_vaddr: u64,
        scratch: u64,
    ) -> io::Result<()> {
        const DT_NULL: u64 = 0;
        const DT_INIT: u64 = 12;
        const DT_INIT_ARRAY: u64 = 25;
        const DT_INIT_ARRAYSZ: u64 = 27;

        let Some(dyn_off) = elf.vaddr_to_offset(dyn_vaddr) else {
            return Ok(());
        };

        let mut init_fn: Option<u64> = None;
        let mut init_array: Option<u64> = None;
        let mut init_arraysz: u64 = 0;

        let mut off = dyn_off;
        loop {
            if off + 16 > data.len() { break; }
            let d_tag = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            let d_val = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            off += 16;
            match d_tag {
                DT_NULL => break,
                DT_INIT => init_fn = Some(d_val + delta),
                DT_INIT_ARRAY => init_array = Some(d_val + delta),
                DT_INIT_ARRAYSZ => init_arraysz = d_val,
                _ => {}
            }
        }

        let call = |fn_addr: u64| -> io::Result<()> {
            let args = [0u64; 6];
            remote_call(handle, tracer, saved, scratch, fn_addr, &args)?;
            Ok(())
        };

        if let Some(f) = init_fn {
            call(f)?;
        }
        if let Some(arr) = init_array {
            let count = init_arraysz as usize / 8;
            for i in 0..count {
                let slot = arr + i as u64 * 8;
                let mut fn_bytes = [0u8; 8];
                handle.as_inner().mem.read_at(&mut fn_bytes, slot)?;
                let fn_addr = u64::from_le_bytes(fn_bytes);
                if fn_addr != 0 {
                    call(fn_addr)?;
                }
            }
        }

        Ok(())
    }
}
