//! Linux library injection — loader-based (`dlopen` via ptrace) and manual ELF mapping.
//!
//! Both approaches require the caller to have `CAP_SYS_PTRACE` or the same UID as the
//! target, and the kernel's Yama ptrace-scope must be ≤ 1
//! (`/proc/sys/kernel/yama/ptrace_scope`).
//!
//! The ptrace-driven paths are x86-64 only in the current implementation.

use std::ffi::OsStr;
use std::io;
use std::path::Path;

use crate::{Address, ProcessHandle};

/// Loads a shared library into the target via `dlopen` driven by ptrace.
///
/// Returns the module base address on success.
pub(crate) fn load_library(handle: &ProcessHandle, path: &Path) -> io::Result<Address> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::dlopen_inject(handle, path)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (handle, path);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Allocates RWX memory in the target and writes `data` into it.
pub(crate) fn inject_bytes(handle: &ProcessHandle, data: &[u8]) -> io::Result<Address> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::inject_bytes_impl(handle, data)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (handle, data);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Runs code at `entry` in the target, passing `arg` as the first argument.
/// Blocks until the code returns. Returns the return value (`rax`).
pub(crate) fn execute_remote(
    handle: &ProcessHandle,
    entry: Address,
    arg: u64,
) -> io::Result<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::execute_remote_impl(handle, entry, arg)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (handle, entry, arg);
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Maps an ELF shared-object image directly into the target without the OS loader.
///
/// Returns `(base, mapped_size)` on success.
pub(crate) fn map_image(
    handle: &ProcessHandle,
    image: &[u8],
    _hint_name: Option<&OsStr>,
) -> io::Result<(Address, usize)> {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::elf_map(handle, image)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (handle, image);
        Err(io::ErrorKind::Unsupported.into())
    }
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
            if ret == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { regs.assume_init() })
        }

        fn setregs(&self, regs: &user_regs_struct) -> io::Result<()> {
            let ret = unsafe {
                ptrace(PTRACE_SETREGS, self.pid, 0usize, regs as *const _ as usize)
            };
            if ret == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
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
                if ret == -1 {
                    return Err(io::Error::last_os_error());
                }
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
        fn drop(&mut self) {
            let _ = self.detach();
        }
    }

    // ─── remote syscall injection ────────────────────────────────────────────

    /// Inject an `mmap` syscall into the target via ptrace, returning the mapped address.
    fn remote_mmap(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        size: usize,
        prot: i32,
    ) -> io::Result<u64> {
        let syscall_addr = find_syscall_insn(handle)?;

        // mmap(NULL, size, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
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

    /// Inject an `mprotect` syscall into the target via ptrace.
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

    /// Find a `syscall` instruction (0f 05) in the target's libc executable mapping.
    fn find_syscall_insn(handle: &ProcessHandle) -> io::Result<u64> {
        let maps = handle.as_inner().maps()?;
        let rx = maps
            .iter()
            .find(|e| {
                e.protection.executable()
                    && e.protection.readable()
                    && e.path().map_or(false, |p| p.to_string_lossy().contains("libc"))
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

    fn elf_flags_to_prot(flags: u32) -> i32 {
        let mut p = libc::PROT_NONE;
        if flags & 4 != 0 { p |= libc::PROT_READ; }
        if flags & 2 != 0 { p |= libc::PROT_WRITE; }
        if flags & 1 != 0 { p |= libc::PROT_EXEC; }
        p
    }

    // ─── remote function call via ptrace ─────────────────────────────────────

    /// Call a function in the target at `fn_addr` with up to 6 integer arguments.
    /// Places an INT3 return trap in `scratch`, sets up the call frame, and runs
    /// until SIGTRAP. Returns `rax`.
    fn remote_call(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        scratch: u64,
        fn_addr: u64,
        args: &[u64; 6],
    ) -> io::Result<u64> {
        // Write INT3 near the end of the scratch page as the return address.
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

        // Stack: push the trap return address.
        regs.rsp = ret_addr;
        regs.rsp -= 8;
        handle.as_inner().mem.write_at(&ret_addr.to_le_bytes(), regs.rsp)?;

        tracer.setregs(&regs)?;
        tracer.cont_and_wait()?;

        let after = tracer.getregs()?;
        Ok(after.rax)
    }

    // ─── dlopen symbol resolution ────────────────────────────────────────────

    /// Resolves `__libc_dlopen_mode` (or `dlopen`) in the target by finding libc's
    /// base address in the target, then adding the symbol's file-relative vaddr read
    /// from the on-disk ELF.
    fn resolve_dlopen(handle: &ProcessHandle) -> io::Result<u64> {
        let target_maps = handle.as_inner().maps()?;
        let target_libc = target_maps
            .iter()
            .find(|e| {
                e.path().map_or(false, |p| {
                    let s = p.to_string_lossy();
                    s.contains("/libc.so") || s.contains("/libc-")
                })
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "libc not found in target maps")
            })?;
        let target_libc_base = target_libc.start as u64;
        let libc_path = target_libc.path().unwrap();

        // resolve_local_sym reads the ELF from disk; for ET_DYN shared libraries the
        // st_value is already the offset from load-base 0, so the remote address is
        // just target_base + st_value.
        let offset = resolve_local_sym(&libc_path, "__libc_dlopen_mode")?
            .or_else(|| resolve_local_sym(&libc_path, "dlopen").ok().flatten())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "dlopen symbol not found in libc")
            })?;

        Ok(target_libc_base + offset)
    }

    /// Read the on-disk ELF at `lib_path` and return the `st_value` (file-relative
    /// vaddr) of the named dynamic symbol, or `None` if not found.
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

        if shoff == 0 || shnum == 0 {
            return Ok(None);
        }

        // Find .dynsym and its linked .dynstr.
        let mut dynsym_off = 0usize;
        let mut dynsym_size = 0usize;
        let mut dynstr_off = 0usize;

        for i in 0..shnum {
            let base = shoff + i * shentsize;
            if base + shentsize > data.len() { break; }
            // SHT_DYNSYM = 11
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

        if dynsym_off == 0 || dynstr_off == 0 {
            return Ok(None);
        }

        let count = dynsym_size / 24; // Elf64_Sym = 24 bytes
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

    // ─── dlopen injection entry ──────────────────────────────────────────────

    pub(super) fn dlopen_inject(handle: &ProcessHandle, path: &Path) -> io::Result<Address> {
        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        // Allocate a scratch page for the path string and the return-address trap.
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

        // Write the library path into the scratch region.
        handle.as_inner().mem.write_at(&path_bytes, scratch)?;

        let dlopen_addr = resolve_dlopen(handle)?;

        // __libc_dlopen_mode(path, RTLD_NOW)
        let args = [scratch, libc::RTLD_NOW as u64, 0, 0, 0, 0];
        let result = remote_call(handle, &tracer, &saved, scratch, dlopen_addr, &args)?;

        tracer.setregs(&saved)?;
        tracer.detach()?;

        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "dlopen returned NULL — library not found or symbol resolution failed",
            ));
        }

        // Find the new mapping by path.
        let after_maps = handle.as_inner().maps()?;
        let lib_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        let base = after_maps
            .iter()
            .filter(|e| {
                e.path().map_or(false, |p| {
                    std::fs::canonicalize(&p).ok().as_deref() == Some(lib_path.as_path())
                })
            })
            .map(|e| e.start)
            .min()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "new module not found in maps after dlopen",
                )
            })?;

        Ok(Address::new(base))
    }

    // ─── low-level primitives ─────────────────────────────────────────────

    pub(super) fn inject_bytes_impl(
        handle: &ProcessHandle,
        data: &[u8],
    ) -> io::Result<Address> {
        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        let size = (data.len() + 0xfff) & !0xfff;
        let addr = remote_mmap(
            handle,
            &tracer,
            &saved,
            size,
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
            handle,
            &tracer,
            &saved,
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;

        let args = [arg, 0, 0, 0, 0, 0];
        let result = remote_call(
            handle,
            &tracer,
            &saved,
            scratch,
            entry.get() as u64,
            &args,
        )?;

        tracer.setregs(&saved)?;
        tracer.detach()?;
        Ok(result)
    }

    // ─── ELF manual mapping ─────────────────────────────────────────────────

    pub(super) fn elf_map(
        handle: &ProcessHandle,
        image: &[u8],
    ) -> io::Result<(Address, usize)> {
        parse_and_map_elf(handle, image)
    }

    fn parse_and_map_elf(
        handle: &ProcessHandle,
        data: &[u8],
    ) -> io::Result<(Address, usize)> {
        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not an ELF file"));
        }
        if data[4] != 2 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "32-bit ELF not supported"));
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

        // ET_DYN = 3 (shared object / PIE)
        if read_u16(0x10) != 3 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "only ET_DYN ELF supported"));
        }
        let phoff = read_u64(0x20) as usize;
        let phentsize = read_u16(0x36) as usize;
        let phnum = read_u16(0x38) as usize;

        const PT_LOAD: u32 = 1;
        const PT_DYNAMIC: u32 = 2;

        struct LoadSeg {
            offset: usize,
            vaddr: u64,
            filesz: usize,
            memsz: usize,
            flags: u32,
        }

        let mut load_segs: Vec<LoadSeg> = Vec::new();
        let mut dyn_vaddr: Option<u64> = None;

        for i in 0..phnum {
            let base = phoff + i * phentsize;
            let p_type = read_u32(base);
            let p_flags = read_u32(base + 0x4);
            let p_offset = read_u64(base + 0x8) as usize;
            let p_vaddr = read_u64(base + 0x10);
            let p_filesz = read_u64(base + 0x20) as usize;
            let p_memsz = read_u64(base + 0x28) as usize;
            match p_type {
                PT_LOAD => load_segs.push(LoadSeg {
                    offset: p_offset,
                    vaddr: p_vaddr,
                    filesz: p_filesz,
                    memsz: p_memsz,
                    flags: p_flags,
                }),
                PT_DYNAMIC => dyn_vaddr = Some(p_vaddr),
                _ => {}
            }
        }

        if load_segs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no PT_LOAD segments"));
        }

        let base_vaddr = load_segs.iter().map(|s| s.vaddr).min().unwrap();
        let top_vaddr = load_segs.iter().map(|s| s.vaddr + s.memsz as u64).max().unwrap();
        let total_size = (top_vaddr - base_vaddr) as usize;
        let aligned_size = (total_size + 0xfff) & !0xfff;

        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        // Allocate memory for the image in the target.
        let mapped_base = remote_mmap(
            handle,
            &tracer,
            &saved,
            aligned_size,
            libc::PROT_READ | libc::PROT_WRITE,
        )?;
        let delta = mapped_base - base_vaddr;

        // Write each PT_LOAD segment's file-backed portion.
        for seg in &load_segs {
            if seg.filesz > 0 {
                let src = &data[seg.offset..seg.offset + seg.filesz];
                handle.as_inner().mem.write_at(src, seg.vaddr + delta)?;
            }
        }

        // Apply R_X86_64_RELATIVE relocations from SHT_RELA sections.
        apply_rela_relocations(handle, data, mapped_base, delta, &read_u16, &read_u32, &read_u64)?;

        // Resolve JUMP_SLOT / GLOB_DAT imports from the dynamic segment.
        if let Some(dv) = dyn_vaddr {
            resolve_imports(handle, data, delta, dv)?;
        }

        // Apply correct segment protections.
        for seg in &load_segs {
            let addr = (seg.vaddr + delta) as u64;
            let size = ((seg.memsz + 0xfff) & !0xfff) as u64;
            let _ = remote_mprotect(handle, &tracer, &saved, addr, size, seg.flags);
        }

        // Allocate a separate scratch page for init calls so we don't corrupt the
        // mapped image.
        let scratch = remote_mmap(
            handle,
            &tracer,
            &saved,
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )?;

        // Call DT_INIT and DT_INIT_ARRAY.
        if let Some(dv) = dyn_vaddr {
            call_init(handle, &tracer, &saved, data, delta, dv, scratch)?;
        }

        tracer.setregs(&saved)?;
        tracer.detach()?;

        Ok((Address::new(mapped_base as usize), aligned_size))
    }

    // ─── RELA relocations ────────────────────────────────────────────────────

    fn apply_rela_relocations(
        handle: &ProcessHandle,
        data: &[u8],
        mapped_base: u64,
        delta: u64,
        read_u16: &impl Fn(usize) -> u16,
        read_u32: &impl Fn(usize) -> u32,
        read_u64: &impl Fn(usize) -> u64,
    ) -> io::Result<()> {
        let shoff = read_u64(0x28) as usize;
        let shentsize = read_u16(0x3a) as usize;
        let shnum = read_u16(0x3c) as usize;

        for i in 0..shnum {
            let base = shoff + i * shentsize;
            if base + shentsize > data.len() { break; }
            // SHT_RELA = 4
            if read_u32(base + 0x4) != 4 { continue; }
            let sh_offset = read_u64(base + 0x18) as usize;
            let sh_size = read_u64(base + 0x20) as usize;
            let sh_entsize = read_u64(base + 0x38) as usize;
            if sh_entsize == 0 { continue; }

            let count = sh_size / sh_entsize;
            for j in 0..count {
                let roff = sh_offset + j * sh_entsize;
                if roff + 24 > data.len() { break; }
                let r_offset = read_u64(roff);
                let r_info = read_u64(roff + 8);
                let r_addend = read_u64(roff + 16) as i64;
                let r_type = (r_info & 0xffffffff) as u32;

                // R_X86_64_RELATIVE = 8: value = base + addend
                if r_type == 8 {
                    let val = (mapped_base as i64 + r_addend) as u64;
                    let target_addr = r_offset + delta;
                    handle.as_inner().mem.write_at(&val.to_le_bytes(), target_addr)?;
                }
                // GLOB_DAT (6) and JUMP_SLOT (7) are handled in resolve_imports.
            }
        }
        Ok(())
    }

    // ─── dynamic import resolution ───────────────────────────────────────────

    fn resolve_imports(
        handle: &ProcessHandle,
        data: &[u8],
        delta: u64,
        dyn_vaddr: u64,
    ) -> io::Result<()> {
        const DT_NULL: u64 = 0;
        const DT_STRTAB: u64 = 5;
        const DT_SYMTAB: u64 = 6;
        const DT_JMPREL: u64 = 23;
        const DT_PLTRELSZ: u64 = 2;

        let phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap()) as usize;
        let phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;

        let dyn_file_off = vaddr_to_file_off(data, dyn_vaddr, phoff, phentsize, phnum)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "PT_DYNAMIC not in any PT_LOAD")
            })?;

        let mut strtab_vaddr = None;
        let mut symtab_vaddr = None;
        let mut jmprel_vaddr = None;
        let mut jmprel_sz = 0u64;

        let mut off = dyn_file_off;
        loop {
            if off + 16 > data.len() { break; }
            let d_tag = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            let d_val = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            off += 16;
            match d_tag {
                DT_NULL => break,
                DT_STRTAB => strtab_vaddr = Some(d_val),
                DT_SYMTAB => symtab_vaddr = Some(d_val),
                DT_JMPREL => jmprel_vaddr = Some(d_val),
                DT_PLTRELSZ => jmprel_sz = d_val,
                _ => {}
            }
        }

        if let (Some(jrel), Some(strtab), Some(symtab)) =
            (jmprel_vaddr, strtab_vaddr, symtab_vaddr)
        {
            let jrel_off = vaddr_to_file_off(data, jrel, phoff, phentsize, phnum);
            let strtab_off = vaddr_to_file_off(data, strtab, phoff, phentsize, phnum);
            let symtab_off = vaddr_to_file_off(data, symtab, phoff, phentsize, phnum);

            if let (Some(jrel_off), Some(strtab_off), Some(symtab_off)) =
                (jrel_off, strtab_off, symtab_off)
            {
                let count = jmprel_sz as usize / 24;
                for i in 0..count {
                    let roff = jrel_off + i * 24;
                    if roff + 24 > data.len() { break; }
                    let r_offset =
                        u64::from_le_bytes(data[roff..roff + 8].try_into().unwrap());
                    let r_info =
                        u64::from_le_bytes(data[roff + 8..roff + 16].try_into().unwrap());
                    let r_sym = (r_info >> 32) as usize;
                    let r_type = (r_info & 0xffffffff) as u32;

                    // R_X86_64_GLOB_DAT = 6, R_X86_64_JUMP_SLOT = 7
                    if r_type != 6 && r_type != 7 { continue; }

                    let sym_off = symtab_off + r_sym * 24;
                    if sym_off + 4 > data.len() { continue; }
                    let st_name =
                        u32::from_le_bytes(data[sym_off..sym_off + 4].try_into().unwrap())
                            as usize;
                    let name_off = strtab_off + st_name;
                    let name_end = data[name_off..]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|n| name_off + n)
                        .unwrap_or(data.len());
                    let sym_name =
                        std::str::from_utf8(&data[name_off..name_end]).unwrap_or("");

                    if let Some(sym_addr) = find_export_in_target(handle, sym_name) {
                        let target_addr = r_offset + delta;
                        handle
                            .as_inner()
                            .mem
                            .write_at(&sym_addr.to_le_bytes(), target_addr)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn vaddr_to_file_off(
        data: &[u8],
        vaddr: u64,
        phoff: usize,
        phentsize: usize,
        phnum: usize,
    ) -> Option<usize> {
        for i in 0..phnum {
            let base = phoff + i * phentsize;
            if base + phentsize > data.len() { break; }
            let p_type = u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
            if p_type != 1 { continue; } // PT_LOAD
            let p_offset = u64::from_le_bytes(data[base + 0x8..base + 0x10].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(data[base + 0x10..base + 0x18].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(data[base + 0x20..base + 0x28].try_into().unwrap());
            if vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz {
                return Some((vaddr - p_vaddr + p_offset) as usize);
            }
        }
        None
    }

    /// Look up an exported symbol in the target's loaded modules by reading their
    /// on-disk ELF dynsym tables and sliding by the actual load address.
    fn find_export_in_target(handle: &ProcessHandle, sym_name: &str) -> Option<u64> {
        let maps = handle.as_inner().maps().ok()?;
        let mut seen_paths: std::collections::HashSet<String> = Default::default();
        for entry in &maps {
            let path = entry.path()?;
            let path_s = path.to_string_lossy().into_owned();
            if !seen_paths.insert(path_s.clone()) { continue; }
            if path_s.starts_with('[') { continue; }

            let Ok(module_data) = std::fs::read(&path) else { continue };
            if module_data.len() < 64 || &module_data[0..4] != b"\x7fELF" { continue; }

            let read_u16 = |off: usize| -> u16 {
                u16::from_le_bytes(module_data[off..off + 2].try_into().unwrap())
            };
            let read_u32 = |off: usize| -> u32 {
                u32::from_le_bytes(module_data[off..off + 4].try_into().unwrap())
            };
            let read_u64m = |off: usize| -> u64 {
                u64::from_le_bytes(module_data[off..off + 8].try_into().unwrap())
            };

            let shoff = read_u64m(0x28) as usize;
            let shentsize = read_u16(0x3a) as usize;
            let shnum = read_u16(0x3c) as usize;
            if shoff == 0 { continue; }

            let mut dynsym_off = 0usize;
            let mut dynsym_size = 0usize;
            let mut dynstr_off = 0usize;

            for i in 0..shnum {
                let base = shoff + i * shentsize;
                if base + shentsize > module_data.len() { break; }
                if read_u32(base + 0x4) == 11 {
                    dynsym_off = read_u64m(base + 0x18) as usize;
                    dynsym_size = read_u64m(base + 0x20) as usize;
                    let link = read_u32(base + 0x28) as usize;
                    if link < shnum {
                        let sbase = shoff + link * shentsize;
                        dynstr_off = read_u64m(sbase + 0x18) as usize;
                    }
                }
            }
            if dynsym_off == 0 { continue; }

            let count = dynsym_size / 24;
            for i in 0..count {
                let sym_base = dynsym_off + i * 24;
                if sym_base + 24 > module_data.len() { break; }
                let st_name = read_u32(sym_base) as usize;
                let st_value = read_u64m(sym_base + 0x8);
                if st_value == 0 { continue; }
                let name_off = dynstr_off + st_name;
                let name_end = module_data[name_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|n| name_off + n)
                    .unwrap_or(module_data.len());
                if &module_data[name_off..name_end] == sym_name.as_bytes() {
                    // Compute the module's load slide: runtime base - file base.
                    let runtime_base = entry.start as u64;
                    let phoff = read_u64m(0x20) as usize;
                    let phentsize = read_u16(0x36) as usize;
                    let phnum = read_u16(0x38) as usize;
                    let file_base_vaddr = (0..phnum)
                        .filter_map(|j| {
                            let b = phoff + j * phentsize;
                            if b + phentsize > module_data.len() { return None; }
                            if read_u32(b) != 1 { return None; } // PT_LOAD
                            Some(read_u64m(b + 0x10))
                        })
                        .min()
                        .unwrap_or(0);
                    return Some(st_value + runtime_base - file_base_vaddr);
                }
            }
        }
        None
    }

    // ─── init functions ──────────────────────────────────────────────────────

    fn call_init(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        data: &[u8],
        delta: u64,
        dyn_vaddr: u64,
        scratch: u64,
    ) -> io::Result<()> {
        const DT_NULL: u64 = 0;
        const DT_INIT: u64 = 12;
        const DT_INIT_ARRAY: u64 = 25;
        const DT_INIT_ARRAYSZ: u64 = 27;

        let phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap()) as usize;
        let phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;

        let Some(dyn_off) = vaddr_to_file_off(data, dyn_vaddr, phoff, phentsize, phnum) else {
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
