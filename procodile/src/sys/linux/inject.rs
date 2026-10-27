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
    use std::path::Path;

    use libc::{
        PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH, PTRACE_GETREGS, PTRACE_SETREGS,
        PTRACE_SINGLESTEP, pid_t, ptrace, user_regs_struct, waitpid,
    };

    use crate::{Address, ProcessHandle};
    use crate::memory::Protection;
    
    
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
            // Wait for the process to stop.
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

        /// Continue and wait for the process to stop again (SIGTRAP / any signal).
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

    // ─── syscall injection ───────────────────────────────────────────────────

    /// Find a `syscall` instruction (0f 05) in the target's libc rx mapping,
    /// inject an `mmap` syscall, and return the resulting address.
    fn remote_mmap(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        size: usize,
        prot: i32,
    ) -> io::Result<u64> {
        

        let syscall_addr = find_syscall_insn(handle)?;

        // Build register state for mmap(NULL, size, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0).
        let mut regs = *saved;
        regs.rip = syscall_addr;
        regs.rax = libc::SYS_mmap as u64;
        regs.rdi = 0;                                  // addr = NULL
        regs.rsi = size as u64;                        // length
        regs.rdx = prot as u64;                        // prot
        regs.r10 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64; // flags
        regs.r8 = u64::MAX;                            // fd = -1
        regs.r9 = 0;                                   // offset

        tracer.setregs(&regs)?;
        tracer.singlestep_and_wait()?;

        let after = tracer.getregs()?;
        let mapped = after.rax;
        if mapped > u64::MAX - 0x1000 {
            // mmap failed — rax holds a negative errno.
            return Err(io::Error::from_raw_os_error(-(mapped as i64) as i32));
        }
        Ok(mapped)
    }

    /// Find the address of a `syscall` (0f 05) instruction in the target's libc
    /// executable mapping.
    fn find_syscall_insn(handle: &ProcessHandle) -> io::Result<u64> {
        use std::os::unix::fs::FileExt;

        let maps = handle.as_inner().maps()?;
        let rx = maps
            .iter()
            .find(|e| {
                e.protection.executable() && e.protection.readable()
                    && e.path().map_or(false, |p| {
                        p.to_string_lossy().contains("libc")
                    })
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no libc rx mapping"))?;

        // Read up to 4 MiB of the mapping to find a syscall insn.
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

    // ─── dlopen symbol resolution ────────────────────────────────────────────

    /// Resolves the address of `__libc_dlopen_mode` in the target by locating libc's
    /// base in both our own process and the target, then offsetting the local symbol.
    fn resolve_dlopen(handle: &ProcessHandle) -> io::Result<u64> {
        // Find libc in the target.
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

        // Find libc in our own process to compute the local base.
        let self_maps_raw = std::fs::read(format!("/proc/{}/maps", std::process::id()))?;
        let self_maps = super::super::maps::parse(&self_maps_raw);
        let self_libc = self_maps
            .iter()
            .find(|e| e.path().as_ref() == Some(&libc_path))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "same libc not loaded in injector process",
                )
            })?;
        let self_libc_base = self_libc.start as u64;

        // Resolve `__libc_dlopen_mode` in our own address space.
        let sym_addr = resolve_local_sym(&libc_path, "__libc_dlopen_mode")?
            .or_else(|| resolve_local_sym(&libc_path, "dlopen").ok().flatten())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "__libc_dlopen_mode not found")
            })?;

        Ok(target_libc_base + (sym_addr - self_libc_base))
    }

    /// Resolve a symbol's virtual address in the given shared library by reading its
    /// ELF dynamic symbol table directly.
    fn resolve_local_sym(
        lib_path: &std::path::Path,
        sym_name: &str,
    ) -> io::Result<Option<u64>> {
        

        let data = std::fs::read(lib_path)?;

        // Minimal ELF parser for dynamic symbol resolution.
        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return Ok(None);
        }
        let is_64 = data[4] == 2;
        if !is_64 {
            return Ok(None); // 32-bit not supported in x86-64 path
        }
        let little = data[5] == 1;
        let read_u16 = |off: usize| -> u16 {
            let b = &data[off..off+2];
            if little { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) }
        };
        let read_u32 = |off: usize| -> u32 {
            let b = &data[off..off+4];
            if little { u32::from_le_bytes([b[0],b[1],b[2],b[3]]) } else { u32::from_be_bytes([b[0],b[1],b[2],b[3]]) }
        };
        let read_u64 = |off: usize| -> u64 {
            let b = &data[off..off+8];
            if little { u64::from_le_bytes(b.try_into().unwrap()) } else { u64::from_be_bytes(b.try_into().unwrap()) }
        };

        let shoff = read_u64(0x28) as usize;
        let shentsize = read_u16(0x3a) as usize;
        let shnum = read_u16(0x3c) as usize;
        let _shstrndx = read_u16(0x3e) as usize;

        if shoff == 0 || shnum == 0 {
            return Ok(None);
        }

        // Find .dynsym and .dynstr sections.
        let mut dynsym_off = 0usize;
        let mut dynsym_size = 0usize;
        let mut dynstr_off = 0usize;

        for i in 0..shnum {
            let base = shoff + i * shentsize;
            if base + shentsize > data.len() { break; }
            let sh_type = read_u32(base + 0x4);
            // SHT_DYNSYM = 11
            if sh_type == 11 {
                dynsym_off = read_u64(base + 0x18) as usize;
                dynsym_size = read_u64(base + 0x20) as usize;
                let link = read_u32(base + 0x28) as usize;
                // linked section is .dynstr
                if link < shnum {
                    let sbase = shoff + link * shentsize;
                    dynstr_off = read_u64(sbase + 0x18) as usize;
                }
            }
        }

        if dynsym_off == 0 || dynstr_off == 0 {
            return Ok(None);
        }

        // Elf64_Sym is 24 bytes.
        let entsize = 24usize;
        let count = dynsym_size / entsize;
        for i in 0..count {
            let base = dynsym_off + i * entsize;
            if base + entsize > data.len() { break; }
            let st_name = read_u32(base) as usize;
            let st_value = read_u64(base + 0x8);
            if st_value == 0 { continue; }
            let name_off = dynstr_off + st_name;
            let name_end = data[name_off..].iter().position(|&b| b == 0)
                .map(|n| name_off + n)
                .unwrap_or(data.len());
            if &data[name_off..name_end] == sym_name.as_bytes() {
                return Ok(Some(st_value));
            }
        }
        Ok(None)
    }

    // ─── remote function call via ptrace ─────────────────────────────────────

    /// Call a function in the target at `fn_addr` with up to 6 integer arguments.
    /// Sets up a trap-on-return by placing a 0xcc-padded return address, then runs
    /// until SIGTRAP. Returns `rax`.
    fn remote_call(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        scratch: u64,
        scratch_size: usize,
        fn_addr: u64,
        args: &[u64; 6],
    ) -> io::Result<u64> {
        use std::os::unix::fs::FileExt;

        // Write INT3 at `scratch + scratch_size - 8` as the return address.
        let ret_addr = scratch + scratch_size as u64 - 8;
        let trap: [u8; 1] = [0xcc];
        handle.as_inner().mem.write_at(&trap, ret_addr)?;

        let mut regs = *saved;
        regs.rip = fn_addr;
        regs.rsp = ret_addr;      // "stack" pointer at the return address slot
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.rcx = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];

        // Push the trap return addr onto the stack.
        regs.rsp -= 8;
        handle.as_inner().mem.write_at(&ret_addr.to_le_bytes(), regs.rsp)?;

        tracer.setregs(&regs)?;
        tracer.cont_and_wait()?;

        let after = tracer.getregs()?;
        Ok(after.rax)
    }

    // ─── dlopen injection entry ──────────────────────────────────────────────

    pub(super) fn dlopen_inject(handle: &ProcessHandle, path: &Path) -> io::Result<Address> {
        use std::os::unix::fs::FileExt;

        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;

        let saved = tracer.getregs()?;

        // Allocate scratch memory via a remote mmap syscall.
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
            libc::PROT_READ | libc::PROT_WRITE,
        )?;

        // Write the path into scratch memory.
        handle.as_inner().mem.write_at(&path_bytes, scratch)?;

        // Resolve dlopen in the target.
        let dlopen_addr = resolve_dlopen(handle)?;

        // Call __libc_dlopen_mode(path, RTLD_NOW=2).
        let args = [scratch, libc::RTLD_NOW as u64, 0, 0, 0, 0];
        let handle_val = remote_call(
            handle, &tracer, &saved, scratch, scratch_size, dlopen_addr, &args,
        )?;

        // Restore original registers.
        tracer.setregs(&saved)?;
        tracer.detach()?;

        if handle_val == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "dlopen returned NULL — library not found or symbol resolution failed",
            ));
        }

        // Determine the module base by scanning the new mapping.
        // The base is typically the lowest address of the new rx segment.
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
                io::Error::new(io::ErrorKind::NotFound, "new module not found in maps after dlopen")
            })?;

        Ok(Address::new(base))
    }

    // ─── ELF manual mapping ──────────────────────────────────────────────────

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
        use std::os::unix::fs::FileExt;

        if data.len() < 64 || &data[0..4] != b"\x7fELF" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not an ELF file"));
        }
        if data[4] != 2 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "32-bit ELF not supported"));
        }

        let read_u16 = |off: usize| -> u16 {
            u16::from_le_bytes(data[off..off+2].try_into().unwrap())
        };
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes(data[off..off+4].try_into().unwrap())
        };
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes(data[off..off+8].try_into().unwrap())
        };

        // ELF header fields.
        let e_type = read_u16(0x10);
        // ET_DYN = 3 (shared object / PIE)
        if e_type != 3 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "only ET_DYN ELF supported"));
        }
        let phoff = read_u64(0x20) as usize;
        let phentsize = read_u16(0x36) as usize;
        let phnum = read_u16(0x38) as usize;

        // PT_LOAD segments determine the total mapped size.
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

        // Attach with ptrace to run remote syscalls.
        let pid = handle.as_inner().pid() as pid_t;
        let mut tracer = PtraceGuard::attach(pid)?;
        let saved = tracer.getregs()?;

        // Reserve memory in the target.
        let mapped_base = remote_mmap(
            handle,
            &tracer,
            &saved,
            aligned_size,
            libc::PROT_READ | libc::PROT_WRITE,
        )?;
        let delta = mapped_base - base_vaddr;

        // Write each PT_LOAD segment.
        for seg in &load_segs {
            if seg.filesz > 0 {
                let src = &data[seg.offset..seg.offset + seg.filesz];
                let dst = seg.vaddr + delta;
                handle.as_inner().mem.write_at(src, dst)?;
            }
        }

        // Apply base relocations (RELA).
        apply_rela_relocations(handle, data, mapped_base, delta, &read_u16, &read_u32, &read_u64)?;

        // Resolve and apply PLT/GOT imports from the dynamic segment.
        if let Some(dv) = dyn_vaddr {
            resolve_imports(handle, data, mapped_base, delta, dv, &read_u64)?;
        }

        // Protect segments with their correct permissions.
        for seg in &load_segs {
            let addr = Address::new((seg.vaddr + delta) as usize);
            let size = (seg.memsz + 0xfff) & !0xfff;
            let _prot = elf_prot_to_protection(seg.flags);
            // Best-effort: mprotect via a remote syscall.
            let _ = remote_mprotect(handle, &tracer, &saved, addr.get() as u64, size as u64, seg.flags);
        }

        // Find and call DT_INIT and DT_INIT_ARRAY.
        if let Some(dv) = dyn_vaddr {
            call_init(handle, &tracer, &saved, data, mapped_base, delta, dv, &read_u64)?;
        }

        tracer.setregs(&saved)?;
        tracer.detach()?;

        Ok((Address::new(mapped_base as usize), aligned_size))
    }

    fn remote_mprotect(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        addr: u64,
        size: u64,
        elf_flags: u32,
    ) -> io::Result<()> {
        

        let syscall_addr = find_syscall_insn(handle)?;

        let prot = elf_prot_to_libc(elf_flags);
        let mut regs = *saved;
        regs.rip = syscall_addr;
        regs.rax = libc::SYS_mprotect as u64;
        regs.rdi = addr;
        regs.rsi = size;
        regs.rdx = prot as u64;

        tracer.setregs(&regs)?;
        tracer.singlestep_and_wait()?;
        tracer.setregs(saved)?;
        Ok(())
    }

    fn elf_prot_to_libc(flags: u32) -> i32 {
        let mut p = libc::PROT_NONE;
        if flags & 4 != 0 { p |= libc::PROT_READ; }
        if flags & 2 != 0 { p |= libc::PROT_WRITE; }
        if flags & 1 != 0 { p |= libc::PROT_EXEC; }
        p
    }

    fn elf_prot_to_protection(flags: u32) -> Protection {
        let mut p = Protection::NONE;
        if flags & 4 != 0 { p |= Protection::READ; }
        if flags & 2 != 0 { p |= Protection::WRITE; }
        if flags & 1 != 0 { p |= Protection::EXECUTE; }
        p
    }

    // SHT_RELA = 4, SHT_REL = 9
    fn apply_rela_relocations(
        handle: &ProcessHandle,
        data: &[u8],
        mapped_base: u64,
        delta: u64,
        read_u16: &impl Fn(usize) -> u16,
        read_u32: &impl Fn(usize) -> u32,
        read_u64: &impl Fn(usize) -> u64,
    ) -> io::Result<()> {
        use std::os::unix::fs::FileExt;

        let shoff = read_u64(0x28) as usize;
        let shentsize = read_u16(0x3a) as usize;
        let shnum = read_u16(0x3c) as usize;

        for i in 0..shnum {
            let base = shoff + i * shentsize;
            if base + shentsize > data.len() { break; }
            let sh_type = read_u32(base + 0x4);
            // SHT_RELA = 4
            if sh_type != 4 { continue; }
            let _sh_addr = read_u64(base + 0x10);
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
                let _r_sym = (r_info >> 32) as u32;

                // R_X86_64_RELATIVE = 8: value = base + addend
                if r_type == 8 {
                    let val = (mapped_base as i64 + r_addend) as u64;
                    let target_addr = r_offset + delta;
                    handle.as_inner().mem.write_at(&val.to_le_bytes(), target_addr)?;
                }
                // Other relocation types (GLOB_DAT, JUMP_SLOT) handled in resolve_imports.
            }
        }
        Ok(())
    }

    fn resolve_imports(
        handle: &ProcessHandle,
        data: &[u8],
        _mapped_base: u64,
        delta: u64,
        dyn_vaddr: u64,
        read_u64: &impl Fn(usize) -> u64,
    ) -> io::Result<()> {
        use std::os::unix::fs::FileExt;

        // Parse the PT_DYNAMIC segment to find DT_JMPREL, DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB.
        const DT_NULL: u64 = 0;
        const DT_STRTAB: u64 = 5;
        const DT_SYMTAB: u64 = 6;
        const DT_JMPREL: u64 = 23;
        const DT_PLTRELSZ: u64 = 2;
        const DT_RELA: u64 = 7;
        const DT_RELASZ: u64 = 8;

        // dyn_vaddr is the vaddr of PT_DYNAMIC in the file; compute its offset.
        // We need to find its offset by matching vaddr in PT_LOAD.
        let _shoff = read_u64(0x28) as usize;
        // Use the mapped segment approach — find the dynheader in data by vaddr.
        let phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap()) as usize;
        let phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;

        // Find the file offset of dyn_vaddr via PT_LOAD mappings.
        let dyn_file_off = vaddr_to_file_off(data, dyn_vaddr, phoff, phentsize, phnum)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PT_DYNAMIC not in any PT_LOAD"))?;

        let mut strtab_vaddr = None;
        let mut symtab_vaddr = None;
        let mut jmprel_vaddr = None;
        let mut jmprel_sz = 0u64;
        let mut rela_vaddr = None;
        let mut rela_sz = 0u64;

        let mut off = dyn_file_off;
        loop {
            if off + 16 > data.len() { break; }
            let d_tag = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
            let d_val = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
            off += 16;
            match d_tag {
                DT_NULL => break,
                DT_STRTAB => strtab_vaddr = Some(d_val),
                DT_SYMTAB => symtab_vaddr = Some(d_val),
                DT_JMPREL => jmprel_vaddr = Some(d_val),
                DT_PLTRELSZ => jmprel_sz = d_val,
                DT_RELA => rela_vaddr = Some(d_val),
                DT_RELASZ => rela_sz = d_val,
                _ => {}
            }
        }

        // Apply JMPREL (PLT) relocations.
        if let (Some(jrel), Some(strtab), Some(symtab)) = (jmprel_vaddr, strtab_vaddr, symtab_vaddr) {
            let jrel_off = vaddr_to_file_off(data, jrel, phoff, phentsize, phnum);
            let strtab_off = vaddr_to_file_off(data, strtab, phoff, phentsize, phnum);
            let symtab_off = vaddr_to_file_off(data, symtab, phoff, phentsize, phnum);

            if let (Some(jrel_off), Some(strtab_off), Some(symtab_off)) = (jrel_off, strtab_off, symtab_off) {
                let count = jmprel_sz as usize / 24; // Elf64_Rela = 24 bytes
                for i in 0..count {
                    let roff = jrel_off + i * 24;
                    if roff + 24 > data.len() { break; }
                    let r_offset = u64::from_le_bytes(data[roff..roff+8].try_into().unwrap());
                    let r_info = u64::from_le_bytes(data[roff+8..roff+16].try_into().unwrap());
                    let _r_addend = i64::from_le_bytes(data[roff+16..roff+24].try_into().unwrap());
                    let r_sym = (r_info >> 32) as usize;
                    let r_type = (r_info & 0xffffffff) as u32;

                    // R_X86_64_JUMP_SLOT = 7, R_X86_64_GLOB_DAT = 6
                    if r_type != 7 && r_type != 6 { continue; }

                    // Get symbol name from dynsym.
                    let sym_off = symtab_off + r_sym * 24; // Elf64_Sym = 24 bytes
                    if sym_off + 4 > data.len() { continue; }
                    let st_name = u32::from_le_bytes(data[sym_off..sym_off+4].try_into().unwrap()) as usize;
                    let name_off = strtab_off + st_name;
                    let name_end = data[name_off..].iter().position(|&b| b == 0)
                        .map(|n| name_off + n)
                        .unwrap_or(data.len());
                    let sym_name = std::str::from_utf8(&data[name_off..name_end])
                        .unwrap_or("");

                    // Find the symbol in the target's loaded modules.
                    if let Some(sym_addr) = find_export_in_target(handle, sym_name) {
                        let target_addr = r_offset + delta;
                        handle.as_inner().mem.write_at(&sym_addr.to_le_bytes(), target_addr)?;
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
            let p_type = u32::from_le_bytes(data[base..base+4].try_into().unwrap());
            if p_type != 1 { continue; } // PT_LOAD
            let p_offset = u64::from_le_bytes(data[base+0x8..base+0x10].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(data[base+0x10..base+0x18].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(data[base+0x20..base+0x28].try_into().unwrap());
            if vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz {
                return Some((vaddr - p_vaddr + p_offset) as usize);
            }
        }
        None
    }

    /// Look up an exported symbol by name in the target's loaded modules by reading their
    /// ELF export tables out of the target process memory.
    fn find_export_in_target(handle: &ProcessHandle, sym_name: &str) -> Option<u64> {
        

        let maps = handle.as_inner().maps().ok()?;
        // For each mapped file, try to find sym_name in its .dynsym.
        let mut seen_paths: std::collections::HashSet<String> = Default::default();
        for entry in &maps {
            let path = entry.path()?;
            let path_s = path.to_string_lossy().into_owned();
            if !seen_paths.insert(path_s.clone()) { continue; }
            if path_s.starts_with('[') { continue; } // [stack], [heap], etc.

            // Read the target module's ELF from disk (same file, same symbols).
            let Ok(module_data) = std::fs::read(path) else { continue };
            if module_data.len() < 64 || &module_data[0..4] != b"\x7fELF" { continue; }

            // Find .dynsym in module_data.
            let read_u16 = |off: usize| -> u16 {
                u16::from_le_bytes(module_data[off..off+2].try_into().unwrap())
            };
            let read_u32 = |off: usize| -> u32 {
                u32::from_le_bytes(module_data[off..off+4].try_into().unwrap())
            };
            let read_u64 = |off: usize| -> u64 {
                u64::from_le_bytes(module_data[off..off+8].try_into().unwrap())
            };

            let shoff = read_u64(0x28) as usize;
            let shentsize = read_u16(0x3a) as usize;
            let shnum = read_u16(0x3c) as usize;
            if shoff == 0 { continue; }

            let mut dynsym_off = 0usize;
            let mut dynsym_size = 0usize;
            let mut dynstr_off = 0usize;

            for i in 0..shnum {
                let base = shoff + i * shentsize;
                if base + shentsize > module_data.len() { break; }
                let sh_type = read_u32(base + 0x4);
                if sh_type == 11 { // SHT_DYNSYM
                    dynsym_off = read_u64(base + 0x18) as usize;
                    dynsym_size = read_u64(base + 0x20) as usize;
                    let link = read_u32(base + 0x28) as usize;
                    if link < shnum {
                        let sbase = shoff + link * shentsize;
                        dynstr_off = read_u64(sbase + 0x18) as usize;
                    }
                }
            }
            if dynsym_off == 0 { continue; }

            let count = dynsym_size / 24;
            for i in 0..count {
                let sym_base = dynsym_off + i * 24;
                if sym_base + 24 > module_data.len() { break; }
                let st_name = read_u32(sym_base) as usize;
                let st_value = read_u64(sym_base + 0x8);
                if st_value == 0 { continue; }
                let name_off = dynstr_off + st_name;
                let name_end = module_data[name_off..].iter().position(|&b| b == 0)
                    .map(|n| name_off + n)
                    .unwrap_or(module_data.len());
                if &module_data[name_off..name_end] == sym_name.as_bytes() {
                    // st_value is the file-relative vaddr; add the module's base.
                    let base = entry.start as u64;
                    // Find the PT_LOAD base vaddr to compute the slide.
                    let phoff = read_u64(0x20) as usize;
                    let phentsize = read_u16(0x36) as usize;
                    let phnum = read_u16(0x38) as usize;
                    let load_base_vaddr = (0..phnum)
                        .filter_map(|j| {
                            let b = phoff + j * phentsize;
                            if b + phentsize > module_data.len() { return None; }
                            let p_type = read_u32(b);
                            if p_type != 1 { return None; }
                            Some(read_u64(b + 0x10))
                        })
                        .min()
                        .unwrap_or(0);
                    let slide = base - load_base_vaddr;
                    return Some(st_value + slide);
                }
            }
        }
        None
    }

    fn call_init(
        handle: &ProcessHandle,
        tracer: &PtraceGuard,
        saved: &user_regs_struct,
        data: &[u8],
        mapped_base: u64,
        delta: u64,
        dyn_vaddr: u64,
        _read_u64: &impl Fn(usize) -> u64,
    ) -> io::Result<()> {
        use std::os::unix::fs::FileExt;

        const DT_INIT: u64 = 12;
        const DT_INIT_ARRAY: u64 = 25;
        const DT_INIT_ARRAYSZ: u64 = 27;
        const DT_NULL: u64 = 0;

        let phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap()) as usize;
        let phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;

        let dyn_off = vaddr_to_file_off(data, dyn_vaddr, phoff, phentsize, phnum);
        let Some(dyn_off) = dyn_off else { return Ok(()); };

        // Allocate a small scratch area for call set-up (reuse an already-mapped region
        // by picking any RW area with enough room — we use the mapped image memory at
        // mapped_base + offset for the return-address trap slot).
        let scratch = mapped_base; // first page of mapped image suffices for the trap slot

        let mut off = dyn_off;
        let mut init_fn: Option<u64> = None;
        let mut init_array: Option<u64> = None;
        let mut init_arraysz: u64 = 0;
        loop {
            if off + 16 > data.len() { break; }
            let d_tag = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
            let d_val = u64::from_le_bytes(data[off+8..off+16].try_into().unwrap());
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
            remote_call(handle, tracer, saved, scratch, 4096, fn_addr, &args)?;
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
