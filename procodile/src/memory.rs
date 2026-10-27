use std::fmt;
use std::mem::MaybeUninit;
use std::ops::{BitOr, BitOrAssign, Range};
use std::path::PathBuf;

use crate::{Address, Error, ProcessHandle, Result};

/// Page protection of a [`Region`].
///
/// Reflected as an opaque type: its semantics are carried by `const` flag values
/// (`READ`, `WRITE`, …) that a derive macro cannot surface. Inspect them via
/// [`Protection::contains`] or the named constants on this type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[cfg_attr(feature = "reflect", facet(opaque))]
pub struct Protection(u8);

impl Protection {
    pub const NONE: Protection = Protection(0);
    pub const READ: Protection = Protection(1 << 0);
    pub const WRITE: Protection = Protection(1 << 1);
    pub const EXECUTE: Protection = Protection(1 << 2);
    /// Writes create a private copy of the page.
    pub const COPY_ON_WRITE: Protection = Protection(1 << 3);
    /// Accessing the page raises a one-shot guard exception (Windows only).
    pub const GUARD: Protection = Protection(1 << 4);
    /// The page is not cached (Windows only).
    pub const NO_CACHE: Protection = Protection(1 << 5);

    pub const READ_WRITE: Protection = Protection(Self::READ.0 | Self::WRITE.0);
    pub const READ_EXECUTE: Protection = Protection(Self::READ.0 | Self::EXECUTE.0);
    pub const READ_WRITE_EXECUTE: Protection =
        Protection(Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0);

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Protection) -> bool {
        self.0 & other.0 == other.0
    }

    /// Readable and not a guard page, i.e. safe to scan.
    pub const fn readable(self) -> bool {
        self.contains(Self::READ) && !self.contains(Self::GUARD)
    }

    pub const fn writable(self) -> bool {
        self.contains(Self::WRITE)
    }

    pub const fn executable(self) -> bool {
        self.contains(Self::EXECUTE)
    }
}

impl BitOr for Protection {
    type Output = Protection;
    fn bitor(self, rhs: Protection) -> Protection {
        Protection(self.0 | rhs.0)
    }
}

impl BitOrAssign for Protection {
    fn bitor_assign(&mut self, rhs: Protection) {
        self.0 |= rhs.0;
    }
}

/// Formats like `/proc/pid/maps`: `rwx`, with `c`/`g` appended for copy-on-write/guard.
impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flag = |p, c| if self.contains(p) { c } else { '-' };
        write!(
            f,
            "{}{}{}",
            flag(Self::READ, 'r'),
            flag(Self::WRITE, 'w'),
            flag(Self::EXECUTE, 'x')
        )?;
        if self.contains(Self::COPY_ON_WRITE) {
            f.write_str("c")?;
        }
        if self.contains(Self::GUARD) {
            f.write_str("g")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Protection({self})")
    }
}

/// What backs a [`Region`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[cfg_attr(feature = "reflect", repr(u8))]
pub enum RegionKind {
    /// Anonymous memory owned by the process: heap, stacks, allocations.
    Private,
    /// A mapped executable image (exe/dll/so). On Linux, any private file mapping.
    Image,
    /// A shared or file mapping that is not an image.
    Mapped,
}

/// A contiguous range of committed memory with uniform protection.
///
/// Reflected as an opaque type because its `path` field is `Option<PathBuf>`, which
/// does not implement `Facet`. Access `base`, `size`, `protection` and `kind` directly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[cfg_attr(feature = "reflect", facet(opaque))]
pub struct Region {
    pub base: Address,
    pub size: usize,
    pub protection: Protection,
    pub kind: RegionKind,
    /// The backing file, when known.
    pub path: Option<PathBuf>,
}

impl Region {
    pub fn end(&self) -> Address {
        self.base + self.size
    }

    pub fn range(&self) -> Range<Address> {
        self.base..self.end()
    }

    pub fn contains(&self, address: Address) -> bool {
        self.range().contains(&address)
    }
}

/// Types that are valid for any bit pattern, and so can be read out of another process.
///
/// # Safety
/// Implementors must be inhabited by every bit pattern of their size and contain no
/// padding, pointers or references (e.g. `#[repr(C)]` structs of integers and floats).
pub unsafe trait Pod: Copy + Send + Sync + 'static {}

macro_rules! impl_pod {
    ($($t:ty),*) => { $(unsafe impl Pod for $t {})* };
}
impl_pod!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

fn as_bytes<T: Pod>(value: &T) -> &[u8] {
    // SAFETY: Pod types have no padding, so every byte is initialized.
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) }
}

impl ProcessHandle {
    /// Reads up to `buf.len()` bytes, returning how many were read. A short count means
    /// the read ran into unreadable memory.
    pub fn read_bytes(&self, address: Address, buf: &mut [u8]) -> Result<usize> {
        self.0
            .read_at(address, buf)
            .map_err(|source| Error::Read { address, source })
    }

    /// Fills all of `buf`, or fails.
    pub fn read_exact(&self, address: Address, buf: &mut [u8]) -> Result<()> {
        let done = self.read_bytes(address, buf)?;
        if done != buf.len() {
            return Err(Error::PartialRead {
                address,
                done,
                expected: buf.len(),
            });
        }
        Ok(())
    }

    pub fn read_vec(&self, address: Address, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0; len];
        self.read_exact(address, &mut buf)?;
        Ok(buf)
    }

    pub fn read<T: Pod>(&self, address: Address) -> Result<T> {
        let mut value = MaybeUninit::<T>::zeroed();
        // SAFETY: zeroed is a valid T (Pod), and it stays valid whatever bytes are read.
        let buf = unsafe {
            std::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, size_of::<T>())
        };
        self.read_exact(address, buf)?;
        Ok(unsafe { value.assume_init() })
    }

    /// Writes up to `buf.len()` bytes, returning how many were written.
    pub fn write_bytes(&self, address: Address, buf: &[u8]) -> Result<usize> {
        self.0
            .write_at(address, buf)
            .map_err(|source| Error::Write { address, source })
    }

    pub fn write_all(&self, address: Address, buf: &[u8]) -> Result<()> {
        let done = self.write_bytes(address, buf)?;
        if done != buf.len() {
            return Err(Error::PartialWrite {
                address,
                done,
                expected: buf.len(),
            });
        }
        Ok(())
    }

    pub fn write<T: Pod>(&self, address: Address, value: &T) -> Result<()> {
        self.write_all(address, as_bytes(value))
    }

    /// All committed regions of the process, in address order. Includes inaccessible
    /// regions; filter on [`Region::protection`] as needed.
    pub fn regions(&self) -> Result<Vec<Region>> {
        self.0.regions().map_err(Error::query("memory regions"))
    }

    pub fn region_at(&self, address: Address) -> Result<Option<Region>> {
        Ok(self.regions()?.into_iter().find(|r| r.contains(address)))
    }

    /// Changes the protection of the pages covering `address..address + size`, returning
    /// the previous protection of the first page.
    ///
    /// Unsupported on Linux, where there is no remote `mprotect`; writes through a handle
    /// ignore page protection there anyway.
    pub fn protect(
        &self,
        address: Address,
        size: usize,
        protection: Protection,
    ) -> Result<Protection> {
        self.0
            .protect(address, size, protection)
            .map_err(Error::operation("change memory protection"))
    }

    /// Allocates `size` bytes of new memory in the process. Unsupported on Linux.
    pub fn allocate(&self, size: usize, protection: Protection) -> Result<Address> {
        self.0
            .allocate(size, protection)
            .map_err(Error::operation("allocate memory"))
    }

    /// Frees memory returned by [`ProcessHandle::allocate`].
    pub fn free(&self, address: Address) -> Result<()> {
        self.0
            .free(address)
            .map_err(Error::operation("free memory"))
    }

    /// Reads a pointer of `width` bytes (4 or 8, see [`ProcessHandle::pointer_width`]).
    pub fn read_pointer(&self, address: Address, width: usize) -> Result<Address> {
        Ok(Address::new(match width {
            4 => self.read::<u32>(address)? as usize,
            _ => self.read::<usize>(address)?,
        }))
    }

    /// Follows a Cheat Engine-style pointer path: starting at `base`, each step reads the
    /// pointer at the current address and adds the next offset. With no offsets this is
    /// just `base`.
    pub fn resolve_pointer_chain(&self, base: Address, offsets: &[isize]) -> Result<Address> {
        let width = self.pointer_width()?;
        offsets.iter().try_fold(base, |address, &offset| {
            Ok(self.read_pointer(address, width)?.wrapping_offset(offset))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_self() {
        let handle = ProcessHandle::open_current().unwrap();
        let mut value: u64 = 0xdead_beef_cafe_f00d;
        let address = Address::new(&raw mut value as usize);

        assert_eq!(handle.read::<u64>(address).unwrap(), 0xdead_beef_cafe_f00d);
        handle.write(address, &42u64).unwrap();
        assert_eq!(unsafe { std::ptr::read_volatile(&raw const value) }, 42);
    }

    #[test]
    fn regions_cover_stack_and_heap() {
        let handle = ProcessHandle::open_current().unwrap();
        let regions = handle.regions().unwrap();
        assert!(regions.windows(2).all(|w| w[0].base < w[1].base));

        let on_stack = 0u32;
        let on_heap = Box::new(0u32);
        for addr in [&raw const on_stack as usize, &raw const *on_heap as usize] {
            let region = handle.region_at(Address::new(addr)).unwrap().unwrap();
            assert!(region.protection.readable() && region.protection.writable());
            assert_eq!(region.kind, RegionKind::Private);
        }
    }

    #[test]
    fn regions_include_own_code() {
        let handle = ProcessHandle::open_current().unwrap();
        let code = Address::new(regions_include_own_code as fn() as usize);
        let region = handle.region_at(code).unwrap().unwrap();
        assert!(region.protection.executable());
        assert_eq!(region.kind, RegionKind::Image);
    }

    #[test]
    fn pointer_chain() {
        struct Node {
            _pad: u64,
            next: *const Node,
            value: u32,
        }
        let leaf = Node {
            _pad: 0,
            next: std::ptr::null(),
            value: 77,
        };
        let mid = Node {
            _pad: 0,
            next: &leaf,
            value: 0,
        };
        let root: *const Node = &mid;

        let handle = ProcessHandle::open_current().unwrap();
        let next = std::mem::offset_of!(Node, next) as isize;
        let value = std::mem::offset_of!(Node, value) as isize;
        let address = handle
            .resolve_pointer_chain(Address::new(&raw const root as usize), &[next, value])
            .unwrap();
        assert_eq!(address, Address::new(&raw const leaf.value as usize));
        assert_eq!(handle.read::<u32>(address).unwrap(), 77);
    }

    #[test]
    fn protection_display() {
        assert_eq!(Protection::READ_EXECUTE.to_string(), "r-x");
        assert_eq!(
            (Protection::READ_WRITE | Protection::COPY_ON_WRITE).to_string(),
            "rw-c"
        );
    }
}
