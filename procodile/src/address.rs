use std::fmt;
use std::num::ParseIntError;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::str::FromStr;

/// An address in another process's address space.
///
/// Deliberately not a pointer: it is never dereferenced locally, and unlike raw pointers it
/// is `Send + Sync`, hashable and supports plain integer arithmetic.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[repr(transparent)]
pub struct Address(usize);

impl Address {
    pub const NULL: Address = Address(0);

    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn get(self) -> usize {
        self.0
    }

    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    pub const fn checked_add(self, rhs: usize) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    pub const fn checked_offset(self, offset: isize) -> Option<Self> {
        match self.0.checked_add_signed(offset) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    pub const fn wrapping_offset(self, offset: isize) -> Self {
        Self(self.0.wrapping_add_signed(offset))
    }

    /// Rounds down to a multiple of `align`, which must be a power of two.
    pub const fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub const fn is_aligned(self, align: usize) -> bool {
        self.0 & (align - 1) == 0
    }
}

impl From<usize> for Address {
    fn from(addr: usize) -> Self {
        Self(addr)
    }
}

impl From<Address> for usize {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

impl Add<usize> for Address {
    type Output = Address;
    fn add(self, rhs: usize) -> Address {
        Address(self.0 + rhs)
    }
}

impl AddAssign<usize> for Address {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs;
    }
}

impl Sub<usize> for Address {
    type Output = Address;
    fn sub(self, rhs: usize) -> Address {
        Address(self.0 - rhs)
    }
}

impl SubAssign<usize> for Address {
    fn sub_assign(&mut self, rhs: usize) {
        self.0 -= rhs;
    }
}

/// Distance in bytes between two addresses.
impl Sub<Address> for Address {
    type Output = usize;
    fn sub(self, rhs: Address) -> usize {
        self.0 - rhs.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#0width$x}",
            self.0,
            width = 2 + 2 * size_of::<usize>()
        )
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

/// Parses a hexadecimal address, with or without a `0x` prefix.
impl FromStr for Address {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let digits = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        usize::from_str_radix(digits, 16).map(Address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        let a: Address = "0x7ffd1000".parse().unwrap();
        assert_eq!(a.get(), 0x7ffd1000);
        assert_eq!("7ffd1000".parse::<Address>().unwrap(), a);
        assert_eq!(format!("{a:?}"), "0x7ffd1000");
        assert_eq!(format!("{a:x}"), "7ffd1000");
    }

    #[test]
    fn arithmetic() {
        let a = Address::new(0x1000);
        assert_eq!(a + 0x10, Address::new(0x1010));
        assert_eq!(Address::new(0x1010) - a, 0x10);
        assert_eq!(a.wrapping_offset(-0x10), Address::new(0xff0));
        assert_eq!(Address::new(0x1234).align_down(0x1000), a);
    }
}
