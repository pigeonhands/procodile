//! Parser for `/proc/<pid>/maps`.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::{Address, Protection, Region, RegionKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MapsEntry {
    pub start: usize,
    pub end: usize,
    pub protection: Protection,
    pub shared: bool,
    pub offset: u64,
    pub inode: u64,
    /// The path or pseudo-name (`[heap]`, `[stack]`, ...); empty for anonymous mappings.
    pub pathname: Vec<u8>,
}

impl MapsEntry {
    pub fn is_file_backed(&self) -> bool {
        self.inode != 0 && self.pathname.first() == Some(&b'/')
    }

    /// The backing file, without the ` (deleted)` marker the kernel appends.
    pub fn path(&self) -> Option<PathBuf> {
        if !self.is_file_backed() {
            return None;
        }
        let path = self
            .pathname
            .strip_suffix(b" (deleted)")
            .unwrap_or(&self.pathname);
        Some(PathBuf::from(OsStr::from_bytes(path)))
    }

    pub fn to_region(&self) -> Region {
        let kind = match (self.is_file_backed(), self.shared) {
            (_, true) => RegionKind::Mapped,
            (true, false) => RegionKind::Image,
            (false, false) => RegionKind::Private,
        };
        Region {
            base: Address::new(self.start),
            size: self.end - self.start,
            protection: self.protection,
            kind,
            path: self.path(),
        }
    }
}

pub(crate) fn parse(contents: &[u8]) -> Vec<MapsEntry> {
    contents
        .split(|&b| b == b'\n')
        .filter_map(parse_line)
        .collect()
}

/// `start-end perms offset dev inode [pathname]`
fn parse_line(line: &[u8]) -> Option<MapsEntry> {
    let mut fields = line.splitn(6, |&b| b == b' ');
    let range = std::str::from_utf8(fields.next()?).ok()?;
    let perms = fields.next()?;
    let offset = std::str::from_utf8(fields.next()?).ok()?;
    let _dev = fields.next()?;
    let inode = std::str::from_utf8(fields.next()?).ok()?;
    // The pathname column is padded with spaces to align it.
    let pathname = fields.next().unwrap_or_default().trim_ascii();

    let (start, end) = range.split_once('-')?;
    let &[r, w, x, s] = perms else {
        return None;
    };

    let mut protection = Protection::NONE;
    if r == b'r' {
        protection |= Protection::READ;
    }
    if w == b'w' {
        protection |= Protection::WRITE;
    }
    if x == b'x' {
        protection |= Protection::EXECUTE;
    }
    let shared = s == b's';

    let mut entry = MapsEntry {
        start: usize::from_str_radix(start, 16).ok()?,
        end: usize::from_str_radix(end, 16).ok()?,
        protection,
        shared,
        offset: u64::from_str_radix(offset, 16).ok()?,
        inode: inode.parse().ok()?,
        pathname: pathname.to_vec(),
    };
    // Private anonymous memory is technically copy-on-write too, but only after fork;
    // flag only file mappings, where it is the interesting case (e.g. .data sections).
    if w == b'w' && !shared && entry.is_file_backed() {
        entry.protection |= Protection::COPY_ON_WRITE;
    }
    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"\
55d0c0a00000-55d0c0a21000 r--p 00000000 103:02 1835123                   /usr/bin/cat
55d0c0a21000-55d0c0a40000 r-xp 00021000 103:02 1835123                   /usr/bin/cat
55d0c1e7e000-55d0c1e9f000 rw-p 00000000 00:00 0                          [heap]
7f2a3c000000-7f2a3c021000 rw-s 00000000 00:01 4242                       /dev/shm/x (deleted)
7f2a3c100000-7f2a3c121000 rw-p 00000000 00:00 0
7ffd5a6c3000-7ffd5a6e4000 rw-p 00000000 00:00 0                          [stack]
";

    #[test]
    fn parses_entries() {
        let entries = parse(SAMPLE);
        assert_eq!(entries.len(), 6);

        let text = &entries[1];
        assert_eq!(text.start, 0x55d0c0a21000);
        assert_eq!(text.offset, 0x21000);
        assert_eq!(text.protection, Protection::READ_EXECUTE);
        assert_eq!(text.to_region().kind, RegionKind::Image);
        assert_eq!(text.path().unwrap(), PathBuf::from("/usr/bin/cat"));

        let heap = entries[2].to_region();
        assert_eq!(heap.kind, RegionKind::Private);
        assert_eq!(heap.path, None);
        assert_eq!(heap.protection, Protection::READ_WRITE);

        let shm = entries[3].to_region();
        assert_eq!(shm.kind, RegionKind::Mapped);
        assert_eq!(shm.path.unwrap(), PathBuf::from("/dev/shm/x"));

        assert_eq!(entries[4].pathname, b"");
        assert_eq!(entries[5].pathname, b"[stack]");
    }
}
