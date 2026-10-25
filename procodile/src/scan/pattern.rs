//! Array-of-bytes (signature) scanning.

use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use super::{Progress, chunks_where, par_map};
use crate::{Address, Error, ProcessHandle, Result};

/// A byte pattern with wildcards, written IDA-style: `48 8b ?? ?? 89 05`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// `None` matches any byte.
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    pub fn exact(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.iter().copied().map(Some).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn matches(&self, haystack: &[u8]) -> bool {
        haystack.len() >= self.len()
            && self
                .bytes
                .iter()
                .zip(haystack)
                .all(|(p, b)| p.is_none_or(|p| p == *b))
    }

    /// Offsets in `haystack` where the pattern starts, below `limit`.
    fn find_in(&self, haystack: &[u8], limit: usize, out: &mut Vec<usize>) {
        let Some(anchor) = self.bytes.iter().position(Option::is_some) else {
            out.extend(0..limit.min((haystack.len() + 1).saturating_sub(self.len())));
            return;
        };
        let anchor_byte = self.bytes[anchor].unwrap();
        let mut start = 0;
        while start < limit && start + self.len() <= haystack.len() {
            let window = &haystack[start + anchor..=haystack.len() - self.len() + anchor];
            let Some(hit) = window.iter().position(|&b| b == anchor_byte) else {
                break;
            };
            let candidate = start + hit;
            if candidate >= limit {
                break;
            }
            if self.matches(&haystack[candidate..]) {
                out.push(candidate);
            }
            start = candidate + 1;
        }
    }
}

impl FromStr for Pattern {
    type Err = ParsePatternError;

    /// Accepts space-separated hex bytes and `?`/`??` wildcards. Without spaces the input
    /// is read two characters at a time (`488b??89`).
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let err = || ParsePatternError(s.to_owned());
        let tokens: Vec<&str> = if s.contains(char::is_whitespace) {
            s.split_whitespace().collect()
        } else {
            if !s.len().is_multiple_of(2) || !s.is_ascii() {
                return Err(err());
            }
            (0..s.len()).step_by(2).map(|i| &s[i..i + 2]).collect()
        };
        let bytes = tokens
            .into_iter()
            .map(|t| match t {
                "?" | "??" => Ok(None),
                _ if t.len() <= 2 => u8::from_str_radix(t, 16).map(Some).map_err(|_| err()),
                _ => Err(err()),
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if bytes.is_empty() {
            return Err(err());
        }
        Ok(Self { bytes })
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.bytes.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            match b {
                Some(b) => write!(f, "{b:02x}")?,
                None => f.write_str("??")?,
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid byte pattern '{0}' (expected e.g. \"48 8b ?? 05\")")]
pub struct ParsePatternError(pub String);

#[derive(Debug, Clone, Default)]
pub struct PatternOptions {
    /// Restrict the search to this range, e.g. one module's span.
    pub range: Option<Range<Address>>,
    /// Only search executable memory, where code signatures live.
    pub executable_only: bool,
    /// Stop after this many matches; `0` means no limit.
    pub limit: usize,
}

/// Finds every address where `pattern` occurs in readable memory, in address order.
pub fn find_pattern(
    handle: &ProcessHandle,
    pattern: &Pattern,
    options: &PatternOptions,
    progress: Option<&Progress>,
) -> Result<Vec<Address>> {
    if pattern.is_empty() {
        return Err(Error::InvalidScan("empty pattern".into()));
    }
    let chunks = chunks_where(handle, options.range.as_ref(), pattern.len(), |r| {
        !options.executable_only || r.protection.executable()
    })?;
    let fallback = Progress::new();
    let progress = progress.unwrap_or(&fallback);
    progress.start(chunks.iter().map(|c| c.positions as u64).sum());

    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let parts = par_map(&chunks, threads, |chunk| {
        let mut offsets = Vec::new();
        if !progress.is_cancelled() {
            let mut bytes = vec![0; chunk.len];
            let read = handle.read_bytes(chunk.base, &mut bytes).unwrap_or(0);
            pattern.find_in(&bytes[..read], chunk.positions, &mut offsets);
            progress.advance(chunk.positions);
        }
        offsets
            .into_iter()
            .map(|o| chunk.base + o)
            .collect::<Vec<_>>()
    });
    if progress.is_cancelled() {
        return Err(Error::Cancelled);
    }

    let mut found: Vec<Address> = parts.into_iter().flatten().collect();
    if options.limit > 0 {
        found.truncate(options.limit);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;

    use super::*;

    #[test]
    fn parse_patterns() {
        let p: Pattern = "48 8B ?? ? 05".parse().unwrap();
        assert_eq!(p.to_string(), "48 8b ?? ?? 05");
        assert_eq!("488b??05".parse::<Pattern>().unwrap().len(), 4);
        assert!("48 8g".parse::<Pattern>().is_err());
        assert!("".parse::<Pattern>().is_err());
    }

    #[test]
    fn find_in_buffer() {
        let p: Pattern = "aa ?? cc".parse().unwrap();
        let mut out = Vec::new();
        p.find_in(&[0xaa, 0x00, 0xcc, 0xaa, 0xbb, 0xcc, 0xaa], 100, &mut out);
        assert_eq!(out, [0, 3]);

        out.clear();
        p.find_in(&[0xaa, 0x00, 0xcc, 0xaa, 0xbb, 0xcc], 3, &mut out);
        assert_eq!(out, [0]);
    }

    #[test]
    fn finds_signature_in_heap() {
        let handle = ProcessHandle::open_current().unwrap();
        let mut buf = vec![0u8; 4096];
        buf[1000..1008].copy_from_slice(&[0x13, 0x37, 0xde, 0xad, 0x99, 0xbe, 0xef, 0x42]);
        let start = Address::new(buf.as_ptr() as usize);
        let options = PatternOptions {
            range: Some(start..start + buf.len()),
            ..Default::default()
        };
        let pattern: Pattern = black_box("13 37 de ad ?? be ef 42").parse().unwrap();
        let found = find_pattern(&handle, &pattern, &options, None).unwrap();
        assert_eq!(found, [start + 1000]);
    }
}
