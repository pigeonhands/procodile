//! lldb-style formatting of memory contents.

use std::fmt::Write;

use clap::ValueEnum;
use procodile::Address;
use procodile::scan::ValueType;

/// The `-f/--format` of `memory read`, named after lldb's formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Hex bytes followed by ASCII (lldb's default, `Y`).
    #[value(alias = "Y")]
    Bytes,
    #[value(alias = "x")]
    Hex,
    #[value(alias = "d")]
    Decimal,
    #[value(alias = "u")]
    Unsigned,
    #[value(alias = "f")]
    Float,
    #[value(alias = "c")]
    Char,
    /// A NUL-terminated string.
    #[value(alias = "s", name = "c-string")]
    CString,
    #[value(alias = "p")]
    Pointer,
}

impl Format {
    pub fn default_size(self, pointer_width: usize) -> usize {
        match self {
            Format::Bytes | Format::Char | Format::CString => 1,
            Format::Pointer => pointer_width,
            Format::Hex | Format::Decimal | Format::Unsigned | Format::Float => 4,
        }
    }

    /// The format and item size that show a value type naturally.
    pub fn for_type(ty: ValueType) -> (Format, usize) {
        let format = match ty {
            ValueType::F32 | ValueType::F64 => Format::Float,
            ValueType::I8 | ValueType::I16 | ValueType::I32 | ValueType::I64 => Format::Decimal,
            _ => Format::Unsigned,
        };
        (format, ty.size())
    }

    fn per_line(self, size: usize) -> usize {
        match self {
            Format::Bytes | Format::Char => 16,
            _ => (16 / size).max(1),
        }
    }
}

/// Renders `bytes` read from `base` like lldb's `memory read`, one line per row.
pub fn memory(base: Address, bytes: &[u8], format: Format, size: usize) -> Vec<String> {
    if format == Format::CString {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        return vec![format!(
            "{base}: {:?}",
            String::from_utf8_lossy(&bytes[..end])
        )];
    }

    let per_line = format.per_line(size);
    let row_bytes = per_line * size;
    bytes
        .chunks(row_bytes)
        .enumerate()
        .map(|(row, chunk)| {
            let mut line = format!("{}:", base + row * row_bytes);
            match format {
                Format::Bytes => {
                    for b in chunk {
                        write!(line, " {b:02x}").unwrap();
                    }
                    let pad = 3 * (row_bytes - chunk.len());
                    write!(line, "{:pad$}  {}", "", ascii(chunk)).unwrap();
                }
                Format::Char => {
                    write!(line, " {}", ascii(chunk)).unwrap();
                }
                _ => {
                    for item in chunk.chunks_exact(size) {
                        write!(line, " {}", item_string(item, format)).unwrap();
                    }
                }
            }
            line
        })
        .collect()
}

fn ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn item_string(item: &[u8], format: Format) -> String {
    let mut raw = [0u8; 8];
    raw[..item.len()].copy_from_slice(item);
    let unsigned = u64::from_ne_bytes(raw);
    let bits = item.len() * 8;
    let signed = if bits == 64 {
        unsigned as i64
    } else {
        ((unsigned << (64 - bits)) as i64) >> (64 - bits)
    };
    match format {
        Format::Hex | Format::Pointer => format!("{unsigned:#0w$x}", w = 2 + item.len() * 2),
        Format::Decimal => signed.to_string(),
        Format::Unsigned => unsigned.to_string(),
        Format::Float => match item.len() {
            4 => f32::from_bits(unsigned as u32).to_string(),
            8 => f64::from_bits(unsigned).to_string(),
            _ => format!("{unsigned:#x}"),
        },
        Format::Bytes | Format::Char | Format::CString => unreachable!(),
    }
}

/// Human-readable byte count, e.g. `1.5 MiB`.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_format() {
        let data: Vec<u8> = (0x41..0x41 + 18).collect();
        let lines = memory(Address::new(0x1000), &data, Format::Bytes, 1);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("  ABCDEFGHIJKLMNOP"));
        assert!(lines[1].starts_with(&format!("{}: 51 52", Address::new(0x1010))));
    }

    #[test]
    fn typed_formats() {
        let data = [(-2i32).to_ne_bytes(), 1.5f32.to_ne_bytes()].concat();
        let decimal = memory(Address::new(0), &data, Format::Decimal, 4);
        assert!(decimal[0].ends_with(" -2 1069547520"));
        let hex = memory(Address::new(0), &data[..4], Format::Hex, 4);
        assert!(hex[0].ends_with(" 0xfffffffe"));
        let float = memory(Address::new(0), &data[4..], Format::Float, 4);
        assert!(float[0].ends_with(" 1.5"));
        let s = memory(Address::new(0), b"hi\0there", Format::CString, 1);
        assert!(s[0].ends_with(": \"hi\""));
    }
}
