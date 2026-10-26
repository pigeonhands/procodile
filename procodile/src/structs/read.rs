//! Reading structures out of a process, and guessing the layout of unknown ones.

use std::ops::Range;

use super::{FieldDef, Primitive, StructDef, Structs, Type};
use crate::{Address, Error, ProcessHandle, Result};

/// Arrays longer than this are cut short when read.
const MAX_ARRAY_ITEMS: usize = 256;
/// How much of a `*const c_char` string is read.
const MAX_STRING: usize = 256;

/// A value read from memory, shaped by its type.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// The raw bits of a primitive, zero-extended; see [`Node::primitive_string`].
    Primitive(Primitive, u64),
    Pointer {
        address: Address,
        /// What it points to, when followed (see the `depth` of [`Structs::read`]).
        target: Option<Box<Node>>,
    },
    Array {
        items: Vec<Node>,
        /// The declared length, which may be more than `items.len()`.
        len: usize,
    },
    /// A `[c_char; N]` or a followed `*const c_char`, up to the first NUL.
    String(String),
    Struct {
        name: String,
        fields: Vec<FieldValue>,
    },
    /// Memory that could not be read.
    Unreadable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldValue {
    pub name: String,
    pub ty: Type,
    pub offset: usize,
    pub address: Address,
    pub value: Node,
}

impl Node {
    /// Formats a primitive's value: integers in decimal, floats, `true`/`false`, and
    /// characters as quoted literals.
    pub fn primitive_string(p: Primitive, bits: u64, pointer_width: usize) -> String {
        let signed = |size: usize| ((bits << (64 - size * 8)) as i64) >> (64 - size * 8);
        match p {
            Primitive::I8 | Primitive::I16 | Primitive::I32 | Primitive::I64 => {
                signed(p.size(pointer_width)).to_string()
            }
            Primitive::ISize => signed(pointer_width).to_string(),
            Primitive::U8 | Primitive::U16 | Primitive::U32 | Primitive::U64 | Primitive::USize => {
                bits.to_string()
            }
            Primitive::F32 => f32::from_bits(bits as u32).to_string(),
            Primitive::F64 => f64::from_bits(bits).to_string(),
            Primitive::Bool => match bits {
                0 => "false".into(),
                1 => "true".into(),
                n => format!("true ({n})"),
            },
            Primitive::Char => format!("{:?}", bits as u8 as char),
        }
    }
}

impl Structs {
    /// Reads struct `name` at `address`. Pointers are followed `depth` levels deep;
    /// `depth = 0` shows them as addresses only.
    pub fn read(
        &self,
        handle: &ProcessHandle,
        name: &str,
        address: Address,
        pointer_width: usize,
        depth: usize,
    ) -> Result<Node> {
        let ty = Type::Struct(name.to_owned());
        let (size, _) = self
            .size_align(&ty, pointer_width)
            .map_err(|e| Error::InvalidType(e.to_string()))?;
        let bytes = handle.read_vec(address, size)?;
        let reader = Reader {
            structs: self,
            handle,
            width: pointer_width,
        };
        Ok(reader.decode(&ty, address, &bytes, depth))
    }
}

struct Reader<'a> {
    structs: &'a Structs,
    handle: &'a ProcessHandle,
    width: usize,
}

impl Reader<'_> {
    /// Decodes `ty` from `bytes`, which hold exactly its size and were read from `address`.
    fn decode(&self, ty: &Type, address: Address, bytes: &[u8], depth: usize) -> Node {
        match ty {
            Type::Primitive(p) => Node::Primitive(*p, read_bits(bytes)),
            Type::Pointer(inner) => {
                let target = Address::new(read_bits(bytes) as usize);
                Node::Pointer {
                    address: target,
                    target: (depth > 0 && !target.is_null() && **inner != Type::Void)
                        .then(|| Box::new(self.follow(inner, target, depth - 1))),
                }
            }
            Type::Array(inner, _) if **inner == Type::Primitive(Primitive::Char) => {
                Node::String(c_string(bytes))
            }
            Type::Array(inner, len) => {
                let Ok((size, _)) = self.structs.size_align(inner, self.width) else {
                    return Node::Unreadable;
                };
                let items = bytes
                    .chunks_exact(size.max(1))
                    .take(MAX_ARRAY_ITEMS)
                    .enumerate()
                    .map(|(i, item)| self.decode(inner, address + i * size, item, depth))
                    .collect();
                Node::Array { items, len: *len }
            }
            Type::Struct(name) => {
                let Ok(layout) = self.structs.layout(name, self.width) else {
                    return Node::Unreadable;
                };
                let fields = layout
                    .fields
                    .into_iter()
                    .map(|f| {
                        let value = self.decode(
                            &f.ty,
                            address + f.offset,
                            &bytes[f.offset..f.offset + f.size],
                            depth,
                        );
                        FieldValue {
                            address: address + f.offset,
                            name: f.name,
                            ty: f.ty,
                            offset: f.offset,
                            value,
                        }
                    })
                    .collect();
                Node::Struct {
                    name: name.clone(),
                    fields,
                }
            }
            Type::Void => Node::Unreadable,
        }
    }

    /// Reads and decodes what a pointer points to.
    fn follow(&self, ty: &Type, address: Address, depth: usize) -> Node {
        if *ty == Type::Primitive(Primitive::Char) {
            let mut buf = vec![0; MAX_STRING];
            return match self.handle.read_bytes(address, &mut buf) {
                Ok(n) if n > 0 => Node::String(c_string(&buf[..n])),
                _ => Node::Unreadable,
            };
        }
        let Ok((size, _)) = self.structs.size_align(ty, self.width) else {
            return Node::Unreadable;
        };
        match self.handle.read_vec(address, size) {
            Ok(bytes) => self.decode(ty, address, &bytes, depth),
            Err(_) => Node::Unreadable,
        }
    }
}

fn read_bits(bytes: &[u8]) -> u64 {
    let mut raw = [0u8; 8];
    let n = bytes.len().min(8);
    raw[..n].copy_from_slice(&bytes[..n]);
    u64::from_ne_bytes(raw)
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// What a stretch of unknown memory looks like.
#[derive(Debug, Clone, PartialEq)]
pub enum GuessKind {
    /// A value that points into mapped memory.
    Pointer(Address),
    /// Printable text, NUL-terminated or running to the end.
    String(String),
    F32(f32),
    F64(f64),
    I32(i32),
    Zero,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Guess {
    pub offset: usize,
    pub size: usize,
    pub kind: GuessKind,
}

/// Guesses the fields of an unknown structure, Cheat Engine "dissect data" style: pointers
/// into mapped memory, text, plausible floats, then 32-bit integers.
pub fn dissect(
    handle: &ProcessHandle,
    address: Address,
    size: usize,
    pointer_width: usize,
) -> Result<Vec<Guess>> {
    let mut bytes = vec![0; size];
    let read = handle.read_bytes(address, &mut bytes)?;
    bytes.truncate(read);
    let mapped: Vec<Range<usize>> = handle
        .regions()?
        .iter()
        .filter(|r| r.protection.readable())
        .map(|r| r.base.get()..r.end().get())
        .collect();
    Ok(guess(&bytes, address, pointer_width, &mapped))
}

fn guess(bytes: &[u8], address: Address, width: usize, mapped: &[Range<usize>]) -> Vec<Guess> {
    let is_mapped = |v: usize| {
        let i = mapped.partition_point(|r| r.start <= v);
        i > 0 && mapped[i - 1].contains(&v)
    };
    let mut guesses = Vec::new();
    // Offsets are relative to `address`, but alignment is of the real address.
    let aligned = |off: usize, n: usize| (address.get() + off).is_multiple_of(n);
    let mut off = 0;
    while off + 4 <= bytes.len() {
        let rest = &bytes[off..];
        let push = |guesses: &mut Vec<Guess>, size, kind| {
            guesses.push(Guess {
                offset: off,
                size,
                kind,
            })
        };

        if aligned(off, width) && rest.len() >= width {
            let v = read_bits(&rest[..width]) as usize;
            if v != 0 && is_mapped(v) {
                push(&mut guesses, width, GuessKind::Pointer(Address::new(v)));
                off += width;
                continue;
            }
        }

        let text = rest
            .iter()
            .take_while(|b| b.is_ascii_graphic() || **b == b' ')
            .count();
        if text >= 4 && rest.get(text).is_none_or(|&b| b == 0) {
            // Include the NUL, and pad to keep later guesses aligned.
            let size = (text + 1).next_multiple_of(4).min(rest.len());
            push(
                &mut guesses,
                size,
                GuessKind::String(String::from_utf8_lossy(&rest[..text]).into_owned()),
            );
            off += size;
            continue;
        }

        if aligned(off, 8) && rest.len() >= 8 {
            let bits = read_bits(&rest[..8]);
            if bits == 0 {
                push(&mut guesses, 8, GuessKind::Zero);
                off += 8;
                continue;
            }
            let lo = bits as u32;
            let hi = (bits >> 32) as u32;
            let v = f64::from_bits(bits);
            // A double's low word is rarely a plausible float or small integer by itself.
            if plausible_f64(v) && !plausible_f32(f32::from_bits(lo)) && lo > 0xffff && hi != 0 {
                push(&mut guesses, 8, GuessKind::F64(v));
                off += 8;
                continue;
            }
        }

        let bits = read_bits(&rest[..4]) as u32;
        let kind = if bits == 0 {
            GuessKind::Zero
        } else if plausible_f32(f32::from_bits(bits)) && bits > 0xffff {
            GuessKind::F32(f32::from_bits(bits))
        } else {
            GuessKind::I32(bits as i32)
        };
        push(&mut guesses, 4, kind);
        off += 4;
    }
    guesses
}

fn plausible_f32(v: f32) -> bool {
    v.is_normal() && (1e-3..=1e7).contains(&v.abs())
}

fn plausible_f64(v: f64) -> bool {
    v.is_normal() && (1e-3..=1e12).contains(&v.abs())
}

impl Guess {
    pub fn ty(&self) -> Type {
        match &self.kind {
            GuessKind::Pointer(_) => Type::Pointer(Box::new(Type::Void)),
            GuessKind::String(_) => {
                Type::Array(Box::new(Type::Primitive(Primitive::Char)), self.size)
            }
            GuessKind::F32(_) => Type::Primitive(Primitive::F32),
            GuessKind::F64(_) => Type::Primitive(Primitive::F64),
            GuessKind::I32(_) => Type::Primitive(Primitive::I32),
            GuessKind::Zero if self.size == 8 => Type::Primitive(Primitive::U64),
            GuessKind::Zero => Type::Primitive(Primitive::U32),
        }
    }
}

/// Turns guesses into a definition with fields named after their offsets (`f_18`), as a
/// starting point to rename and retype. Offsets are only spelled out where natural
/// alignment would not put the field there anyway.
pub fn guesses_to_struct(name: &str, guesses: &[Guess]) -> StructDef {
    let mut end = 0usize;
    let fields = guesses
        .iter()
        .map(|g| {
            let align = match g.kind {
                GuessKind::String(_) => 1,
                _ => g.size,
            };
            let natural = end.next_multiple_of(align);
            end = g.offset + g.size;
            FieldDef {
                name: format!("f_{:x}", g.offset),
                ty: g.ty(),
                offset: (g.offset != natural).then_some(g.offset),
            }
        })
        .collect();
    StructDef {
        name: name.to_owned(),
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Stats {
        armor: i32,
        mana: i32,
        health: i32,
    }

    #[repr(C)]
    struct Player {
        level: u32,
        name: [u8; 12],
        stats: *const Stats,
        speed: f32,
        alive: bool,
        title: *const u8,
    }

    const DEFS: &str = "
        struct Stats { armor: i32, mana: i32, health: i32 }
        struct Player {
            level: u32,
            name: [c_char; 12],
            stats: *const Stats,
            speed: f32,
            alive: bool,
            title: *const c_char,
        }
    ";

    fn field<'a>(node: &'a Node, name: &str) -> &'a Node {
        let Node::Struct { fields, .. } = node else {
            panic!("not a struct: {node:?}")
        };
        &fields.iter().find(|f| f.name == name).unwrap().value
    }

    #[test]
    fn reads_nested_structs() {
        let stats = Stats {
            armor: 5,
            mana: -1,
            health: 100,
        };
        let mut name = [0u8; 12];
        name[..4].copy_from_slice(b"hero");
        let player = Player {
            level: 7,
            name,
            stats: &stats,
            speed: 1.5,
            alive: true,
            title: c"the brave".as_ptr().cast(),
        };

        let mut structs = Structs::new();
        structs.define(DEFS).unwrap();
        let handle = ProcessHandle::open_current().unwrap();
        let width = size_of::<usize>();
        assert_eq!(
            structs.layout("Player", width).unwrap().size,
            size_of::<Player>()
        );

        let address = Address::new(&raw const player as usize);
        let shallow = structs.read(&handle, "Player", address, width, 0).unwrap();
        assert_eq!(
            field(&shallow, "level"),
            &Node::Primitive(Primitive::U32, 7)
        );
        assert_eq!(field(&shallow, "name"), &Node::String("hero".into()));
        assert_eq!(
            field(&shallow, "stats"),
            &Node::Pointer {
                address: Address::new(&raw const stats as usize),
                target: None
            }
        );
        let Node::Primitive(Primitive::F32, bits) = field(&shallow, "speed") else {
            panic!()
        };
        assert_eq!(Node::primitive_string(Primitive::F32, *bits, width), "1.5");

        let deep = structs.read(&handle, "Player", address, width, 1).unwrap();
        let Node::Pointer {
            target: Some(stats_node),
            ..
        } = field(&deep, "stats")
        else {
            panic!()
        };
        assert_eq!(
            field(stats_node, "mana"),
            &Node::Primitive(Primitive::I32, (-1i32) as u32 as u64)
        );
        let Node::Pointer {
            target: Some(title),
            ..
        } = field(&deep, "title")
        else {
            panic!()
        };
        assert_eq!(**title, Node::String("the brave".into()));
    }

    #[test]
    fn primitive_formatting() {
        assert_eq!(Node::primitive_string(Primitive::I8, 0xff, 8), "-1");
        assert_eq!(Node::primitive_string(Primitive::ISize, u64::MAX, 8), "-1");
        assert_eq!(
            Node::primitive_string(Primitive::ISize, 0xffff_ffff, 4),
            "-1"
        );
        assert_eq!(Node::primitive_string(Primitive::Bool, 1, 8), "true");
        assert_eq!(
            Node::primitive_string(Primitive::Char, b'A' as u64, 8),
            "'A'"
        );
    }

    #[test]
    fn dissect_guesses() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1000usize.to_ne_bytes()); // pointer into "mapped" memory
        bytes.extend_from_slice(b"hero\0\0\0\0"); // string, padded
        bytes.extend_from_slice(&1.5f32.to_ne_bytes());
        bytes.extend_from_slice(&42i32.to_ne_bytes());
        bytes.extend_from_slice(&0u64.to_ne_bytes());
        bytes.extend_from_slice(&1234.5678f64.to_ne_bytes());

        let mapped = 0x1000..0x2000;
        let guesses = guess(
            &bytes,
            Address::new(0x10000),
            8,
            std::slice::from_ref(&mapped),
        );
        let kinds: Vec<&GuessKind> = guesses.iter().map(|g| &g.kind).collect();
        assert_eq!(
            kinds,
            [
                &GuessKind::Pointer(Address::new(0x1000)),
                &GuessKind::String("hero".into()),
                &GuessKind::F32(1.5),
                &GuessKind::I32(42),
                &GuessKind::Zero,
                &GuessKind::F64(1234.5678),
            ]
        );
        let def = guesses_to_struct("Unknown", &guesses);
        assert!(def.fields.iter().all(|f| f.offset.is_none()), "{def}");
        let mut structs = Structs::new();
        structs.define(&def.to_string()).unwrap();
        assert_eq!(structs.layout("Unknown", 8).unwrap().size, bytes.len());
    }
}
