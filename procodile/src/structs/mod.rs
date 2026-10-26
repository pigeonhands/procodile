//! Structure definitions: describing how data is laid out in another process, so it can be
//! read as named fields instead of raw bytes.
//!
//! Definitions use Rust's struct syntax:
//!
//! ```text
//! struct Player {
//!     level: u32,
//!     name: [c_char; 16],
//!     stats: *const Stats,
//!     #[offset(0x40)]          // explicit offset; the gap is padding
//!     position: [f32; 3],
//! }
//! ```
//!
//! Fields are laid out as with `#[repr(C)]`: in order, with natural alignment, unless given
//! an explicit offset. Layout depends on the target's pointer size, so it is computed per
//! use rather than stored.

mod parse;
mod read;

use std::collections::BTreeMap;
use std::fmt;

pub use parse::ParseError;
pub use read::{FieldValue, Guess, GuessKind, Node, dissect, guesses_to_struct};

/// A primitive field type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Primitive {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    Bool,
    /// A byte shown as a character (`c_char`); arrays of it and pointers to it are shown
    /// as strings.
    Char,
    /// An unsigned integer the size of a pointer (`usize`, `size_t`, `uintptr_t`).
    USize,
    /// A signed integer the size of a pointer (`isize`, `ssize_t`, `intptr_t`).
    ISize,
}

impl Primitive {
    pub fn size(self, pointer_width: usize) -> usize {
        match self {
            Self::I8 | Self::U8 | Self::Bool | Self::Char => 1,
            Self::I16 | Self::U16 => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 => 8,
            Self::USize | Self::ISize => pointer_width,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::I8 => "i8",
            Self::U8 => "u8",
            Self::I16 => "i16",
            Self::U16 => "u16",
            Self::I32 => "i32",
            Self::U32 => "u32",
            Self::I64 => "i64",
            Self::U64 => "u64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bool => "bool",
            Self::Char => "c_char",
            Self::USize => "usize",
            Self::ISize => "isize",
        }
    }

    /// Recognizes Rust's primitive names and the fixed-size `std::ffi` C types.
    pub fn from_name(name: &str) -> Option<Primitive> {
        Some(match name {
            "i8" | "c_schar" => Self::I8,
            "u8" | "c_uchar" => Self::U8,
            "i16" | "c_short" => Self::I16,
            "u16" | "c_ushort" => Self::U16,
            "i32" | "c_int" => Self::I32,
            "u32" | "c_uint" => Self::U32,
            "i64" | "c_longlong" => Self::I64,
            "u64" | "c_ulonglong" => Self::U64,
            "f32" | "c_float" => Self::F32,
            "f64" | "c_double" => Self::F64,
            "bool" => Self::Bool,
            "c_char" => Self::Char,
            "usize" => Self::USize,
            "isize" => Self::ISize,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Primitive(Primitive),
    /// A pointer (`*const T` or `*mut T`); `*const c_void` points to `Void`.
    Pointer(Box<Type>),
    Array(Box<Type>, usize),
    /// A structure, by name.
    Struct(String),
    /// Only valid behind a pointer.
    Void,
}

/// Rust syntax: `u32`, `*const Stats`, `[f32; 3]`, `*const c_void`.
impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Primitive(p) => f.write_str(p.name()),
            Type::Pointer(inner) => write!(f, "*const {inner}"),
            Type::Array(inner, n) => write!(f, "[{inner}; {n}]"),
            Type::Struct(name) => f.write_str(name),
            Type::Void => f.write_str("c_void"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    pub name: String,
    pub ty: Type,
    /// An explicit offset; otherwise the field follows the previous one, aligned.
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
}

/// Writes the definition back in the syntax it is parsed from.
impl fmt::Display for StructDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "#[repr(C)]")?;
        writeln!(f, "struct {} {{", self.name)?;
        for field in &self.fields {
            if let Some(offset) = field.offset {
                writeln!(f, "    #[offset({offset:#x})]")?;
            }
            writeln!(f, "    {}: {},", field.name, field.ty)?;
        }
        write!(f, "}}")
    }
}

/// A field with its position worked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaidField {
    pub name: String,
    pub ty: Type,
    pub offset: usize,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub name: String,
    pub size: usize,
    pub align: usize,
    pub fields: Vec<LaidField>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LayoutError {
    #[error("unknown struct '{0}'")]
    Unknown(String),
    #[error("struct '{0}' contains itself")]
    Recursive(String),
    #[error("'c_void' is only valid behind a pointer (field '{0}')")]
    Void(String),
    #[error(
        "field '{field}' of '{name}' starts at {offset:#x}, before the end of the previous field ({end:#x})"
    )]
    Overlap {
        name: String,
        field: String,
        offset: usize,
        end: usize,
    },
}

/// A set of structure definitions that can refer to each other.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Structs {
    defs: BTreeMap<String, StructDef>,
}

impl Structs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses definitions and adds them, replacing any with the same names. Returns the
    /// names defined. Nothing is added if parsing fails.
    pub fn define(&mut self, source: &str) -> Result<Vec<String>, ParseError> {
        let defs = parse::parse(source)?;
        let names = defs.iter().map(|d| d.name.clone()).collect();
        for def in defs {
            self.defs.insert(def.name.clone(), def);
        }
        Ok(names)
    }

    pub fn insert(&mut self, def: StructDef) {
        self.defs.insert(def.name.clone(), def);
    }

    pub fn get(&self, name: &str) -> Option<&StructDef> {
        self.defs.get(name)
    }

    pub fn remove(&mut self, name: &str) -> Option<StructDef> {
        self.defs.remove(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &StructDef> {
        self.defs.values()
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// Lays out `name` for a target with the given pointer width.
    pub fn layout(&self, name: &str, pointer_width: usize) -> Result<Layout, LayoutError> {
        self.layout_inner(name, pointer_width, &mut Vec::new())
    }

    /// Size and alignment of a type.
    pub fn size_align(
        &self,
        ty: &Type,
        pointer_width: usize,
    ) -> Result<(usize, usize), LayoutError> {
        self.size_align_inner(ty, pointer_width, &mut Vec::new(), "")
    }

    fn layout_inner(
        &self,
        name: &str,
        width: usize,
        stack: &mut Vec<String>,
    ) -> Result<Layout, LayoutError> {
        let def = self
            .defs
            .get(name)
            .ok_or_else(|| LayoutError::Unknown(name.to_owned()))?;
        if stack.iter().any(|s| s == name) {
            return Err(LayoutError::Recursive(name.to_owned()));
        }
        stack.push(name.to_owned());

        let mut fields = Vec::with_capacity(def.fields.len());
        let (mut end, mut align) = (0usize, 1usize);
        for field in &def.fields {
            let (size, field_align) =
                self.size_align_inner(&field.ty, width, stack, &field.name)?;
            let offset = match field.offset {
                Some(offset) if offset < end => {
                    return Err(LayoutError::Overlap {
                        name: name.to_owned(),
                        field: field.name.clone(),
                        offset,
                        end,
                    });
                }
                Some(offset) => offset,
                None => end.next_multiple_of(field_align),
            };
            align = align.max(field_align);
            end = offset + size;
            fields.push(LaidField {
                name: field.name.clone(),
                ty: field.ty.clone(),
                offset,
                size,
            });
        }
        stack.pop();
        Ok(Layout {
            name: name.to_owned(),
            size: end.next_multiple_of(align),
            align,
            fields,
        })
    }

    fn size_align_inner(
        &self,
        ty: &Type,
        width: usize,
        stack: &mut Vec<String>,
        field: &str,
    ) -> Result<(usize, usize), LayoutError> {
        Ok(match ty {
            Type::Primitive(p) => (p.size(width), p.size(width)),
            Type::Pointer(_) => (width, width),
            Type::Array(inner, n) => {
                let (size, align) = self.size_align_inner(inner, width, stack, field)?;
                (size * n, align)
            }
            Type::Struct(name) => {
                let layout = self.layout_inner(name, width, stack)?;
                (layout.size, layout.align)
            }
            Type::Void => return Err(LayoutError::Void(field.to_owned())),
        })
    }
}

/// All definitions, in the syntax they are parsed from.
impl fmt::Display for Structs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, def) in self.defs.values().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            writeln!(f, "{def}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "
        // A comment.
        struct Stats { armor: i32, mana: i32, health: i32 }

        #[repr(C)]
        pub struct Player {
            pub level: u32,
            name: [c_char; 13],
            stats: *const Stats,   /* pointer to another struct */
            inline_stats: Stats,
            #[offset(0x40)]
            position: [f32; 3],
            user_data: *mut std::ffi::c_void,
            alive: bool,
        }
    ";

    #[test]
    fn layout_follows_repr_c() {
        let mut structs = Structs::new();
        assert_eq!(structs.define(SOURCE).unwrap(), ["Stats", "Player"]);

        let player = structs.layout("Player", 8).unwrap();
        let offsets: Vec<(&str, usize)> = player
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.offset))
            .collect();
        assert_eq!(
            offsets,
            [
                ("level", 0),
                ("name", 4),
                ("stats", 0x18),
                ("inline_stats", 0x20),
                ("position", 0x40),
                ("user_data", 0x50),
                ("alive", 0x58),
            ]
        );
        assert_eq!((player.size, player.align), (0x60, 8));

        // 32-bit targets have 4-byte pointers.
        let player32 = structs.layout("Player", 4).unwrap();
        assert_eq!(player32.fields[2].offset, 0x14);
        assert_eq!(player32.size, 0x54);
    }

    #[test]
    fn layout_errors() {
        let mut structs = Structs::new();
        structs
            .define("struct A { b: B } struct B { a: A }")
            .unwrap();
        assert!(matches!(
            structs.layout("A", 8),
            Err(LayoutError::Recursive(_))
        ));
        assert!(matches!(
            structs.layout("Nope", 8),
            Err(LayoutError::Unknown(_))
        ));

        structs
            .define("struct C { a: u64, #[offset(4)] b: u32 }")
            .unwrap();
        assert!(matches!(
            structs.layout("C", 8),
            Err(LayoutError::Overlap { .. })
        ));

        // A pointer to itself is fine.
        structs
            .define("struct Node { next: *mut Node, value: u32 }")
            .unwrap();
        assert_eq!(structs.layout("Node", 8).unwrap().size, 16);
    }

    #[test]
    fn display_round_trips() {
        let mut structs = Structs::new();
        structs.define(SOURCE).unwrap();
        let text = structs.to_string();
        assert!(text.contains("    name: [c_char; 13],"));
        assert!(text.contains("    stats: *const Stats,"));
        assert!(text.contains("    #[offset(0x40)]\n    position: [f32; 3],"));
        assert!(text.contains("    user_data: *const c_void,"));

        let mut again = Structs::new();
        again.define(&text).unwrap();
        assert_eq!(again, structs);
    }
}
