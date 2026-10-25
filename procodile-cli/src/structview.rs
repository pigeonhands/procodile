//! Rendering structures read from memory, in the style of lldb's `p *(T *)addr`.

use procodile::structs::{Layout, Node, Structs, Type};
use procodile::{Address, Module};

use crate::commands::describe;

/// Short arrays of primitives are shown on one line.
const INLINE_ARRAY: usize = 16;

pub struct Render<'a> {
    pub pointer_width: usize,
    pub modules: &'a [Module],
    /// Prefix fields with their offset, like `[0x18]`.
    pub offsets: bool,
}

impl Render<'_> {
    /// `(Player) 0x55d0c1e9f000 = { ... }`, one line per field.
    pub fn node(&self, name: &str, address: Address, node: &Node) -> Vec<String> {
        let mut lines = Vec::new();
        let head = format!("({name}) {address:?} = ");
        self.value(node, 0, head, &mut lines);
        lines
    }

    /// Appends `node` to `lines`, the first line starting with `head`.
    fn value(&self, node: &Node, indent: usize, head: String, lines: &mut Vec<String>) {
        let pad = "  ".repeat(indent);
        match node {
            Node::Struct { fields, .. } => {
                lines.push(format!("{head}{{"));
                for f in fields {
                    let offset = if self.offsets {
                        format!("[{:#x}] ", f.offset)
                    } else {
                        String::new()
                    };
                    let head = format!("{pad}  {offset}{} = ", f.name);
                    self.value(&f.value, indent + 1, head, lines);
                }
                lines.push(format!("{pad}}}"));
            }
            Node::Array { items, len } if self.is_inline(items) => {
                let values: Vec<String> = items.iter().map(|i| self.scalar(i)).collect();
                let more = if *len > items.len() { ", ..." } else { "" };
                lines.push(format!("{head}[{}{more}]", values.join(", ")));
            }
            Node::Array { items, len } => {
                lines.push(format!("{head}["));
                for (i, item) in items.iter().enumerate() {
                    self.value(item, indent + 1, format!("{pad}  [{i}] = "), lines);
                }
                if *len > items.len() {
                    lines.push(format!("{pad}  ... {} more", len - items.len()));
                }
                lines.push(format!("{pad}]"));
            }
            Node::Pointer {
                address,
                target: Some(target),
            } => {
                let pointer = self.pointer(*address);
                match &**target {
                    Node::Struct { name, .. } => self.value(
                        target,
                        indent,
                        format!("{head}{pointer} -> ({name}) "),
                        lines,
                    ),
                    _ => self.value(target, indent, format!("{head}{pointer} -> "), lines),
                }
            }
            _ => lines.push(format!("{head}{}", self.scalar(node))),
        }
    }

    fn is_inline(&self, items: &[Node]) -> bool {
        items.len() <= INLINE_ARRAY
            && items
                .iter()
                .all(|i| matches!(i, Node::Primitive(..) | Node::Pointer { target: None, .. }))
    }

    fn scalar(&self, node: &Node) -> String {
        match node {
            Node::Primitive(p, bits) => Node::primitive_string(*p, *bits, self.pointer_width),
            Node::Pointer { address, .. } => self.pointer(*address),
            Node::String(s) => format!("{s:?}"),
            Node::Unreadable => "<unreadable>".to_owned(),
            Node::Struct { name, .. } => format!("({name}) {{...}}"),
            Node::Array { len, .. } => format!("[{len} items]"),
        }
    }

    fn pointer(&self, address: Address) -> String {
        if address.is_null() {
            return "nullptr".to_owned();
        }
        match describe(self.modules, address) {
            m if m.is_empty() => format!("{address:?}"),
            m => format!("{address:?} ({m})"),
        }
    }
}

/// The layout of a struct with offsets and sizes, like gdb's `ptype /o`.
pub fn layout(structs: &Structs, layout: &Layout, pointer_width: usize) -> Vec<String> {
    let mut lines = vec![format!("/* offset | size */  struct {} {{", layout.name)];
    let mut end = 0;
    for f in &layout.fields {
        if f.offset > end {
            lines.push(format!(
                "/* {end:#6x} | {:#4x} */      <padding>",
                f.offset - end
            ));
        }
        let ty = f.ty.to_string();
        let (base, suffix) = match ty.find('[') {
            Some(i) => (&ty[..i], &ty[i..]),
            None => (ty.as_str(), ""),
        };
        let sep = if base.ends_with('*') { "" } else { " " };
        lines.push(format!(
            "/* {:#6x} | {:#4x} */      {base}{sep}{}{suffix};{}",
            f.offset,
            f.size,
            f.name,
            nested_hint(structs, &f.ty, pointer_width)
        ));
        end = f.offset + f.size;
    }
    if layout.size > end {
        lines.push(format!(
            "/* {end:#6x} | {:#4x} */      <padding>",
            layout.size - end
        ));
    }
    lines.push(format!(
        "                        }} /* total size {:#x}, align {} */",
        layout.size, layout.align
    ));
    lines
}

/// Notes a pointer to a struct that is not defined, which can only be shown as an address.
fn nested_hint(structs: &Structs, ty: &Type, pointer_width: usize) -> String {
    let mut ty = ty;
    while let Type::Pointer(inner) | Type::Array(inner, _) = ty {
        ty = inner;
    }
    match ty {
        Type::Struct(name) if structs.layout(name, pointer_width).is_err() => {
            format!("  // {name} is not defined")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use procodile::structs::{FieldValue, Primitive};

    use super::*;

    #[test]
    fn renders_like_lldb() {
        let node = Node::Struct {
            name: "Player".into(),
            fields: vec![
                FieldValue {
                    name: "level".into(),
                    ty: Type::Primitive(Primitive::U32),
                    offset: 0,
                    address: Address::new(0x1000),
                    value: Node::Primitive(Primitive::U32, 7),
                },
                FieldValue {
                    name: "pos".into(),
                    ty: Type::Array(Box::new(Type::Primitive(Primitive::F32)), 2),
                    offset: 4,
                    address: Address::new(0x1004),
                    value: Node::Array {
                        items: vec![
                            Node::Primitive(Primitive::F32, 1.5f32.to_bits() as u64),
                            Node::Primitive(Primitive::F32, 2.0f32.to_bits() as u64),
                        ],
                        len: 2,
                    },
                },
                FieldValue {
                    name: "next".into(),
                    ty: Type::Pointer(Box::new(Type::Struct("Player".into()))),
                    offset: 0x10,
                    address: Address::new(0x1010),
                    value: Node::Pointer {
                        address: Address::NULL,
                        target: None,
                    },
                },
            ],
        };
        let render = Render {
            pointer_width: 8,
            modules: &[],
            offsets: true,
        };
        let lines = render.node("Player", Address::new(0x1000), &node);
        assert_eq!(
            lines,
            [
                format!("(Player) {:?} = {{", Address::new(0x1000)),
                "  [0x0] level = 7".to_owned(),
                "  [0x4] pos = [1.5, 2]".to_owned(),
                "  [0x10] next = nullptr".to_owned(),
                "}".to_owned(),
            ]
        );
    }
}
