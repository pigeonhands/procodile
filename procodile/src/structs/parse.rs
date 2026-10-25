//! Parser for the C-like definition syntax.
//!
//! ```text
//! file   := (struct ';'?)*
//! struct := 'struct' NAME '{' field* '}'
//! field  := (NUMBER ':')? type declarator (',' declarator)* ';'
//! type   := ('struct' | 'const' | 'volatile')* WORD+
//! declarator := '*'* NAME ('[' NUMBER ']')*
//! ```
//!
//! `//` and `/* */` comments are ignored.

use super::{FieldDef, Primitive, StructDef, Type};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Number(usize),
    Punct(char),
}

pub(super) fn parse(source: &str) -> Result<Vec<StructDef>, ParseError> {
    let tokens = tokenize(source)?;
    let mut p = Parser { tokens, pos: 0 };
    let mut defs = Vec::new();
    while p.peek().is_some() {
        defs.push(p.parse_struct()?);
        while p.eat_punct(';') {}
    }
    Ok(defs)
}

fn tokenize(source: &str) -> Result<Vec<(Token, usize)>, ParseError> {
    let mut tokens = Vec::new();
    let mut chars = source.char_indices().peekable();
    let mut line = 1;
    while let Some(&(i, c)) = chars.peek() {
        match c {
            '\n' => {
                line += 1;
                chars.next();
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            '/' if source[i..].starts_with("//") => {
                while chars.peek().is_some_and(|&(_, c)| c != '\n') {
                    chars.next();
                }
            }
            '/' if source[i..].starts_with("/*") => {
                let end = source[i + 2..].find("*/").ok_or(ParseError {
                    line,
                    message: "unterminated comment".into(),
                })?;
                let comment = &source[i..i + 2 + end + 2];
                line += comment.matches('\n').count();
                while chars.peek().is_some_and(|&(j, _)| j < i + comment.len()) {
                    chars.next();
                }
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut word = String::new();
                while let Some(&(_, c)) = chars.peek() {
                    if !(c.is_ascii_alphanumeric() || c == '_') {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push((Token::Word(word), line));
            }
            c if c.is_ascii_digit() => {
                let mut text = String::new();
                while let Some(&(_, c)) = chars.peek() {
                    if !c.is_ascii_alphanumeric() {
                        break;
                    }
                    text.push(c);
                    chars.next();
                }
                let n = match text.strip_prefix("0x").or(text.strip_prefix("0X")) {
                    Some(hex) => usize::from_str_radix(hex, 16),
                    None => text.parse(),
                }
                .map_err(|_| ParseError {
                    line,
                    message: format!("invalid number '{text}'"),
                })?;
                tokens.push((Token::Number(n), line));
            }
            '{' | '}' | ';' | '[' | ']' | '*' | ':' | ',' => {
                tokens.push((Token::Punct(c), line));
                chars.next();
            }
            _ => {
                return Err(ParseError {
                    line,
                    message: format!("unexpected '{c}'"),
                });
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|(t, _)| t)
    }

    fn line(&self) -> usize {
        self.tokens
            .get(self.pos)
            .or(self.tokens.last())
            .map_or(1, |(_, l)| *l)
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            line: self.line(),
            message: message.into(),
        })
    }

    fn eat_punct(&mut self, c: char) -> bool {
        if self.peek() == Some(&Token::Punct(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, c: char) -> Result<(), ParseError> {
        if self.eat_punct(c) {
            Ok(())
        } else {
            self.error(format!("expected '{c}'"))
        }
    }

    fn word(&mut self) -> Option<String> {
        match self.peek() {
            Some(Token::Word(w)) => {
                let w = w.clone();
                self.pos += 1;
                Some(w)
            }
            _ => None,
        }
    }

    fn number(&mut self) -> Result<usize, ParseError> {
        match self.peek() {
            Some(&Token::Number(n)) => {
                self.pos += 1;
                Ok(n)
            }
            _ => self.error("expected a number"),
        }
    }

    fn parse_struct(&mut self) -> Result<StructDef, ParseError> {
        if self.word().as_deref() != Some("struct") {
            return self.error("expected 'struct'");
        }
        let Some(name) = self.word() else {
            return self.error("expected a struct name");
        };
        self.expect_punct('{')?;
        let mut fields: Vec<FieldDef> = Vec::new();
        while !self.eat_punct('}') {
            if self.peek().is_none() {
                return self.error(format!("missing '}}' for struct {name}"));
            }
            for field in self.parse_fields()? {
                if fields.iter().any(|f| f.name == field.name) {
                    return self.error(format!("duplicate field '{}' in {name}", field.name));
                }
                fields.push(field);
            }
        }
        Ok(StructDef { name, fields })
    }

    fn parse_fields(&mut self) -> Result<Vec<FieldDef>, ParseError> {
        let offset = match self.peek() {
            Some(Token::Number(_)) => {
                let n = self.number()?;
                self.expect_punct(':')?;
                Some(n)
            }
            _ => None,
        };

        // The type is every word before the first declarator. A declarator's name is the
        // last word before `;`, `,` or `[`, so collect words and decide afterwards.
        let mut words = Vec::new();
        while let Some(w) = self.word() {
            if !matches!(w.as_str(), "struct" | "const" | "volatile") {
                words.push(w);
            }
        }
        let mut fields = Vec::new();
        let mut first = true;
        loop {
            let mut stars = 0;
            while self.eat_punct('*') {
                stars += 1;
            }
            let name = if first && stars == 0 {
                // `int x;`: the name was collected with the type words.
                if words.len() < 2 {
                    return self.error("expected a type and a field name");
                }
                words.pop().unwrap()
            } else {
                match self.word() {
                    Some(name) => name,
                    None => return self.error("expected a field name"),
                }
            };
            if words.is_empty() {
                return self.error(format!("missing type for field '{name}'"));
            }

            let mut ty = self.base_type(&words)?;
            for _ in 0..stars {
                ty = Type::Pointer(Box::new(ty));
            }
            let mut dims = Vec::new();
            while self.eat_punct('[') {
                dims.push(self.number()?);
                self.expect_punct(']')?;
            }
            for &n in dims.iter().rev() {
                ty = Type::Array(Box::new(ty), n);
            }
            if ty == Type::Void {
                return self.error(format!(
                    "field '{name}' cannot be void (did you mean void *?)"
                ));
            }
            fields.push(FieldDef {
                name,
                ty,
                // Only the first declarator can have the explicit offset.
                offset: if first { offset } else { None },
            });
            first = false;
            if self.eat_punct(',') {
                continue;
            }
            self.expect_punct(';')?;
            return Ok(fields);
        }
    }

    fn base_type(&self, words: &[String]) -> Result<Type, ParseError> {
        let joined = words.join(" ");
        if let Some(p) = Primitive::from_name(&joined) {
            return Ok(Type::Primitive(p));
        }
        match words {
            [w] if w == "void" => Ok(Type::Void),
            [w] if w == "long" || w == "ulong" => {
                self.error("'long' is 4 bytes on Windows and 8 on Linux; use i32/u32 or i64/u64")
            }
            [w] => Ok(Type::Struct(w.clone())),
            _ if words.iter().any(|w| w == "long") => self.error(format!(
                "'{joined}' differs between platforms; use a fixed-size type like u64"
            )),
            _ => self.error(format!("unknown type '{joined}'")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(source: &str) -> Result<Vec<FieldDef>, ParseError> {
        parse(&format!("struct T {{ {source} }}")).map(|mut d| d.remove(0).fields)
    }

    #[test]
    fn types_and_declarators() {
        let f = field("unsigned int a, *b, c[2][3];").unwrap();
        let uint = Type::Primitive(Primitive::U32);
        assert_eq!(f[0].ty, uint);
        assert_eq!(f[1].ty, Type::Pointer(Box::new(uint.clone())));
        assert_eq!(
            f[2].ty,
            Type::Array(Box::new(Type::Array(Box::new(uint), 3)), 2)
        );

        let f = field("const struct Foo **pp; void *v; 0x10: char s[4];").unwrap();
        assert_eq!(
            f[0].ty,
            Type::Pointer(Box::new(Type::Pointer(Box::new(Type::Struct(
                "Foo".into()
            )))))
        );
        assert_eq!(f[1].ty, Type::Pointer(Box::new(Type::Void)));
        assert_eq!(f[2].offset, Some(0x10));
    }

    #[test]
    fn errors_have_lines() {
        let err = parse("struct A {\n  int x;\n  long y;\n};").unwrap_err();
        assert_eq!(err.line, 3);
        assert!(err.message.contains("long"));

        assert!(field("void v;").is_err());
        assert!(field("int;").is_err());
        assert!(field("int a; int a;").is_err());
        assert!(parse("struct A { int x; ").is_err());
        assert!(parse("struct A { int x; } /* open").is_err());
        assert!(parse("union U { int x; };").is_err());
    }
}
