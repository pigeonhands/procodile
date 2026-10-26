//! Parser for the Rust-like definition syntax.
//!
//! ```text
//! file   := item*
//! item   := attr* vis? 'struct' NAME '{' (field (',' field)* ','?)? '}'
//! field  := attr* vis? NAME ':' type
//! type   := ('*const' | '*mut') type | '[' type ';' NUMBER ']' | '(' ')' | path
//! path   := NAME ('::' NAME)*          // only the last segment counts
//! attr   := '#' '[' ... ']'            // `#[offset(N)]` on a field; others are ignored
//! vis    := 'pub' ('(' ... ')')?
//! ```
//!
//! `//` and `/* */` comments are ignored, as are stray `;` between items.

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
    loop {
        while p.eat_punct(';') {}
        if p.peek().is_none() {
            return Ok(defs);
        }
        defs.push(p.parse_struct()?);
    }
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
                    if !(c.is_ascii_alphanumeric() || c == '_') {
                        break;
                    }
                    text.push(c);
                    chars.next();
                }
                let digits = text.replace('_', "");
                let n = match digits.strip_prefix("0x").or(digits.strip_prefix("0X")) {
                    Some(hex) => usize::from_str_radix(hex, 16),
                    None => digits.parse(),
                }
                .map_err(|_| ParseError {
                    line,
                    message: format!("invalid number '{text}'"),
                })?;
                tokens.push((Token::Number(n), line));
            }
            '{' | '}' | '[' | ']' | '(' | ')' | ';' | ':' | ',' | '*' | '#' | '!' | '=' | '"'
            | '<' | '>' | '&' => {
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

    fn eat_word(&mut self, word: &str) -> bool {
        if matches!(self.peek(), Some(Token::Word(w)) if w == word) {
            self.pos += 1;
            true
        } else {
            false
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

    /// Skips tokens up to the bracket matching an already-consumed `open`.
    fn skip_group(&mut self, open: char, close: char) -> Result<(), ParseError> {
        let mut depth = 1;
        while depth > 0 {
            match self.peek() {
                None => return self.error(format!("missing '{close}'")),
                Some(Token::Punct(c)) if *c == open => depth += 1,
                Some(Token::Punct(c)) if *c == close => depth -= 1,
                _ => {}
            }
            self.pos += 1;
        }
        Ok(())
    }

    /// Parses `#[...]` attributes, returning the value of an `#[offset(N)]`.
    fn attributes(&mut self) -> Result<Option<usize>, ParseError> {
        let mut offset = None;
        while self.eat_punct('#') {
            self.expect_punct('[')?;
            if self.eat_word("offset") {
                self.expect_punct('(')?;
                offset = Some(self.number()?);
                self.expect_punct(')')?;
                self.expect_punct(']')?;
            } else {
                // `#[repr(C)]`, `#[derive(...)]`, doc comments as attributes, ...
                self.skip_group('[', ']')?;
            }
        }
        Ok(offset)
    }

    fn visibility(&mut self) -> Result<(), ParseError> {
        if self.eat_word("pub") && self.eat_punct('(') {
            self.skip_group('(', ')')?;
        }
        Ok(())
    }

    fn parse_struct(&mut self) -> Result<StructDef, ParseError> {
        if self.attributes()?.is_some() {
            return self.error("#[offset] goes on fields, not structs");
        }
        self.visibility()?;
        if !self.eat_word("struct") {
            return self.error("expected 'struct'");
        }
        let Some(name) = self.word() else {
            return self.error("expected a struct name");
        };
        if self.peek() == Some(&Token::Punct('<')) {
            return self.error(format!("generic structs are not supported ({name})"));
        }
        self.expect_punct('{')?;

        let mut fields: Vec<FieldDef> = Vec::new();
        loop {
            if self.eat_punct('}') {
                break;
            }
            if self.peek().is_none() {
                return self.error(format!("missing '}}' for struct {name}"));
            }
            let field = self.parse_field()?;
            if fields.iter().any(|f| f.name == field.name) {
                return self.error(format!("duplicate field '{}' in {name}", field.name));
            }
            fields.push(field);
            if !self.eat_punct(',') {
                self.expect_punct('}')?;
                break;
            }
        }
        Ok(StructDef { name, fields })
    }

    fn parse_field(&mut self) -> Result<FieldDef, ParseError> {
        let offset = self.attributes()?;
        self.visibility()?;
        let Some(name) = self.word() else {
            return self.error("expected a field name");
        };
        if !self.eat_punct(':') {
            return self.error(format!("expected ':' after field name '{name}'"));
        }
        let ty = self.parse_type()?;
        if ty == Type::Void {
            return self.error(format!(
                "field '{name}' cannot be c_void (did you mean *const c_void?)"
            ));
        }
        Ok(FieldDef { name, ty, offset })
    }

    fn parse_type(&mut self) -> Result<Type, ParseError> {
        if self.eat_punct('*') {
            if !(self.eat_word("const") || self.eat_word("mut")) {
                return self.error("expected 'const' or 'mut' after '*'");
            }
            return Ok(Type::Pointer(Box::new(self.parse_type()?)));
        }
        if self.eat_punct('&') {
            return self.error("references are not supported; use *const T");
        }
        if self.eat_punct('[') {
            let inner = self.parse_type()?;
            if !self.eat_punct(';') {
                return self.error("slices are not supported; use [T; N]");
            }
            let n = self.number()?;
            self.expect_punct(']')?;
            return Ok(Type::Array(Box::new(inner), n));
        }
        if self.eat_punct('(') {
            self.expect_punct(')')?;
            return Ok(Type::Void);
        }

        // A path like `std::ffi::c_char`: only the last segment matters.
        let Some(mut name) = self.word() else {
            return self.error("expected a type");
        };
        while self.peek() == Some(&Token::Punct(':'))
            && self.tokens.get(self.pos + 1).map(|(t, _)| t) == Some(&Token::Punct(':'))
        {
            self.pos += 2;
            name = match self.word() {
                Some(next) => next,
                None => return self.error("expected a name after '::'"),
            };
        }
        if self.peek() == Some(&Token::Punct('<')) {
            return self.error(format!(
                "generic types like {name}<...> are not supported; use *const T for Box/&"
            ));
        }
        if let Some(p) = Primitive::from_name(&name) {
            return Ok(Type::Primitive(p));
        }
        match name.as_str() {
            "c_void" => Ok(Type::Void),
            "char" => self.error("Rust's char is 4 bytes; use c_char for text or u32"),
            "c_long" | "c_ulong" => self.error(format!(
                "{name} is 4 bytes on Windows and 8 on Linux; use i32/u32 or i64/u64"
            )),
            "i128" | "u128" => self.error(format!("{name} is not supported")),
            _ => Ok(Type::Struct(name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(source: &str) -> Result<Vec<FieldDef>, ParseError> {
        parse(&format!("struct T {{ {source} }}")).map(|mut d| d.remove(0).fields)
    }

    #[test]
    fn types() {
        let f = fields(
            "a: u32, b: *mut u32, c: [[u32; 3]; 2], d: *const *const Foo, e: *const (), \
             g: std::ffi::c_char, #[offset(0x10)] pub h: [c_char; 4],",
        )
        .unwrap();
        let uint = Type::Primitive(Primitive::U32);
        assert_eq!(f[0].ty, uint);
        assert_eq!(f[1].ty, Type::Pointer(Box::new(uint.clone())));
        assert_eq!(
            f[2].ty,
            Type::Array(Box::new(Type::Array(Box::new(uint), 3)), 2)
        );
        assert_eq!(
            f[3].ty,
            Type::Pointer(Box::new(Type::Pointer(Box::new(Type::Struct(
                "Foo".into()
            )))))
        );
        assert_eq!(f[4].ty, Type::Pointer(Box::new(Type::Void)));
        assert_eq!(f[5].ty, Type::Primitive(Primitive::Char));
        assert_eq!(f[6].offset, Some(0x10));
    }

    #[test]
    fn items() {
        let defs = parse(
            "/// docs\n#[derive(Debug)]\n#[repr(C)]\npub(crate) struct A { x: u8 }\n\
             struct B {}\n;\nstruct C { y: A }",
        )
        .unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["A", "B", "C"]);
    }

    #[test]
    fn errors_have_lines() {
        let err = parse("struct A {\n  x: u32,\n  y: char,\n}").unwrap_err();
        assert_eq!(err.line, 3);
        assert!(err.message.contains("c_char"));

        assert!(fields("v: c_void").is_err());
        assert!(fields("x u32").is_err());
        assert!(fields("x: u32 y: u32").is_err());
        assert!(fields("a: u32, a: u32").is_err());
        assert!(fields("p: *u32").is_err());
        assert!(fields("s: &[u8]").is_err());
        assert!(fields("v: Vec<u8>").is_err());
        assert!(fields("n: c_long").is_err());
        assert!(parse("struct A { x: u32, ").is_err());
        assert!(parse("struct A { x: u32 } /* open").is_err());
        assert!(parse("union U { x: u32 }").is_err());
        assert!(parse("#[offset(4)] struct A {}").is_err());
    }
}
