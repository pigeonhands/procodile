//! Address expressions, e.g. `0x7ffd1000`, `game.exe+0x1c`, `[[$0]+8]-4`, `#3`.
//!
//! ```text
//! expr := term (('+' | '-') term)*
//! term := number | module | '[' expr ']' | '(' expr ')' | '$' index | '#' index
//! ```
//!
//! Numbers are decimal unless prefixed with `0x`, as in lldb. A module is its file name
//! (`libc.so.6`), quoted if it contains other characters (`"ld-linux-x86-64.so.2"`).
//! `[x]` reads the pointer at `x`, `$N` is address table entry N, and `#N` is scan
//! result N.

use procodile::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Number(u64),
    Module(String),
    Deref(Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Table(usize),
    ScanResult(usize),
}

/// What an expression can refer to.
pub trait Env {
    fn module_base(&self, name: &str) -> Result<Address, String>;
    fn read_pointer(&self, address: Address) -> Result<Address, String>;
    fn table_entry(&self, index: usize) -> Result<Address, String>;
    fn scan_result(&self, index: usize) -> Result<Address, String>;
}

impl Expr {
    pub fn eval(&self, env: &dyn Env) -> Result<Address, String> {
        Ok(match self {
            Expr::Number(n) => Address::new(*n as usize),
            Expr::Module(name) => env.module_base(name)?,
            Expr::Deref(inner) => env.read_pointer(inner.eval(env)?)?,
            Expr::Add(a, b) => Address::new(a.eval(env)?.get().wrapping_add(b.eval(env)?.get())),
            Expr::Sub(a, b) => Address::new(a.eval(env)?.get().wrapping_sub(b.eval(env)?.get())),
            Expr::Table(i) => env.table_entry(*i)?,
            Expr::ScanResult(i) => env.scan_result(*i)?,
        })
    }
}

pub fn parse(input: &str) -> Result<Expr, String> {
    let mut p = Parser { src: input, pos: 0 };
    let expr = p.expr()?;
    p.skip_ws();
    if p.pos != input.len() {
        return Err(p.error("unexpected input"));
    }
    Ok(expr)
}

/// Parses a plain number: decimal, `0x` hex, or `0b` binary, with an optional `-`.
pub fn parse_number(input: &str) -> Result<i128, String> {
    let s = input.trim();
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let magnitude = if let Some(hex) = digits.strip_prefix("0x").or(digits.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else if let Some(bin) = digits.strip_prefix("0b") {
        u64::from_str_radix(bin, 2)
    } else {
        digits.parse::<u64>()
    }
    .map_err(|_| format!("invalid number '{input}'"))?;
    Ok(if negative {
        -(magnitude as i128)
    } else {
        magnitude as i128
    })
}

/// For clap: a non-negative number that fits in `usize`.
pub fn parse_usize(input: &str) -> Result<usize, String> {
    let n = parse_number(input)?;
    usize::try_from(n).map_err(|_| format!("'{input}' is out of range"))
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, message: &str) -> String {
        format!("{message} at column {} in '{}'", self.pos + 1, self.src)
    }

    fn rest(&self) -> &str {
        &self.src[self.pos..]
    }

    fn skip_ws(&mut self) {
        let trimmed = self.rest().trim_start();
        self.pos = self.src.len() - trimmed.len();
    }

    fn eat(&mut self, c: char) -> bool {
        self.skip_ws();
        if self.rest().starts_with(c) {
            self.pos += c.len_utf8();
            true
        } else {
            false
        }
    }

    fn take_while(&mut self, f: impl Fn(char) -> bool) -> &str {
        let start = self.pos;
        let len = self.rest().find(|c| !f(c)).unwrap_or(self.rest().len());
        self.pos += len;
        &self.src[start..self.pos]
    }

    fn expr(&mut self) -> Result<Expr, String> {
        let mut lhs = self.term()?;
        loop {
            if self.eat('+') {
                lhs = Expr::Add(Box::new(lhs), Box::new(self.term()?));
            } else if self.eat('-') {
                lhs = Expr::Sub(Box::new(lhs), Box::new(self.term()?));
            } else {
                return Ok(lhs);
            }
        }
    }

    fn term(&mut self) -> Result<Expr, String> {
        self.skip_ws();
        if self.eat('[') {
            let inner = self.expr()?;
            if !self.eat(']') {
                return Err(self.error("expected ']'"));
            }
            return Ok(Expr::Deref(Box::new(inner)));
        }
        if self.eat('(') {
            let inner = self.expr()?;
            if !self.eat(')') {
                return Err(self.error("expected ')'"));
            }
            return Ok(inner);
        }
        if self.eat('$') {
            return self.index().map(Expr::Table);
        }
        if self.eat('#') {
            return self.index().map(Expr::ScanResult);
        }
        if self.eat('"') {
            let name = self.take_while(|c| c != '"').to_owned();
            if !self.eat('"') {
                return Err(self.error("unterminated module name"));
            }
            return Ok(Expr::Module(name));
        }

        let Some(first) = self.rest().chars().next() else {
            return Err(self.error("expected an address"));
        };
        if first.is_ascii_digit() {
            let word = self.take_while(|c| c.is_ascii_alphanumeric()).to_owned();
            return parse_number(&word)
                .map(|n| Expr::Number(n as u64))
                .map_err(|_| self.error(&format!("invalid number '{word}' (hex needs 0x)")));
        }
        if first.is_alphabetic() || first == '_' {
            let name = self.take_while(|c| c.is_alphanumeric() || c == '_' || c == '.');
            return Ok(Expr::Module(name.to_owned()));
        }
        Err(self.error(&format!("unexpected '{first}'")))
    }

    fn index(&mut self) -> Result<usize, String> {
        let digits = self.take_while(|c| c.is_ascii_digit());
        digits.parse().map_err(|_| self.error("expected an index"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEnv;

    impl Env for TestEnv {
        fn module_base(&self, name: &str) -> Result<Address, String> {
            match name {
                "game.exe" => Ok(Address::new(0x400000)),
                "ld-linux.so.2" => Ok(Address::new(0x7000)),
                _ => Err(format!("no module '{name}'")),
            }
        }
        fn read_pointer(&self, address: Address) -> Result<Address, String> {
            Ok(address + 0x1000)
        }
        fn table_entry(&self, index: usize) -> Result<Address, String> {
            Ok(Address::new(0x10 * index))
        }
        fn scan_result(&self, index: usize) -> Result<Address, String> {
            Ok(Address::new(0x100 * index))
        }
    }

    fn eval(s: &str) -> usize {
        parse(s).unwrap().eval(&TestEnv).unwrap().get()
    }

    #[test]
    fn numbers() {
        assert_eq!(eval("0x10"), 16);
        assert_eq!(eval("10"), 10);
        assert_eq!(eval("0x10 + 4 - 0x2"), 18);
        assert!(parse("7ffd").is_err());
        assert!(parse("1f").is_err());
    }

    #[test]
    fn modules_and_pointers() {
        assert_eq!(eval("game.exe+0x1c"), 0x40001c);
        assert_eq!(eval("\"ld-linux.so.2\"+1"), 0x7001);
        assert_eq!(eval("[game.exe+8]+4"), 0x401008 + 4);
        assert_eq!(eval("[[0x10]]"), 0x2010);
        assert_eq!(eval("$2+(#1-0x10)"), 0x20 + 0x100 - 0x10);
        assert!(parse("[0x10").is_err());
        assert!(parse("0x10 +").is_err());
        assert!(parse("nope").unwrap().eval(&TestEnv).is_err());
    }

    #[test]
    fn plain_numbers() {
        assert_eq!(parse_number("-0x10").unwrap(), -16);
        assert_eq!(parse_number("0b101").unwrap(), 5);
        assert!(parse_usize("-1").is_err());
    }
}
