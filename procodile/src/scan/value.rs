use std::fmt;
use std::str::FromStr;

use crate::Pod;

/// The type of value a scan looks for. Values are read in the target's native byte order,
/// which is assumed to match ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[cfg_attr(feature = "reflect", repr(u8))]
pub enum ValueType {
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
}

impl ValueType {
    pub const ALL: [ValueType; 10] = [
        Self::I8,
        Self::U8,
        Self::I16,
        Self::U16,
        Self::I32,
        Self::U32,
        Self::I64,
        Self::U64,
        Self::F32,
        Self::F64,
    ];

    pub const fn size(self) -> usize {
        match self {
            Self::I8 | Self::U8 => 1,
            Self::I16 | Self::U16 => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 => 8,
        }
    }

    pub const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    pub const fn name(self) -> &'static str {
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
        }
    }

    /// Parses a value of this type. Integers accept a `0x` prefix and, for unsigned types,
    /// negative numbers that fit the signed type of the same size (stored as two's
    /// complement).
    pub fn parse(self, s: &str) -> Result<Value, ParseValueError> {
        let s = s.trim();
        let err = || ParseValueError {
            ty: self,
            input: s.to_owned(),
        };
        if self.is_float() {
            let v: f64 = s.parse().map_err(|_| err())?;
            return Ok(match self {
                Self::F32 => Value::F32(v as f32),
                _ => Value::F64(v),
            });
        }

        let (negative, digits) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        let magnitude = match digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0X"))
        {
            Some(hex) => u128::from_str_radix(hex, 16),
            None => digits.parse::<u128>(),
        }
        .map_err(|_| err())?;
        let n: i128 = if negative {
            -i128::try_from(magnitude).map_err(|_| err())?
        } else {
            i128::try_from(magnitude).map_err(|_| err())?
        };

        macro_rules! fit {
            ($variant:ident, $t:ty, $signed:ty) => {
                <$t>::try_from(n)
                    .ok()
                    .or_else(|| <$signed>::try_from(n).ok().map(|v| v as $t))
                    .map(Value::$variant)
                    .ok_or_else(err)
            };
        }
        match self {
            Self::I8 => fit!(I8, i8, i8),
            Self::U8 => fit!(U8, u8, i8),
            Self::I16 => fit!(I16, i16, i16),
            Self::U16 => fit!(U16, u16, i16),
            Self::I32 => fit!(I32, i32, i32),
            Self::U32 => fit!(U32, u32, i32),
            Self::I64 => fit!(I64, i64, i64),
            Self::U64 => fit!(U64, u64, i64),
            Self::F32 | Self::F64 => unreachable!(),
        }
    }

    /// Decodes a value from exactly `self.size()` native-endian bytes.
    pub fn decode(self, bytes: &[u8]) -> Value {
        with_scalar!(self, T => T::read(bytes).into_value())
    }
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Accepts Rust names (`i32`, `f64`) and C-style aliases (`int`, `float`, `byte`, ...).
impl FromStr for ValueType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "i8" | "char" | "int8" => Self::I8,
            "u8" | "byte" | "uint8" => Self::U8,
            "i16" | "short" | "int16" => Self::I16,
            "u16" | "ushort" | "uint16" => Self::U16,
            "i32" | "int" | "int32" => Self::I32,
            "u32" | "uint" | "uint32" => Self::U32,
            "i64" | "long" | "int64" => Self::I64,
            "u64" | "ulong" | "uint64" => Self::U64,
            "f32" | "float" => Self::F32,
            "f64" | "double" => Self::F64,
            _ => return Err(format!("unknown value type '{s}'")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{input}' is not a valid {ty}")]
pub struct ParseValueError {
    pub ty: ValueType,
    pub input: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
#[cfg_attr(feature = "reflect", repr(C))]
pub enum Value {
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
}

impl Value {
    pub fn ty(self) -> ValueType {
        match self {
            Self::I8(_) => ValueType::I8,
            Self::U8(_) => ValueType::U8,
            Self::I16(_) => ValueType::I16,
            Self::U16(_) => ValueType::U16,
            Self::I32(_) => ValueType::I32,
            Self::U32(_) => ValueType::U32,
            Self::I64(_) => ValueType::I64,
            Self::U64(_) => ValueType::U64,
            Self::F32(_) => ValueType::F32,
            Self::F64(_) => ValueType::F64,
        }
    }

    /// Native-endian bytes, as they would be stored in memory.
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::I8(v) => v.to_ne_bytes().to_vec(),
            Self::U8(v) => v.to_ne_bytes().to_vec(),
            Self::I16(v) => v.to_ne_bytes().to_vec(),
            Self::U16(v) => v.to_ne_bytes().to_vec(),
            Self::I32(v) => v.to_ne_bytes().to_vec(),
            Self::U32(v) => v.to_ne_bytes().to_vec(),
            Self::I64(v) => v.to_ne_bytes().to_vec(),
            Self::U64(v) => v.to_ne_bytes().to_vec(),
            Self::F32(v) => v.to_ne_bytes().to_vec(),
            Self::F64(v) => v.to_ne_bytes().to_vec(),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I8(v) => v.fmt(f),
            Self::U8(v) => v.fmt(f),
            Self::I16(v) => v.fmt(f),
            Self::U16(v) => v.fmt(f),
            Self::I32(v) => v.fmt(f),
            Self::U32(v) => v.fmt(f),
            Self::I64(v) => v.fmt(f),
            Self::U64(v) => v.fmt(f),
            Self::F32(v) => v.fmt(f),
            Self::F64(v) => v.fmt(f),
        }
    }
}

/// The primitive types behind [`ValueType`], so scan loops can be monomorphized.
pub(crate) trait Scalar: Pod + PartialOrd {
    fn read(bytes: &[u8]) -> Self;
    fn from_value(value: Value) -> Option<Self>;
    fn into_value(self) -> Value;
    fn approx_eq(self, other: Self, tolerance: f64) -> bool;
    fn wrapping_add(self, other: Self) -> Self;
}

macro_rules! impl_int_scalar {
    ($($t:ty => $variant:ident),*) => {$(
        impl Scalar for $t {
            #[inline(always)]
            fn read(bytes: &[u8]) -> Self {
                <$t>::from_ne_bytes(bytes[..size_of::<$t>()].try_into().unwrap())
            }
            fn from_value(value: Value) -> Option<Self> {
                match value { Value::$variant(v) => Some(v), _ => None }
            }
            fn into_value(self) -> Value { Value::$variant(self) }
            #[inline(always)]
            fn approx_eq(self, other: Self, _: f64) -> bool { self == other }
            #[inline(always)]
            fn wrapping_add(self, other: Self) -> Self { <$t>::wrapping_add(self, other) }
        }
    )*};
}
impl_int_scalar!(i8 => I8, u8 => U8, i16 => I16, u16 => U16, i32 => I32, u32 => U32, i64 => I64, u64 => U64);

macro_rules! impl_float_scalar {
    ($($t:ty => $variant:ident),*) => {$(
        impl Scalar for $t {
            #[inline(always)]
            fn read(bytes: &[u8]) -> Self {
                <$t>::from_ne_bytes(bytes[..size_of::<$t>()].try_into().unwrap())
            }
            fn from_value(value: Value) -> Option<Self> {
                match value { Value::$variant(v) => Some(v), _ => None }
            }
            fn into_value(self) -> Value { Value::$variant(self) }
            #[inline(always)]
            fn approx_eq(self, other: Self, tolerance: f64) -> bool {
                self == other || ((self - other).abs() as f64) <= tolerance
            }
            #[inline(always)]
            fn wrapping_add(self, other: Self) -> Self { self + other }
        }
    )*};
}
impl_float_scalar!(f32 => F32, f64 => F64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_values() {
        assert_eq!(ValueType::I32.parse("-5").unwrap(), Value::I32(-5));
        assert_eq!(ValueType::U8.parse("0xff").unwrap(), Value::U8(255));
        assert_eq!(ValueType::U8.parse("-1").unwrap(), Value::U8(255));
        assert!(ValueType::U8.parse("256").is_err());
        assert!(ValueType::I8.parse("128").is_err());
        assert_eq!(ValueType::F32.parse("1.5").unwrap(), Value::F32(1.5));
        assert_eq!("double".parse::<ValueType>().unwrap(), ValueType::F64);
    }

    #[test]
    fn decode_round_trips() {
        for v in [Value::I16(-300), Value::U64(u64::MAX), Value::F64(-2.25)] {
            assert_eq!(v.ty().decode(&v.to_bytes()), v);
        }
    }
}
