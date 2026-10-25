use std::ffi::c_void;

/// Addresses are always interpreted as hex; an optional `0x`/`0X` prefix is stripped.
pub fn parse_address(input: &str) -> Result<*const c_void, String> {
    let trimmed = input.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    usize::from_str_radix(digits, 16)
        .map(|addr| addr as *const c_void)
        .map_err(|_| format!("invalid address '{input}' (expected hex, e.g. 0x7ff6a2b31000)"))
}

/// Values to write are given as a hex byte string, optionally `0x`-prefixed,
/// with optional whitespace between byte pairs (e.g. "de ad be ef" or "0xdeadbeef").
pub fn parse_bytes(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    let digits: String = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    if digits.is_empty() {
        return Err("no bytes given".to_string());
    }
    if digits.len() % 2 != 0 {
        return Err(format!("odd number of hex digits in '{input}'"));
    }

    (0..digits.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&digits[i..i + 2], 16)
                .map_err(|_| format!("invalid hex byte in '{input}'"))
        })
        .collect()
}
