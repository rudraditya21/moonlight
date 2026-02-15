use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleResult};
use crate::metadata::ModuleMetadata;
use crate::options::{ModuleOption, ModuleOptionKind, ModuleOptionValue, ModuleOptions};

#[derive(Clone, Copy)]
pub enum Endian {
    Little,
    Big,
}

pub type NopGenerator = fn(usize, &[u8]) -> Result<Vec<u8>, ModuleError>;

pub struct NopModule {
    base: ModuleBase,
    generator: NopGenerator,
}

impl NopModule {
    pub fn new(metadata: ModuleMetadata, generator: NopGenerator, default_len: i64) -> Self {
        let options = build_nop_options(default_len);
        NopModule {
            base: ModuleBase::new(metadata, options),
            generator,
        }
    }

    pub(crate) fn generate_bytes(&self) -> Result<Vec<u8>, ModuleError> {
        self.base.validate()?;
        let length = read_length(self.base.options())?;
        let badchars = read_badchars(self.base.options())?;
        (self.generator)(length, &badchars)
    }
}

impl Module for NopModule {
    fn metadata(&self) -> &ModuleMetadata {
        self.base.metadata()
    }

    fn options(&self) -> &ModuleOptions {
        self.base.options()
    }

    fn options_mut(&mut self) -> &mut ModuleOptions {
        self.base.options_mut()
    }

    fn run(&mut self, _ctx: &ModuleContext) -> Result<ModuleResult, ModuleError> {
        let bytes = self.generate_bytes()?;
        let hex = format_bytes_hex(&bytes);
        Ok(ModuleResult::ok(&format!(
            "nop bytes ({}): {}",
            bytes.len(),
            hex
        )))
    }
}

pub fn build_nop_options(default_len: i64) -> ModuleOptions {
    ModuleOptions::new(vec![
        ModuleOption::new(
            "LENGTH",
            "NOP sled length in bytes",
            ModuleOptionKind::Integer,
            true,
        )
        .with_default(ModuleOptionValue::Integer(default_len)),
        ModuleOption::new(
            "BADCHARS",
            "Hex bytes to avoid (e.g. \\\\x00\\\\x0a or 00,0a)",
            ModuleOptionKind::String,
            false,
        )
        .with_default(ModuleOptionValue::String(String::new())),
    ])
}

fn read_length(options: &ModuleOptions) -> Result<usize, ModuleError> {
    let len_str = options
        .get("LENGTH")
        .map(|opt| opt.value_as_string())
        .unwrap_or_default();
    let len: usize = len_str
        .parse()
        .map_err(|_| ModuleError::Validation("LENGTH must be a positive integer".to_string()))?;
    if len == 0 {
        return Err(ModuleError::Validation(
            "LENGTH must be greater than zero".to_string(),
        ));
    }
    Ok(len)
}

fn read_badchars(options: &ModuleOptions) -> Result<Vec<u8>, ModuleError> {
    let bad_str = options
        .get("BADCHARS")
        .map(|opt| opt.value_as_string())
        .unwrap_or_default();
    parse_badchars(&bad_str).map_err(ModuleError::Validation)
}

pub fn generate_sled_from_u32(
    length: usize,
    badchars: &[u8],
    pool: &[u32],
    endian: Endian,
) -> Result<Vec<u8>, ModuleError> {
    if length % 4 != 0 {
        return Err(ModuleError::Validation(
            "LENGTH must be a multiple of 4 bytes for this architecture".to_string(),
        ));
    }
    if pool.is_empty() {
        return Err(ModuleError::Execution("NOP pool is empty".to_string()));
    }

    let badmap = build_badchar_map(badchars);
    let mut filtered: Vec<[u8; 4]> = Vec::with_capacity(pool.len());
    for &op in pool {
        let bytes = match endian {
            Endian::Little => op.to_le_bytes(),
            Endian::Big => op.to_be_bytes(),
        };
        if !has_badchar(&bytes, &badmap) {
            filtered.push(bytes);
        }
    }

    if filtered.is_empty() {
        return Err(ModuleError::Execution(
            "no NOPs available after badchar filtering".to_string(),
        ));
    }

    let mut out = Vec::with_capacity(length);
    let mut idx = 0usize;
    while out.len() < length {
        let bytes = filtered[idx % filtered.len()];
        out.extend_from_slice(&bytes);
        idx += 1;
    }
    Ok(out)
}

pub fn generate_fill(length: usize, badchars: &[u8], fill: u8) -> Result<Vec<u8>, ModuleError> {
    if length == 0 {
        return Err(ModuleError::Validation(
            "LENGTH must be greater than zero".to_string(),
        ));
    }
    let badmap = build_badchar_map(badchars);
    if badmap[fill as usize] {
        return Err(ModuleError::Execution(
            "fill byte is excluded by BADCHARS".to_string(),
        ));
    }
    Ok(vec![fill; length])
}

pub fn format_bytes_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for byte in bytes {
        out.push_str(&format!("\\x{:02x}", byte));
    }
    out
}

fn build_badchar_map(badchars: &[u8]) -> [bool; 256] {
    let mut map = [false; 256];
    for &b in badchars {
        map[b as usize] = true;
    }
    map
}

fn has_badchar(bytes: &[u8], map: &[bool; 256]) -> bool {
    bytes.iter().any(|b| map[*b as usize])
}

fn parse_badchars(input: &str) -> Result<Vec<u8>, String> {
    let text = input.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.contains("\\x") || text.contains("\\X") {
        return parse_badchars_escaped(text);
    }
    parse_badchars_hex(text)
}

fn parse_badchars_escaped(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            if i + 3 >= bytes.len() {
                return Err("badchars contains an incomplete escape".to_string());
            }
            let next = bytes[i + 1];
            if next == b'x' || next == b'X' {
                let hi = hex_val(bytes[i + 2])
                    .ok_or_else(|| "badchars escape must use hex digits".to_string())?;
                let lo = hex_val(bytes[i + 3])
                    .ok_or_else(|| "badchars escape must use hex digits".to_string())?;
                out.push((hi << 4) | lo);
                i += 4;
                continue;
            }
            return Err("badchars escape must be in the form \\xHH".to_string());
        }
        if b == b',' || b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        return Err("badchars must be \\xHH escapes or hex pairs".to_string());
    }
    Ok(out)
}

fn parse_badchars_hex(text: &str) -> Result<Vec<u8>, String> {
    let mut hex = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '0' && i + 1 < chars.len() && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
            i += 2;
            continue;
        }
        if c.is_ascii_hexdigit() {
            hex.push(c);
            i += 1;
            continue;
        }
        if c == ',' || c.is_whitespace() {
            i += 1;
            continue;
        }
        return Err(format!("invalid character in badchars: {c}"));
    }
    if hex.len() % 2 != 0 {
        return Err("badchars hex length must be even".to_string());
    }
    let mut out = Vec::new();
    let hex_bytes = hex.as_bytes();
    let mut idx = 0usize;
    while idx < hex_bytes.len() {
        let hi = hex_val(hex_bytes[idx])
            .ok_or_else(|| "badchars must be valid hex bytes".to_string())?;
        let lo = hex_val(hex_bytes[idx + 1])
            .ok_or_else(|| "badchars must be valid hex bytes".to_string())?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_badchars_escaped_format() {
        let parsed = parse_badchars("\\x00\\x0a").expect("parse");
        assert_eq!(parsed, vec![0x00, 0x0a]);
    }

    #[test]
    fn parse_badchars_hex_pairs() {
        let parsed = parse_badchars("00, 0a 2f").expect("parse");
        assert_eq!(parsed, vec![0x00, 0x0a, 0x2f]);
    }

    #[test]
    fn generate_sled_filters_badchars() {
        let pool = [0x11223344, 0x55667788];
        let bytes = generate_sled_from_u32(8, &[0x22], &pool, Endian::Big).expect("sled");
        assert_eq!(bytes.len(), 8);
        assert!(!bytes.contains(&0x22));
    }
}
