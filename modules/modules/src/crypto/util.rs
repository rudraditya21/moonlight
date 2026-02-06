use crate::options::{ModuleOption, ModuleOptionKind, ModuleOptionValue, ModuleOptions};

pub fn build_hash_options() -> ModuleOptions {
    let options = vec![
        ModuleOption::new("INPUT", "Input string to hash", ModuleOptionKind::String, true),
        ModuleOption::new("HASH", "Optional expected hash (hex)", ModuleOptionKind::String, false),
        ModuleOption::new("OUTPUT_HEX", "Return hex output", ModuleOptionKind::Bool, false)
            .with_default(ModuleOptionValue::Bool(true)),
    ];
    ModuleOptions::new(options)
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let high = hex_value(bytes[i]).ok_or_else(|| "invalid hex".to_string())?;
        let low = hex_value(bytes[i + 1]).ok_or_else(|| "invalid hex".to_string())?;
        out.push((high << 4) | low);
        i += 2;
    }
    Ok(out)
}

pub fn normalize_hex(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

pub fn normalize_expected_hex(input: &str, expected_len: usize) -> Result<String, String> {
    let normalized = normalize_hex(input);
    if normalized.len() != expected_len {
        return Err(format!(
            "expected hash length {expected_len} hex chars, got {}",
            normalized.len()
        ));
    }
    decode_hex(&normalized)?;
    Ok(normalized)
}

fn hex_value(b: u8) -> Option<u8> {
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
    fn hex_decode() {
        assert_eq!(decode_hex("0a1b").unwrap(), vec![0x0a, 0x1b]);
    }
}
