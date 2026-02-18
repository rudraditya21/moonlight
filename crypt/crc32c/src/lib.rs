use std::sync::OnceLock;

const POLY: u32 = 0x1EDC6F41;
const POLY_REFLECTED: u32 = POLY.reverse_bits();
const INIT: u32 = 0xFFFF_FFFF;
const XOR_OUT: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone)]
pub struct Crc32c {
    state: u32,
}

impl Crc32c {
    pub fn new() -> Self {
        Crc32c { state: INIT }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state = update(self.state, data);
    }

    pub fn finalize(self) -> u32 {
        self.state ^ XOR_OUT
    }

    pub fn finalize_hex(self) -> String {
        format!("{:08x}", self.finalize())
    }
}

impl Default for Crc32c {
    fn default() -> Self {
        Crc32c::new()
    }
}

pub fn update(mut crc: u32, data: &[u8]) -> u32 {
    let table = table();
    for &byte in data {
        let idx = ((crc as u8) ^ byte) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc
}

pub fn digest(data: &[u8]) -> u32 {
    let mut hasher = Crc32c::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn digest_hex(data: &[u8]) -> String {
    format!("{:08x}", digest(data))
}

fn table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut bit = 0;
            while bit < 8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ POLY_REFLECTED;
                } else {
                    crc >>= 1;
                }
                bit += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_vectors() {
        let cases = [
            ("", "00000000"),
            ("123456789", "e3069283"),
            ("The quick brown fox jumps over the lazy dog", "22620404"),
        ];
        for (input, expected) in cases {
            assert_eq!(digest_hex(input.as_bytes()), expected);
        }
    }

    #[test]
    fn incremental_update_matches_one_shot() {
        let data = b"moonlight-crc32c";
        let mut hasher = Crc32c::new();
        hasher.update(&data[..4]);
        hasher.update(&data[4..10]);
        hasher.update(&data[10..]);
        assert_eq!(hasher.finalize(), digest(data));
    }
}
