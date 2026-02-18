use std::sync::OnceLock;

const POLY: u64 = 0xAD93_D235_94C9_35A9;
const POLY_REFLECTED: u64 = POLY.reverse_bits();
const INIT: u64 = 0x0000_0000_0000_0000;
const XOR_OUT: u64 = 0x0000_0000_0000_0000;

#[derive(Debug, Clone)]
pub struct Crc64Jones {
    state: u64,
}

impl Crc64Jones {
    pub fn new() -> Self {
        Crc64Jones { state: INIT }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.state = update(self.state, data);
    }

    pub fn finalize(self) -> u64 {
        self.state ^ XOR_OUT
    }

    pub fn finalize_hex(self) -> String {
        format!("{:016x}", self.finalize())
    }
}

impl Default for Crc64Jones {
    fn default() -> Self {
        Crc64Jones::new()
    }
}

pub fn update(mut crc: u64, data: &[u8]) -> u64 {
    let table = table();
    for &byte in data {
        let idx = ((crc as u8) ^ byte) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc
}

pub fn digest(data: &[u8]) -> u64 {
    let mut hasher = Crc64Jones::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn digest_hex(data: &[u8]) -> String {
    format!("{:016x}", digest(data))
}

fn table() -> &'static [u64; 256] {
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u64; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u64;
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
    fn crc64_jones_vectors() {
        let cases = [("", "0000000000000000"), ("123456789", "e9c6d914c4b8d9ca")];
        for (input, expected) in cases {
            assert_eq!(digest_hex(input.as_bytes()), expected);
        }
    }

    #[test]
    fn incremental_update_matches_one_shot() {
        let data = b"moonlight-crc64-jones";
        let mut hasher = Crc64Jones::new();
        hasher.update(&data[..8]);
        hasher.update(&data[8..]);
        assert_eq!(hasher.finalize(), digest(data));
    }
}
