const INIT_STATE: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

#[derive(Debug, Clone)]
pub struct Md4 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    length_bits: u64,
}

impl Md4 {
    pub fn new() -> Self {
        Md4 {
            state: INIT_STATE,
            buffer: [0u8; 64],
            buffer_len: 0,
            length_bits: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.update_with_len(data, true);
    }

    fn update_with_len(&mut self, data: &[u8], count_len: bool) {
        if count_len {
            self.length_bits = self.length_bits.wrapping_add((data.len() as u64) * 8);
        }
        let mut offset = 0;
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..self.buffer_len + needed]
                    .copy_from_slice(&data[..needed]);
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
                offset = needed;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while offset + 64 <= data.len() {
            let block = &data[offset..offset + 64];
            self.process_block(block);
            offset += 64;
        }

        if offset < data.len() {
            let remaining = &data[offset..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.length_bits;
        let mut padding = [0u8; 64];
        padding[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            64 + 56 - self.buffer_len
        };
        self.update_with_len(&padding[..pad_len], false);

        let length_bytes = bit_len.to_le_bytes();
        self.update_with_len(&length_bytes, false);

        let mut out = [0u8; 16];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            let start = i * 4;
            x[i] = u32::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        // Round 1
        round1(&mut a, b, c, d, x[0], 3);
        round1(&mut d, a, b, c, x[1], 7);
        round1(&mut c, d, a, b, x[2], 11);
        round1(&mut b, c, d, a, x[3], 19);
        round1(&mut a, b, c, d, x[4], 3);
        round1(&mut d, a, b, c, x[5], 7);
        round1(&mut c, d, a, b, x[6], 11);
        round1(&mut b, c, d, a, x[7], 19);
        round1(&mut a, b, c, d, x[8], 3);
        round1(&mut d, a, b, c, x[9], 7);
        round1(&mut c, d, a, b, x[10], 11);
        round1(&mut b, c, d, a, x[11], 19);
        round1(&mut a, b, c, d, x[12], 3);
        round1(&mut d, a, b, c, x[13], 7);
        round1(&mut c, d, a, b, x[14], 11);
        round1(&mut b, c, d, a, x[15], 19);

        // Round 2
        round2(&mut a, b, c, d, x[0], 3);
        round2(&mut d, a, b, c, x[4], 5);
        round2(&mut c, d, a, b, x[8], 9);
        round2(&mut b, c, d, a, x[12], 13);
        round2(&mut a, b, c, d, x[1], 3);
        round2(&mut d, a, b, c, x[5], 5);
        round2(&mut c, d, a, b, x[9], 9);
        round2(&mut b, c, d, a, x[13], 13);
        round2(&mut a, b, c, d, x[2], 3);
        round2(&mut d, a, b, c, x[6], 5);
        round2(&mut c, d, a, b, x[10], 9);
        round2(&mut b, c, d, a, x[14], 13);
        round2(&mut a, b, c, d, x[3], 3);
        round2(&mut d, a, b, c, x[7], 5);
        round2(&mut c, d, a, b, x[11], 9);
        round2(&mut b, c, d, a, x[15], 13);

        // Round 3
        round3(&mut a, b, c, d, x[0], 3);
        round3(&mut d, a, b, c, x[8], 9);
        round3(&mut c, d, a, b, x[4], 11);
        round3(&mut b, c, d, a, x[12], 15);
        round3(&mut a, b, c, d, x[2], 3);
        round3(&mut d, a, b, c, x[10], 9);
        round3(&mut c, d, a, b, x[6], 11);
        round3(&mut b, c, d, a, x[14], 15);
        round3(&mut a, b, c, d, x[1], 3);
        round3(&mut d, a, b, c, x[9], 9);
        round3(&mut c, d, a, b, x[5], 11);
        round3(&mut b, c, d, a, x[13], 15);
        round3(&mut a, b, c, d, x[3], 3);
        round3(&mut d, a, b, c, x[11], 9);
        round3(&mut c, d, a, b, x[7], 11);
        round3(&mut b, c, d, a, x[15], 15);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

impl Default for Md4 {
    fn default() -> Self {
        Md4::new()
    }
}

pub fn digest(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn digest_hex(data: &[u8]) -> String {
    to_hex(&digest(data))
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn round1(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a.wrapping_add(f(b, c, d)).wrapping_add(x).rotate_left(s);
}

fn round2(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a
        .wrapping_add(g(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x5a827999)
        .rotate_left(s);
}

fn round3(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
    *a = a
        .wrapping_add(h(b, c, d))
        .wrapping_add(x)
        .wrapping_add(0x6ed9eba1)
        .rotate_left(s);
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_vectors() {
        let cases = [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(digest_hex(input.as_bytes()), expected);
        }
    }
}
