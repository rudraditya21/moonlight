const INIT_STATE: [u32; 10] = [
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
    0x76543210,
    0xFEDCBA98,
    0x89ABCDEF,
    0x01234567,
    0x3C2D1E0F,
];

const R: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15,
    3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13,
    11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0,
    5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const R_PRIME: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13,
    5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2,
    10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15,
    10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const S: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7,
    15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5,
    12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11,
    6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const S_PRIME: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9,
    11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13,
    13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9,
    12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

#[derive(Debug, Clone)]
pub struct Ripemd320 {
    state: [u32; 10],
    buffer: [u8; 64],
    buffer_len: usize,
    length_bits: u64,
}

impl Ripemd320 {
    pub fn new() -> Self {
        Ripemd320 {
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

    pub fn finalize(mut self) -> [u8; 40] {
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

        let mut out = [0u8; 40];
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

        let mut al = self.state[0];
        let mut bl = self.state[1];
        let mut cl = self.state[2];
        let mut dl = self.state[3];
        let mut el = self.state[4];

        let mut ar = self.state[5];
        let mut br = self.state[6];
        let mut cr = self.state[7];
        let mut dr = self.state[8];
        let mut er = self.state[9];

        for i in 0..80 {
            let t = al
                .wrapping_add(f(i, bl, cl, dl))
                .wrapping_add(x[R[i]])
                .wrapping_add(k(i))
                .rotate_left(S[i])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t;

            let t = ar
                .wrapping_add(f_prime(i, br, cr, dr))
                .wrapping_add(x[R_PRIME[i]])
                .wrapping_add(k_prime(i))
                .rotate_left(S_PRIME[i])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t;
        }

        let t = self.state[1]
            .wrapping_add(cl)
            .wrapping_add(dr);
        self.state[1] = self.state[2]
            .wrapping_add(dl)
            .wrapping_add(er);
        self.state[2] = self.state[3]
            .wrapping_add(el)
            .wrapping_add(ar);
        self.state[3] = self.state[4]
            .wrapping_add(al)
            .wrapping_add(br);
        self.state[4] = self.state[0]
            .wrapping_add(bl)
            .wrapping_add(cr);
        self.state[0] = t;

        let t = self.state[6]
            .wrapping_add(cr)
            .wrapping_add(dl);
        self.state[6] = self.state[7]
            .wrapping_add(dr)
            .wrapping_add(el);
        self.state[7] = self.state[8]
            .wrapping_add(er)
            .wrapping_add(al);
        self.state[8] = self.state[9]
            .wrapping_add(ar)
            .wrapping_add(bl);
        self.state[9] = self.state[5]
            .wrapping_add(br)
            .wrapping_add(cl);
        self.state[5] = t;
    }
}

impl Default for Ripemd320 {
    fn default() -> Self {
        Ripemd320::new()
    }
}

fn f(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

fn f_prime(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0..=15 => x ^ (y | !z),
        16..=31 => (x & z) | (y & !z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & y) | (!x & z),
        _ => x ^ y ^ z,
    }
}

fn k(round: usize) -> u32 {
    match round {
        0..=15 => 0x00000000,
        16..=31 => 0x5A827999,
        32..=47 => 0x6ED9EBA1,
        48..=63 => 0x8F1BBCDC,
        _ => 0xA953FD4E,
    }
}

fn k_prime(round: usize) -> u32 {
    match round {
        0..=15 => 0x50A28BE6,
        16..=31 => 0x5C4DD124,
        32..=47 => 0x6D703EF3,
        48..=63 => 0x7A6D76E9,
        _ => 0x00000000,
    }
}

pub fn digest(data: &[u8]) -> [u8; 40] {
    let mut hasher = Ripemd320::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn digest_hex(data: &[u8]) -> String {
    to_hex(&digest(data))
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
    fn ripemd320_vectors() {
        let cases = [
            (
                "",
                "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
            ),
            (
                "abc",
                "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(digest_hex(input.as_bytes()), expected);
        }
    }
}
