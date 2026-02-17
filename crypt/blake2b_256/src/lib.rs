const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[derive(Debug, Clone)]
pub struct Blake2b<const OUT: usize> {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    t0: u64,
    t1: u64,
}

impl<const OUT: usize> Blake2b<OUT> {
    pub fn new() -> Self {
        let mut state = IV;
        let param = 0x01010000u64 ^ (OUT as u64);
        state[0] ^= param;
        Blake2b {
            state,
            buffer: [0u8; 128],
            buffer_len: 0,
            t0: 0,
            t1: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let needed = 128 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..self.buffer_len + needed]
                    .copy_from_slice(&data[..needed]);
                self.buffer_len = 128;
                offset = needed;
                if offset < data.len() {
                    self.increment_counter(128);
                    self.compress(&self.buffer, false);
                    self.buffer_len = 0;
                } else {
                    return;
                }
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while offset + 128 < data.len() {
            let block = &data[offset..offset + 128];
            self.increment_counter(128);
            self.compress(block, false);
            offset += 128;
        }

        if offset < data.len() {
            let remaining = &data[offset..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    pub fn finalize(mut self) -> [u8; OUT] {
        self.increment_counter(self.buffer_len as u64);
        for i in self.buffer_len..128 {
            self.buffer[i] = 0;
        }
        self.compress(&self.buffer, true);
        let mut out = [0u8; OUT];
        let mut offset = 0;
        for word in &self.state {
            let bytes = word.to_le_bytes();
            for b in bytes {
                if offset >= OUT {
                    return out;
                }
                out[offset] = b;
                offset += 1;
            }
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }

    fn increment_counter(&mut self, inc: u64) {
        let prev = self.t0;
        self.t0 = self.t0.wrapping_add(inc);
        if self.t0 < prev {
            self.t1 = self.t1.wrapping_add(1);
        }
    }

    fn compress(&mut self, block: &[u8], last: bool) {
        let mut m = [0u64; 16];
        for i in 0..16 {
            let start = i * 8;
            m[i] = u64::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
                block[start + 4],
                block[start + 5],
                block[start + 6],
                block[start + 7],
            ]);
        }

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.state);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t0;
        v[13] ^= self.t1;
        if last {
            v[14] = !v[14];
        }

        for round in 0..12 {
            let s = SIGMA[round];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.state[i] ^= v[i] ^ v[i + 8];
        }
    }
}

impl<const OUT: usize> Default for Blake2b<OUT> {
    fn default() -> Self {
        Blake2b::new()
    }
}

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

const OUT: usize = 32;

pub type Blake2bHasher = Blake2b<OUT>;

pub fn digest(data: &[u8]) -> [u8; OUT] {
    let mut hasher = Blake2bHasher::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn digest_hex(data: &[u8]) -> String {
    to_hex(&digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_256_vectors() {
        let cases = [
            (
                "",
                "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            ),
            (
                "abc",
                "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
            ),
            (
                "message digest",
                "31a65b562925c6ffefdafa0ad830f4e33eff148856c2b4754de273814adf8b85",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(digest_hex(input.as_bytes()), expected);
        }
    }
}
