const ROUNDS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTATION: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

#[derive(Debug, Clone)]
pub struct Keccak<const RATE: usize, const OUT: usize> {
    state: [u64; 25],
    buffer: [u8; RATE],
    buffer_len: usize,
}

impl<const RATE: usize, const OUT: usize> Keccak<RATE, OUT> {
    pub fn new() -> Self {
        Keccak {
            state: [0u64; 25],
            buffer: [0u8; RATE],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        if self.buffer_len > 0 {
            let needed = RATE - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..self.buffer_len + needed]
                    .copy_from_slice(&data[..needed]);
                let block = self.buffer;
                self.absorb_block(&block);
                self.buffer_len = 0;
                offset = needed;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while offset + RATE <= data.len() {
            let block = &data[offset..offset + RATE];
            self.absorb_block(block);
            offset += RATE;
        }

        if offset < data.len() {
            let remaining = &data[offset..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    pub fn finalize(mut self) -> [u8; OUT] {
        self.apply_padding();
        self.squeeze()
    }

    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }

    fn absorb_block(&mut self, block: &[u8]) {
        let lanes = RATE / 8;
        for i in 0..lanes {
            let start = i * 8;
            let lane = u64::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
                block[start + 4],
                block[start + 5],
                block[start + 6],
                block[start + 7],
            ]);
            self.state[i] ^= lane;
        }
        keccak_f(&mut self.state);
    }

    fn apply_padding(&mut self) {
        self.buffer[self.buffer_len] = 0x01;
        for i in self.buffer_len + 1..RATE {
            self.buffer[i] = 0;
        }
        self.buffer[RATE - 1] |= 0x80;
        let block = self.buffer;
        self.absorb_block(&block);
        self.buffer_len = 0;
    }

    fn squeeze(mut self) -> [u8; OUT] {
        let mut out = [0u8; OUT];
        let mut offset = 0;
        loop {
            let lanes = RATE / 8;
            for i in 0..lanes {
                let bytes = self.state[i].to_le_bytes();
                for b in bytes {
                    if offset >= OUT {
                        return out;
                    }
                    out[offset] = b;
                    offset += 1;
                }
            }
            if offset >= OUT {
                return out;
            }
            keccak_f(&mut self.state);
        }
    }
}

impl<const RATE: usize, const OUT: usize> Default for Keccak<RATE, OUT> {
    fn default() -> Self {
        Keccak::new()
    }
}

fn keccak_f(state: &mut [u64; 25]) {
    for &rc in &ROUNDS {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let rot = ROTATION[x][y];
                let v = state[x + 5 * y].rotate_left(rot);
                let nx = y;
                let ny = (2 * x + 3 * y) % 5;
                b[nx + 5 * ny] = v;
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                let idx = x + 5 * y;
                state[idx] = b[idx] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        state[0] ^= rc;
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub type KeccakHasher = Keccak<104, 48>;

pub fn digest(data: &[u8]) -> [u8; 48] {
    let mut hasher = KeccakHasher::new();
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
    fn keccak_384_vectors() {
        let cases = [
            ("", "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff"),
            ("abc", "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e"),
        ];
        for (input, expected) in cases {
            assert_eq!(digest_hex(input.as_bytes()), expected);
        }
    }
}
