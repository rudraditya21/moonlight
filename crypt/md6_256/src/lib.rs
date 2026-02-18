const WORD_BITS: usize = 64;
const BLOCK_WORDS: usize = 64;
const CHAIN_WORDS: usize = 16;
const INPUT_WORDS: usize = 89;
const BLOCK_BITS: usize = BLOCK_WORDS * WORD_BITS;
const CHAIN_BITS: usize = CHAIN_WORDS * WORD_BITS;
const DIGEST_BITS: usize = 256;
const DIGEST_WORDS: usize = DIGEST_BITS / WORD_BITS;
const MAX_LEVEL: u8 = 64;

const Q: [u64; 15] = [
    0x7311c2812425cfa0,
    0x6432286434aac8e7,
    0xb60450e9ef68b7c1,
    0xe8fb23908d9f06f1,
    0xdd2e76cba691e5bf,
    0x0cd0d63b2c30bc41,
    0x1f8ccf6823058f8a,
    0x54e5ed5b88e3775d,
    0x4ad12aae0a6d6031,
    0x3e7f16bb88222e0d,
    0x8af8671d3fb50c2c,
    0x995ad1178bd25c31,
    0xc878c1dd04c4b633,
    0x3b72066c7a1552ac,
    0x0d6f3522631effcb,
];

const RS: [u32; 16] = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
const LS: [u32; 16] = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];

const S0: u64 = 0x0123_4567_89ab_cdef;
const S_MASK: u64 = 0x7311_c281_2425_cfa0;

#[derive(Debug, Clone)]
pub struct Md6_256 {
    data: Vec<u8>,
}

impl Md6_256 {
    pub fn new() -> Self {
        Md6_256 { data: Vec::new() }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.data.extend_from_slice(input);
    }

    pub fn finalize(self) -> [u8; 32] {
        digest(&self.data)
    }

    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }
}

impl Default for Md6_256 {
    fn default() -> Self {
        Md6_256::new()
    }
}

pub fn digest(data: &[u8]) -> [u8; 32] {
    let root = md6_root_chain(data);
    // MD6-256 keeps the least significant 256 bits of the final 1024-bit chain value.
    let mut out = [0u8; 32];
    for (idx, word) in root[(CHAIN_WORDS - DIGEST_WORDS)..].iter().enumerate() {
        out[idx * 8..idx * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn digest_hex(data: &[u8]) -> String {
    to_hex(&digest(data))
}

fn md6_root_chain(data: &[u8]) -> [u64; CHAIN_WORDS] {
    let rounds = default_rounds(DIGEST_BITS as u16, 0);
    let (mut blocks, mut p_bits) = build_leaf_blocks(data);
    let mut level: u8 = 0;

    loop {
        let is_last_level = blocks.len() == 1;
        let mut chains = Vec::with_capacity(blocks.len());

        for (idx, block) in blocks.iter().enumerate() {
            let z = if is_last_level { 1 } else { 0 };
            chains.push(compress_node(
                *block,
                rounds,
                level,
                idx as u64,
                z,
                p_bits[idx],
            ));
        }

        if is_last_level {
            return chains[0];
        }

        let (next_blocks, next_p_bits) = build_parent_blocks(&chains);
        blocks = next_blocks;
        p_bits = next_p_bits;
        level = level.saturating_add(1);
    }
}

fn default_rounds(d: u16, keylen_bytes: u8) -> u16 {
    let min = if keylen_bytes > 0 { 80 } else { 0 };
    min.max(40 + d / 4)
}

fn build_leaf_blocks(data: &[u8]) -> (Vec<[u64; BLOCK_WORDS]>, Vec<u16>) {
    let original_bits = data.len() * 8;
    let pad_zeros = (BLOCK_BITS - ((original_bits + 1) % BLOCK_BITS)) % BLOCK_BITS;

    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % (BLOCK_BITS / 8) != 0 {
        padded.push(0);
    }

    let mut blocks = Vec::with_capacity(padded.len() / (BLOCK_BITS / 8));
    for chunk in padded.chunks(BLOCK_BITS / 8) {
        blocks.push(bytes_to_block_words(chunk));
    }

    let mut p_bits = vec![0u16; blocks.len()];
    if let Some(last) = p_bits.last_mut() {
        *last = pad_zeros as u16;
    }

    (blocks, p_bits)
}

fn build_parent_blocks(chains: &[[u64; CHAIN_WORDS]]) -> (Vec<[u64; BLOCK_WORDS]>, Vec<u16>) {
    let groups = chains.len().div_ceil(BLOCK_WORDS / CHAIN_WORDS);
    let mut blocks = Vec::with_capacity(groups);
    let mut p_bits = Vec::with_capacity(groups);

    for group_index in 0..groups {
        let start = group_index * (BLOCK_WORDS / CHAIN_WORDS);
        let end = (start + (BLOCK_WORDS / CHAIN_WORDS)).min(chains.len());
        let present = end - start;

        let mut block = [0u64; BLOCK_WORDS];
        for (slot, chain) in chains[start..end].iter().enumerate() {
            let offset = slot * CHAIN_WORDS;
            block[offset..offset + CHAIN_WORDS].copy_from_slice(chain);
        }

        blocks.push(block);
        p_bits.push(((BLOCK_WORDS / CHAIN_WORDS - present) * CHAIN_BITS) as u16);
    }

    (blocks, p_bits)
}

fn bytes_to_block_words(bytes: &[u8]) -> [u64; BLOCK_WORDS] {
    debug_assert_eq!(bytes.len(), BLOCK_BITS / 8);
    let mut out = [0u64; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        let j = i * 8;
        out[i] = u64::from_be_bytes([
            bytes[j],
            bytes[j + 1],
            bytes[j + 2],
            bytes[j + 3],
            bytes[j + 4],
            bytes[j + 5],
            bytes[j + 6],
            bytes[j + 7],
        ]);
    }
    out
}

fn compress_node(
    block: [u64; BLOCK_WORDS],
    rounds: u16,
    level: u8,
    index: u64,
    z: u8,
    p: u16,
) -> [u64; CHAIN_WORDS] {
    let mut n = [0u64; INPUT_WORDS];
    n[0..15].copy_from_slice(&Q);
    n[15..23].fill(0);
    n[23] = u_word(level, index);
    n[24] = v_word(rounds, MAX_LEVEL, z, p, 0, DIGEST_BITS as u16);
    n[25..(25 + BLOCK_WORDS)].copy_from_slice(&block);

    compress_words(&n, rounds)
}

fn u_word(level: u8, index: u64) -> u64 {
    ((level as u64) << 56) | (index & 0x00ff_ffff_ffff_ffff)
}

fn v_word(rounds: u16, l: u8, z: u8, p: u16, keylen: u8, d: u16) -> u64 {
    (((rounds as u64) & 0x0fff) << 52)
        | (((l as u64) & 0x00ff) << 44)
        | (((z as u64) & 0x000f) << 40)
        | (((p as u64) & 0xffff) << 24)
        | (((keylen as u64) & 0x00ff) << 16)
        | ((d as u64) & 0x0fff)
}

fn compress_words(input: &[u64; INPUT_WORDS], rounds: u16) -> [u64; CHAIN_WORDS] {
    let total_words = INPUT_WORDS + CHAIN_WORDS * rounds as usize;
    let mut a = vec![0u64; total_words];
    a[..INPUT_WORDS].copy_from_slice(input);

    let mut s = S0;
    for i in INPUT_WORDS..total_words {
        let mut x = s ^ a[i - 89] ^ a[i - 17];
        x ^= (a[i - 18] & a[i - 21]) ^ (a[i - 31] & a[i - 67]);
        let shift_idx = (i - INPUT_WORDS) % CHAIN_WORDS;
        x ^= x >> RS[shift_idx];
        a[i] = x ^ (x << LS[shift_idx]);
        s = (s << 1) ^ (s >> 63) ^ (s & S_MASK);
    }

    let mut out = [0u64; CHAIN_WORDS];
    out.copy_from_slice(&a[(total_words - CHAIN_WORDS)..]);
    out
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
    fn md6_256_len_and_determinism() {
        let a = digest_hex(b"abc");
        let b = digest_hex(b"abc");
        assert_eq!(a.len(), 64);
        assert_eq!(a, b);
        assert_ne!(a, digest_hex(b"abcd"));
    }

    #[test]
    fn md6_256_streaming_matches_one_shot() {
        let one_shot = digest_hex(b"message digest");

        let mut hasher = Md6_256::new();
        hasher.update(b"message");
        hasher.update(b" ");
        hasher.update(b"digest");

        assert_eq!(one_shot, hasher.finalize_hex());
    }

    #[test]
    fn md6_256_empty_known_value() {
        let empty = digest_hex(b"");
        // Locked to this implementation to catch accidental regressions.
        assert_eq!(
            empty,
            "6a28f41a00b4f999fa4116c15f2a86b95652e7a88ab18fdcb4e7dfcc51561be9"
        );
    }
}
