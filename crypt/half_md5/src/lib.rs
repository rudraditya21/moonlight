#[derive(Debug, Clone)]
pub struct HalfMd5 {
    inner: md5::Md5,
}

impl HalfMd5 {
    pub fn new() -> Self {
        HalfMd5 {
            inner: md5::Md5::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 8] {
        let full = self.inner.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(&full[..8]);
        out
    }

    pub fn finalize_hex(self) -> String {
        to_hex(&self.finalize())
    }
}

impl Default for HalfMd5 {
    fn default() -> Self {
        HalfMd5::new()
    }
}

pub fn digest(data: &[u8]) -> [u8; 8] {
    let mut hasher = HalfMd5::new();
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
    fn half_md5_vectors() {
        let cases = [
            ("", "d41d8cd98f00b204"),
            ("abc", "900150983cd24fb0"),
            ("message digest", "f96b697d7cb7938d"),
        ];
        for (input, expected) in cases {
            assert_eq!(digest_hex(input.as_bytes()), expected);
        }
    }
}
