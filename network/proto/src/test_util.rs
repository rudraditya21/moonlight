use std::panic::{catch_unwind, AssertUnwindSafe};

pub fn fuzz_bytes<F: FnMut(&[u8])>(iterations: usize, max_len: usize, seed: u64, mut f: F) {
    let mut state = seed;
    for _ in 0..iterations {
        let len = (next_u64(&mut state) as usize) % (max_len + 1);
        let mut buf = vec![0u8; len];
        fill_bytes(&mut state, &mut buf);
        let result = catch_unwind(AssertUnwindSafe(|| f(&buf)));
        assert!(result.is_ok(), "fuzz target panicked");
    }
}

pub fn fuzz_strings<F: FnMut(&str)>(iterations: usize, max_len: usize, seed: u64, mut f: F) {
    fuzz_bytes(iterations, max_len, seed, |data| {
        let text = String::from_utf8_lossy(data);
        f(&text);
    });
}

#[macro_export]
macro_rules! skip_if_perm {
    ($expr:expr) => {{
        match $expr {
            Ok(value) => value,
            Err(corelib::error::CoreError::Io(err))
                if err.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                return;
            }
            Err(err) => panic!("{} failed: {:?}", stringify!($expr), err),
        }
    }};
}

fn fill_bytes(state: &mut u64, out: &mut [u8]) {
    for chunk in out.chunks_mut(8) {
        let value = next_u64(state).to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&value[..len]);
    }
}

fn next_u64(state: &mut u64) -> u64 {
    let mut z = state.wrapping_add(0x9e3779b97f4a7c15);
    *state = z;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}
