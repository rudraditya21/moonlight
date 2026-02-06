use std::fs::File;
use std::io::{Read, Result as IoResult};
use std::path::Path;

use corelib::error::{CoreError, CoreResult};

pub fn file_hash(path: &Path) -> CoreResult<u64> {
    let mut file = File::open(path).map_err(CoreError::Io)?;
    let mut buf = [0u8; 8192];
    let mut hash = 0xcbf29ce484222325u64;
    loop {
        let read = file.read(&mut buf).map_err(CoreError::Io)?;
        if read == 0 {
            break;
        }
        hash = fnv1a64_update(hash, &buf[..read]);
    }
    Ok(hash)
}

fn fnv1a64_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn file_metadata_fingerprint(path: &Path) -> CoreResult<(u64, u64)> {
    let metadata = path.metadata().map_err(CoreError::Io)?;
    let size = metadata.len();
    let mtime = metadata
        .modified()
        .map_err(CoreError::Io)?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::Parse("mtime before epoch".to_string()))?
        .as_secs();
    Ok((size, mtime))
}

pub fn file_fingerprint_with_hash(
    path: &Path,
    size: u64,
    mtime: u64,
) -> CoreResult<FileFingerprint> {
    let hash = file_hash(path)?;
    Ok(FileFingerprint { size, mtime, hash })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFingerprint {
    pub size: u64,
    pub mtime: u64,
    pub hash: u64,
}

impl FileFingerprint {
    pub fn matches_fast(&self, size: u64, mtime: u64) -> bool {
        self.size == size && self.mtime == mtime
    }
}

pub fn read_to_string(path: &Path) -> CoreResult<String> {
    let mut file = File::open(path).map_err(CoreError::Io)?;
    let mut data = String::new();
    file.read_to_string(&mut data).map_err(CoreError::Io)?;
    Ok(data)
}

pub fn ensure_dir(path: &Path) -> IoResult<()> {
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(path)
}
