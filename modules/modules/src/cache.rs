use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use corelib::error::{CoreError, CoreResult};

use crate::hash::FileFingerprint;
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank, ModuleReference};

const CACHE_MAGIC: &[u8; 4] = b"MLMC";
const CACHE_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct CachedEntry {
    pub manifest_path: String,
    pub fingerprint: FileFingerprint,
    pub metadata: ModuleMetadata,
}

#[derive(Debug, Clone)]
pub struct ModuleCache {
    pub entries: Vec<CachedEntry>,
}

impl ModuleCache {
    pub fn load(path: &Path) -> CoreResult<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let mut file = File::open(path).map_err(CoreError::Io)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(CoreError::Io)?;
        let mut cursor = 0;
        if read_bytes(&data, &mut cursor, 4)? != CACHE_MAGIC {
            return Ok(None);
        }
        let version = read_u32(&data, &mut cursor)?;
        if version != CACHE_VERSION {
            return Ok(None);
        }
        let count = read_u32(&data, &mut cursor)? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let manifest_path = read_string(&data, &mut cursor)?;
            let size = read_u64(&data, &mut cursor)?;
            let mtime = read_u64(&data, &mut cursor)?;
            let hash = read_u64(&data, &mut cursor)?;
            let metadata = read_metadata(&data, &mut cursor)?;
            entries.push(CachedEntry {
                manifest_path,
                fingerprint: FileFingerprint { size, mtime, hash },
                metadata,
            });
        }
        Ok(Some(ModuleCache { entries }))
    }

    pub fn save(&self, path: &Path) -> CoreResult<()> {
        let mut out = Vec::new();
        out.extend_from_slice(CACHE_MAGIC);
        write_u32(&mut out, CACHE_VERSION);
        write_u32(&mut out, self.entries.len() as u32);
        for entry in &self.entries {
            write_string(&mut out, &entry.manifest_path);
            write_u64(&mut out, entry.fingerprint.size);
            write_u64(&mut out, entry.fingerprint.mtime);
            write_u64(&mut out, entry.fingerprint.hash);
            write_metadata(&mut out, &entry.metadata);
        }
        let mut file = File::create(path).map_err(CoreError::Io)?;
        file.write_all(&out).map_err(CoreError::Io)?;
        Ok(())
    }

    pub fn as_map(&self) -> HashMap<String, CachedEntry> {
        let mut map = HashMap::with_capacity(self.entries.len());
        for entry in &self.entries {
            map.insert(entry.manifest_path.clone(), entry.clone());
        }
        map
    }
}

fn write_metadata(out: &mut Vec<u8>, metadata: &ModuleMetadata) {
    write_string(out, &metadata.name);
    write_string(out, &metadata.description);
    write_u8(out, category_to_u8(&metadata.category));
    write_u8(out, rank_to_u8(metadata.rank));
    write_string(out, &metadata.author);
    write_vec_string(out, &metadata.platforms);
    write_vec_string(out, &metadata.tags);
    write_optional_string(out, metadata.entrypoint.as_deref());
    write_u32(out, metadata.references.len() as u32);
    for reference in &metadata.references {
        write_string(out, &reference.kind);
        write_string(out, &reference.value);
    }
}

fn read_metadata(data: &[u8], cursor: &mut usize) -> CoreResult<ModuleMetadata> {
    let name = read_string(data, cursor)?;
    let description = read_string(data, cursor)?;
    let category = u8_to_category(read_u8(data, cursor)?);
    let rank = u8_to_rank(read_u8(data, cursor)?);
    let author = read_string(data, cursor)?;
    let platforms = read_vec_string(data, cursor)?;
    let tags = read_vec_string(data, cursor)?;
    let entrypoint = read_optional_string(data, cursor)?;
    let ref_count = read_u32(data, cursor)? as usize;
    let mut references = Vec::with_capacity(ref_count);
    for _ in 0..ref_count {
        let kind = read_string(data, cursor)?;
        let value = read_string(data, cursor)?;
        references.push(ModuleReference { kind, value });
    }

    let mut metadata = ModuleMetadata::new(&name, &description, category, &author).with_rank(rank);
    for platform in platforms {
        metadata = metadata.with_platform(&platform);
    }
    for tag in tags {
        metadata = metadata.with_tag(&tag);
    }
    if let Some(entrypoint) = entrypoint {
        metadata = metadata.with_entrypoint(&entrypoint);
    }
    for reference in references {
        metadata = metadata.with_reference(&reference.kind, &reference.value);
    }
    Ok(metadata)
}

fn category_to_u8(category: &ModuleCategory) -> u8 {
    match category {
        ModuleCategory::Core => 1,
        ModuleCategory::Exploit => 2,
        ModuleCategory::Payload => 3,
        ModuleCategory::Auxiliary => 4,
        ModuleCategory::Post => 5,
        ModuleCategory::Evasion => 6,
        ModuleCategory::Unknown => 0,
    }
}

fn u8_to_category(value: u8) -> ModuleCategory {
    match value {
        1 => ModuleCategory::Core,
        2 => ModuleCategory::Exploit,
        3 => ModuleCategory::Payload,
        4 => ModuleCategory::Auxiliary,
        5 => ModuleCategory::Post,
        6 => ModuleCategory::Evasion,
        _ => ModuleCategory::Unknown,
    }
}

fn rank_to_u8(rank: ModuleRank) -> u8 {
    match rank {
        ModuleRank::Manual => 1,
        ModuleRank::Low => 2,
        ModuleRank::Average => 3,
        ModuleRank::Normal => 4,
        ModuleRank::Good => 5,
        ModuleRank::Great => 6,
        ModuleRank::Excellent => 7,
        ModuleRank::Unknown => 0,
    }
}

fn u8_to_rank(value: u8) -> ModuleRank {
    match value {
        1 => ModuleRank::Manual,
        2 => ModuleRank::Low,
        3 => ModuleRank::Average,
        4 => ModuleRank::Normal,
        5 => ModuleRank::Good,
        6 => ModuleRank::Great,
        7 => ModuleRank::Excellent,
        _ => ModuleRank::Unknown,
    }
}

fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_u8(data: &[u8], cursor: &mut usize) -> CoreResult<u8> {
    if *cursor >= data.len() {
        return Err(CoreError::Parse("unexpected EOF".to_string()));
    }
    let value = data[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> CoreResult<u32> {
    if *cursor + 4 > data.len() {
        return Err(CoreError::Parse("unexpected EOF".to_string()));
    }
    let value = u32::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn read_u64(data: &[u8], cursor: &mut usize) -> CoreResult<u64> {
    if *cursor + 8 > data.len() {
        return Err(CoreError::Parse("unexpected EOF".to_string()));
    }
    let value = u64::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
        data[*cursor + 4],
        data[*cursor + 5],
        data[*cursor + 6],
        data[*cursor + 7],
    ]);
    *cursor += 8;
    Ok(value)
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn write_optional_string(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(v) => {
            out.push(1);
            write_string(out, v);
        }
        None => out.push(0),
    }
}

fn write_vec_string(out: &mut Vec<u8>, values: &[String]) {
    write_u32(out, values.len() as u32);
    for value in values {
        write_string(out, value);
    }
}

fn read_string(data: &[u8], cursor: &mut usize) -> CoreResult<String> {
    let len = read_u32(data, cursor)? as usize;
    if *cursor + len > data.len() {
        return Err(CoreError::Parse("unexpected EOF".to_string()));
    }
    let value = std::str::from_utf8(&data[*cursor..*cursor + len])
        .map_err(|_| CoreError::Parse("invalid string".to_string()))?;
    *cursor += len;
    Ok(value.to_string())
}

fn read_optional_string(data: &[u8], cursor: &mut usize) -> CoreResult<Option<String>> {
    let flag = read_u8(data, cursor)?;
    if flag == 0 {
        return Ok(None);
    }
    Ok(Some(read_string(data, cursor)?))
}

fn read_vec_string(data: &[u8], cursor: &mut usize) -> CoreResult<Vec<String>> {
    let count = read_u32(data, cursor)? as usize;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_string(data, cursor)?);
    }
    Ok(values)
}

fn read_bytes<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> CoreResult<&'a [u8]> {
    if *cursor + len > data.len() {
        return Err(CoreError::Parse("unexpected EOF".to_string()));
    }
    let out = &data[*cursor..*cursor + len];
    *cursor += len;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_roundtrip() {
        let metadata =
            ModuleMetadata::new("aux/http/test", "desc", ModuleCategory::Auxiliary, "me")
                .with_rank(ModuleRank::Good)
                .with_platform("linux")
                .with_tag("http")
                .with_entrypoint("module.rs");
        let entry = CachedEntry {
            manifest_path: "mods/test/module.json".to_string(),
            fingerprint: FileFingerprint {
                size: 10,
                mtime: 20,
                hash: 30,
            },
            metadata,
        };
        let cache = ModuleCache {
            entries: vec![entry],
        };
        let path = std::env::temp_dir().join("moonlight_cache_test.bin");
        cache.save(&path).expect("save");
        let loaded = ModuleCache::load(&path).expect("load").expect("some");
        assert_eq!(loaded.entries.len(), 1);
        std::fs::remove_file(path).ok();
    }
}
