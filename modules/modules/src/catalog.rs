use std::collections::HashMap;
use std::path::{Path, PathBuf};

use corelib::error::{CoreError, CoreResult};
use phf::PhfMap;

use crate::cache::{CachedEntry, ModuleCache};
use crate::hash::{
    ensure_dir, file_fingerprint_with_hash, file_metadata_fingerprint, read_to_string,
};
use crate::manifest::ModuleManifest;
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};

#[derive(Debug, Clone)]
pub struct ModuleRecord {
    pub metadata: ModuleMetadata,
    pub manifest_path: PathBuf,
    pub entrypoint_path: Option<PathBuf>,
    pub search_text: String,
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub term: Option<String>,
    pub category: Option<ModuleCategory>,
    pub rank: Option<ModuleRank>,
    pub platform: Option<String>,
    pub tags: Vec<String>,
    pub limit: Option<usize>,
}

impl SearchQuery {
    pub fn new() -> Self {
        SearchQuery {
            term: None,
            category: None,
            rank: None,
            platform: None,
            tags: Vec::new(),
            limit: None,
        }
    }
}

#[derive(Debug, Clone)]
struct TagRange {
    start: usize,
    len: usize,
}

#[derive(Debug, Clone)]
struct StringIndex {
    map: PhfMap<usize>,
    ranges: Vec<TagRange>,
    entries: Vec<usize>,
}

impl StringIndex {
    fn build(map: HashMap<String, Vec<usize>>) -> CoreResult<Option<Self>> {
        if map.is_empty() {
            return Ok(None);
        }
        let mut entries = Vec::new();
        let mut ranges = Vec::new();
        let mut phf_entries = Vec::with_capacity(map.len());
        let mut sorted_keys: Vec<String> = map.keys().cloned().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            let mut list = map.get(&key).cloned().unwrap_or_default();
            list.sort_unstable();
            list.dedup();
            let start = entries.len();
            entries.extend_from_slice(&list);
            let range = TagRange {
                start,
                len: list.len(),
            };
            phf_entries.push((key, ranges.len()));
            ranges.push(range);
        }
        let map = PhfMap::build(phf_entries).map_err(|e| CoreError::Parse(e))?;
        Ok(Some(StringIndex {
            map,
            ranges,
            entries,
        }))
    }

    fn get(&self, key: &str) -> Option<&[usize]> {
        let idx = self.map.get(&key.to_lowercase())?;
        let range = &self.ranges[*idx];
        Some(&self.entries[range.start..range.start + range.len])
    }
}

#[derive(Debug, Clone)]
pub struct ModuleCatalog {
    records: Vec<ModuleRecord>,
    name_index: Option<PhfMap<usize>>,
    tag_index: Option<StringIndex>,
    platform_index: Option<StringIndex>,
    token_index: Option<StringIndex>,
    category_index: Vec<Vec<usize>>,
    rank_index: Vec<Vec<usize>>,
}

impl ModuleCatalog {
    pub fn load(root: &Path, cache_dir: &Path) -> CoreResult<Self> {
        if !root.exists() {
            return ModuleCatalog::from_records(Vec::new());
        }
        ensure_dir(cache_dir).map_err(CoreError::Io)?;
        let cache_path = cache_dir.join("module_index.bin");
        let cache = ModuleCache::load(&cache_path)?;
        let cache_map = cache.as_ref().map(|c| c.as_map()).unwrap_or_default();

        let manifest_files = find_manifest_files(root)?;
        let mut records = Vec::with_capacity(manifest_files.len());
        let mut cached_entries = Vec::with_capacity(manifest_files.len());

        for manifest_path in manifest_files {
            let (size, mtime) = file_metadata_fingerprint(&manifest_path)?;
            let rel_path = manifest_path
                .strip_prefix(root)
                .unwrap_or(&manifest_path)
                .to_string_lossy()
                .to_string();
            if let Some(entry) = cache_map.get(&rel_path) {
                if entry.fingerprint.matches_fast(size, mtime) {
                    let metadata = entry.metadata.clone();
                    let fingerprint = entry.fingerprint.clone();
                    let record = build_record(metadata.clone(), &manifest_path);
                    records.push(record);
                    cached_entries.push(CachedEntry {
                        manifest_path: rel_path,
                        fingerprint,
                        metadata,
                    });
                    continue;
                }
            }
            let content = read_to_string(&manifest_path)?;
            let manifest = ModuleManifest::parse_str(&content)
                .map_err(|e| CoreError::Parse(format!("{}: {}", rel_path, e)))?;
            let metadata = manifest.metadata.clone();
            let fingerprint = file_fingerprint_with_hash(&manifest_path, size, mtime)?;
            let record = build_record(metadata.clone(), &manifest_path);
            records.push(record);
            cached_entries.push(CachedEntry {
                manifest_path: rel_path,
                fingerprint,
                metadata,
            });
        }

        let catalog = ModuleCatalog::from_records(records)?;
        let cache = ModuleCache {
            entries: cached_entries,
        };
        cache.save(&cache_path)?;
        Ok(catalog)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get_by_name(&self, name: &str) -> Option<&ModuleRecord> {
        if let Some(index) = &self.name_index {
            let idx = index.get(&name.to_lowercase())?;
            return self.records.get(*idx);
        }
        self.records
            .iter()
            .find(|record| record.metadata.name.eq_ignore_ascii_case(name))
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModuleRecord> {
        self.records.iter()
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<&ModuleRecord> {
        let mut candidates: Option<Vec<usize>> = None;

        if let Some(category) = query.category {
            let idx = category_to_index(category);
            let list = self.category_index.get(idx).cloned().unwrap_or_default();
            candidates = Some(list);
        }

        if let Some(rank) = query.rank {
            let idx = rank_to_index(rank);
            let list = self.rank_index.get(idx).cloned().unwrap_or_default();
            candidates = Some(intersect_candidates(candidates, &list));
        }

        if let Some(platform) = &query.platform {
            if let Some(index) = &self.platform_index {
                if let Some(list) = index.get(platform) {
                    candidates = Some(intersect_candidates(candidates, list));
                } else {
                    return Vec::new();
                }
            }
        }

        if !query.tags.is_empty() {
            let mut lists = Vec::new();
            if let Some(index) = &self.tag_index {
                for tag in &query.tags {
                    if let Some(list) = index.get(tag) {
                        lists.push(list);
                    } else {
                        return Vec::new();
                    }
                }
            }
            if !lists.is_empty() {
                lists.sort_by_key(|l| l.len());
                let base = lists.remove(0);
                let mut filtered = Vec::new();
                for &idx in base {
                    if lists.iter().all(|list| list.binary_search(&idx).is_ok()) {
                        filtered.push(idx);
                    }
                }
                candidates = Some(intersect_candidates(candidates, &filtered));
            }
        }

        let mut results = Vec::new();
        let term = query.term.as_ref().map(|t| t.to_ascii_lowercase());
        let limit = query.limit.unwrap_or(usize::MAX);
        let token_candidates = if let Some(term) = &term {
            let tokens = tokenize_text(term);
            if !tokens.is_empty() {
                if let Some(index) = &self.token_index {
                    let mut lists = Vec::new();
                    for token in tokens {
                        if let Some(list) = index.get(&token) {
                            lists.push(list);
                        } else {
                            return Vec::new();
                        }
                    }
                    lists.sort_by_key(|l| l.len());
                    let base = lists.remove(0);
                    let mut filtered = Vec::new();
                    for &idx in base {
                        if lists.iter().all(|list| list.binary_search(&idx).is_ok()) {
                            filtered.push(idx);
                        }
                    }
                    Some(filtered)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut base = candidates;
        if let Some(token_list) = token_candidates {
            base = Some(intersect_candidates(base, &token_list));
        }

        let iter: Box<dyn Iterator<Item = usize>> = if let Some(list) = base {
            Box::new(list.into_iter())
        } else {
            Box::new(0..self.records.len())
        };

        for idx in iter {
            let record = &self.records[idx];
            if let Some(term) = &term {
                if !record.search_text.contains(term) {
                    continue;
                }
            }
            results.push(record);
            if results.len() >= limit {
                break;
            }
        }

        results
    }

    fn from_records(records: Vec<ModuleRecord>) -> CoreResult<Self> {
        let mut name_entries = Vec::with_capacity(records.len());
        let mut tag_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut platform_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut token_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut category_index = vec![Vec::new(); CATEGORY_COUNT];
        let mut rank_index = vec![Vec::new(); RANK_COUNT];

        for (idx, record) in records.iter().enumerate() {
            name_entries.push((record.metadata.name.to_lowercase(), idx));
            for tag in &record.metadata.tags {
                tag_map.entry(tag.to_lowercase()).or_default().push(idx);
            }
            for platform in &record.metadata.platforms {
                platform_map
                    .entry(platform.to_lowercase())
                    .or_default()
                    .push(idx);
            }
            let tokens = tokenize_text(&record.search_text);
            for token in tokens {
                token_map.entry(token).or_default().push(idx);
            }
            category_index[category_to_index(record.metadata.category)].push(idx);
            rank_index[rank_to_index(record.metadata.rank)].push(idx);
        }

        let name_index = if name_entries.is_empty() {
            None
        } else {
            Some(PhfMap::build(name_entries).map_err(|e| CoreError::Parse(e))?)
        };
        let tag_index = StringIndex::build(tag_map)?;
        let platform_index = StringIndex::build(platform_map)?;
        let token_index = StringIndex::build(token_map)?;

        Ok(ModuleCatalog {
            records,
            name_index,
            tag_index,
            platform_index,
            token_index,
            category_index,
            rank_index,
        })
    }
}

fn intersect_candidates(existing: Option<Vec<usize>>, list: &[usize]) -> Vec<usize> {
    match existing {
        None => list.to_vec(),
        Some(mut current) => {
            current.retain(|idx| list.binary_search(idx).is_ok());
            current
        }
    }
}

fn find_manifest_files(root: &Path) -> CoreResult<Vec<PathBuf>> {
    let mut stack = vec![root.to_path_buf()];
    let mut manifests = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(CoreError::Io)?;
        for entry in entries {
            let entry = entry.map_err(CoreError::Io)?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.eq_ignore_ascii_case("module.json") {
                    manifests.push(path);
                }
            }
        }
    }
    manifests.sort();
    Ok(manifests)
}

fn build_record(metadata: ModuleMetadata, manifest_path: &Path) -> ModuleRecord {
    let entrypoint_path = metadata.entrypoint.as_ref().map(|entry| {
        let base = manifest_path.parent().unwrap_or(manifest_path);
        base.join(entry)
    });
    let search_text = build_search_text(&metadata);
    ModuleRecord {
        metadata,
        manifest_path: manifest_path.to_path_buf(),
        entrypoint_path,
        search_text,
    }
}

const CATEGORY_COUNT: usize = 7;
const RANK_COUNT: usize = 8;

fn category_to_index(category: ModuleCategory) -> usize {
    match category {
        ModuleCategory::Core => 0,
        ModuleCategory::Exploit => 1,
        ModuleCategory::Payload => 2,
        ModuleCategory::Auxiliary => 3,
        ModuleCategory::Post => 4,
        ModuleCategory::Evasion => 5,
        ModuleCategory::Unknown => 6,
    }
}

fn rank_to_index(rank: ModuleRank) -> usize {
    match rank {
        ModuleRank::Manual => 0,
        ModuleRank::Low => 1,
        ModuleRank::Average => 2,
        ModuleRank::Normal => 3,
        ModuleRank::Good => 4,
        ModuleRank::Great => 5,
        ModuleRank::Excellent => 6,
        ModuleRank::Unknown => 7,
    }
}

fn build_search_text(metadata: &ModuleMetadata) -> String {
    let mut out = String::new();
    out.push_str(&metadata.name.to_ascii_lowercase());
    out.push(' ');
    out.push_str(&metadata.description.to_ascii_lowercase());
    for tag in &metadata.tags {
        out.push(' ');
        out.push_str(&tag.to_ascii_lowercase());
    }
    for platform in &metadata.platforms {
        out.push(' ');
        out.push_str(&platform.to_ascii_lowercase());
    }
    out
}

fn tokenize_text(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            tokens.push(current.clone());
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens.sort();
    tokens.dedup();
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_manifest(path: &Path, name: &str, category: &str, tags: &[&str]) {
        let tags_json = tags
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect::<Vec<String>>()
            .join(",");
        let content = format!(
            "{{\n  \"name\": \"{}\",\n  \"description\": \"{}\",\n  \"category\": \"{}\",\n  \"author\": \"me\",\n  \"tags\": [{}]\n}}",
            name, name, category, tags_json
        );
        std::fs::write(path, content).expect("write manifest");
    }

    #[test]
    fn build_catalog_and_search() {
        let root = std::env::temp_dir().join("moonlight_catalog_test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create root");
        let mod_a = root.join("aux");
        let mod_b = root.join("exploit");
        std::fs::create_dir_all(&mod_a).expect("create a");
        std::fs::create_dir_all(&mod_b).expect("create b");
        write_manifest(
            &mod_a.join("module.json"),
            "aux/http/test",
            "auxiliary",
            &["http"],
        );
        write_manifest(
            &mod_b.join("module.json"),
            "exploit/ssh/test",
            "exploit",
            &["ssh"],
        );

        let cache_dir = root.join(".cache");
        let catalog = ModuleCatalog::load(&root, &cache_dir).expect("load catalog");
        assert_eq!(catalog.len(), 2);

        let mut query = SearchQuery::new();
        query.tags.push("http".to_string());
        let results = catalog.search(&query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata.name, "aux/http/test");

        std::fs::remove_dir_all(&root).ok();
    }
}
