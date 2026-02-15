use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use phf::PhfMap;

use crate::cache::CachedEntry;
use crate::hash::{
    ensure_dir, file_fingerprint_with_hash, file_metadata_fingerprint, read_to_string,
};
use crate::manifest::ModuleManifest;
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank, ModuleReference};

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
struct LoadedIndex {
    version: u32,
    entries: Vec<CachedEntry>,
    name_index: Option<PhfMap<usize>>,
    tag_index: Option<StringIndex>,
    platform_index: Option<StringIndex>,
    token_index: Option<StringIndex>,
    category_index: Vec<Vec<usize>>,
    rank_index: Vec<Vec<usize>>,
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
        let index_path = cache_dir.join("module_index.bin");
        let loaded_index = load_index(&index_path)?;
        let cache_map = loaded_index
            .as_ref()
            .map(|idx| cached_entry_map(&idx.entries))
            .unwrap_or_default();

        let manifest_files = find_manifest_files(root)?;
        let tasks = manifest_files
            .iter()
            .map(|manifest_path| {
                let rel_path = manifest_path
                    .strip_prefix(root)
                    .unwrap_or(manifest_path)
                    .to_string_lossy()
                    .to_string();
                ManifestTask {
                    manifest_path: manifest_path.to_path_buf(),
                    rel_path,
                }
            })
            .collect::<Vec<_>>();
        let mut results = process_manifest_tasks(tasks, &cache_map)?;

        let needs_rewrite = loaded_index
            .as_ref()
            .map(|idx| idx.version != INDEX_VERSION)
            .unwrap_or(false);
        let unchanged = loaded_index.is_some()
            && results.len() == cache_map.len()
            && results.iter().all(|item| item.fast_match);
        if unchanged && !needs_rewrite {
            return Ok(catalog_from_index(loaded_index.unwrap(), root));
        }

        results.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        let mut records = Vec::with_capacity(results.len());
        let mut cached_entries = Vec::with_capacity(results.len());
        for item in results {
            let record = build_record(item.metadata.clone(), &item.manifest_path);
            records.push(record);
            cached_entries.push(CachedEntry {
                manifest_path: item.rel_path,
                fingerprint: item.fingerprint,
                metadata: item.metadata,
            });
        }

        let catalog = ModuleCatalog::from_records(records)?;
        save_index(&index_path, &cached_entries, &catalog)?;
        Ok(catalog)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn has_name_index(&self) -> bool {
        self.name_index.is_some()
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
        let mut constrained = false;

        if let Some(category) = query.category {
            let idx = category_to_index(category);
            let list = self.category_index.get(idx).cloned().unwrap_or_default();
            candidates = Some(list);
            constrained = true;
        }

        if let Some(rank) = query.rank {
            let idx = rank_to_index(rank);
            let list = self.rank_index.get(idx).cloned().unwrap_or_default();
            candidates = Some(intersect_candidates(candidates, &list));
            constrained = true;
        }

        if let Some(platform) = &query.platform {
            if let Some(index) = &self.platform_index {
                if let Some(list) = index.get(platform) {
                    candidates = Some(intersect_candidates(candidates, list));
                    constrained = true;
                } else {
                    return Vec::new();
                }
            } else {
                return Vec::new();
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
            } else {
                return Vec::new();
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
                constrained = true;
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
                    constrained = true;
                    Some(filtered)
                } else {
                    return Vec::new();
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

        if !constrained {
            return Vec::new();
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

#[derive(Debug, Clone)]
struct ManifestTask {
    manifest_path: PathBuf,
    rel_path: String,
}

#[derive(Debug, Clone)]
struct ManifestProcessed {
    manifest_path: PathBuf,
    rel_path: String,
    metadata: ModuleMetadata,
    fingerprint: crate::hash::FileFingerprint,
    fast_match: bool,
}

fn process_manifest_tasks(
    tasks: Vec<ManifestTask>,
    cache_map: &HashMap<String, CachedEntry>,
) -> CoreResult<Vec<ManifestProcessed>> {
    if tasks.is_empty() {
        return Ok(Vec::new());
    }
    let worker_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let workers = worker_count.min(tasks.len()).max(1);
    let chunk_size = (tasks.len() + workers - 1) / workers;
    let cache_map = Arc::new(cache_map.clone());
    let mut handles = Vec::with_capacity(workers);
    for chunk in tasks.chunks(chunk_size) {
        let cache_map = Arc::clone(&cache_map);
        let chunk_vec = chunk.to_vec();
        handles.push(thread::spawn(
            move || -> CoreResult<Vec<ManifestProcessed>> {
                let mut out = Vec::with_capacity(chunk_vec.len());
                for task in chunk_vec {
                    out.push(process_manifest_task(task, &cache_map)?);
                }
                Ok(out)
            },
        ));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for handle in handles {
        let chunk = handle
            .join()
            .map_err(|_| CoreError::Message("manifest worker panicked".to_string()))??;
        results.extend(chunk);
    }
    Ok(results)
}

fn process_manifest_task(
    task: ManifestTask,
    cache_map: &HashMap<String, CachedEntry>,
) -> CoreResult<ManifestProcessed> {
    let (size, mtime) = file_metadata_fingerprint(&task.manifest_path)?;
    if let Some(entry) = cache_map.get(&task.rel_path) {
        if entry.fingerprint.matches_fast(size, mtime) {
            return Ok(ManifestProcessed {
                manifest_path: task.manifest_path,
                rel_path: task.rel_path,
                metadata: entry.metadata.clone(),
                fingerprint: entry.fingerprint.clone(),
                fast_match: true,
            });
        }
    }
    let content = read_to_string(&task.manifest_path)?;
    let manifest = ModuleManifest::parse_str(&content)
        .map_err(|e| CoreError::Parse(format!("{}: {}", task.rel_path, e)))?;
    let metadata = manifest.metadata;
    let fingerprint = file_fingerprint_with_hash(&task.manifest_path, size, mtime)?;
    Ok(ManifestProcessed {
        manifest_path: task.manifest_path,
        rel_path: task.rel_path,
        metadata,
        fingerprint,
        fast_match: false,
    })
}

fn cached_entry_map(entries: &[CachedEntry]) -> HashMap<String, CachedEntry> {
    let mut map = HashMap::with_capacity(entries.len());
    for entry in entries {
        map.insert(entry.manifest_path.clone(), entry.clone());
    }
    map
}

fn catalog_from_index(index: LoadedIndex, root: &Path) -> ModuleCatalog {
    let mut records = Vec::with_capacity(index.entries.len());
    for entry in index.entries {
        let manifest_path = root.join(&entry.manifest_path);
        let record = build_record(entry.metadata, &manifest_path);
        records.push(record);
    }
    ModuleCatalog {
        records,
        name_index: index.name_index,
        tag_index: index.tag_index,
        platform_index: index.platform_index,
        token_index: index.token_index,
        category_index: index.category_index,
        rank_index: index.rank_index,
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

const CATEGORY_COUNT: usize = 8;
const RANK_COUNT: usize = 8;
const INDEX_MAGIC: &[u8; 4] = b"MLMI";
const INDEX_VERSION_V1: u32 = 1;
const INDEX_VERSION_V2: u32 = 2;
const INDEX_VERSION_V3: u32 = 3;
const INDEX_VERSION: u32 = INDEX_VERSION_V3;

fn category_to_index(category: ModuleCategory) -> usize {
    match category {
        ModuleCategory::Core => 0,
        ModuleCategory::Exploit => 1,
        ModuleCategory::Payload => 2,
        ModuleCategory::Auxiliary => 3,
        ModuleCategory::Post => 4,
        ModuleCategory::Nop => 5,
        ModuleCategory::Evasion => 6,
        ModuleCategory::Unknown => 7,
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

#[derive(Debug, Clone)]
struct StringTable {
    values: Vec<String>,
    map: HashMap<String, u32>,
}

impl StringTable {
    fn id_of(&self, value: &str) -> CoreResult<u32> {
        self.map
            .get(value)
            .copied()
            .ok_or_else(|| CoreError::Parse(format!("string not in table: {value}")))
    }

    fn get(&self, id: u32) -> CoreResult<&str> {
        let idx = id as usize;
        self.values
            .get(idx)
            .map(|s| s.as_str())
            .ok_or_else(|| CoreError::Parse(format!("string id out of range: {id}")))
    }
}

#[derive(Debug, Clone)]
struct StringTableBuilder {
    map: HashMap<String, u32>,
    values: Vec<String>,
}

impl StringTableBuilder {
    fn new() -> Self {
        StringTableBuilder {
            map: HashMap::new(),
            values: Vec::new(),
        }
    }

    fn intern(&mut self, value: &str) -> u32 {
        if let Some(id) = self.map.get(value) {
            return *id;
        }
        let id = self.values.len() as u32;
        self.values.push(value.to_string());
        self.map.insert(value.to_string(), id);
        id
    }

    fn finish(self) -> StringTable {
        StringTable {
            values: self.values,
            map: self.map,
        }
    }
}

fn collect_strings(
    table: &mut StringTableBuilder,
    entries: &[CachedEntry],
    catalog: &ModuleCatalog,
) {
    for entry in entries {
        table.intern(&entry.manifest_path);
        collect_metadata_strings(table, &entry.metadata);
    }
    if let Some(name_index) = &catalog.name_index {
        collect_phf_map_strings(table, name_index);
    }
    if let Some(tag_index) = &catalog.tag_index {
        collect_phf_map_strings(table, &tag_index.map);
    }
    if let Some(platform_index) = &catalog.platform_index {
        collect_phf_map_strings(table, &platform_index.map);
    }
    if let Some(token_index) = &catalog.token_index {
        collect_phf_map_strings(table, &token_index.map);
    }
}

fn collect_phf_map_strings(table: &mut StringTableBuilder, map: &PhfMap<usize>) {
    for slot in map.slots() {
        if let Some(entry) = slot {
            table.intern(entry.key());
        }
    }
}

fn collect_metadata_strings(table: &mut StringTableBuilder, metadata: &ModuleMetadata) {
    table.intern(&metadata.name);
    table.intern(&metadata.description);
    table.intern(&metadata.author);
    for platform in &metadata.platforms {
        table.intern(platform);
    }
    for tag in &metadata.tags {
        table.intern(tag);
    }
    if let Some(entrypoint) = &metadata.entrypoint {
        table.intern(entrypoint);
    }
    for reference in &metadata.references {
        table.intern(&reference.kind);
        table.intern(&reference.value);
    }
}

fn load_index(path: &Path) -> CoreResult<Option<LoadedIndex>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(path).map_err(CoreError::Io)?;
    let mut cursor = 0;
    if read_bytes(&data, &mut cursor, 4)? != INDEX_MAGIC {
        return Ok(None);
    }
    let version = read_u32(&data, &mut cursor)?;
    match version {
        INDEX_VERSION_V1 => load_index_v1(&data, &mut cursor),
        INDEX_VERSION_V2 => load_index_v2(&data, &mut cursor),
        _ => Ok(None),
    }
}

fn load_index_v1(data: &[u8], cursor: &mut usize) -> CoreResult<Option<LoadedIndex>> {
    let entry_count = read_u32(data, cursor)? as usize;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let manifest_path = read_string(data, cursor)?;
        let size = read_u64(data, cursor)?;
        let mtime = read_u64(data, cursor)?;
        let hash = read_u64(data, cursor)?;
        let metadata = read_metadata_v1(data, cursor)?;
        entries.push(CachedEntry {
            manifest_path,
            fingerprint: crate::hash::FileFingerprint { size, mtime, hash },
            metadata,
        });
    }
    let name_index = read_phf_map_option_v1(data, cursor)?;
    let tag_index = read_string_index_v1(data, cursor)?;
    let platform_index = read_string_index_v1(data, cursor)?;
    let token_index = read_string_index_v1(data, cursor)?;
    let category_index = read_index_lists(data, cursor)?;
    let rank_index = read_index_lists(data, cursor)?;

    Ok(Some(LoadedIndex {
        version: INDEX_VERSION_V1,
        entries,
        name_index,
        tag_index,
        platform_index,
        token_index,
        category_index,
        rank_index,
    }))
}

fn load_index_v2(data: &[u8], cursor: &mut usize) -> CoreResult<Option<LoadedIndex>> {
    let table = read_string_table(data, cursor)?;
    let entry_count = read_u32(data, cursor)? as usize;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let manifest_id = read_u32(data, cursor)?;
        let manifest_path = string_from_id(&table, manifest_id)?;
        let size = read_u64(data, cursor)?;
        let mtime = read_u64(data, cursor)?;
        let hash = read_u64(data, cursor)?;
        let metadata = read_metadata_v2(data, cursor, &table)?;
        entries.push(CachedEntry {
            manifest_path,
            fingerprint: crate::hash::FileFingerprint { size, mtime, hash },
            metadata,
        });
    }
    let name_index = read_phf_map_option_v2(data, cursor, &table)?;
    let tag_index = read_string_index_v2(data, cursor, &table)?;
    let platform_index = read_string_index_v2(data, cursor, &table)?;
    let token_index = read_string_index_v2(data, cursor, &table)?;
    let category_index = read_index_lists(data, cursor)?;
    let rank_index = read_index_lists(data, cursor)?;

    Ok(Some(LoadedIndex {
        version: INDEX_VERSION_V2,
        entries,
        name_index,
        tag_index,
        platform_index,
        token_index,
        category_index,
        rank_index,
    }))
}

fn save_index(path: &Path, entries: &[CachedEntry], catalog: &ModuleCatalog) -> CoreResult<()> {
    let mut builder = StringTableBuilder::new();
    collect_strings(&mut builder, entries, catalog);
    let table = builder.finish();

    let mut out = Vec::new();
    out.extend_from_slice(INDEX_MAGIC);
    write_u32(&mut out, INDEX_VERSION);
    write_string_table(&mut out, &table);
    write_u32(&mut out, entries.len() as u32);
    for entry in entries {
        write_u32(&mut out, table.id_of(&entry.manifest_path)?);
        write_u64(&mut out, entry.fingerprint.size);
        write_u64(&mut out, entry.fingerprint.mtime);
        write_u64(&mut out, entry.fingerprint.hash);
        write_metadata_v2(&mut out, &entry.metadata, &table)?;
    }
    write_phf_map_option_v2(&mut out, &catalog.name_index, &table)?;
    write_string_index_v2(&mut out, &catalog.tag_index, &table)?;
    write_string_index_v2(&mut out, &catalog.platform_index, &table)?;
    write_string_index_v2(&mut out, &catalog.token_index, &table)?;
    write_index_lists(&mut out, &catalog.category_index)?;
    write_index_lists(&mut out, &catalog.rank_index)?;

    std::fs::write(path, out).map_err(CoreError::Io)?;
    Ok(())
}

fn write_string_table(out: &mut Vec<u8>, table: &StringTable) {
    write_u32(out, table.values.len() as u32);
    for value in &table.values {
        write_string(out, value);
    }
}

fn read_string_table(data: &[u8], cursor: &mut usize) -> CoreResult<StringTable> {
    let count = read_u32(data, cursor)? as usize;
    let mut values = Vec::with_capacity(count);
    let mut map = HashMap::with_capacity(count);
    for idx in 0..count {
        let value = read_string(data, cursor)?;
        map.insert(value.clone(), idx as u32);
        values.push(value);
    }
    Ok(StringTable { values, map })
}

fn string_from_id(table: &StringTable, id: u32) -> CoreResult<String> {
    Ok(table.get(id)?.to_string())
}

fn write_string_index_v2(
    out: &mut Vec<u8>,
    index: &Option<StringIndex>,
    table: &StringTable,
) -> CoreResult<()> {
    match index {
        None => {
            write_u8(out, 0);
            Ok(())
        }
        Some(index) => {
            write_u8(out, 1);
            write_phf_map_v2(out, &index.map, table)?;
            write_u32(out, index.ranges.len() as u32);
            for range in &index.ranges {
                write_u32(out, range.start as u32);
                write_u32(out, range.len as u32);
            }
            write_u32(out, index.entries.len() as u32);
            for &value in &index.entries {
                write_u32(out, value as u32);
            }
            Ok(())
        }
    }
}

fn read_string_index_v2(
    data: &[u8],
    cursor: &mut usize,
    table: &StringTable,
) -> CoreResult<Option<StringIndex>> {
    let present = read_u8(data, cursor)?;
    if present == 0 {
        return Ok(None);
    }
    let map = read_phf_map_v2(data, cursor, table)?;
    let ranges_len = read_u32(data, cursor)? as usize;
    let mut ranges = Vec::with_capacity(ranges_len);
    for _ in 0..ranges_len {
        let start = read_u32(data, cursor)? as usize;
        let len = read_u32(data, cursor)? as usize;
        ranges.push(TagRange { start, len });
    }
    let entries_len = read_u32(data, cursor)? as usize;
    let mut entries = Vec::with_capacity(entries_len);
    for _ in 0..entries_len {
        entries.push(read_u32(data, cursor)? as usize);
    }
    Ok(Some(StringIndex {
        map,
        ranges,
        entries,
    }))
}

fn write_phf_map_option_v2(
    out: &mut Vec<u8>,
    map: &Option<PhfMap<usize>>,
    table: &StringTable,
) -> CoreResult<()> {
    match map {
        None => {
            write_u8(out, 0);
            Ok(())
        }
        Some(map) => {
            write_u8(out, 1);
            write_phf_map_v2(out, map, table)
        }
    }
}

fn read_phf_map_option_v2(
    data: &[u8],
    cursor: &mut usize,
    table: &StringTable,
) -> CoreResult<Option<PhfMap<usize>>> {
    let present = read_u8(data, cursor)?;
    if present == 0 {
        return Ok(None);
    }
    Ok(Some(read_phf_map_v2(data, cursor, table)?))
}

fn write_phf_map_v2(out: &mut Vec<u8>, map: &PhfMap<usize>, table: &StringTable) -> CoreResult<()> {
    write_u32(out, map.len() as u32);
    write_u32(out, map.seeds().len() as u32);
    for &seed in map.seeds() {
        write_i64(out, seed);
    }
    write_u32(out, map.slots().len() as u32);
    for slot in map.slots() {
        match slot {
            None => write_u8(out, 0),
            Some(entry) => {
                write_u8(out, 1);
                let key_id = table.id_of(entry.key())?;
                write_u32(out, key_id);
                write_u32(out, *entry.value() as u32);
            }
        }
    }
    Ok(())
}

fn read_phf_map_v2(
    data: &[u8],
    cursor: &mut usize,
    table: &StringTable,
) -> CoreResult<PhfMap<usize>> {
    let size = read_u32(data, cursor)? as usize;
    let seeds_len = read_u32(data, cursor)? as usize;
    let mut seeds = Vec::with_capacity(seeds_len);
    for _ in 0..seeds_len {
        seeds.push(read_i64(data, cursor)?);
    }
    let slots_len = read_u32(data, cursor)? as usize;
    let mut slots = Vec::with_capacity(slots_len);
    for _ in 0..slots_len {
        let present = read_u8(data, cursor)?;
        if present == 0 {
            slots.push(None);
        } else {
            let key_id = read_u32(data, cursor)?;
            let key = string_from_id(table, key_id)?;
            let value = read_u32(data, cursor)? as usize;
            slots.push(Some(phf::Slot::new(key, value)));
        }
    }
    Ok(PhfMap::from_parts(seeds, slots, size))
}

fn write_metadata_v2(
    out: &mut Vec<u8>,
    metadata: &ModuleMetadata,
    table: &StringTable,
) -> CoreResult<()> {
    write_u32(out, table.id_of(&metadata.name)?);
    write_u32(out, table.id_of(&metadata.description)?);
    write_u8(out, category_to_u8(&metadata.category));
    write_u8(out, rank_to_u8(metadata.rank));
    write_u32(out, table.id_of(&metadata.author)?);
    write_u32(out, metadata.platforms.len() as u32);
    for platform in &metadata.platforms {
        write_u32(out, table.id_of(platform)?);
    }
    write_u32(out, metadata.tags.len() as u32);
    for tag in &metadata.tags {
        write_u32(out, table.id_of(tag)?);
    }
    match &metadata.entrypoint {
        Some(entrypoint) => {
            write_u8(out, 1);
            write_u32(out, table.id_of(entrypoint)?);
        }
        None => write_u8(out, 0),
    }
    write_u32(out, metadata.references.len() as u32);
    for reference in &metadata.references {
        write_u32(out, table.id_of(&reference.kind)?);
        write_u32(out, table.id_of(&reference.value)?);
    }
    Ok(())
}

fn read_metadata_v2(
    data: &[u8],
    cursor: &mut usize,
    table: &StringTable,
) -> CoreResult<ModuleMetadata> {
    let name_id = read_u32(data, cursor)?;
    let desc_id = read_u32(data, cursor)?;
    let category = u8_to_category(read_u8(data, cursor)?);
    let rank = u8_to_rank(read_u8(data, cursor)?);
    let author_id = read_u32(data, cursor)?;
    let name = table.get(name_id)?.to_string();
    let description = table.get(desc_id)?.to_string();
    let author = table.get(author_id)?.to_string();
    let platforms_len = read_u32(data, cursor)? as usize;
    let mut platforms = Vec::with_capacity(platforms_len);
    for _ in 0..platforms_len {
        let id = read_u32(data, cursor)?;
        platforms.push(table.get(id)?.to_string());
    }
    let tags_len = read_u32(data, cursor)? as usize;
    let mut tags = Vec::with_capacity(tags_len);
    for _ in 0..tags_len {
        let id = read_u32(data, cursor)?;
        tags.push(table.get(id)?.to_string());
    }
    let entrypoint = match read_u8(data, cursor)? {
        0 => None,
        _ => {
            let id = read_u32(data, cursor)?;
            Some(table.get(id)?.to_string())
        }
    };
    let ref_count = read_u32(data, cursor)? as usize;
    let mut references = Vec::with_capacity(ref_count);
    for _ in 0..ref_count {
        let kind_id = read_u32(data, cursor)?;
        let value_id = read_u32(data, cursor)?;
        references.push(ModuleReference {
            kind: table.get(kind_id)?.to_string(),
            value: table.get(value_id)?.to_string(),
        });
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

fn read_string_index_v1(data: &[u8], cursor: &mut usize) -> CoreResult<Option<StringIndex>> {
    let present = read_u8(data, cursor)?;
    if present == 0 {
        return Ok(None);
    }
    let map = read_phf_map_v1(data, cursor)?;
    let ranges_len = read_u32(data, cursor)? as usize;
    let mut ranges = Vec::with_capacity(ranges_len);
    for _ in 0..ranges_len {
        let start = read_u32(data, cursor)? as usize;
        let len = read_u32(data, cursor)? as usize;
        ranges.push(TagRange { start, len });
    }
    let entries_len = read_u32(data, cursor)? as usize;
    let mut entries = Vec::with_capacity(entries_len);
    for _ in 0..entries_len {
        entries.push(read_u32(data, cursor)? as usize);
    }
    Ok(Some(StringIndex {
        map,
        ranges,
        entries,
    }))
}

fn write_index_lists(out: &mut Vec<u8>, lists: &[Vec<usize>]) -> CoreResult<()> {
    write_u32(out, lists.len() as u32);
    for list in lists {
        write_u32(out, list.len() as u32);
        for &value in list {
            write_u32(out, value as u32);
        }
    }
    Ok(())
}

fn read_index_lists(data: &[u8], cursor: &mut usize) -> CoreResult<Vec<Vec<usize>>> {
    let count = read_u32(data, cursor)? as usize;
    let mut lists = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(data, cursor)? as usize;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(read_u32(data, cursor)? as usize);
        }
        lists.push(list);
    }
    Ok(lists)
}

fn read_phf_map_option_v1(data: &[u8], cursor: &mut usize) -> CoreResult<Option<PhfMap<usize>>> {
    let present = read_u8(data, cursor)?;
    if present == 0 {
        return Ok(None);
    }
    Ok(Some(read_phf_map_v1(data, cursor)?))
}

fn read_phf_map_v1(data: &[u8], cursor: &mut usize) -> CoreResult<PhfMap<usize>> {
    let size = read_u32(data, cursor)? as usize;
    let seeds_len = read_u32(data, cursor)? as usize;
    let mut seeds = Vec::with_capacity(seeds_len);
    for _ in 0..seeds_len {
        seeds.push(read_i64(data, cursor)?);
    }
    let slots_len = read_u32(data, cursor)? as usize;
    let mut slots = Vec::with_capacity(slots_len);
    for _ in 0..slots_len {
        let present = read_u8(data, cursor)?;
        if present == 0 {
            slots.push(None);
        } else {
            let key = read_string(data, cursor)?;
            let value = read_u32(data, cursor)? as usize;
            slots.push(Some(phf::Slot::new(key, value)));
        }
    }
    Ok(PhfMap::from_parts(seeds, slots, size))
}

fn read_metadata_v1(data: &[u8], cursor: &mut usize) -> CoreResult<ModuleMetadata> {
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
        ModuleCategory::Nop => 6,
        ModuleCategory::Evasion => 7,
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
        6 => ModuleCategory::Nop,
        7 => ModuleCategory::Evasion,
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

fn write_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn read_bytes<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> CoreResult<&'a [u8]> {
    if *cursor + len > data.len() {
        return Err(CoreError::Parse("unexpected EOF".to_string()));
    }
    let slice = &data[*cursor..*cursor + len];
    *cursor += len;
    Ok(slice)
}

fn read_u8(data: &[u8], cursor: &mut usize) -> CoreResult<u8> {
    let value = read_bytes(data, cursor, 1)?[0];
    Ok(value)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> CoreResult<u32> {
    let bytes = read_bytes(data, cursor, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], cursor: &mut usize) -> CoreResult<u64> {
    let bytes = read_bytes(data, cursor, 8)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_i64(data: &[u8], cursor: &mut usize) -> CoreResult<i64> {
    let bytes = read_bytes(data, cursor, 8)?;
    Ok(i64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_string(data: &[u8], cursor: &mut usize) -> CoreResult<String> {
    let len = read_u32(data, cursor)? as usize;
    let bytes = read_bytes(data, cursor, len)?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| CoreError::Parse("invalid UTF-8".to_string()))?;
    Ok(text.to_string())
}

fn read_vec_string(data: &[u8], cursor: &mut usize) -> CoreResult<Vec<String>> {
    let count = read_u32(data, cursor)? as usize;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_string(data, cursor)?);
    }
    Ok(values)
}

fn read_optional_string(data: &[u8], cursor: &mut usize) -> CoreResult<Option<String>> {
    let present = read_u8(data, cursor)?;
    if present == 0 {
        return Ok(None);
    }
    Ok(Some(read_string(data, cursor)?))
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
