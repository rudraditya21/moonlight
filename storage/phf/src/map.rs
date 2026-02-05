use crate::builder::build_internal;

#[derive(Debug, Clone)]
pub struct Slot<V> {
    pub(crate) key: String,
    pub(crate) value: V,
}

#[derive(Debug, Clone)]
pub struct PhfMap<V> {
    pub(crate) seeds: Vec<i64>,
    pub(crate) slots: Vec<Option<Slot<V>>>,
    pub(crate) size: usize,
}

impl<V> PhfMap<V> {
    pub fn build(entries: Vec<(String, V)>) -> Result<Self, String> {
        build_internal(entries, 1_000_000)
    }

    pub(crate) fn build_with(entries: Vec<(String, V)>, max_seed: u64) -> Result<Self, String> {
        build_internal(entries, max_seed)
    }

    pub(crate) fn empty() -> Self {
        PhfMap {
            seeds: Vec::new(),
            slots: Vec::new(),
            size: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        if self.size == 0 {
            return None;
        }
        let bucket = (hash64(key.as_bytes(), 0) % self.seeds.len() as u64) as usize;
        let seed = self.seeds[bucket];
        let slot = if seed < 0 {
            (-seed - 1) as usize
        } else {
            (hash64(key.as_bytes(), seed as u64) % self.slots.len() as u64) as usize
        };
        match &self.slots[slot] {
            Some(entry) if entry.key == key => Some(&entry.value),
            _ => None,
        }
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.slots.iter().filter_map(|slot| slot.as_ref().map(|s| s.key.as_str()))
    }
}

pub(crate) fn hash64(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325u64 ^ seed.wrapping_mul(0x9e3779b97f4a7c15);
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::PhfMap;

    #[test]
    fn builds_and_queries() {
        let entries = vec![
            ("alpha".to_string(), 1),
            ("bravo".to_string(), 2),
            ("charlie".to_string(), 3),
            ("delta".to_string(), 4),
            ("echo".to_string(), 5),
        ];
        let map = PhfMap::build(entries).expect("build phf");
        assert_eq!(map.get("alpha"), Some(&1));
        assert_eq!(map.get("delta"), Some(&4));
        assert!(map.get("zulu").is_none());
    }

    #[test]
    fn handles_singleton() {
        let map = PhfMap::build(vec![("only".to_string(), 42)]).expect("build phf");
        assert_eq!(map.get("only"), Some(&42));
    }
}
