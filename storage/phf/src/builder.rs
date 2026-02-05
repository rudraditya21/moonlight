use crate::map::{hash64, Slot};
use crate::PhfMap;

pub struct PhfBuilder {
    max_seed: u64,
}

impl PhfBuilder {
    pub fn new() -> Self {
        PhfBuilder { max_seed: 100_000 }
    }

    pub fn with_max_seed(mut self, max_seed: u64) -> Self {
        self.max_seed = max_seed;
        self
    }

    pub fn build<V>(&self, entries: Vec<(String, V)>) -> Result<PhfMap<V>, String> {
        PhfMap::build_with(entries, self.max_seed)
    }
}

impl Default for PhfBuilder {
    fn default() -> Self {
        PhfBuilder::new()
    }
}

pub(crate) fn build_internal<V>(entries: Vec<(String, V)>, max_seed: u64) -> Result<PhfMap<V>, String> {
    let size = entries.len();
    if size == 0 {
        return Ok(PhfMap::empty());
    }

    let mut buckets: Vec<Vec<(String, V)>> = Vec::with_capacity(size);
    for _ in 0..size {
        buckets.push(Vec::new());
    }
    for (key, value) in entries {
        let h = hash64(key.as_bytes(), 0);
        let bucket = (h % size as u64) as usize;
        buckets[bucket].push((key, value));
    }

    let mut bucket_indices: Vec<usize> = (0..size).collect();
    bucket_indices.sort_by_key(|&i| std::cmp::Reverse(buckets[i].len()));

    let mut seeds: Vec<i64> = vec![0; size];
    let mut slots: Vec<Option<Slot<V>>> = Vec::with_capacity(size);
    for _ in 0..size {
        slots.push(None);
    }

    for bucket_index in bucket_indices {
        let bucket = &mut buckets[bucket_index];
        if bucket.is_empty() {
            continue;
        }
        if bucket.len() == 1 {
            let (key, value) = bucket.pop().unwrap();
            let mut slot = (hash64(key.as_bytes(), 0) % size as u64) as usize;
            while slots[slot].is_some() {
                slot = (slot + 1) % size;
            }
            seeds[bucket_index] = -((slot as i64) + 1);
            slots[slot] = Some(Slot { key, value });
            continue;
        }

        let mut seed = 0;
        let mut placed = false;
        while seed < max_seed {
            let mut used = Vec::with_capacity(bucket.len());
            let mut collision = false;
            for (key, _) in bucket.iter() {
                let slot = (hash64(key.as_bytes(), seed) % size as u64) as usize;
                if slots[slot].is_some() || used.contains(&slot) {
                    collision = true;
                    break;
                }
                used.push(slot);
            }
            if !collision {
                seeds[bucket_index] = seed as i64;
                for ((key, value), slot) in bucket.drain(..).zip(used.into_iter()) {
                    slots[slot] = Some(Slot { key, value });
                }
                placed = true;
                break;
            }
            seed += 1;
        }
        if !placed {
            return Err(format!("unable to build perfect hash map (bucket {bucket_index})"));
        }
    }

    Ok(PhfMap { seeds, slots, size })
}
