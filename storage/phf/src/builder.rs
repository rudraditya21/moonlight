use crate::map::{hash64, Slot};
use crate::PhfMap;

pub struct PhfBuilder {
    max_seed: u64,
}

impl PhfBuilder {
    pub fn new() -> Self {
        PhfBuilder {
            max_seed: 1_000_000,
        }
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

pub(crate) fn build_internal<V>(
    entries: Vec<(String, V)>,
    max_seed: u64,
) -> Result<PhfMap<V>, String> {
    let entry_count = entries.len();
    if entry_count == 0 {
        return Ok(PhfMap::empty());
    }

    let mut entries: Vec<Option<(String, V)>> = entries.into_iter().map(Some).collect();
    let size_factors = [2usize, 3, 4, 5];
    let bucket_seeds = [0u64, 1, 7, 13, 31, 63, 127, 255];

    for factor in size_factors {
        let size = entry_count * factor + 1;
        for &bucket_seed in &bucket_seeds {
            if let Ok(map) = try_build(&mut entries, size, max_seed, bucket_seed) {
                return Ok(map);
            }
        }
    }

    Err("unable to build perfect hash map".to_string())
}

fn try_build<V>(
    entries: &mut [Option<(String, V)>],
    size: usize,
    max_seed: u64,
    bucket_seed: u64,
) -> Result<PhfMap<V>, String> {
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); size];
    for (idx, entry) in entries.iter().enumerate() {
        let Some((key, _)) = entry.as_ref() else {
            continue;
        };
        let h = hash64(key.as_bytes(), bucket_seed);
        let bucket = (h % size as u64) as usize;
        buckets[bucket].push(idx);
    }

    let mut bucket_indices: Vec<usize> = (0..size).collect();
    bucket_indices.sort_by_key(|&i| std::cmp::Reverse(buckets[i].len()));

    let mut seeds: Vec<i64> = vec![0; size];
    let mut slot_marks: Vec<u32> = vec![0; size];
    let mut occupied: Vec<bool> = vec![false; size];
    let mut mark_id: u32 = 1;
    let mut placements: Vec<(usize, usize)> = Vec::with_capacity(entries.len());

    for bucket_index in bucket_indices {
        let bucket = &buckets[bucket_index];
        if bucket.is_empty() {
            continue;
        }
        if bucket.len() == 1 {
            let entry_idx = bucket[0];
            let (key, _) = entries[entry_idx].as_ref().unwrap();
            let mut slot = (hash64(key.as_bytes(), bucket_seed) % size as u64) as usize;
            while occupied[slot] {
                slot = (slot + 1) % size;
            }
            seeds[bucket_index] = -((slot as i64) + 1);
            placements.push((entry_idx, slot));
            occupied[slot] = true;
            continue;
        }

        let mut seed = 0u64;
        let mut placed = false;
        while seed < max_seed {
            let mut used_slots: Vec<usize> = Vec::with_capacity(bucket.len());
            let mut collision = false;
            for &entry_idx in bucket {
                let (key, _) = entries[entry_idx].as_ref().unwrap();
                let slot = (hash64(key.as_bytes(), seed) % size as u64) as usize;
                if slot_marks[slot] == mark_id || occupied[slot] {
                    collision = true;
                    break;
                }
                slot_marks[slot] = mark_id;
                used_slots.push(slot);
            }
            if !collision {
                seeds[bucket_index] = seed as i64;
                for (&entry_idx, slot) in bucket.iter().zip(used_slots.into_iter()) {
                    placements.push((entry_idx, slot));
                    occupied[slot] = true;
                }
                placed = true;
                break;
            }
            seed += 1;
            mark_id = mark_id.wrapping_add(1).max(1);
        }
        if !placed {
            return Err(format!(
                "unable to build perfect hash map (bucket {bucket_index})"
            ));
        }
    }

    let mut slots: Vec<Option<Slot<V>>> = Vec::with_capacity(size);
    for _ in 0..size {
        slots.push(None);
    }
    for (entry_idx, slot) in placements {
        let (key, value) = entries[entry_idx].take().expect("entry already taken");
        slots[slot] = Some(Slot { key, value });
    }

    Ok(PhfMap { seeds, slots, size })
}
