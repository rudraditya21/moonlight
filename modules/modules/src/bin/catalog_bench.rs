use std::time::Instant;

use modules::{ModuleCatalog, SearchQuery};

fn main() {
    let total = env_usize("MOONLIGHT_PERF_MODULES", 10_000);
    let index_cold_ms_target = env_u128("MOONLIGHT_PERF_INDEX_MS_COLD", 1200);
    let index_warm_ms_target = env_u128("MOONLIGHT_PERF_INDEX_MS_WARM", 600);
    let search_ms_target = env_u128("MOONLIGHT_PERF_SEARCH_MS", 30);

    let root = std::env::temp_dir().join(format!("moonlight_perf_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create root");

    for i in 0..total {
        let dir = root.join(format!("auxiliary/crypto/mod_{i}"));
        std::fs::create_dir_all(&dir).expect("create module dir");
        let tag = format!("tag{}", i % 100);
        let content = format!(
            "{{\n  \"name\": \"auxiliary/crypto/mod_{i}\",\n  \"description\": \"Module {i}\",\n  \"category\": \"auxiliary\",\n  \"rank\": \"normal\",\n  \"author\": \"bench\",\n  \"platforms\": [\"cross\"],\n  \"tags\": [\"crypto\", \"{tag}\"],\n  \"entrypoint\": \"module.rs\"\n}}"
        );
        std::fs::write(dir.join("module.json"), content).expect("write manifest");
    }

    let cache_dir = root.join(".cache");
    let _ = std::fs::remove_dir_all(&cache_dir);
    let start = Instant::now();
    let catalog_cold = ModuleCatalog::load(&root, &cache_dir).expect("load catalog");
    let index_cold_ms = start.elapsed().as_millis();

    if !catalog_cold.has_name_index() {
        panic!("name index missing (lookup not O(1))");
    }

    let mut warnings = Vec::new();
    if index_cold_ms > index_cold_ms_target {
        warnings.push(format!(
            "index build too slow (cold): {}ms (target {}ms)",
            index_cold_ms, index_cold_ms_target
        ));
    }

    let start = Instant::now();
    let catalog_warm = ModuleCatalog::load(&root, &cache_dir).expect("load catalog warm");
    let index_warm_ms = start.elapsed().as_millis();

    if index_warm_ms > index_warm_ms_target {
        warnings.push(format!(
            "index build too slow (warm): {}ms (target {}ms)",
            index_warm_ms, index_warm_ms_target
        ));
    }

    let mut query = SearchQuery::new();
    query.tags.push("tag42".to_string());
    query.limit = Some(50);
    let start = Instant::now();
    let results = catalog_warm.search(&query);
    let search_ms = start.elapsed().as_millis();

    if results.is_empty() {
        panic!("search returned no results");
    }

    if search_ms > search_ms_target {
        warnings.push(format!(
            "search too slow: {}ms (target {}ms)",
            search_ms, search_ms_target
        ));
    }

    let _ = std::fs::remove_dir_all(&root);
    if warnings.is_empty() {
        println!(
            "OK: index cold {}ms (target {}ms), warm {}ms (target {}ms), search {}ms (target {}ms)",
            index_cold_ms,
            index_cold_ms_target,
            index_warm_ms,
            index_warm_ms_target,
            search_ms,
            search_ms_target
        );
    } else {
        println!(
            "WARN: index cold {}ms (target {}ms), warm {}ms (target {}ms), search {}ms (target {}ms)",
            index_cold_ms,
            index_cold_ms_target,
            index_warm_ms,
            index_warm_ms_target,
            search_ms,
            search_ms_target
        );
        for warning in warnings {
            println!("WARN: {}", warning);
        }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u128(key: &str, default: u128) -> u128 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(default)
}
