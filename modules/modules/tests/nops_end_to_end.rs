use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use modules::{
    register_builtin_modules, Module, ModuleCatalog, ModuleCategory, ModuleContext,
    ModuleRegistryBuilder, SearchQuery,
};

fn build_registry() -> modules::ModuleRegistry {
    let mut builder = ModuleRegistryBuilder::new();
    register_builtin_modules(&mut builder);
    builder.build().expect("build registry")
}

fn nop_names() -> Vec<&'static str> {
    vec![
        "nops/mipsbe/better",
        "nops/aarch64/simple",
        "nops/cmd/generic",
        "nops/riscv32le/simple",
        "nops/riscv64le/simple",
        "nops/loongarch64/simple",
    ]
}

fn temp_cache_dir() -> PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    dir.push(format!("moonlight-nops-cache-{nanos}"));
    dir
}

fn parse_hex_bytes(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                out.push((hi << 4) | lo);
                i += 4;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[test]
fn nop_modules_run_default() {
    let registry = build_registry();
    for name in nop_names() {
        let mut module = registry.create(name).expect("module");
        module.options_mut().set("LENGTH", "16").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.success, "{name} should succeed");
        assert!(result.message.contains("nop bytes"), "{name} message");
        let bytes = parse_hex_bytes(&result.message);
        assert_eq!(bytes.len(), 16, "{name} length");
    }
}

#[test]
fn nop_length_validation() {
    let registry = build_registry();
    for name in nop_names() {
        let mut module = registry.create(name).expect("module");
        let len = if name == "nops/cmd/generic" { "3" } else { "3" };
        module.options_mut().set("LENGTH", len).expect("set");
        let result = module.run(&ModuleContext { session_id: 1 });
        if name == "nops/cmd/generic" {
            assert!(result.is_ok(), "cmd/generic should accept any length");
        } else {
            assert!(result.is_err(), "{name} should reject non-multiple length");
        }
    }
}

#[test]
fn nop_badchars_filtering() {
    let registry = build_registry();
    for name in nop_names() {
        let mut module = registry.create(name).expect("module");
        module.options_mut().set("LENGTH", "16").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        let bytes = parse_hex_bytes(&result.message);
        assert!(!bytes.is_empty(), "{name} output bytes");
        let pick = bytes[0];
        let bad = format!("{:02x}", pick);
        let mut module = registry.create(name).expect("module");
        module.options_mut().set("LENGTH", "16").expect("set");
        module.options_mut().set("BADCHARS", &bad).expect("set");
        match module.run(&ModuleContext { session_id: 1 }) {
            Ok(res) => {
                let filtered = parse_hex_bytes(&res.message);
                assert!(!filtered.contains(&pick), "{name} filtered badchar");
            }
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("no NOPs available") || msg.contains("fill byte is excluded"),
                    "{name} unexpected error: {msg}"
                );
            }
        }
    }
}

#[test]
fn nop_catalog_indexed() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../registry")
        .canonicalize()
        .expect("registry path");
    let cache = temp_cache_dir();
    fs::create_dir_all(&cache).expect("cache dir");
    let catalog = ModuleCatalog::load(&root, &cache).expect("load catalog");
    for name in nop_names() {
        let record = catalog.get_by_name(name);
        assert!(record.is_some(), "catalog missing {name}");
    }
    let mut query = SearchQuery::new();
    query.category = Some(ModuleCategory::Nop);
    let results = catalog.search(&query);
    assert!(results.len() >= 6, "expected nops in catalog");
}
