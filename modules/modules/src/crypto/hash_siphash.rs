use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::{ModuleOption, ModuleOptionKind, ModuleOptions};

use super::util::{decode_hex, normalize_expected_hex};

pub struct HashSipHashModule {
    base: ModuleBase,
}

impl HashSipHashModule {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_siphash",
            "Compute or verify SipHash-2-4 digests",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("siphash")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_siphash_options();
        HashSipHashModule {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashSipHashModule {
    fn metadata(&self) -> &ModuleMetadata {
        self.base.metadata()
    }

    fn options(&self) -> &ModuleOptions {
        self.base.options()
    }

    fn options_mut(&mut self) -> &mut ModuleOptions {
        self.base.options_mut()
    }

    fn run(&mut self, _ctx: &ModuleContext) -> Result<ModuleResult, ModuleError> {
        self.base.validate()?;
        let input = self
            .options()
            .get("INPUT")
            .map(|o| o.value_as_string())
            .unwrap_or_default();
        let key = self
            .options()
            .get("KEY")
            .map(|o| o.value_as_string())
            .unwrap_or_default();
        let expected = self
            .options()
            .get("HASH")
            .map(|o| o.value_as_string())
            .unwrap_or_default();

        let key = parse_key(&key).map_err(ModuleError::Execution)?;
        let hash = siphash::digest_hex(input.as_bytes(), key);
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("siphash: {}", hash)));
        }

        let expected = normalize_expected_hex(&expected, 16).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "siphash match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashSipHashFactory;

impl ModuleFactory for HashSipHashFactory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_siphash",
                "Compute or verify SipHash-2-4 digests",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("siphash")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashSipHashModule::new())
    }
}

fn build_siphash_options() -> ModuleOptions {
    ModuleOptions::new(vec![
        ModuleOption::new(
            "INPUT",
            "Input string to hash",
            ModuleOptionKind::String,
            true,
        ),
        ModuleOption::new(
            "KEY",
            "128-bit key as 32 hex chars (optionally 0x-prefixed)",
            ModuleOptionKind::String,
            true,
        ),
        ModuleOption::new(
            "HASH",
            "Optional expected hash (16 hex chars)",
            ModuleOptionKind::String,
            false,
        ),
    ])
}

fn parse_key(input: &str) -> Result<[u8; 16], String> {
    let mut key = input.trim();
    if let Some(rest) = key.strip_prefix("0x").or_else(|| key.strip_prefix("0X")) {
        key = rest;
    }

    let raw = decode_hex(key)?;
    if raw.len() != 16 {
        return Err("siphash key must be exactly 16 bytes (32 hex chars)".to_string());
    }

    let mut out = [0u8; 16];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siphash_module_compute() {
        let mut module = HashSipHashModule::new();
        module.options_mut().set("INPUT", "").expect("set");
        module
            .options_mut()
            .set("KEY", "000102030405060708090a0b0c0d0e0f")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("726fdb47dd0e0e31"));
    }

    #[test]
    fn siphash_module_verify() {
        let mut module = HashSipHashModule::new();
        module.options_mut().set("INPUT", "").expect("set");
        module
            .options_mut()
            .set("KEY", "000102030405060708090a0b0c0d0e0f")
            .expect("set");
        module
            .options_mut()
            .set("HASH", "726fdb47dd0e0e31")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
    }

    #[test]
    fn siphash_module_rejects_bad_key() {
        let mut module = HashSipHashModule::new();
        module.options_mut().set("INPUT", "").expect("set");
        module.options_mut().set("KEY", "beef").expect("set");
        let err = module
            .run(&ModuleContext { session_id: 1 })
            .expect_err("run");
        assert!(err.to_string().contains("16 bytes"));
    }
}
