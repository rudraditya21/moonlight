use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashMd4Module {
    base: ModuleBase,
}

impl HashMd4Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_md4",
            "Compute or verify MD4 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashMd4Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashMd4Module {
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
        let expected = self
            .options()
            .get("HASH")
            .map(|o| o.value_as_string())
            .unwrap_or_default();
        let hash = md4::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("md4: {}", hash)));
        }
        let expected = normalize_expected_hex(&expected, 32).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "md4 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashMd4Factory;

impl ModuleFactory for HashMd4Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_md4",
                "Compute or verify MD4 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashMd4Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_module_compute() {
        let mut module = HashMd4Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("a448017aaf21d8525fc10ae87aa6729d"));
    }

    #[test]
    fn md4_module_verify() {
        let mut module = HashMd4Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        module
            .options_mut()
            .set("HASH", "a448017aaf21d8525fc10ae87aa6729d")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module
            .options_mut()
            .set("HASH", "00000000000000000000000000000000")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
