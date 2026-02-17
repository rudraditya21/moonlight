use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashKeccak224Module {
    base: ModuleBase,
}

impl HashKeccak224Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_keccak_224",
            "Compute or verify Keccak-224 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("keccak-224")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashKeccak224Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashKeccak224Module {
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
        let hash = keccak_224::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("keccak-224: {}", hash)));
        }
        let expected = normalize_expected_hex(&expected, 56).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "keccak-224 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashKeccak224Factory;

impl ModuleFactory for HashKeccak224Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_keccak_224",
                "Compute or verify Keccak-224 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("keccak-224")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashKeccak224Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_224_module_compute() {
        let mut module = HashKeccak224Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("c30411768506ebe1"));
    }

    #[test]
    fn keccak_224_module_verify() {
        let mut module = HashKeccak224Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        module
            .options_mut()
            .set(
                "HASH",
                "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8",
            )
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module
            .options_mut()
            .set(
                "HASH",
                "00000000000000000000000000000000000000000000000000000000",
            )
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
