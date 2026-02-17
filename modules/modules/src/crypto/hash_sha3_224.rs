use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashSha3_224Module {
    base: ModuleBase,
}

impl HashSha3_224Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_sha3_224",
            "Compute or verify SHA3-224 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("sha3-224")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashSha3_224Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashSha3_224Module {
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
        let hash = sha3_224::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("sha3-224: {}", hash)));
        }
        let expected = normalize_expected_hex(&expected, 56).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "sha3-224 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashSha3_224Factory;

impl ModuleFactory for HashSha3_224Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_sha3_224",
                "Compute or verify SHA3-224 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("sha3-224")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashSha3_224Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_224_module_compute() {
        let mut module = HashSha3_224Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result
            .message
            .contains("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"));
    }

    #[test]
    fn sha3_224_module_verify() {
        let mut module = HashSha3_224Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        module
            .options_mut()
            .set("HASH", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module
            .options_mut()
            .set("HASH", "00000000000000000000000000000000000000000000000000000000")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
