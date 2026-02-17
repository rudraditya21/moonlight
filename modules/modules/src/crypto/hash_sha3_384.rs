use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashSha3_384Module {
    base: ModuleBase,
}

impl HashSha3_384Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_sha3_384",
            "Compute or verify SHA3-384 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("sha3-384")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashSha3_384Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashSha3_384Module {
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
        let hash = sha3_384::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("sha3-384: {}", hash)));
        }
        let expected = normalize_expected_hex(&expected, 96).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "sha3-384 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashSha3_384Factory;

impl ModuleFactory for HashSha3_384Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_sha3_384",
                "Compute or verify SHA3-384 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("sha3-384")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashSha3_384Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_384_module_compute() {
        let mut module = HashSha3_384Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result
            .message
            .contains("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"));
    }

    #[test]
    fn sha3_384_module_verify() {
        let mut module = HashSha3_384Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        module
            .options_mut()
            .set("HASH", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module
            .options_mut()
            .set("HASH", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
