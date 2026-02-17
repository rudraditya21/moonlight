use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashSha384Module {
    base: ModuleBase,
}

impl HashSha384Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_sha2_384",
            "Compute or verify SHA2-384 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("sha2-384")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashSha384Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashSha384Module {
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
        let hash = sha384::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("sha2-384: {}", hash)));
        }
        let expected = normalize_expected_hex(&expected, 96).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "sha2-384 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashSha384Factory;

impl ModuleFactory for HashSha384Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_sha2_384",
                "Compute or verify SHA2-384 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("sha2-384")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashSha384Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha384_module_compute() {
        let mut module = HashSha384Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result
            .message
            .contains("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"));
    }
}
