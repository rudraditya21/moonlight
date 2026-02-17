use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashBlake2b256Module {
    base: ModuleBase,
}

impl HashBlake2b256Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_blake2b_256",
            "Compute or verify BLAKE2b-256 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("blake2b-256")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashBlake2b256Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashBlake2b256Module {
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
        let hash = blake2b_256::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("blake2b-256: {}", hash)));
        }
        let expected = normalize_expected_hex(&expected, 64).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "blake2b-256 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashBlake2b256Factory;

impl ModuleFactory for HashBlake2b256Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_blake2b_256",
                "Compute or verify BLAKE2b-256 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("blake2b-256")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashBlake2b256Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_256_module_compute() {
        let mut module = HashBlake2b256Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("bddd813c63423972"));
    }

    #[test]
    fn blake2b_256_module_verify() {
        let mut module = HashBlake2b256Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        module
            .options_mut()
            .set(
                "HASH",
                "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
            )
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module
            .options_mut()
            .set(
                "HASH",
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
