use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashKeccak512Module {
    base: ModuleBase,
}

impl HashKeccak512Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_keccak_512",
            "Compute or verify Keccak-512 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("keccak-512")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashKeccak512Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashKeccak512Module {
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
        let hash = keccak_512::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("keccak-512: {}", hash)));
        }
        let expected = normalize_expected_hex(&expected, 128).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "keccak-512 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashKeccak512Factory;

impl ModuleFactory for HashKeccak512Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_keccak_512",
                "Compute or verify Keccak-512 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("keccak-512")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashKeccak512Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_512_module_compute() {
        let mut module = HashKeccak512Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("18587dc2ea106b9a"));
    }

    #[test]
    fn keccak_512_module_verify() {
        let mut module = HashKeccak512Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        module
            .options_mut()
            .set(
                "HASH",
                "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
            )
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module
            .options_mut()
            .set("HASH", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
