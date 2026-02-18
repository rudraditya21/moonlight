use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashMd6_256Module {
    base: ModuleBase,
}

impl HashMd6_256Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_md6_256",
            "Compute or verify MD6-256 hashes",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("md6-256")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashMd6_256Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashMd6_256Module {
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

        let hash = md6_256::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("md6-256: {}", hash)));
        }

        let expected = normalize_expected_hex(&expected, 64).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "md6-256 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashMd6_256Factory;

impl ModuleFactory for HashMd6_256Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_md6_256",
                "Compute or verify MD6-256 hashes",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("md6-256")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashMd6_256Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md6_256_module_compute() {
        let mut module = HashMd6_256Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result
            .message
            .contains("97cb9399b5586321ae724d1026383d25d03c249756413951aa8575c3e3450074"));
    }

    #[test]
    fn md6_256_module_verify() {
        let mut module = HashMd6_256Module::new();
        module.options_mut().set("INPUT", "abc").expect("set");
        module
            .options_mut()
            .set(
                "HASH",
                "97cb9399b5586321ae724d1026383d25d03c249756413951aa8575c3e3450074",
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
