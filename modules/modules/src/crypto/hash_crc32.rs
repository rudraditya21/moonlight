use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashCrc32Module {
    base: ModuleBase,
}

impl HashCrc32Module {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_crc32",
            "Compute or verify CRC32 checksums",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("crc32")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashCrc32Module {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashCrc32Module {
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

        let hash = crc32::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("crc32: {}", hash)));
        }

        let expected = normalize_expected_hex(&expected, 8).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "crc32 match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashCrc32Factory;

impl ModuleFactory for HashCrc32Factory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_crc32",
                "Compute or verify CRC32 checksums",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("crc32")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashCrc32Module::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_module_compute() {
        let mut module = HashCrc32Module::new();
        module.options_mut().set("INPUT", "123456789").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("cbf43926"));
    }

    #[test]
    fn crc32_module_verify() {
        let mut module = HashCrc32Module::new();
        module.options_mut().set("INPUT", "123456789").expect("set");
        module.options_mut().set("HASH", "cbf43926").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module.options_mut().set("HASH", "00000000").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
