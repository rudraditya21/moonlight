use crate::base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};
use crate::options::ModuleOptions;

use super::util::{build_hash_options, normalize_expected_hex};

pub struct HashCrc64JonesModule {
    base: ModuleBase,
}

impl HashCrc64JonesModule {
    pub fn new() -> Self {
        let metadata = ModuleMetadata::new(
            "auxiliary/crypto/hash_crc64_jones",
            "Compute or verify CRC64-Jones checksums",
            ModuleCategory::Auxiliary,
            "moonlight",
        )
        .with_rank(ModuleRank::Normal)
        .with_tag("crypto")
        .with_tag("hash")
        .with_tag("crc64-jones")
        .with_platform("cross")
        .with_entrypoint("module.rs");
        let options = build_hash_options();
        HashCrc64JonesModule {
            base: ModuleBase::new(metadata, options),
        }
    }
}

impl Module for HashCrc64JonesModule {
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

        let hash = crc64_jones::digest_hex(input.as_bytes());
        if expected.is_empty() {
            return Ok(ModuleResult::ok(&format!("crc64-jones: {}", hash)));
        }

        let expected = normalize_expected_hex(&expected, 16).map_err(ModuleError::Execution)?;
        let ok = expected == hash;
        Ok(ModuleResult::ok(&format!(
            "crc64-jones match: {}",
            if ok { "true" } else { "false" }
        )))
    }
}

pub struct HashCrc64JonesFactory;

impl ModuleFactory for HashCrc64JonesFactory {
    fn metadata(&self) -> &ModuleMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "auxiliary/crypto/hash_crc64_jones",
                "Compute or verify CRC64-Jones checksums",
                ModuleCategory::Auxiliary,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("crypto")
            .with_tag("hash")
            .with_tag("crc64-jones")
            .with_platform("cross")
            .with_entrypoint("module.rs")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(HashCrc64JonesModule::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc64_jones_module_compute() {
        let mut module = HashCrc64JonesModule::new();
        module.options_mut().set("INPUT", "123456789").expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("e9c6d914c4b8d9ca"));
    }

    #[test]
    fn crc64_jones_module_verify() {
        let mut module = HashCrc64JonesModule::new();
        module.options_mut().set("INPUT", "123456789").expect("set");
        module
            .options_mut()
            .set("HASH", "e9c6d914c4b8d9ca")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("true"));
        module
            .options_mut()
            .set("HASH", "0000000000000000")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(result.message.contains("false"));
    }
}
