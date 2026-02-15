use std::sync::OnceLock;

use crate::base::{Module, ModuleFactory};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};

use super::util::{generate_sled_from_u32, Endian, NopModule};

const NOPS: [u32; 5] = [
    0xd503201f, // nop
    0xaa0103e1, // mov x1, x1
    0xaa0203e2, // mov x2, x2
    0x2a0303e3, // mov w3, w3
    0x2a0403e4, // mov w4, w4
];

fn generate(length: usize, badchars: &[u8]) -> Result<Vec<u8>, crate::base::ModuleError> {
    generate_sled_from_u32(length, badchars, &NOPS, Endian::Little)
}

pub struct NopAarch64SimpleFactory;

impl ModuleFactory for NopAarch64SimpleFactory {
    fn metadata(&self) -> &ModuleMetadata {
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "nops/aarch64/simple",
                "Simple AArch64 NOP generator",
                ModuleCategory::Nop,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("nop")
            .with_tag("aarch64")
            .with_platform("aarch64")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(NopModule::new(self.metadata().clone(), generate, 32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::ModuleContext;

    #[test]
    fn aarch64_simple_length() {
        let factory = NopAarch64SimpleFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 16);
        module.options_mut().set("LENGTH", "16").expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn aarch64_simple_badchars() {
        let factory = NopAarch64SimpleFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 16);
        module.options_mut().set("LENGTH", "16").expect("set");
        module
            .options_mut()
            .set("BADCHARS", "\\x1f")
            .expect("set");
        let result = module.run(&ModuleContext { session_id: 1 }).expect("run");
        assert!(!result.message.contains("\\x1f"));
    }
}
