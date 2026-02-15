use std::sync::OnceLock;

use crate::base::{Module, ModuleFactory};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};

use super::util::{generate_sled_from_u32, Endian, NopModule};

const NOPS: [u32; 80] = [
    0x03c0018c, 0x03c001ad, 0x03c001ce, 0x03c001ef, 0x03c00210, 0x03c00231, 0x03c00252, 0x03c00273,
    0x03c00294, 0x03c002b5, 0x03c002d6, 0x03c002f7, 0x03c00318, 0x03c00339, 0x03c0035a, 0x03c0037b,
    0x03c0039c, 0x03c003bd, 0x03c003de, 0x03c003ff, 0x0380018c, 0x038001ad, 0x038001ce, 0x038001ef,
    0x03800210, 0x03800231, 0x03800252, 0x03800273, 0x03800294, 0x038002b5, 0x038002d6, 0x038002f7,
    0x03800318, 0x03800339, 0x0380035a, 0x0380037b, 0x0380039c, 0x038003bd, 0x038003de, 0x038003ff,
    0x02c0018c, 0x02c001ad, 0x02c001ce, 0x02c001ef, 0x02c00210, 0x02c00231, 0x02c00252, 0x02c00273,
    0x02c00294, 0x02c002b5, 0x02c002d6, 0x02c002f7, 0x02c00318, 0x02c00339, 0x02c0035a, 0x02c0037b,
    0x02c0039c, 0x02c003bd, 0x02c003de, 0x02c003ff, 0x0280018c, 0x028001ad, 0x028001ce, 0x028001ef,
    0x02800210, 0x02800231, 0x02800252, 0x02800273, 0x02800294, 0x028002b5, 0x028002d6, 0x028002f7,
    0x02800318, 0x02800339, 0x0280035a, 0x0280037b, 0x0280039c, 0x028003bd, 0x028003de, 0x028003ff,
];

fn generate(length: usize, badchars: &[u8]) -> Result<Vec<u8>, crate::base::ModuleError> {
    generate_sled_from_u32(length, badchars, &NOPS, Endian::Little)
}

pub struct NopLoongarch64SimpleFactory;

impl ModuleFactory for NopLoongarch64SimpleFactory {
    fn metadata(&self) -> &ModuleMetadata {
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "nops/loongarch64/simple",
                "Simple LoongArch64 NOP generator",
                ModuleCategory::Nop,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("nop")
            .with_tag("loongarch64")
            .with_platform("loongarch64")
        })
    }

    fn create(&self) -> Box<dyn Module> {
        Box::new(NopModule::new(self.metadata().clone(), generate, 32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loongarch64_simple_length() {
        let factory = NopLoongarch64SimpleFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 16);
        module.options_mut().set("LENGTH", "16").expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn loongarch64_simple_badchars() {
        let factory = NopLoongarch64SimpleFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 8);
        module.options_mut().set("LENGTH", "8").expect("set");
        module.options_mut().set("BADCHARS", "\\x8c").expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert!(!bytes.contains(&0x8c));
    }
}
