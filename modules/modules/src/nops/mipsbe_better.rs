use std::sync::OnceLock;

use crate::base::{Module, ModuleFactory, ModuleError};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};

use super::util::{generate_sled_from_u32, Endian, NopModule};

fn make_or(reg: u32) -> u32 {
    let op = 0x00000025;
    op | (reg << 21) | (reg << 11)
}

fn make_sll(reg: u32) -> u32 {
    let op = 0x00000000;
    op | (reg << 16) | (reg << 11)
}

fn make_sra(reg: u32) -> u32 {
    let op = 0x00000003;
    op | (reg << 16) | (reg << 11)
}

fn make_srl(reg: u32) -> u32 {
    let op = 0x00000002;
    op | (reg << 16) | (reg << 11)
}

fn make_xori(reg: u32) -> u32 {
    let op = 0x38000000;
    op | (reg << 21) | (reg << 16)
}

fn make_ori(reg: u32) -> u32 {
    let op = 0x34000000;
    op | (reg << 21) | (reg << 16)
}

fn pool() -> &'static [u32] {
    static POOL: OnceLock<Vec<u32>> = OnceLock::new();
    POOL.get_or_init(|| {
        let regs = [1u32, 2, 3, 4, 5];
        let mut ops = Vec::new();
        for reg in regs {
            ops.push(make_or(reg));
            ops.push(make_sll(reg));
            ops.push(make_sra(reg));
            ops.push(make_srl(reg));
            ops.push(make_xori(reg));
            ops.push(make_ori(reg));
        }
        ops
    })
}

fn generate(length: usize, badchars: &[u8]) -> Result<Vec<u8>, ModuleError> {
    generate_sled_from_u32(length, badchars, pool(), Endian::Big)
}

pub struct NopMipsbeBetterFactory;

impl ModuleFactory for NopMipsbeBetterFactory {
    fn metadata(&self) -> &ModuleMetadata {
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "nops/mipsbe/better",
                "Mixed MIPS (big endian) NOP generator",
                ModuleCategory::Nop,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("nop")
            .with_tag("mipsbe")
            .with_platform("mipsbe")
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
    fn mipsbe_better_length() {
        let factory = NopMipsbeBetterFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 12);
        module.options_mut().set("LENGTH", "12").expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert_eq!(bytes.len(), 12);
    }

    #[test]
    fn mipsbe_better_badchars() {
        let factory = NopMipsbeBetterFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 8);
        module.options_mut().set("LENGTH", "8").expect("set");
        module
            .options_mut()
            .set("BADCHARS", "\\xff")
            .expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert!(!bytes.contains(&0xff));
    }
}
