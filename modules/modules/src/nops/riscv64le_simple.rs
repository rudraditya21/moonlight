use std::sync::OnceLock;

use crate::base::{Module, ModuleFactory};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};

use super::util::{generate_sled_from_u32, Endian, NopModule};

const NOPS: [u32; 25] = [
    0x400282b3, // sub t0, t0, 0
    0x40030333, // sub t1, t1, 0
    0x400383b3, // sub t2, t2, 0
    0x400e0e33, // sub t3, t3, 0
    0x400e8eb3, // sub t4, t4, 0
    0x400f0f33, // sub t5, t5, 0
    0x400f8fb3, // sub t6, t6, 0
    0x01102013, // slti x0, x0, 0x11
    0x7ff02013, // slti x0, x0, 0x7ff
    0x01103013, // sltiu x0, x0, 0x11
    0x7ff03013, // sltiu x0, x0, 0x7ff
    0x01105013, // srli x0, x0, 0x11
    0x03f05013, // srli x0, x0, 0x3f
    0x01101013, // slli x0, x0, 0x11
    0x03f01013, // slli x0, x0, 0x3f
    0x41105013, // srai x0, x0, 0x11
    0x43f05013, // srai x0, x0, 0x3f
    0x01106013, // ori x0, x0, 0x11
    0x7ff06013, // ori x0, x0, 0x7ff
    0x01104013, // xori x0, x0, 0x11
    0x7ff04013, // xori x0, x0, 0x7ff
    0x01107013, // andi x0, x0, 0x11
    0x7ff07013, // andi x0, x0, 0x7ff
    0x10101037, // lui x0, 0x10101
    0xfffff037, // lui x0, 0xfffff
];

fn generate(length: usize, badchars: &[u8]) -> Result<Vec<u8>, crate::base::ModuleError> {
    generate_sled_from_u32(length, badchars, &NOPS, Endian::Little)
}

pub struct NopRiscv64leSimpleFactory;

impl ModuleFactory for NopRiscv64leSimpleFactory {
    fn metadata(&self) -> &ModuleMetadata {
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "nops/riscv64le/simple",
                "Simple RISC-V 64-bit NOP generator",
                ModuleCategory::Nop,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("nop")
            .with_tag("riscv64le")
            .with_platform("riscv64le")
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
    fn riscv64_simple_length() {
        let factory = NopRiscv64leSimpleFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 20);
        module.options_mut().set("LENGTH", "20").expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert_eq!(bytes.len(), 20);
    }

    #[test]
    fn riscv64_simple_badchars() {
        let factory = NopRiscv64leSimpleFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 8);
        module.options_mut().set("LENGTH", "8").expect("set");
        module.options_mut().set("BADCHARS", "\\x13").expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert!(!bytes.contains(&0x13));
    }
}
