use std::sync::OnceLock;

use crate::base::{Module, ModuleFactory};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank};

use super::util::{generate_fill, NopModule};

fn generate(length: usize, badchars: &[u8]) -> Result<Vec<u8>, crate::base::ModuleError> {
    generate_fill(length, badchars, b' ')
}

pub struct NopCmdGenericFactory;

impl ModuleFactory for NopCmdGenericFactory {
    fn metadata(&self) -> &ModuleMetadata {
        static META: OnceLock<ModuleMetadata> = OnceLock::new();
        META.get_or_init(|| {
            ModuleMetadata::new(
                "nops/cmd/generic",
                "Generic command NOP generator",
                ModuleCategory::Nop,
                "moonlight",
            )
            .with_rank(ModuleRank::Normal)
            .with_tag("nop")
            .with_tag("cmd")
            .with_platform("cmd")
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
    fn cmd_generic_length() {
        let factory = NopCmdGenericFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 12);
        module.options_mut().set("LENGTH", "12").expect("set");
        let bytes = module.generate_bytes().expect("generate");
        assert_eq!(bytes.len(), 12);
        assert!(bytes.iter().all(|b| *b == b' '));
    }

    #[test]
    fn cmd_generic_badchars_blocked() {
        let factory = NopCmdGenericFactory;
        let mut module = NopModule::new(factory.metadata().clone(), generate, 8);
        module.options_mut().set("LENGTH", "8").expect("set");
        module
            .options_mut()
            .set("BADCHARS", "\\x20")
            .expect("set");
        let result = module.generate_bytes();
        assert!(result.is_err());
    }
}
