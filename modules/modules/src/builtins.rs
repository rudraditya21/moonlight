use crate::registry::ModuleRegistryBuilder;

use crate::crypto::{
    HashMd5Factory, HashSha1Factory, HashSha256Factory, HashSha384Factory, HashSha512Factory,
};
use crate::nops::{
    NopAarch64SimpleFactory, NopCmdGenericFactory, NopLoongarch64SimpleFactory,
    NopMipsbeBetterFactory, NopRiscv32leSimpleFactory, NopRiscv64leSimpleFactory,
};

pub fn register_builtin_modules(builder: &mut ModuleRegistryBuilder) {
    let _ = builder.register(Box::new(HashMd5Factory));
    let _ = builder.register(Box::new(HashSha1Factory));
    let _ = builder.register(Box::new(HashSha256Factory));
    let _ = builder.register(Box::new(HashSha384Factory));
    let _ = builder.register(Box::new(HashSha512Factory));
    let _ = builder.register(Box::new(NopAarch64SimpleFactory));
    let _ = builder.register(Box::new(NopCmdGenericFactory));
    let _ = builder.register(Box::new(NopLoongarch64SimpleFactory));
    let _ = builder.register(Box::new(NopMipsbeBetterFactory));
    let _ = builder.register(Box::new(NopRiscv32leSimpleFactory));
    let _ = builder.register(Box::new(NopRiscv64leSimpleFactory));
}
