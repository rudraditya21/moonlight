use crate::registry::ModuleRegistryBuilder;

use crate::crypto::{
    HashBlake2b256Factory, HashBlake2b512Factory, HashBlake2s256Factory, HashCrc32Factory,
    HashCrc32cFactory, HashCrc64JonesFactory, HashHalfMd5Factory, HashKeccak224Factory,
    HashKeccak256Factory, HashKeccak384Factory, HashKeccak512Factory, HashMd4Factory,
    HashMd5Factory, HashMd6_256Factory, HashRecipeFactory, HashRipemd160Factory,
    HashRipemd320Factory, HashSha1Factory, HashSha224Factory, HashSha256Factory, HashSha384Factory,
    HashSha3_224Factory, HashSha3_256Factory, HashSha3_384Factory, HashSha3_512Factory,
    HashSha512Factory, HashSipHashFactory,
};
use crate::exploit::linux::telnet::GnuInetutilsTelnetdAuthBypassFactory;
use crate::nops::{
    NopAarch64SimpleFactory, NopCmdGenericFactory, NopLoongarch64SimpleFactory,
    NopMipsbeBetterFactory, NopRiscv32leSimpleFactory, NopRiscv64leSimpleFactory,
};

pub fn register_builtin_modules(builder: &mut ModuleRegistryBuilder) {
    let _ = builder.register(Box::new(HashMd4Factory));
    let _ = builder.register(Box::new(HashMd5Factory));
    let _ = builder.register(Box::new(HashSipHashFactory));
    let _ = builder.register(Box::new(HashCrc32Factory));
    let _ = builder.register(Box::new(HashCrc32cFactory));
    let _ = builder.register(Box::new(HashCrc64JonesFactory));
    let _ = builder.register(Box::new(HashRecipeFactory));
    let _ = builder.register(Box::new(HashHalfMd5Factory));
    let _ = builder.register(Box::new(HashMd6_256Factory));
    let _ = builder.register(Box::new(HashBlake2b256Factory));
    let _ = builder.register(Box::new(HashBlake2b512Factory));
    let _ = builder.register(Box::new(HashBlake2s256Factory));
    let _ = builder.register(Box::new(HashKeccak224Factory));
    let _ = builder.register(Box::new(HashKeccak256Factory));
    let _ = builder.register(Box::new(HashKeccak384Factory));
    let _ = builder.register(Box::new(HashKeccak512Factory));
    let _ = builder.register(Box::new(HashSha3_224Factory));
    let _ = builder.register(Box::new(HashSha3_256Factory));
    let _ = builder.register(Box::new(HashSha3_384Factory));
    let _ = builder.register(Box::new(HashSha3_512Factory));
    let _ = builder.register(Box::new(HashRipemd160Factory));
    let _ = builder.register(Box::new(HashRipemd320Factory));
    let _ = builder.register(Box::new(HashSha224Factory));
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
    let _ = builder.register(Box::new(GnuInetutilsTelnetdAuthBypassFactory));
}
