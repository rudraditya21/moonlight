use crate::registry::ModuleRegistryBuilder;

use crate::crypto::{
    HashMd5Factory, HashSha1Factory, HashSha256Factory, HashSha384Factory, HashSha512Factory,
};

pub fn register_builtin_modules(builder: &mut ModuleRegistryBuilder) {
    let _ = builder.register(Box::new(HashMd5Factory));
    let _ = builder.register(Box::new(HashSha1Factory));
    let _ = builder.register(Box::new(HashSha256Factory));
    let _ = builder.register(Box::new(HashSha384Factory));
    let _ = builder.register(Box::new(HashSha512Factory));
}
