mod base;
mod metadata;
mod options;
mod registry;

pub use base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
pub use metadata::{ModuleCategory, ModuleMetadata, ModuleReference};
pub use options::{ModuleOption, ModuleOptionKind, ModuleOptionValue, ModuleOptions};
pub use registry::{ModuleEntry, ModuleRegistry, ModuleRegistryBuilder, RegistryError};
