mod base;
mod cache;
mod catalog;
mod hash;
mod json;
mod manifest;
mod metadata;
mod options;
mod registry;

pub use base::{Module, ModuleBase, ModuleContext, ModuleError, ModuleFactory, ModuleResult};
pub use catalog::{ModuleCatalog, ModuleRecord, SearchQuery};
pub use metadata::{ModuleCategory, ModuleMetadata, ModuleRank, ModuleReference};
pub use options::{ModuleOption, ModuleOptionKind, ModuleOptionValue, ModuleOptions};
pub use registry::{ModuleEntry, ModuleRegistry, ModuleRegistryBuilder, RegistryError};
