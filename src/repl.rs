use crate::config::Config;
use modules::{
    register_builtin_modules, ModuleCatalog, ModuleRegistry, ModuleRegistryBuilder, RegistryError,
};
use repl::{Repl, ReplError};
use std::path::Path;

pub fn run(config: Config) -> Result<(), ReplError> {
    let registry = build_registry().map_err(|e| ReplError::Registry(e.to_string()))?;
    let catalog =
        match ModuleCatalog::load(Path::new(&config.module_path), Path::new(&config.cache_dir)) {
            Ok(catalog) => {
                if !catalog.validation_errors().is_empty() {
                    eprintln!(
                        "Module catalog validation rejected {} manifest(s):",
                        catalog.validation_errors().len()
                    );
                    for err in catalog.validation_errors() {
                        eprintln!("  - {err}");
                    }
                }
                Some(catalog)
            }
            Err(err) => {
                eprintln!("Module catalog load error: {err}");
                None
            }
        };
    let mut repl = Repl::new(config.prompt, registry, catalog);
    repl.run()
}

fn build_registry() -> Result<ModuleRegistry, RegistryError> {
    let mut builder = ModuleRegistryBuilder::new();
    register_builtin_modules(&mut builder);
    builder.build()
}
