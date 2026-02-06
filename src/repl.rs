use crate::config::Config;
use modules::{ModuleCatalog, ModuleRegistry, ModuleRegistryBuilder, RegistryError};
use repl::{Repl, ReplError};
use std::path::Path;

pub fn run(config: Config) -> Result<(), ReplError> {
    let registry = build_registry().map_err(|e| ReplError::Registry(e.to_string()))?;
    let catalog =
        match ModuleCatalog::load(Path::new(&config.module_path), Path::new(&config.cache_dir)) {
            Ok(catalog) => Some(catalog),
            Err(err) => {
                eprintln!("Module catalog load error: {err}");
                None
            }
        };
    let mut repl = Repl::new(config.prompt, registry, catalog);
    repl.run()
}

fn build_registry() -> Result<ModuleRegistry, RegistryError> {
    // Empty registry for now; modules will be added as they are implemented.
    ModuleRegistryBuilder::new().build()
}
