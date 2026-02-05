use crate::config::Config;
use modules::{ModuleRegistry, RegistryError};
use repl::{Repl, ReplError};

pub fn run(config: Config) -> Result<(), ReplError> {
    let registry = build_registry().map_err(|e| ReplError::Registry(e.to_string()))?;
    let mut repl = Repl::new(config.prompt, registry);
    repl.run()
}

fn build_registry() -> Result<ModuleRegistry, RegistryError> {
    // Empty registry for now; modules will be added as they are implemented.
    ModuleRegistry::new()
}
