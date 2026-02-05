use crate::base::ModuleFactory;
use crate::metadata::ModuleMetadata;
use phf::PhfMap;

#[derive(Debug)]
pub enum RegistryError {
    Duplicate(String),
    Frozen,
    Build(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::Duplicate(name) => write!(f, "duplicate module name: {name}"),
            RegistryError::Frozen => write!(f, "registry is frozen"),
            RegistryError::Build(msg) => write!(f, "registry build error: {msg}"),
        }
    }
}

impl std::error::Error for RegistryError {}

pub struct ModuleRegistry {
    factories: Vec<Box<dyn ModuleFactory>>,
    index: Option<PhfMap<usize>>,
    frozen: bool,
}

impl ModuleRegistry {
    pub fn new() -> Result<Self, RegistryError> {
        Ok(ModuleRegistry {
            factories: Vec::new(),
            index: None,
            frozen: false,
        })
    }

    pub fn register(&mut self, factory: Box<dyn ModuleFactory>) -> Result<(), RegistryError> {
        if self.frozen {
            return Err(RegistryError::Frozen);
        }
        let name = factory.metadata().name.to_lowercase();
        if self
            .factories
            .iter()
            .any(|f| f.metadata().name.eq_ignore_ascii_case(&name))
        {
            return Err(RegistryError::Duplicate(name));
        }
        self.factories.push(factory);
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<(), RegistryError> {
        if self.frozen {
            return Ok(());
        }
        let mut entries = Vec::with_capacity(self.factories.len());
        for (idx, factory) in self.factories.iter().enumerate() {
            entries.push((factory.metadata().name.to_lowercase(), idx));
        }
        if !entries.is_empty() {
            let map = PhfMap::build(entries).map_err(RegistryError::Build)?;
            self.index = Some(map);
        }
        self.frozen = true;
        Ok(())
    }

    pub fn list(&self) -> Vec<ModuleMetadata> {
        self.factories
            .iter()
            .map(|f| f.metadata().clone())
            .collect()
    }

    pub fn get_factory(&self, name: &str) -> Option<&Box<dyn ModuleFactory>> {
        if let Some(map) = &self.index {
            let idx = map.get(&name.to_lowercase())?;
            return self.factories.get(*idx);
        }
        self.factories
            .iter()
            .find(|f| f.metadata().name.eq_ignore_ascii_case(name))
    }
}
