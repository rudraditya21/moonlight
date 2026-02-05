use std::collections::HashSet;

use crate::base::{Module, ModuleFactory};
use crate::metadata::ModuleMetadata;
use phf::PhfMap;

#[derive(Debug)]
pub enum RegistryError {
    Duplicate(String),
    Build(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::Duplicate(name) => write!(f, "duplicate module name: {name}"),
            RegistryError::Build(msg) => write!(f, "registry build error: {msg}"),
        }
    }
}

impl std::error::Error for RegistryError {}

pub struct ModuleEntry {
    key: String,
    metadata: ModuleMetadata,
    factory: Box<dyn ModuleFactory>,
}

impl ModuleEntry {
    pub fn metadata(&self) -> &ModuleMetadata {
        &self.metadata
    }

    pub fn create(&self) -> Box<dyn Module> {
        self.factory.create()
    }
}

pub struct ModuleRegistryBuilder {
    entries: Vec<ModuleEntry>,
    names: HashSet<String>,
}

impl ModuleRegistryBuilder {
    pub fn new() -> Self {
        ModuleRegistryBuilder {
            entries: Vec::new(),
            names: HashSet::new(),
        }
    }

    pub fn register(&mut self, factory: Box<dyn ModuleFactory>) -> Result<(), RegistryError> {
        let key = factory.metadata().name.to_lowercase();
        if !self.names.insert(key.clone()) {
            return Err(RegistryError::Duplicate(key));
        }
        let metadata = factory.metadata().clone();
        self.entries.push(ModuleEntry {
            key,
            metadata,
            factory,
        });
        Ok(())
    }

    pub fn build(self) -> Result<ModuleRegistry, RegistryError> {
        let mut index_entries = Vec::with_capacity(self.entries.len());
        for (idx, entry) in self.entries.iter().enumerate() {
            index_entries.push((entry.key.clone(), idx));
        }
        let index = if index_entries.is_empty() {
            None
        } else {
            PhfMap::build(index_entries)
                .map(Some)
                .map_err(RegistryError::Build)?
        };
        Ok(ModuleRegistry {
            entries: self.entries,
            index,
        })
    }
}

pub struct ModuleRegistry {
    entries: Vec<ModuleEntry>,
    index: Option<PhfMap<usize>>,
}

impl ModuleRegistry {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModuleEntry> {
        self.entries.iter()
    }

    pub fn iter_metadata(&self) -> impl Iterator<Item = &ModuleMetadata> {
        self.entries.iter().map(|entry| &entry.metadata)
    }

    pub fn get_entry(&self, name: &str) -> Option<&ModuleEntry> {
        if let Some(index) = &self.index {
            if let Some(idx) = index.get(&name.to_lowercase()) {
                return self.entries.get(*idx);
            }
        }
        self.entries
            .iter()
            .find(|entry| entry.metadata.name.eq_ignore_ascii_case(name))
    }

    pub fn get_factory(&self, name: &str) -> Option<&Box<dyn ModuleFactory>> {
        self.get_entry(name).map(|entry| &entry.factory)
    }

    pub fn create(&self, name: &str) -> Option<Box<dyn Module>> {
        self.get_entry(name).map(|entry| entry.create())
    }
}
