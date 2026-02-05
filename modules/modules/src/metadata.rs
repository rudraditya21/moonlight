#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleCategory {
    Core,
    Exploit,
    Payload,
    Auxiliary,
    Post,
    Evasion,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleReference {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleMetadata {
    pub name: String,
    pub description: String,
    pub category: ModuleCategory,
    pub author: String,
    pub references: Vec<ModuleReference>,
}

impl ModuleMetadata {
    pub fn new(name: &str, description: &str, category: ModuleCategory, author: &str) -> Self {
        ModuleMetadata {
            name: name.to_string(),
            description: description.to_string(),
            category,
            author: author.to_string(),
            references: Vec::new(),
        }
    }

    pub fn with_reference(mut self, kind: &str, value: &str) -> Self {
        self.references.push(ModuleReference {
            kind: kind.to_string(),
            value: value.to_string(),
        });
        self
    }
}
