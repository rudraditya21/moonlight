#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleCategory {
    Core,
    Exploit,
    Payload,
    Auxiliary,
    Post,
    Evasion,
    Unknown,
}

impl ModuleCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleCategory::Core => "core",
            ModuleCategory::Exploit => "exploit",
            ModuleCategory::Payload => "payload",
            ModuleCategory::Auxiliary => "auxiliary",
            ModuleCategory::Post => "post",
            ModuleCategory::Evasion => "evasion",
            ModuleCategory::Unknown => "unknown",
        }
    }

    pub fn parse(input: &str) -> Self {
        match input.to_ascii_lowercase().as_str() {
            "core" => ModuleCategory::Core,
            "exploit" | "exploits" => ModuleCategory::Exploit,
            "payload" | "payloads" => ModuleCategory::Payload,
            "auxiliary" | "aux" => ModuleCategory::Auxiliary,
            "post" => ModuleCategory::Post,
            "evasion" => ModuleCategory::Evasion,
            _ => ModuleCategory::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModuleRank {
    Manual,
    Low,
    Average,
    Normal,
    Good,
    Great,
    Excellent,
    Unknown,
}

impl ModuleRank {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleRank::Manual => "manual",
            ModuleRank::Low => "low",
            ModuleRank::Average => "average",
            ModuleRank::Normal => "normal",
            ModuleRank::Good => "good",
            ModuleRank::Great => "great",
            ModuleRank::Excellent => "excellent",
            ModuleRank::Unknown => "unknown",
        }
    }

    pub fn parse(input: &str) -> Self {
        match input.to_ascii_lowercase().as_str() {
            "manual" => ModuleRank::Manual,
            "low" => ModuleRank::Low,
            "average" => ModuleRank::Average,
            "normal" => ModuleRank::Normal,
            "good" => ModuleRank::Good,
            "great" => ModuleRank::Great,
            "excellent" => ModuleRank::Excellent,
            _ => ModuleRank::Unknown,
        }
    }
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
    pub rank: ModuleRank,
    pub author: String,
    pub platforms: Vec<String>,
    pub tags: Vec<String>,
    pub entrypoint: Option<String>,
    pub references: Vec<ModuleReference>,
}

impl ModuleMetadata {
    pub fn new(name: &str, description: &str, category: ModuleCategory, author: &str) -> Self {
        ModuleMetadata {
            name: name.to_string(),
            description: description.to_string(),
            category,
            rank: ModuleRank::Unknown,
            author: author.to_string(),
            platforms: Vec::new(),
            tags: Vec::new(),
            entrypoint: None,
            references: Vec::new(),
        }
    }

    pub fn with_rank(mut self, rank: ModuleRank) -> Self {
        self.rank = rank;
        self
    }

    pub fn with_platform(mut self, platform: &str) -> Self {
        self.platforms.push(platform.to_string());
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    pub fn with_entrypoint(mut self, entrypoint: &str) -> Self {
        self.entrypoint = Some(entrypoint.to_string());
        self
    }

    pub fn with_reference(mut self, kind: &str, value: &str) -> Self {
        self.references.push(ModuleReference {
            kind: kind.to_string(),
            value: value.to_string(),
        });
        self
    }
}
