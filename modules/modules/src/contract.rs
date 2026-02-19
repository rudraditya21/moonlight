#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModuleRuntime {
    Builtin,
    Dynlib,
}

impl ModuleRuntime {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleRuntime::Builtin => "builtin",
            ModuleRuntime::Dynlib => "dynlib",
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input.to_ascii_lowercase().as_str() {
            "builtin" | "built-in" => Some(ModuleRuntime::Builtin),
            "dynlib" | "dynamic" | "shared" => Some(ModuleRuntime::Dynlib),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ModuleCompatibilityPolicy {
    pub min_manifest_version: u32,
    pub max_manifest_version: u32,
    pub min_module_api_version: u32,
    pub max_module_api_version: u32,
}

impl ModuleCompatibilityPolicy {
    pub fn catalog_default() -> Self {
        Self {
            min_manifest_version: MODULE_MANIFEST_VERSION_V1,
            max_manifest_version: MODULE_MANIFEST_VERSION_V1,
            min_module_api_version: MODULE_API_VERSION_V1,
            max_module_api_version: MODULE_API_VERSION_V1,
        }
    }

    pub fn dynlib_loader_default() -> Self {
        Self {
            min_manifest_version: MODULE_MANIFEST_VERSION_V1,
            max_manifest_version: MODULE_MANIFEST_VERSION_V1,
            min_module_api_version: MODULE_API_VERSION_V1,
            max_module_api_version: MODULE_API_VERSION_V1,
        }
    }

    pub fn supports_manifest_version(&self, version: u32) -> bool {
        (self.min_manifest_version..=self.max_manifest_version).contains(&version)
    }

    pub fn supports_module_api_version(&self, version: u32) -> bool {
        (self.min_module_api_version..=self.max_module_api_version).contains(&version)
    }
}

pub const MODULE_MANIFEST_VERSION_V1: u32 = 1;
pub const MODULE_API_VERSION_V1: u32 = 1;
