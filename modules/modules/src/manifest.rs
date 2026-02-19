use crate::json::{parse_json, JsonValue};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank, ModuleReference};
use crate::{ModuleCompatibilityPolicy, ModuleRuntime};

#[derive(Debug, Clone)]
pub struct ModuleManifest {
    pub manifest_version: u32,
    pub module_api_version: u32,
    pub runtime: ModuleRuntime,
    pub metadata: ModuleMetadata,
}

impl ModuleManifest {
    pub fn parse_str(input: &str) -> Result<Self, String> {
        let value = parse_json(input).map_err(|e| e.to_string())?;
        let obj = match value {
            JsonValue::Object(map) => map,
            _ => return Err("manifest must be a JSON object".to_string()),
        };
        validate_allowed_keys(&obj)?;
        let manifest_version = get_u32(&obj, "manifest_version")?;
        let module_api_version = get_u32(&obj, "module_api_version")?;
        let runtime = get_runtime(&obj, "runtime")?;
        let name = get_string(&obj, "name")?;
        let description = get_string(&obj, "description")?;
        let category = get_string(&obj, "category")?;
        let author = get_string(&obj, "author")?;
        let rank = get_string(&obj, "rank")?;
        let platforms = get_string_array(&obj, "platforms")?;
        let tags = get_string_array(&obj, "tags")?;
        let entrypoint = get_optional_string(&obj, "entrypoint");
        let references = get_references(&obj)?;

        let mut metadata = ModuleMetadata::new(
            &name,
            &description,
            ModuleCategory::parse(&category),
            &author,
        )
        .with_rank(ModuleRank::parse(&rank));
        for platform in platforms {
            metadata = metadata.with_platform(&platform);
        }
        for tag in tags {
            metadata = metadata.with_tag(&tag);
        }
        if let Some(entrypoint) = entrypoint {
            metadata = metadata.with_entrypoint(&entrypoint);
        }
        for reference in references {
            metadata = metadata.with_reference(&reference.kind, &reference.value);
        }

        let manifest = ModuleManifest {
            manifest_version,
            module_api_version,
            runtime,
            metadata,
        };
        manifest.validate_semantics()?;
        Ok(manifest)
    }

    pub fn validate_against_policy(
        &self,
        policy: &ModuleCompatibilityPolicy,
    ) -> Result<(), String> {
        if !policy.supports_manifest_version(self.manifest_version) {
            return Err(format!(
                "unsupported manifest_version '{}' (supported: {}..={})",
                self.manifest_version, policy.min_manifest_version, policy.max_manifest_version
            ));
        }
        if !policy.supports_module_api_version(self.module_api_version) {
            return Err(format!(
                "unsupported module_api_version '{}' (supported: {}..={})",
                self.module_api_version,
                policy.min_module_api_version,
                policy.max_module_api_version
            ));
        }
        if self.runtime == ModuleRuntime::Dynlib && self.metadata.entrypoint.is_none() {
            return Err("dynlib module requires 'entrypoint'".to_string());
        }
        Ok(())
    }

    pub fn validate_dynlib_compatibility(
        &self,
        policy: &ModuleCompatibilityPolicy,
        exported_api_version: u32,
    ) -> Result<(), String> {
        self.validate_against_policy(policy)?;
        if self.runtime != ModuleRuntime::Dynlib {
            return Err(format!(
                "dynlib loader requires runtime='dynlib', got '{}'",
                self.runtime.as_str()
            ));
        }
        if self.module_api_version != exported_api_version {
            return Err(format!(
                "manifest module_api_version '{}' does not match exported API '{}'",
                self.module_api_version, exported_api_version
            ));
        }
        Ok(())
    }

    fn validate_semantics(&self) -> Result<(), String> {
        if self.metadata.category == ModuleCategory::Unknown {
            return Err("manifest field 'category' is unknown".to_string());
        }
        if self.metadata.rank == ModuleRank::Unknown {
            return Err("manifest field 'rank' is unknown".to_string());
        }
        if self.metadata.name.trim().is_empty() {
            return Err("manifest field 'name' cannot be empty".to_string());
        }
        if self.metadata.description.trim().is_empty() {
            return Err("manifest field 'description' cannot be empty".to_string());
        }
        if self.metadata.author.trim().is_empty() {
            return Err("manifest field 'author' cannot be empty".to_string());
        }
        if self.metadata.platforms.is_empty() {
            return Err("manifest field 'platforms' cannot be empty".to_string());
        }
        if self.metadata.tags.is_empty() {
            return Err("manifest field 'tags' cannot be empty".to_string());
        }
        if !is_valid_module_name(&self.metadata.name) {
            return Err(format!(
                "manifest field 'name' is not a valid module path: '{}'",
                self.metadata.name
            ));
        }
        if !category_matches_name(self.metadata.category, &self.metadata.name) {
            return Err(format!(
                "manifest category '{}' does not match module path '{}'",
                self.metadata.category.as_str(),
                self.metadata.name
            ));
        }
        if self.metadata.entrypoint.is_none() {
            return Err("missing manifest field 'entrypoint'".to_string());
        }
        Ok(())
    }
}

fn validate_allowed_keys(
    map: &std::collections::BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        "manifest_version",
        "module_api_version",
        "runtime",
        "name",
        "description",
        "category",
        "rank",
        "author",
        "platforms",
        "tags",
        "entrypoint",
        "references",
    ];
    for key in map.keys() {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(format!("unsupported manifest field '{key}'"));
        }
    }
    Ok(())
}

fn get_string(
    map: &std::collections::BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<String, String> {
    match map.get(key) {
        Some(JsonValue::String(value)) => Ok(value.clone()),
        Some(_) => Err(format!("manifest field '{key}' must be a string")),
        None => Err(format!("missing manifest field '{key}'")),
    }
}

fn get_u32(map: &std::collections::BTreeMap<String, JsonValue>, key: &str) -> Result<u32, String> {
    match map.get(key) {
        Some(JsonValue::Number(value)) => {
            if *value < 0.0 || value.fract() != 0.0 || *value > (u32::MAX as f64) {
                return Err(format!("manifest field '{key}' must be a positive integer"));
            }
            Ok(*value as u32)
        }
        Some(_) => Err(format!("manifest field '{key}' must be a number")),
        None => Err(format!("missing manifest field '{key}'")),
    }
}

fn get_runtime(
    map: &std::collections::BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<ModuleRuntime, String> {
    let value = get_string(map, key)?;
    ModuleRuntime::parse(&value).ok_or_else(|| {
        format!(
            "manifest field '{key}' must be one of: builtin, dynlib (got '{}')",
            value
        )
    })
}

fn get_optional_string(
    map: &std::collections::BTreeMap<String, JsonValue>,
    key: &str,
) -> Option<String> {
    match map.get(key) {
        Some(JsonValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn get_string_array(
    map: &std::collections::BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<Vec<String>, String> {
    match map.get(key) {
        Some(JsonValue::Array(values)) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    JsonValue::String(text) => out.push(text.clone()),
                    _ => {
                        return Err(format!(
                            "manifest field '{key}' must be an array of strings"
                        ))
                    }
                }
            }
            Ok(out)
        }
        Some(_) => Err(format!("manifest field '{key}' must be an array")),
        None => Err(format!("missing manifest field '{key}'")),
    }
}

fn get_references(
    map: &std::collections::BTreeMap<String, JsonValue>,
) -> Result<Vec<ModuleReference>, String> {
    let mut refs = Vec::new();
    let values = match map.get("references") {
        None => return Ok(refs),
        Some(JsonValue::Array(values)) => values,
        Some(_) => {
            return Err("manifest field 'references' must be an array".to_string());
        }
    };
    for value in values {
        let JsonValue::Object(obj) = value else {
            return Err("manifest field 'references' must be an array of objects".to_string());
        };
        let kind = match obj.get("kind") {
            Some(JsonValue::String(v)) => v.clone(),
            Some(_) => return Err("manifest field 'references.kind' must be a string".to_string()),
            None => return Err("manifest field 'references.kind' is missing".to_string()),
        };
        let val = match obj.get("value") {
            Some(JsonValue::String(v)) => v.clone(),
            Some(_) => return Err("manifest field 'references.value' must be a string".to_string()),
            None => return Err("manifest field 'references.value' is missing".to_string()),
        };
        refs.push(ModuleReference { kind, value: val });
    }
    Ok(refs)
}

fn is_valid_module_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('/') || name.ends_with('/') || name.contains("//") {
        return false;
    }
    for part in name.split('/') {
        if part.is_empty() {
            return false;
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return false;
        }
    }
    true
}

fn category_matches_name(category: ModuleCategory, name: &str) -> bool {
    match category {
        ModuleCategory::Core => name.starts_with("core/"),
        ModuleCategory::Exploit => name.starts_with("exploit/"),
        ModuleCategory::Payload => name.starts_with("payload/"),
        ModuleCategory::Auxiliary => name.starts_with("auxiliary/"),
        ModuleCategory::Post => name.starts_with("post/"),
        ModuleCategory::Nop => name.starts_with("nop/") || name.starts_with("nops/"),
        ModuleCategory::Evasion => name.starts_with("evasion/"),
        ModuleCategory::Unknown => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest() {
        let input = r#"{
            "manifest_version": 1,
            "module_api_version": 1,
            "runtime": "builtin",
            "name": "auxiliary/http/test",
            "description": "Test module",
            "category": "auxiliary",
            "rank": "normal",
            "author": "moonlight",
            "platforms": ["linux"],
            "tags": ["http", "scanner"],
            "entrypoint": "module.rs",
            "references": [{"kind": "cve", "value": "2024-0001"}]
        }"#;
        let manifest = ModuleManifest::parse_str(input).expect("parse");
        assert_eq!(manifest.metadata.name, "auxiliary/http/test");
        assert_eq!(manifest.manifest_version, 1);
        assert_eq!(manifest.module_api_version, 1);
        assert_eq!(manifest.runtime, ModuleRuntime::Builtin);
        assert_eq!(manifest.metadata.rank, ModuleRank::Normal);
        assert_eq!(manifest.metadata.platforms, vec!["linux".to_string()]);
        assert_eq!(manifest.metadata.tags.len(), 2);
        assert_eq!(manifest.metadata.references.len(), 1);
    }

    #[test]
    fn reject_unknown_field() {
        let input = r#"{
            "manifest_version": 1,
            "module_api_version": 1,
            "runtime": "builtin",
            "name": "auxiliary/http/test",
            "description": "Test module",
            "category": "auxiliary",
            "rank": "normal",
            "author": "moonlight",
            "platforms": ["linux"],
            "tags": ["http"],
            "entrypoint": "module.rs",
            "extra": true
        }"#;
        let err = ModuleManifest::parse_str(input).expect_err("expected error");
        assert!(err.contains("unsupported manifest field 'extra'"));
    }

    #[test]
    fn reject_category_path_mismatch() {
        let input = r#"{
            "manifest_version": 1,
            "module_api_version": 1,
            "runtime": "builtin",
            "name": "auxiliary/http/test",
            "description": "Test module",
            "category": "exploit",
            "rank": "normal",
            "author": "moonlight",
            "platforms": ["linux"],
            "tags": ["http"],
            "entrypoint": "module.rs"
        }"#;
        let err = ModuleManifest::parse_str(input).expect_err("expected error");
        assert!(err.contains("does not match module path"));
    }

    #[test]
    fn policy_rejects_unsupported_api_version() {
        let input = r#"{
            "manifest_version": 1,
            "module_api_version": 2,
            "runtime": "dynlib",
            "name": "auxiliary/test/dynlib_echo",
            "description": "Test module",
            "category": "auxiliary",
            "rank": "normal",
            "author": "moonlight",
            "platforms": ["cross"],
            "tags": ["test"],
            "entrypoint": "libmoonlight_dynlib_test"
        }"#;
        let manifest = ModuleManifest::parse_str(input).expect("parse");
        let policy = ModuleCompatibilityPolicy::dynlib_loader_default();
        let err = manifest
            .validate_against_policy(&policy)
            .expect_err("expected policy mismatch");
        assert!(err.contains("unsupported module_api_version"));
    }
}
