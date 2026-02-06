use crate::json::{parse_json, JsonValue};
use crate::metadata::{ModuleCategory, ModuleMetadata, ModuleRank, ModuleReference};

#[derive(Debug, Clone)]
pub struct ModuleManifest {
    pub metadata: ModuleMetadata,
}

impl ModuleManifest {
    pub fn parse_str(input: &str) -> Result<Self, String> {
        let value = parse_json(input).map_err(|e| e.to_string())?;
        let obj = match value {
            JsonValue::Object(map) => map,
            _ => return Err("manifest must be a JSON object".to_string()),
        };
        let name = get_string(&obj, "name")?;
        let description = get_string(&obj, "description")?;
        let category = get_string(&obj, "category").unwrap_or_else(|_| "unknown".to_string());
        let author = get_string(&obj, "author").unwrap_or_else(|_| "unknown".to_string());
        let rank = get_string(&obj, "rank").unwrap_or_else(|_| "unknown".to_string());
        let platforms = get_string_array(&obj, "platforms").unwrap_or_default();
        let tags = get_string_array(&obj, "tags").unwrap_or_default();
        let entrypoint = get_optional_string(&obj, "entrypoint");
        let references = get_references(&obj);

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

        Ok(ModuleManifest { metadata })
    }
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

fn get_references(map: &std::collections::BTreeMap<String, JsonValue>) -> Vec<ModuleReference> {
    let mut refs = Vec::new();
    let Some(JsonValue::Array(values)) = map.get("references") else {
        return refs;
    };
    for value in values {
        let JsonValue::Object(obj) = value else {
            continue;
        };
        let kind = match obj.get("kind") {
            Some(JsonValue::String(v)) => v.clone(),
            _ => continue,
        };
        let val = match obj.get("value") {
            Some(JsonValue::String(v)) => v.clone(),
            _ => continue,
        };
        refs.push(ModuleReference { kind, value: val });
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_manifest() {
        let input = r#"{
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
        assert_eq!(manifest.metadata.rank, ModuleRank::Normal);
        assert_eq!(manifest.metadata.platforms, vec!["linux".to_string()]);
        assert_eq!(manifest.metadata.tags.len(), 2);
        assert_eq!(manifest.metadata.references.len(), 1);
    }
}
