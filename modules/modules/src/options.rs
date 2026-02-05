use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleOptionKind {
    String,
    Bool,
    Integer,
    Address,
    Port,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleOptionValue {
    String(String),
    Bool(bool),
    Integer(i64),
    Address(String),
    Port(u16),
}

impl ModuleOptionValue {
    pub fn as_string(&self) -> String {
        match self {
            ModuleOptionValue::String(v) => v.clone(),
            ModuleOptionValue::Bool(v) => v.to_string(),
            ModuleOptionValue::Integer(v) => v.to_string(),
            ModuleOptionValue::Address(v) => v.clone(),
            ModuleOptionValue::Port(v) => v.to_string(),
        }
    }
}

impl fmt::Display for ModuleOptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

#[derive(Debug, Clone)]
pub struct ModuleOption {
    pub name: String,
    pub description: String,
    pub kind: ModuleOptionKind,
    pub required: bool,
    pub default: Option<ModuleOptionValue>,
    pub value: Option<ModuleOptionValue>,
}

impl ModuleOption {
    pub fn new(name: &str, description: &str, kind: ModuleOptionKind, required: bool) -> Self {
        ModuleOption {
            name: name.to_string(),
            description: description.to_string(),
            kind,
            required,
            default: None,
            value: None,
        }
    }

    pub fn with_default(mut self, value: ModuleOptionValue) -> Self {
        self.default = Some(value.clone());
        self.value = Some(value);
        self
    }

    pub fn set_from_str(&mut self, input: &str) -> Result<(), String> {
        let parsed = match self.kind {
            ModuleOptionKind::String => ModuleOptionValue::String(input.to_string()),
            ModuleOptionKind::Bool => {
                let v = match input.to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "y" => true,
                    "0" | "false" | "no" | "n" => false,
                    _ => return Err(format!("invalid boolean: {input}")),
                };
                ModuleOptionValue::Bool(v)
            }
            ModuleOptionKind::Integer => {
                let v: i64 = input.parse().map_err(|_| format!("invalid integer: {input}"))?;
                ModuleOptionValue::Integer(v)
            }
            ModuleOptionKind::Address => {
                if input.is_empty() {
                    return Err("address cannot be empty".to_string());
                }
                ModuleOptionValue::Address(input.to_string())
            }
            ModuleOptionKind::Port => {
                let v: u16 = input.parse().map_err(|_| format!("invalid port: {input}"))?;
                ModuleOptionValue::Port(v)
            }
        };
        self.value = Some(parsed);
        Ok(())
    }

    pub fn value_as_string(&self) -> String {
        self.value
            .as_ref()
            .or(self.default.as_ref())
            .map(|v| v.as_string())
            .unwrap_or_else(|| "".to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ModuleOptions {
    options: Vec<ModuleOption>,
}

impl ModuleOptions {
    pub fn new(options: Vec<ModuleOption>) -> Self {
        ModuleOptions { options }
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModuleOption> {
        self.options.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut ModuleOption> {
        self.options.iter_mut()
    }

    pub fn get(&self, name: &str) -> Option<&ModuleOption> {
        self.options.iter().find(|opt| opt.name.eq_ignore_ascii_case(name))
    }

    pub fn set(&mut self, name: &str, value: &str) -> Result<(), String> {
        let opt = self
            .options
            .iter_mut()
            .find(|opt| opt.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("unknown option: {name}"))?;
        opt.set_from_str(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        for opt in &self.options {
            if opt.required && opt.value.is_none() && opt.default.is_none() {
                return Err(format!("required option not set: {}", opt.name));
            }
        }
        Ok(())
    }
}
