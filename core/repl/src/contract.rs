use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

impl OutputMode {
    pub fn as_str(self) -> &'static str {
        match self {
            OutputMode::Human => "human",
            OutputMode::Json => "json",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "human" | "text" => Some(OutputMode::Human),
            "json" => Some(OutputMode::Json),
            _ => None,
        }
    }

    pub fn is_json(self) -> bool {
        matches!(self, OutputMode::Json)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliCode {
    Ok,
    Usage,
    NotFound,
    Validation,
    PolicyDenied,
    Execution,
    Io,
    Unsupported,
}

impl CliCode {
    pub fn as_str(self) -> &'static str {
        match self {
            CliCode::Ok => "ML-CLI-0000",
            CliCode::Usage => "ML-CLI-0001",
            CliCode::NotFound => "ML-CLI-0002",
            CliCode::Validation => "ML-CLI-0003",
            CliCode::PolicyDenied => "ML-CLI-0004",
            CliCode::Execution => "ML-CLI-0005",
            CliCode::Io => "ML-CLI-0006",
            CliCode::Unsupported => "ML-CLI-0007",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResponse {
    pub command: String,
    pub ok: bool,
    pub code: CliCode,
    pub message: String,
    pub data: BTreeMap<String, String>,
}

impl CommandResponse {
    pub fn ok(command: &str, message: &str) -> Self {
        Self {
            command: command.to_string(),
            ok: true,
            code: CliCode::Ok,
            message: message.to_string(),
            data: BTreeMap::new(),
        }
    }

    pub fn err(command: &str, code: CliCode, message: &str) -> Self {
        Self {
            command: command.to_string(),
            ok: false,
            code,
            message: message.to_string(),
            data: BTreeMap::new(),
        }
    }

    pub fn with_field(mut self, key: &str, value: impl ToString) -> Self {
        self.data.insert(key.to_string(), value.to_string());
        self
    }

    pub fn render_human(&self) -> String {
        if self.ok {
            if self.data.is_empty() {
                return format!("[{}] {}", self.code.as_str(), self.message);
            }
            let pairs = self
                .data
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(" ");
            format!("[{}] {} ({})", self.code.as_str(), self.message, pairs)
        } else {
            format!("[{}] {}", self.code.as_str(), self.message)
        }
    }

    pub fn render_json(&self) -> String {
        let data = self
            .data
            .iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", escape_json(k), escape_json(v)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"command\":\"{}\",\"ok\":{},\"code\":\"{}\",\"message\":\"{}\",\"data\":{{{}}}}}",
            escape_json(&self.command),
            if self.ok { "true" } else { "false" },
            self.code.as_str(),
            escape_json(&self.message),
            data
        )
    }
}

pub fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_mode_parse_is_stable() {
        assert_eq!(OutputMode::parse("human"), Some(OutputMode::Human));
        assert_eq!(OutputMode::parse("json"), Some(OutputMode::Json));
        assert_eq!(OutputMode::parse("nope"), None);
    }

    #[test]
    fn cli_codes_are_stable() {
        assert_eq!(CliCode::Ok.as_str(), "ML-CLI-0000");
        assert_eq!(CliCode::PolicyDenied.as_str(), "ML-CLI-0004");
        assert_eq!(CliCode::Io.as_str(), "ML-CLI-0006");
    }

    #[test]
    fn command_response_renders_json_for_automation() {
        let line = CommandResponse::ok("run", "module executed")
            .with_field("module", "exploit/linux/test")
            .with_field("session_id", "1")
            .render_json();
        assert!(line.starts_with('{'));
        assert!(line.contains("\"command\":\"run\""));
        assert!(line.contains("\"code\":\"ML-CLI-0000\""));
        assert!(line.contains("\"session_id\":\"1\""));
    }

    #[test]
    fn escape_json_handles_control_characters() {
        let escaped = escape_json("hello\n\"world\"");
        assert_eq!(escaped, "hello\\n\\\"world\\\"");
    }
}
