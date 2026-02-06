use std::env;

pub struct Palette {
    enabled: bool,
}

impl Palette {
    pub fn new() -> Self {
        Palette {
            enabled: colors_enabled(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn prompt_base(&self, text: &str) -> String {
        self.paint(text, "1;31")
    }

    pub fn prompt_module(&self, text: &str) -> String {
        self.paint(text, "1;36")
    }

    pub fn success(&self, text: &str) -> String {
        self.paint(text, "32")
    }

    pub fn error(&self, text: &str) -> String {
        self.paint(text, "31")
    }

    pub fn warning(&self, text: &str) -> String {
        self.paint(text, "33")
    }

    pub fn info(&self, text: &str) -> String {
        self.paint(text, "34")
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint(text, "2")
    }

    fn paint(&self, text: &str, code: &str) -> String {
        if !self.enabled {
            return text.to_string();
        }
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

fn colors_enabled() -> bool {
    if env::var("NO_COLOR").is_ok() {
        return false;
    }
    let term = env::var("TERM").unwrap_or_default();
    if term == "dumb" {
        return false;
    }
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}
