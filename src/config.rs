#[derive(Debug, Clone)]
pub struct Config {
    pub no_banner: bool,
    pub prompt: String,
}

impl Config {
    pub fn load() -> Self {
        let no_banner = std::env::var("MOONLIGHT_NO_BANNER")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let prompt = std::env::var("MOONLIGHT_PROMPT").unwrap_or_else(|_| "moonlight> ".to_string());

        Config { no_banner, prompt }
    }
}
