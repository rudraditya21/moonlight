#[derive(Debug, Clone)]
pub struct Config {
    pub no_banner: bool,
    pub prompt: String,
    pub module_path: String,
    pub cache_dir: String,
}

impl Config {
    pub fn load() -> Self {
        let no_banner = std::env::var("MOONLIGHT_NO_BANNER")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let prompt =
            std::env::var("MOONLIGHT_PROMPT").unwrap_or_else(|_| "moonlight> ".to_string());
        let module_path =
            std::env::var("MOONLIGHT_MODULE_PATH").unwrap_or_else(|_| "module_store".to_string());
        let cache_dir =
            std::env::var("MOONLIGHT_CACHE_DIR").unwrap_or_else(|_| ".moonlight".to_string());

        Config {
            no_banner,
            prompt,
            module_path,
            cache_dir,
        }
    }
}
