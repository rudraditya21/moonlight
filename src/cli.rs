#[derive(Debug, Clone, Copy)]
pub struct CliOptions {
    pub show_help: bool,
    pub show_version: bool,
    pub no_banner: bool,
    pub no_repl: bool,
}

impl CliOptions {
    pub fn parse() -> Self {
        let mut opts = CliOptions {
            show_help: false,
            show_version: false,
            no_banner: false,
            no_repl: false,
        };

        for arg in std::env::args().skip(1) {
            match arg.as_str() {
                "-h" | "--help" => opts.show_help = true,
                "-V" | "--version" => opts.show_version = true,
                "--no-banner" => opts.no_banner = true,
                "--no-repl" => opts.no_repl = true,
                _ => {
                    eprintln!("Unknown argument: {arg}");
                    opts.show_help = true;
                }
            }
        }

        opts
    }
}
