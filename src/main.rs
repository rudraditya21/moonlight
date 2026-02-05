mod banner;
mod cli;
mod config;
mod repl;

use crate::cli::CliOptions;
use crate::config::Config;

fn main() {
    let opts = CliOptions::parse();
    if opts.show_help {
        println!("moonlight - Metasploit-style framework reimplemented in Rust");
        println!("\nUsage:\n  moonlight [--no-banner] [--no-repl] [--version]");
        return;
    }
    if opts.show_version {
        println!("moonlight {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let config = Config::load();
    if !(opts.no_banner || config.no_banner) {
        banner::print();
    }

    if opts.no_repl {
        eprintln!("No REPL requested. Exiting.");
        return;
    }

    if let Err(err) = repl::run(config) {
        eprintln!("REPL terminated with error: {err}");
        std::process::exit(1);
    }
}
