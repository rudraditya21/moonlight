use std::io::{self, Write};

use corelib::ids::Id;
use modules::{
    Module, ModuleCatalog, ModuleCategory, ModuleContext, ModuleRank, ModuleRegistry, SearchQuery,
};

use crate::history::History;
use crate::parser::tokenize;

#[derive(Debug)]
pub enum ReplError {
    Io(String),
    Parse(String),
    Registry(String),
}

impl std::fmt::Display for ReplError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplError::Io(msg) => write!(f, "io error: {msg}"),
            ReplError::Parse(msg) => write!(f, "parse error: {msg}"),
            ReplError::Registry(msg) => write!(f, "registry error: {msg}"),
        }
    }
}

impl std::error::Error for ReplError {}

pub struct Repl {
    prompt: String,
    registry: ModuleRegistry,
    catalog: Option<ModuleCatalog>,
    history: History,
    active: Option<Box<dyn Module>>,
    session_id: Id,
}

impl Repl {
    pub fn new(prompt: String, registry: ModuleRegistry, catalog: Option<ModuleCatalog>) -> Self {
        Repl {
            prompt,
            registry,
            catalog,
            history: History::new(500),
            active: None,
            session_id: Id::next(),
        }
    }

    pub fn run(&mut self) -> Result<(), ReplError> {
        let stdin = io::stdin();
        loop {
            print!("{}", self.prompt);
            io::stdout()
                .flush()
                .map_err(|e| ReplError::Io(e.to_string()))?;

            let mut line = String::new();
            let bytes = stdin
                .read_line(&mut line)
                .map_err(|e| ReplError::Io(e.to_string()))?;
            if bytes == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            self.history.add(line.to_string());

            let tokens = match tokenize(line) {
                Ok(tokens) => tokens,
                Err(err) => {
                    println!("Error: {err}");
                    continue;
                }
            };
            if tokens.is_empty() {
                continue;
            }
            if self.handle_command(&tokens) {
                break;
            }
        }
        Ok(())
    }

    fn handle_command(&mut self, tokens: &[String]) -> bool {
        let cmd = tokens[0].to_lowercase();
        match cmd.as_str() {
            "help" => self.cmd_help(),
            "exit" | "quit" => return true,
            "history" => self.cmd_history(),
            "use" => self.cmd_use(tokens),
            "show" => self.cmd_show(tokens),
            "search" => self.cmd_search(tokens),
            "set" => self.cmd_set(tokens),
            "get" => self.cmd_get(tokens),
            "run" => self.cmd_run(),
            _ => println!("Unknown command: {}", tokens[0]),
        }
        false
    }

    fn cmd_help(&self) {
        println!("Commands:");
        println!("  help                Show this help");
        println!("  show modules         List modules");
        println!("  use <name>           Select module");
        println!("  show options         Show module options");
        println!("  search <query>       Search modules");
        println!("  set <opt> <value>    Set module option");
        println!("  get <opt>            Get module option");
        println!("  run                  Execute module");
        println!("  history              Show command history");
        println!("  exit|quit            Exit the console");
    }

    fn cmd_history(&self) {
        for (idx, entry) in self.history.iter() {
            println!("{:>4}  {}", idx + 1, entry);
        }
    }

    fn cmd_use(&mut self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!("Usage: use <module>");
            return;
        }
        let name = &tokens[1];
        let Some(module) = self.registry.create(name) else {
            println!("Module not found: {name}");
            return;
        };
        self.active = Some(module);
        println!("Using module: {name}");
    }

    fn cmd_show(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!("Usage: show <modules|options>");
            return;
        }
        match tokens[1].as_str() {
            "modules" => {
                if let Some(catalog) = &self.catalog {
                    let limit = tokens
                        .get(2)
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(50);
                    let total = catalog.len();
                    if total == 0 {
                        println!("No modules indexed.");
                        return;
                    }
                    println!("Indexed modules: {total}. Showing up to {limit}.");
                    for record in catalog.iter().take(limit) {
                        println!("{} - {}", record.metadata.name, record.metadata.description);
                    }
                    if total > limit {
                        println!("Use: search <term> [--category <cat>] [--rank <rank>] [--platform <platform>] [--tag <tag>]");
                    }
                } else if self.registry.is_empty() {
                    println!("No modules registered.");
                } else {
                    for meta in self.registry.iter_metadata() {
                        println!("{} - {}", meta.name, meta.description);
                    }
                }
            }
            "options" => {
                let Some(module) = &self.active else {
                    println!("No active module.");
                    return;
                };
                println!("Options for {}:", module.metadata().name);
                for opt in module.options().iter() {
                    let value = opt.value_as_string();
                    let required = if opt.required { "yes" } else { "no" };
                    println!(
                        "  {:<16} {:<8} {:<6} {}",
                        opt.name,
                        opt.kind_string(),
                        required,
                        value
                    );
                }
            }
            _ => println!("Unknown show target: {}", tokens[1]),
        }
    }

    fn cmd_set(&mut self, tokens: &[String]) {
        if tokens.len() < 3 {
            println!("Usage: set <option> <value>");
            return;
        }
        let Some(module) = &mut self.active else {
            println!("No active module.");
            return;
        };
        let key = &tokens[1];
        let value = tokens[2..].join(" ");
        if let Err(err) = module.options_mut().set(key, &value) {
            println!("Error: {err}");
        }
    }

    fn cmd_get(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!("Usage: get <option>");
            return;
        }
        let Some(module) = &self.active else {
            println!("No active module.");
            return;
        };
        let key = &tokens[1];
        let Some(opt) = module.options().get(key) else {
            println!("Unknown option: {key}");
            return;
        };
        println!("{} = {}", opt.name, opt.value_as_string());
    }

    fn cmd_search(&self, tokens: &[String]) {
        let Some(catalog) = &self.catalog else {
            println!("No module catalog loaded.");
            return;
        };
        if tokens.len() < 2 {
            println!("Usage: search <term> [--category <cat>] [--rank <rank>] [--platform <platform>] [--tag <tag>] [--limit <n>]");
            return;
        }
        let mut query = SearchQuery::new();
        let mut terms = Vec::new();
        let mut i = 1;
        while i < tokens.len() {
            match tokens[i].as_str() {
                "--category" | "--cat" => {
                    i += 1;
                    if let Some(val) = tokens.get(i) {
                        let category = ModuleCategory::parse(val);
                        if category == ModuleCategory::Unknown {
                            println!("Unknown category: {val}");
                        } else {
                            query.category = Some(category);
                        }
                    }
                }
                "--rank" => {
                    i += 1;
                    if let Some(val) = tokens.get(i) {
                        let rank = ModuleRank::parse(val);
                        if rank == ModuleRank::Unknown {
                            println!("Unknown rank: {val}");
                        } else {
                            query.rank = Some(rank);
                        }
                    }
                }
                "--platform" => {
                    i += 1;
                    if let Some(val) = tokens.get(i) {
                        query.platform = Some(val.to_string());
                    }
                }
                "--tag" => {
                    i += 1;
                    if let Some(val) = tokens.get(i) {
                        query.tags.push(val.to_string());
                    }
                }
                "--limit" => {
                    i += 1;
                    if let Some(val) = tokens.get(i) {
                        if let Ok(limit) = val.parse::<usize>() {
                            query.limit = Some(limit);
                        }
                    }
                }
                other => {
                    terms.push(other.to_string());
                }
            }
            i += 1;
        }
        if !terms.is_empty() {
            query.term = Some(terms.join(" "));
        }
        let results = catalog.search(&query);
        if results.is_empty() {
            println!("No matching modules.");
            return;
        }
        for record in results {
            let rank = record.metadata.rank.as_str();
            let category = record.metadata.category.as_str();
            println!(
                "{} [{}] [{}] - {}",
                record.metadata.name, category, rank, record.metadata.description
            );
        }
    }

    fn cmd_run(&mut self) {
        let Some(module) = &mut self.active else {
            println!("No active module.");
            return;
        };
        if let Err(err) = module.options().validate() {
            println!("Option validation failed: {err}");
            return;
        }
        let ctx = ModuleContext {
            session_id: self.session_id.0,
        };
        match module.run(&ctx) {
            Ok(result) => {
                if result.success {
                    println!("Success: {}", result.message);
                } else {
                    println!("Failed: {}", result.message);
                }
            }
            Err(err) => println!("Module error: {err}"),
        }
    }
}

trait ModuleOptionExt {
    fn kind_string(&self) -> &str;
}

impl ModuleOptionExt for modules::ModuleOption {
    fn kind_string(&self) -> &str {
        match self.kind {
            modules::ModuleOptionKind::String => "string",
            modules::ModuleOptionKind::Bool => "bool",
            modules::ModuleOptionKind::Integer => "int",
            modules::ModuleOptionKind::Address => "addr",
            modules::ModuleOptionKind::Port => "port",
        }
    }
}
