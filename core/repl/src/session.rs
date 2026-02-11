use std::collections::HashSet;

use corelib::ids::Id;
use modules::{
    load_dyn_module, Module, ModuleCatalog, ModuleCategory, ModuleContext, ModuleRank,
    ModuleRegistry, SearchQuery,
};

use crate::ansi::Palette;
use crate::history::History;
use crate::line::{read_line, Completer, CompletionResult};
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
    prompt_base: String,
    registry: ModuleRegistry,
    catalog: Option<ModuleCatalog>,
    history: History,
    active: Option<Box<dyn Module>>,
    session_id: Id,
    palette: Palette,
}

impl Repl {
    pub fn new(prompt: String, registry: ModuleRegistry, catalog: Option<ModuleCatalog>) -> Self {
        Repl {
            prompt_base: normalize_prompt(&prompt),
            registry,
            catalog,
            history: History::new(500),
            active: None,
            session_id: Id::next(),
            palette: Palette::new(),
        }
    }

    pub fn run(&mut self) -> Result<(), ReplError> {
        loop {
            let prompt = self.prompt_text();
            let completer = ReplCompleter { repl: self };
            let line = read_line(&prompt, &completer, self.history.entries())
                .map_err(|e| ReplError::Io(e.to_string()))?;
            let Some(line) = line else {
                break;
            };
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            self.history.add(line.to_string());

            let tokens = match tokenize(line) {
                Ok(tokens) => tokens,
                Err(err) => {
                    println!("{}", self.palette.error(&format!("Error: {err}")));
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
            "info" => self.cmd_info(tokens),
            _ => println!(
                "{}",
                self.palette
                    .error(&format!("Unknown command: {}", tokens[0]))
            ),
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
        println!("  info [module]        Show module details");
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
            println!("{}", self.palette.warning("Usage: use <module>"));
            return;
        }
        let name = &tokens[1];
        let Some(module) = self.registry.create(name) else {
            if let Some(catalog) = &self.catalog {
                if let Some(record) = catalog.get_by_name(name) {
                    if let Some(entrypoint) = &record.entrypoint_path {
                        match load_dyn_module(entrypoint) {
                            Ok(module) => {
                                self.active = Some(module);
                                println!(
                                    "{}",
                                    self.palette.success(&format!("Using module: {name}"))
                                );
                                return;
                            }
                            Err(err) => {
                                println!(
                                    "{}",
                                    self.palette.error(&format!("Module load failed: {err}"))
                                );
                                return;
                            }
                        }
                    }
                }
            }
            println!(
                "{}",
                self.palette.error(&format!("Module not found: {name}"))
            );
            return;
        };
        self.active = Some(module);
        println!("{}", self.palette.success(&format!("Using module: {name}")));
    }

    fn cmd_show(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!("{}", self.palette.warning("Usage: show <modules|options>"));
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
                        println!("{}", self.palette.warning("No modules indexed."));
                        return;
                    }
                    println!(
                        "{}",
                        self.palette
                            .info(&format!("Indexed modules: {total}. Showing up to {limit}."))
                    );
                    let rows: Vec<(&str, &str)> = catalog
                        .iter()
                        .take(limit)
                        .map(|record| {
                            (
                                record.metadata.name.as_str(),
                                record.metadata.description.as_str(),
                            )
                        })
                        .collect();
                    print_aligned_rows(&rows);
                    if total > limit {
                        println!(
                            "{}",
                            self.palette.dim(
                                "Use: search <term> [--category <cat>] [--rank <rank>] [--platform <platform>] [--tag <tag>]"
                            )
                        );
                    }
                } else if self.registry.is_empty() {
                    println!("{}", self.palette.warning("No modules registered."));
                } else {
                    let rows: Vec<(&str, &str)> = self
                        .registry
                        .iter_metadata()
                        .map(|meta| (meta.name.as_str(), meta.description.as_str()))
                        .collect();
                    print_aligned_rows(&rows);
                }
            }
            "options" => {
                let Some(module) = &self.active else {
                    println!("{}", self.palette.warning("No active module."));
                    return;
                };
                println!(
                    "{}",
                    self.palette
                        .info(&format!("Options for {}:", module.metadata().name))
                );
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
            _ => println!(
                "{}",
                self.palette
                    .error(&format!("Unknown show target: {}", tokens[1]))
            ),
        }
    }

    fn cmd_set(&mut self, tokens: &[String]) {
        if tokens.len() < 3 {
            println!("{}", self.palette.warning("Usage: set <option> <value>"));
            return;
        }
        let Some(module) = &mut self.active else {
            println!("{}", self.palette.warning("No active module."));
            return;
        };
        let key = &tokens[1];
        let value = tokens[2..].join(" ");
        if let Err(err) = module.options_mut().set(key, &value) {
            println!("{}", self.palette.error(&format!("Error: {err}")));
        }
    }

    fn cmd_get(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!("{}", self.palette.warning("Usage: get <option>"));
            return;
        }
        let Some(module) = &self.active else {
            println!("{}", self.palette.warning("No active module."));
            return;
        };
        let key = &tokens[1];
        let Some(opt) = module.options().get(key) else {
            println!("{}", self.palette.error(&format!("Unknown option: {key}")));
            return;
        };
        println!("{} = {}", opt.name, opt.value_as_string());
    }

    fn cmd_search(&self, tokens: &[String]) {
        let Some(catalog) = &self.catalog else {
            println!("{}", self.palette.warning("No module catalog loaded."));
            return;
        };
        if tokens.len() < 2 {
            println!(
                "{}",
                self.palette.warning(
                    "Usage: search <term> [--category <cat>] [--rank <rank>] [--platform <platform>] [--tag <tag>] [--limit <n>]"
                )
            );
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
                            println!(
                                "{}",
                                self.palette.error(&format!("Unknown category: {val}"))
                            );
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
                            println!("{}", self.palette.error(&format!("Unknown rank: {val}")));
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
            println!(
                "{}",
                self.palette.warning(
                    "No matching modules. Search requires term, tag, platform, category, or rank."
                )
            );
            return;
        }
        let mut rows = Vec::with_capacity(results.len());
        for record in results {
            let rank = record.metadata.rank.as_str();
            let category = record.metadata.category.as_str();
            let label = format!("{} [{}] [{}]", record.metadata.name, category, rank);
            rows.push((label, record.metadata.description.as_str()));
        }
        print_aligned_owned_rows(&rows);
    }

    fn cmd_run(&mut self) {
        let Some(module) = &mut self.active else {
            println!("{}", self.palette.warning("No active module."));
            return;
        };
        if let Err(err) = module.options().validate() {
            println!(
                "{}",
                self.palette
                    .error(&format!("Option validation failed: {err}"))
            );
            return;
        }
        let ctx = ModuleContext {
            session_id: self.session_id.0,
        };
        match module.run(&ctx) {
            Ok(result) => {
                if result.success {
                    println!(
                        "{}",
                        self.palette
                            .success(&format!("Success: {}", result.message))
                    );
                } else {
                    println!(
                        "{}",
                        self.palette.error(&format!("Failed: {}", result.message))
                    );
                }
            }
            Err(err) => println!("{}", self.palette.error(&format!("Module error: {err}"))),
        }
    }

    fn cmd_info(&self, tokens: &[String]) {
        let mut name = None;
        if tokens.len() > 1 {
            name = Some(tokens[1].as_str());
        }
        if name.is_none() {
            if let Some(module) = &self.active {
                self.print_module_info(module.metadata(), Some(module.options()));
                return;
            }
            println!("{}", self.palette.warning("Usage: info [module]"));
            return;
        }
        let name = name.unwrap();
        if let Some(entry) = self.registry.get_entry(name) {
            let module = entry.create();
            self.print_module_info(entry.metadata(), Some(module.options()));
            return;
        }
        if let Some(catalog) = &self.catalog {
            if let Some(record) = catalog
                .iter()
                .find(|m| m.metadata.name.eq_ignore_ascii_case(name))
            {
                self.print_module_info(&record.metadata, None);
                return;
            }
        }
        println!(
            "{}",
            self.palette.error(&format!("Module not found: {name}"))
        );
    }

    fn print_module_info(
        &self,
        metadata: &modules::ModuleMetadata,
        options: Option<&modules::ModuleOptions>,
    ) {
        println!("{}", self.palette.info("Module Information"));
        println!("Name:        {}", metadata.name);
        println!("Description: {}", metadata.description);
        println!("Category:    {}", metadata.category.as_str());
        println!("Rank:        {}", metadata.rank.as_str());
        println!("Author:      {}", metadata.author);
        if !metadata.platforms.is_empty() {
            println!("Platforms:   {}", metadata.platforms.join(", "));
        }
        if !metadata.tags.is_empty() {
            println!("Tags:        {}", metadata.tags.join(", "));
        }
        if let Some(entrypoint) = &metadata.entrypoint {
            if !entrypoint.is_empty() {
                println!("Entrypoint:  {}", entrypoint);
            }
        }
        if let Some(options) = options {
            println!();
            println!("{}", self.palette.info("Options"));
            for opt in options.iter() {
                let required = if opt.required { "yes" } else { "no" };
                println!(
                    "  {:<16} {:<8} {:<6} {}",
                    opt.name,
                    opt.kind_string(),
                    required,
                    opt.value_as_string()
                );
            }
        }
    }

    fn prompt_text(&self) -> String {
        let base = if self.prompt_base.is_empty() {
            "moonlight"
        } else {
            self.prompt_base.as_str()
        };
        let base = self.palette.prompt_base(base);
        if let Some(module) = &self.active {
            let module_name = self.palette.prompt_module(module.metadata().name.as_str());
            format!("{}({})> ", base, module_name)
        } else {
            format!("{}> ", base)
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

fn normalize_prompt(prompt: &str) -> String {
    let trimmed = prompt.trim_end();
    let base = trimmed.strip_suffix('>').unwrap_or(trimmed);
    let base = base.trim_end();
    if base.is_empty() {
        "moonlight".to_string()
    } else {
        base.to_string()
    }
}

struct ReplCompleter<'a> {
    repl: &'a Repl,
}

impl<'a> Completer for ReplCompleter<'a> {
    fn complete(&self, line: &str) -> CompletionResult {
        self.repl.complete(line)
    }
}

impl Repl {
    fn complete(&self, line: &str) -> CompletionResult {
        let trimmed_end = line.trim_end_matches(|c: char| c.is_whitespace());
        let ends_with_space = trimmed_end.len() != line.len();
        let (start, current) = if ends_with_space {
            (line.len(), "")
        } else if let Some(pos) = line.rfind(|c: char| c.is_whitespace()) {
            (pos + 1, &line[pos + 1..])
        } else {
            (0, line)
        };
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let token_index = if ends_with_space {
            tokens.len()
        } else {
            tokens.len().saturating_sub(1)
        };
        let mut candidates = Vec::new();

        if tokens.is_empty() || token_index == 0 {
            candidates = command_candidates(current);
        } else {
            let cmd = tokens[0].to_lowercase();
            match cmd.as_str() {
                "use" | "info" => {
                    if token_index == 1 {
                        candidates = module_candidates(self, current);
                    }
                }
                "set" | "get" => {
                    if token_index == 1 {
                        candidates = option_candidates(self, current);
                    }
                }
                "show" => {
                    if token_index == 1 {
                        candidates = ["modules", "options"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    }
                }
                "search" => {
                    candidates = search_flag_candidates(current);
                }
                _ => {}
            }
        }
        candidates.sort();
        candidates.dedup();
        CompletionResult { start, candidates }
    }
}

fn command_candidates(prefix: &str) -> Vec<String> {
    let commands = [
        "help", "show", "use", "search", "set", "get", "run", "history", "info", "exit", "quit",
    ];
    commands
        .iter()
        .filter(|cmd| cmd.starts_with(prefix))
        .map(|cmd| cmd.to_string())
        .collect()
}

fn module_candidates(repl: &Repl, prefix: &str) -> Vec<String> {
    let mut names = HashSet::new();
    for meta in repl.registry.iter_metadata() {
        if meta.name.starts_with(prefix) {
            names.insert(meta.name.clone());
        }
    }
    if let Some(catalog) = &repl.catalog {
        for record in catalog.iter() {
            if record.metadata.name.starts_with(prefix) {
                names.insert(record.metadata.name.clone());
            }
        }
    }
    names.into_iter().collect()
}

fn option_candidates(repl: &Repl, prefix: &str) -> Vec<String> {
    let Some(module) = &repl.active else {
        return Vec::new();
    };
    module
        .options()
        .iter()
        .map(|opt| opt.name.clone())
        .filter(|name| name.starts_with(prefix))
        .collect()
}

fn search_flag_candidates(prefix: &str) -> Vec<String> {
    let flags = [
        "--category",
        "--cat",
        "--rank",
        "--platform",
        "--tag",
        "--limit",
    ];
    flags
        .iter()
        .filter(|flag| flag.starts_with(prefix))
        .map(|flag| flag.to_string())
        .collect()
}

fn print_aligned_rows(rows: &[(&str, &str)]) {
    if rows.is_empty() {
        return;
    }
    let max_width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    for (name, desc) in rows {
        println!("{name:<width$} - {desc}", width = max_width);
    }
}

fn print_aligned_owned_rows(rows: &[(String, &str)]) {
    if rows.is_empty() {
        return;
    }
    let max_width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    for (name, desc) in rows {
        println!("{name:<width$} - {desc}", width = max_width);
    }
}
