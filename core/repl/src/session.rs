use std::io::{self, Write};

use corelib::ids::Id;
use modules::{Module, ModuleContext, ModuleRegistry};

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
    history: History,
    active: Option<Box<dyn Module>>,
    session_id: Id,
}

impl Repl {
    pub fn new(prompt: String, registry: ModuleRegistry) -> Self {
        Repl {
            prompt,
            registry,
            history: History::new(500),
            active: None,
            session_id: Id::next(),
        }
    }

    pub fn run(&mut self) -> Result<(), ReplError> {
        self.registry
            .finalize()
            .map_err(|e| ReplError::Registry(e.to_string()))?;

        let stdin = io::stdin();
        loop {
            print!("{}", self.prompt);
            io::stdout().flush().map_err(|e| ReplError::Io(e.to_string()))?;

            let mut line = String::new();
            let bytes = stdin.read_line(&mut line).map_err(|e| ReplError::Io(e.to_string()))?;
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
        let Some(factory) = self.registry.get_factory(name) else {
            println!("Module not found: {name}");
            return;
        };
        self.active = Some(factory.create());
        println!("Using module: {name}");
    }

    fn cmd_show(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!("Usage: show <modules|options>");
            return;
        }
        match tokens[1].as_str() {
            "modules" => {
                let list = self.registry.list();
                if list.is_empty() {
                    println!("No modules registered.");
                } else {
                    for meta in list {
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
                    println!("  {:<16} {:<8} {:<6} {}", opt.name, opt.kind_string(), required, value);
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
