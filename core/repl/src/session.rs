use std::collections::HashSet;
use std::io::{self, Write};

use corelib::ids::Id;
use corelib::policy::{
    Capability, DecisionKind, ModuleContext as PolicyModuleContext, PolicyEngine, PolicyRequest,
};
use modules::{
    load_dyn_module, Module, ModuleCatalog, ModuleCategory, ModuleContext, ModuleRank,
    ModuleRegistry, SearchQuery,
};

use crate::ansi::Palette;
use crate::history::History;
use crate::line::{read_line, Completer, CompletionResult};
use crate::parser::tokenize;
use crate::sessions::SessionManager;

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
    sessions: SessionManager,
    policy: PolicyEngine,
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
            sessions: SessionManager::new(),
            policy: PolicyEngine::new(),
            palette: Palette::new(),
        }
    }

    pub fn run(&mut self) -> Result<(), ReplError> {
        loop {
            let mut _polled_bytes = 0usize;
            for outcome in self.sessions.poll_all() {
                _polled_bytes = _polled_bytes.saturating_add(outcome.bytes_read);
                if let Some(err) = outcome.error {
                    if outcome.is_partitioned {
                        eprintln!("session {} partitioned: {}", outcome.id, err);
                    } else {
                        eprintln!("session {} poll error: {}", outcome.id, err);
                    }
                }
            }
            let recovered = self.sessions.recover_partitioned();
            if !recovered.is_empty() {
                println!(
                    "{}",
                    self.palette.success(&format!(
                        "Recovered partitioned session(s): {}",
                        recovered
                            .iter()
                            .map(|id| id.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                );
            }
            let reaped_stale = self.sessions.reap_stale();
            if !reaped_stale.is_empty() {
                println!(
                    "{}",
                    self.palette.warning(&format!(
                        "Reaped {} stale session(s): {}",
                        reaped_stale.len(),
                        reaped_stale
                            .iter()
                            .map(|id| id.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                );
            }
            let reaped_partitioned = self.sessions.reap_partitioned();
            if !reaped_partitioned.is_empty() {
                println!(
                    "{}",
                    self.palette.warning(&format!(
                        "Reaped partitioned session(s): {}",
                        reaped_partitioned
                            .iter()
                            .map(|id| id.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                );
            }
            self.sessions.reap_closed();

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
        if let Err(err) = self.sessions.close_all() {
            eprintln!("session cleanup failed: {err}");
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
            "run" => self.cmd_run(tokens),
            "policy" => self.cmd_policy(tokens),
            "info" => self.cmd_info(tokens),
            "sessions" => self.cmd_sessions(tokens),
            "interact" => self.cmd_interact(tokens),
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
        println!("  run --yes            Execute without prompt when confirmation is required");
        println!("  policy               Show guardrail policy and capabilities");
        println!("  policy enable <cap>  Enable a capability (exploit_execution, payload_execution, evasion_execution, public_targets, wide_target_scope, bulk_session_control)");
        println!("  policy disable <cap> Disable a capability");
        println!("  sessions             List sessions");
        println!("  sessions -k <id>     Close a session");
        println!("  sessions -K          Close all sessions");
        println!("  sessions -r <id>     Read buffered output for one session");
        println!("  sessions -R          Read buffered output for all background sessions");
        println!("  interact <id>        Interact with a session");
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
                print_options_table(module.options());
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

    fn cmd_run(&mut self, tokens: &[String]) {
        let Some(module) = self.active.as_ref() else {
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
        let metadata = module.metadata().clone();
        let target = extract_target_from_options(module.options());
        let policy_module = match PolicyModuleContext::new(
            &metadata.name,
            metadata.category.as_str(),
            metadata.rank.as_str(),
            metadata.tags.clone(),
        ) {
            Ok(value) => value,
            Err(err) => {
                println!(
                    "{}",
                    self.palette.error(&format!("Policy metadata error: {err}"))
                );
                return;
            }
        };
        let decision = self.policy.evaluate(&PolicyRequest::execute_module(
            policy_module,
            target.clone(),
        ));
        let explicit_yes = tokens
            .iter()
            .any(|token| token.eq_ignore_ascii_case("--yes") || token.eq_ignore_ascii_case("-y"));

        match decision.kind {
            DecisionKind::Deny => {
                println!(
                    "{}",
                    self.palette
                        .error(&format!("Policy blocked run: {}", decision.reason))
                );
                println!(
                    "{}",
                    self.palette
                        .info("Use `policy` to inspect/enable capabilities before retrying.")
                );
                return;
            }
            DecisionKind::RequireConfirmation if !explicit_yes => {
                if !self
                    .confirm_intent(&format!("{} [yes/no]: ", decision.reason))
                    .unwrap_or(false)
                {
                    println!(
                        "{}",
                        self.palette.warning("Run canceled by policy confirmation.")
                    );
                    return;
                }
            }
            _ => {}
        }

        let ctx = ModuleContext {
            session_id: self.session_id.0,
        };
        let Some(module) = self.active.as_mut() else {
            println!("{}", self.palette.warning("No active module."));
            return;
        };
        let module_name = module.metadata().name.clone();
        match module.run(&ctx) {
            Ok(mut result) => {
                if let Some(session) = result.take_session() {
                    let kind = session.kind().to_string();
                    let target = session.target();
                    let id = self.sessions.register(module_name, session);
                    println!(
                        "{}",
                        self.palette
                            .success(&format!("Session {id} opened ({kind} -> {target})"))
                    );
                }
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

    fn cmd_sessions(&mut self, tokens: &[String]) {
        self.sessions.reap_closed();
        if tokens.len() == 1 {
            let snapshots = self.sessions.snapshots();
            if snapshots.is_empty() {
                println!("{}", self.palette.warning("No active sessions."));
                return;
            }
            let headers = [
                "Id", "State", "Attach", "Pending", "Idle(s)", "Type", "Target", "Module",
            ];
            let mut rows = Vec::with_capacity(snapshots.len());
            let mut widths = [
                headers[0].len(),
                headers[1].len(),
                headers[2].len(),
                headers[3].len(),
                headers[4].len(),
                headers[5].len(),
                headers[6].len(),
                headers[7].len(),
            ];
            for snap in snapshots {
                let state = if !snap.is_open {
                    "closed".to_string()
                } else if snap.is_partitioned {
                    let age = snap.partition_age_secs.unwrap_or(0);
                    format!("partitioned({age}s,e={})", snap.consecutive_errors)
                } else {
                    "open".to_string()
                };
                let attach = if snap.is_attached {
                    "attached".to_string()
                } else {
                    "bg".to_string()
                };
                let row = [
                    snap.id.to_string(),
                    state,
                    attach,
                    snap.pending_bytes.to_string(),
                    snap.idle_secs.to_string(),
                    snap.kind,
                    snap.target,
                    snap.module_name,
                ];
                for (idx, col) in row.iter().enumerate() {
                    widths[idx] = widths[idx].max(col.len());
                }
                rows.push(row);
            }
            println!(
                "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {:<w5$}  {:<w6$}  {:<w7$}",
                headers[0],
                headers[1],
                headers[2],
                headers[3],
                headers[4],
                headers[5],
                headers[6],
                headers[7],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2],
                w3 = widths[3],
                w4 = widths[4],
                w5 = widths[5],
                w6 = widths[6],
                w7 = widths[7]
            );
            println!(
                "{:-<w0$}  {:-<w1$}  {:-<w2$}  {:-<w3$}  {:-<w4$}  {:-<w5$}  {:-<w6$}  {:-<w7$}",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2],
                w3 = widths[3],
                w4 = widths[4],
                w5 = widths[5],
                w6 = widths[6],
                w7 = widths[7]
            );
            for row in rows {
                println!(
                    "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {:<w5$}  {:<w6$}  {:<w7$}",
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                    row[5],
                    row[6],
                    row[7],
                    w0 = widths[0],
                    w1 = widths[1],
                    w2 = widths[2],
                    w3 = widths[3],
                    w4 = widths[4],
                    w5 = widths[5],
                    w6 = widths[6],
                    w7 = widths[7]
                );
            }
            return;
        }

        match tokens[1].as_str() {
            "-k" | "--kill" => {
                let Some(id_raw) = tokens.get(2) else {
                    println!("{}", self.palette.warning("Usage: sessions -k <id>"));
                    return;
                };
                let Ok(id) = id_raw.parse::<u32>() else {
                    println!("{}", self.palette.error("Session id must be an integer."));
                    return;
                };
                let explicit_yes = tokens
                    .iter()
                    .any(|token| token.eq_ignore_ascii_case("--yes") || token.eq_ignore_ascii_case("-y"));
                let decision = self.policy.evaluate(&PolicyRequest::close_session());
                match decision.kind {
                    DecisionKind::Deny => {
                        println!(
                            "{}",
                            self.palette.error(&format!("Policy blocked session close: {}", decision.reason))
                        );
                        return;
                    }
                    DecisionKind::RequireConfirmation if !explicit_yes => {
                        if !self
                            .confirm_intent(&format!("{} [yes/no]: ", decision.reason))
                            .unwrap_or(false)
                        {
                            println!("{}", self.palette.warning("Session close canceled."));
                            return;
                        }
                    }
                    _ => {}
                }
                match self.sessions.close_and_remove(id) {
                    Ok(true) => {
                        println!("{}", self.palette.success(&format!("Session {id} closed.")))
                    }
                    Ok(false) => println!(
                        "{}",
                        self.palette.error(&format!("Session {id} not found."))
                    ),
                    Err(err) => println!(
                        "{}",
                        self.palette
                            .error(&format!("Failed to close session {id}: {err}"))
                    ),
                }
            }
            "-r" | "--read" => {
                let Some(id_raw) = tokens.get(2) else {
                    println!("{}", self.palette.warning("Usage: sessions -r <id>"));
                    return;
                };
                let Ok(id) = id_raw.parse::<u32>() else {
                    println!("{}", self.palette.error("Session id must be an integer."));
                    return;
                };
                if let Err(err) = self.sessions.poll(id) {
                    println!("{}", self.palette.error(&format!("{err}")));
                    return;
                }
                match self.sessions.read_buffered(id) {
                    Ok(data) if data.is_empty() => {
                        println!(
                            "{}",
                            self.palette.info(&format!("Session {id} has no buffered output."))
                        );
                    }
                    Ok(data) => {
                        print!("{}", String::from_utf8_lossy(&data));
                    }
                    Err(err) => println!("{}", self.palette.error(&format!("{err}"))),
                }
            }
            "-R" | "--read-all" => {
                for outcome in self.sessions.poll_all() {
                    if let Some(err) = outcome.error {
                        if outcome.is_partitioned {
                            eprintln!("session {} partitioned: {}", outcome.id, err);
                        } else {
                            eprintln!("session {} poll error: {}", outcome.id, err);
                        }
                    }
                }
                let recovered = self.sessions.recover_partitioned();
                if !recovered.is_empty() {
                    println!(
                        "{}",
                        self.palette.success(&format!(
                            "Recovered partitioned session(s): {}",
                            recovered
                                .iter()
                                .map(|id| id.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    );
                }
                let outputs = self.sessions.read_all_background();
                if outputs.is_empty() {
                    println!("{}", self.palette.info("No background output available."));
                    return;
                }
                for (id, bytes) in outputs {
                    println!("{}", self.palette.info(&format!("[session {id}]")));
                    print!("{}", String::from_utf8_lossy(&bytes));
                }
            }
            "-K" | "--kill-all" => {
                let explicit_yes = tokens
                    .iter()
                    .any(|token| token.eq_ignore_ascii_case("--yes") || token.eq_ignore_ascii_case("-y"));
                let decision = self.policy.evaluate(&PolicyRequest::close_all_sessions());
                match decision.kind {
                    DecisionKind::Deny => {
                        println!(
                            "{}",
                            self.palette
                                .error(&format!("Policy blocked close-all: {}", decision.reason))
                        );
                        return;
                    }
                    DecisionKind::RequireConfirmation if !explicit_yes => {
                        if !self
                            .confirm_intent(&format!("{} [yes/no]: ", decision.reason))
                            .unwrap_or(false)
                        {
                            println!("{}", self.palette.warning("Close-all canceled."));
                            return;
                        }
                    }
                    _ => {}
                }

                match self.sessions.close_all() {
                    Ok(count) => println!(
                        "{}",
                        self.palette.success(&format!("Closed {count} session(s)."))
                    ),
                    Err(err) => println!(
                        "{}",
                        self.palette
                            .error(&format!("Failed to close sessions: {err}"))
                    ),
                }
            }
            _ => println!(
                "{}",
                self.palette
                    .warning("Usage: sessions | sessions -k <id> [--yes] | sessions -K [--yes] | sessions -r <id> | sessions -R")
            ),
        }
    }

    fn cmd_policy(&mut self, tokens: &[String]) {
        if tokens.len() == 1 {
            let granted = self.policy.granted_capabilities();
            println!("{}", self.palette.info("Policy Guardrails"));
            if granted.is_empty() {
                println!(
                    "{}",
                    self.palette
                        .warning("No elevated capabilities enabled (safe-by-default mode active).")
                );
            } else {
                println!("Enabled capabilities:");
                for capability in granted {
                    println!("  - {}", capability.as_str());
                }
            }
            println!("Available capabilities:");
            for capability in all_capabilities() {
                println!("  - {}", capability.as_str());
            }
            return;
        }

        if tokens.len() < 3 {
            println!(
                "{}",
                self.palette
                    .warning("Usage: policy <enable|disable> <capability>")
            );
            return;
        }

        let action = tokens[1].to_ascii_lowercase();
        let Some(capability) = Capability::parse(&tokens[2]) else {
            println!(
                "{}",
                self.palette
                    .error(&format!("Unknown capability: {}", tokens[2]))
            );
            return;
        };

        match action.as_str() {
            "enable" => {
                self.policy.grant(capability);
                println!(
                    "{}",
                    self.palette
                        .success(&format!("Enabled capability: {}", capability.as_str()))
                );
            }
            "disable" => {
                self.policy.revoke(capability);
                println!(
                    "{}",
                    self.palette
                        .success(&format!("Disabled capability: {}", capability.as_str()))
                );
            }
            _ => println!(
                "{}",
                self.palette
                    .warning("Usage: policy <enable|disable> <capability>")
            ),
        }
    }

    fn cmd_interact(&mut self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!("{}", self.palette.warning("Usage: interact <id>"));
            return;
        }
        let Ok(id) = tokens[1].parse::<u32>() else {
            println!("{}", self.palette.error("Session id must be an integer."));
            return;
        };
        if !self.sessions.has(id) {
            println!(
                "{}",
                self.palette.error(&format!("Session {id} not found."))
            );
            return;
        }
        if let Err(err) = self.interact_session(id) {
            println!("{}", self.palette.error(&format!("Interact error: {err}")));
        }
    }

    fn interact_session(&mut self, id: u32) -> Result<(), ReplError> {
        self.sessions
            .attach(id)
            .map_err(|e| ReplError::Io(format!("session attach failed: {e}")))?;

        let result = (|| -> Result<(), ReplError> {
            loop {
                if !self.sessions.has(id) {
                    println!("{}", self.palette.warning(&format!("Session {id} closed.")));
                    return Ok(());
                }
                self.sessions
                    .poll(id)
                    .map_err(|e| ReplError::Io(format!("session read failed: {e}")))?;
                let pending = self
                    .sessions
                    .read_buffered(id)
                    .map_err(|e| ReplError::Io(format!("session read failed: {e}")))?;
                if !pending.is_empty() {
                    print!("{}", String::from_utf8_lossy(&pending));
                }
                let prompt = format!("session({id})> ");
                let completer = ReplCompleter { repl: self };
                let line = read_line(&prompt, &completer, self.history.entries())
                    .map_err(|e| ReplError::Io(e.to_string()))?;
                let Some(line) = line else {
                    return Ok(());
                };
                let line = line.trim_end();
                if line.is_empty() {
                    continue;
                }
                self.history.add(format!("session({id}) {line}"));
                let lowered = line.to_ascii_lowercase();
                if lowered == "background" || lowered == "bg" {
                    println!(
                        "{}",
                        self.palette.info(&format!("Backgrounded session {id}."))
                    );
                    return Ok(());
                }
                if lowered == "exit" || lowered == "quit" {
                    self.sessions
                        .close_and_remove(id)
                        .map_err(|e| ReplError::Io(format!("session close failed: {e}")))?;
                    println!("{}", self.palette.success(&format!("Session {id} closed.")));
                    return Ok(());
                }
                let mut payload = line.as_bytes().to_vec();
                payload.push(b'\n');
                self.sessions
                    .write(id, &payload)
                    .map_err(|e| ReplError::Io(format!("session write failed: {e}")))?;
                self.sessions
                    .poll(id)
                    .map_err(|e| ReplError::Io(format!("session read failed: {e}")))?;
                let response = self
                    .sessions
                    .read_buffered(id)
                    .map_err(|e| ReplError::Io(format!("session read failed: {e}")))?;
                if !response.is_empty() {
                    print!("{}", String::from_utf8_lossy(&response));
                }
            }
        })();

        if self.sessions.is_attached(id) {
            let _ = self.sessions.detach(id);
        }

        result
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
            print_options_table(options);
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

    fn confirm_intent(&self, prompt: &str) -> Result<bool, ReplError> {
        print!("{prompt}");
        io::stdout()
            .flush()
            .map_err(|e| ReplError::Io(e.to_string()))?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| ReplError::Io(e.to_string()))?;
        let answer = input.trim().to_ascii_lowercase();
        Ok(matches!(answer.as_str(), "yes" | "y"))
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

fn extract_target_from_options(options: &modules::ModuleOptions) -> Option<String> {
    const TARGET_KEYS: &[&str] = &[
        "rhost",
        "rhosts",
        "target",
        "host",
        "address",
        "ip",
        "remote_host",
    ];

    for option in options.iter() {
        if TARGET_KEYS
            .iter()
            .any(|key| option.name.eq_ignore_ascii_case(key))
        {
            let value = option.value_as_string();
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn all_capabilities() -> &'static [Capability] {
    &[
        Capability::ExploitExecution,
        Capability::PayloadExecution,
        Capability::EvasionExecution,
        Capability::PublicTargets,
        Capability::WideTargetScope,
        Capability::BulkSessionControl,
    ]
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
                "interact" => {
                    if token_index == 1 {
                        candidates = session_id_candidates(self, current);
                    }
                }
                "sessions" => {
                    if token_index == 1 {
                        candidates = [
                            "-k",
                            "--kill",
                            "-K",
                            "--kill-all",
                            "-r",
                            "--read",
                            "-R",
                            "--read-all",
                        ]
                        .iter()
                        .filter(|v| v.starts_with(current))
                        .map(|v| v.to_string())
                        .collect();
                    } else if token_index == 2 {
                        if matches!(
                            tokens.get(1),
                            Some(&"-k") | Some(&"--kill") | Some(&"-r") | Some(&"--read")
                        ) {
                            candidates = session_id_candidates(self, current);
                        }
                    }
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
        "help", "show", "use", "search", "set", "get", "run", "sessions", "interact", "history",
        "info", "exit", "quit",
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

fn session_id_candidates(repl: &Repl, prefix: &str) -> Vec<String> {
    repl.sessions
        .snapshots()
        .into_iter()
        .map(|snap| snap.id.to_string())
        .filter(|id| id.starts_with(prefix))
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

fn print_options_table(options: &modules::ModuleOptions) {
    let headers = ["Name", "Value", "Type", "Required", "Default"];
    let mut rows: Vec<[String; 5]> = Vec::new();
    let mut widths = [
        headers[0].len(),
        headers[1].len(),
        headers[2].len(),
        headers[3].len(),
        headers[4].len(),
    ];

    for opt in options.iter() {
        let value = opt
            .value
            .as_ref()
            .map(|v| v.as_string())
            .unwrap_or_default();
        let default = opt
            .default
            .as_ref()
            .map(|v| v.as_string())
            .unwrap_or_default();
        let kind = opt.kind_string().to_string();
        let required = if opt.required { "yes" } else { "no" }.to_string();
        let row = [opt.name.clone(), value, kind, required, default];
        for (idx, col) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(col.len());
        }
        rows.push(row);
    }

    println!(
        "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}",
        headers[0],
        headers[1],
        headers[2],
        headers[3],
        headers[4],
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4]
    );
    println!(
        "{:-<w0$}  {:-<w1$}  {:-<w2$}  {:-<w3$}  {:-<w4$}",
        "",
        "",
        "",
        "",
        "",
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
        w4 = widths[4]
    );

    for row in rows {
        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}",
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4]
        );
    }
}
