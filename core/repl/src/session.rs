use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

use corelib::campaign::{
    validate_prerequisite_graph, Campaign, CampaignId, MetadataValue, Objective,
    ObjectiveEvaluationEngine, ObjectiveId, ObjectiveReevaluationTrigger, Predicate,
    PredicateSnapshot, RiskLevel, SessionPrivilegeLevel,
};
use corelib::ids::Id;
use corelib::policy::{
    Capability, DecisionKind, ModuleContext as PolicyModuleContext, PolicyEngine, PolicyRequest,
};
use corelib::release::{
    CompatibilityCase, CompatibilityMatrix, DocumentationGate, DocumentationGateSuite,
    MigrationPlan, MigrationPolicy, ReleaseChecklistTemplate, ReleaseCompatibilityPolicy,
    RollbackRegistry, VersionWindow, VersionedControlState,
};
use corelib::time::now_secs;
use modules::{
    load_dyn_module, Module, ModuleCatalog, ModuleCategory, ModuleCompatibilityPolicy,
    ModuleContext, ModuleRank, ModuleRegistry, SearchQuery,
};

use crate::ansi::Palette;
use crate::contract::{escape_json, CliCode, CommandResponse, OutputMode};
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
    output_mode: OutputMode,
    release_compat_policy: ReleaseCompatibilityPolicy,
    release_migration_policy: MigrationPolicy,
    release_state: VersionedControlState,
    release_rollback: RollbackRegistry,
    release_doc_gates: DocumentationGateSuite,
    release_checklist: ReleaseChecklistTemplate,
    campaigns: BTreeMap<CampaignId, Campaign>,
    objectives: BTreeMap<ObjectiveId, Objective>,
    palette: Palette,
}

#[derive(Debug, Clone, Copy)]
struct CommandHelpSpec {
    name: &'static str,
    summary: &'static str,
    usage: &'static str,
    aliases: &'static [&'static str],
    examples: &'static [&'static str],
    notes: &'static [&'static str],
}

const COMMAND_HELP: &[CommandHelpSpec] = &[
    CommandHelpSpec {
        name: "help",
        summary: "Show general help or help for one command",
        usage: "help [command]",
        aliases: &[],
        examples: &["help", "help run", "help release"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "clear",
        summary: "Clear terminal screen",
        usage: "clear",
        aliases: &["cls"],
        examples: &["clear"],
        notes: &[
            "In JSON output mode, clear returns a normal command response instead of terminal control bytes.",
        ],
    },
    CommandHelpSpec {
        name: "show",
        summary: "Show modules/options/globals",
        usage: "show modules | show options | show globals",
        aliases: &[],
        examples: &["show modules", "show options", "show globals"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "use",
        summary: "Select a module",
        usage: "use <module>",
        aliases: &[],
        examples: &["use exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "search",
        summary: "Search module catalog",
        usage: "search <query> [--category <cat>] [--rank <rank>] [--platform <platform>] [--tag <tag>] [--limit <n>]",
        aliases: &[],
        examples: &["search telnet", "search hash --category auxiliary --limit 10"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "info",
        summary: "Show module metadata and options",
        usage: "info [module]",
        aliases: &[],
        examples: &["info", "info exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "set",
        summary: "Set module option value",
        usage: "set <option> <value>",
        aliases: &[],
        examples: &["set RHOST <ip-addr>", "set RPORT <port>"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "get",
        summary: "Get module option value",
        usage: "get <option>",
        aliases: &[],
        examples: &["get RHOST"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "setg",
        summary: "Set global setting",
        usage: "setg <key> <value>",
        aliases: &[],
        examples: &[
            "setg output_mode json",
            "setg session_max_pending_bytes 65536",
            "setg session_drain_bytes 4096",
        ],
        notes: &[],
    },
    CommandHelpSpec {
        name: "getg",
        summary: "Get global setting",
        usage: "getg <key>",
        aliases: &[],
        examples: &["getg output_mode", "getg session_max_pending_bytes"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "run",
        summary: "Execute active module",
        usage: "run [--yes]",
        aliases: &[],
        examples: &["run", "run --yes"],
        notes: &["--yes skips confirmation prompts for that execution."],
    },
    CommandHelpSpec {
        name: "output",
        summary: "Show or set output mode",
        usage: "output [human|json]",
        aliases: &[],
        examples: &["output", "output json"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "policy",
        summary: "Show or update safety capabilities",
        usage: "policy | policy <enable|disable> <capability>",
        aliases: &[],
        examples: &["policy", "policy enable exploit_execution", "policy disable public_targets"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "release",
        summary: "Run release readiness, migration, and rollback workflows",
        usage: "release | release check | release matrix | release migrate ... | release rollback ...",
        aliases: &[],
        examples: &[
            "release check",
            "release migrate plan 1 3",
            "release rollback snapshot pre-release",
        ],
        notes: &[],
    },
    CommandHelpSpec {
        name: "campaign",
        summary: "Manage campaigns",
        usage: "campaign create <name> [description] | campaign list | campaign show <campaign-id> | campaign status [campaign-id [active|paused|completed|failed]]",
        aliases: &[],
        examples: &[
            "campaign create operation-alpha \"Internal validation operation\"",
            "campaign list",
            "campaign status <campaign-id> paused",
        ],
        notes: &[],
    },
    CommandHelpSpec {
        name: "objective",
        summary: "Manage objectives",
        usage: "objective create <campaign-id> <name> --success <predicate[,predicate...]> [--failure <predicate[,predicate...]>] [--risk <low|medium|high>] [--noise-budget <n>] [--description <text>] | objective link-prereq <objective-id> <prerequisite-id> | objective list [campaign-id] | objective status [objective-id [start|evaluate]]",
        aliases: &[],
        examples: &[
            "objective create <campaign-id> foothold --success finding_exists:shell_access --risk high",
            "objective link-prereq <objective-id> <prerequisite-id>",
            "objective status <objective-id> start",
        ],
        notes: &[
            "Predicate formats: finding_exists:<type>, session_privilege:<user|elevated|root>, artifact_tag_match:<tag>, run_succeeded:<module>, custom_metadata_match:<key>=<value>",
        ],
    },
    CommandHelpSpec {
        name: "sessions",
        summary: "List/read/close sessions",
        usage: "sessions | sessions -r <id> | sessions -R | sessions -k <id> [--yes] | sessions -K [--yes]",
        aliases: &[],
        examples: &["sessions", "sessions -r 1", "sessions -k 1 --yes"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "interact",
        summary: "Attach interactive shell to session",
        usage: "interact <session-id>",
        aliases: &[],
        examples: &["interact 1"],
        notes: &["Inside interact mode, use 'background' to detach without closing session."],
    },
    CommandHelpSpec {
        name: "history",
        summary: "Show command history",
        usage: "history",
        aliases: &[],
        examples: &["history"],
        notes: &[],
    },
    CommandHelpSpec {
        name: "exit",
        summary: "Exit the console",
        usage: "exit",
        aliases: &["quit"],
        examples: &["exit", "quit"],
        notes: &[],
    },
];

impl Repl {
    pub fn new(prompt: String, registry: ModuleRegistry, catalog: Option<ModuleCatalog>) -> Self {
        let module_compat = ModuleCompatibilityPolicy::catalog_default();
        let release_compat_policy = ReleaseCompatibilityPolicy::new(
            VersionWindow::new(
                module_compat.min_manifest_version,
                module_compat.max_manifest_version,
            )
            .expect("fixed module manifest range"),
            VersionWindow::new(
                module_compat.min_module_api_version,
                module_compat.max_module_api_version,
            )
            .expect("fixed module API range"),
            VersionWindow::new(1, 3).expect("fixed control-state range"),
            vec!["human".to_string(), "json".to_string()],
            vec!["builtin".to_string(), "dynlib".to_string()],
        )
        .expect("fixed release compatibility policy");

        let release_migration_policy = MigrationPolicy::default_control_plane();
        let release_state =
            VersionedControlState::new(release_migration_policy.supported_min_version)
                .expect("default schema version");
        let release_doc_gates = DocumentationGateSuite::new(vec![
            DocumentationGate::new(
                "module-usage",
                "docs/guide/modules.md",
                vec![
                    "module authoring guide".to_string(),
                    "repl usage".to_string(),
                ],
            )
            .expect("module docs gate"),
            DocumentationGate::new(
                "release-usage",
                "docs/guide/release_operations.md",
                vec![
                    "release operations guide".to_string(),
                    "release command usage".to_string(),
                    "migration workflow".to_string(),
                    "rollback workflow".to_string(),
                    "documentation completeness gates".to_string(),
                ],
            )
            .expect("release docs gate"),
        ])
        .expect("release docs suite");

        Repl {
            prompt_base: normalize_prompt(&prompt),
            registry,
            catalog,
            history: History::new(500),
            active: None,
            session_id: Id::next(),
            sessions: SessionManager::new(),
            policy: PolicyEngine::new(),
            output_mode: OutputMode::Human,
            release_compat_policy,
            release_migration_policy,
            release_state,
            release_rollback: RollbackRegistry::default(),
            release_doc_gates,
            release_checklist: ReleaseChecklistTemplate::default_control_plane(),
            campaigns: BTreeMap::new(),
            objectives: BTreeMap::new(),
            palette: Palette::new(),
        }
    }

    pub fn run(&mut self) -> Result<(), ReplError> {
        loop {
            let mut _polled_bytes = 0usize;
            for outcome in self.sessions.poll_all() {
                _polled_bytes = _polled_bytes.saturating_add(outcome.bytes_read);
                if let Some(err) = outcome.error {
                    if self.output_mode.is_json() {
                        self.emit_response(
                            CommandResponse::err("sessions", CliCode::Execution, &err)
                                .with_field("session_id", outcome.id)
                                .with_field("partitioned", outcome.is_partitioned),
                        );
                    } else if outcome.is_partitioned {
                        eprintln!("session {} partitioned: {}", outcome.id, err);
                    } else {
                        eprintln!("session {} poll error: {}", outcome.id, err);
                    }
                }
            }
            let recovered = self.sessions.recover_partitioned();
            if !recovered.is_empty() {
                self.emit_response(
                    CommandResponse::ok("sessions", "recovered partitioned sessions")
                        .with_field("count", recovered.len()),
                );
            }
            let reaped_stale = self.sessions.reap_stale();
            if !reaped_stale.is_empty() {
                self.emit_response(
                    CommandResponse::ok("sessions", "reaped stale sessions")
                        .with_field("count", reaped_stale.len()),
                );
            }
            let reaped_partitioned = self.sessions.reap_partitioned();
            if !reaped_partitioned.is_empty() {
                self.emit_response(
                    CommandResponse::ok("sessions", "reaped partitioned sessions")
                        .with_field("count", reaped_partitioned.len()),
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
            "help" => self.cmd_help(tokens),
            "clear" | "cls" => self.cmd_clear(),
            "exit" | "quit" => return true,
            "history" => self.cmd_history(),
            "use" => self.cmd_use(tokens),
            "show" => self.cmd_show(tokens),
            "search" => self.cmd_search(tokens),
            "set" => self.cmd_set(tokens),
            "get" => self.cmd_get(tokens),
            "setg" => self.cmd_setg(tokens),
            "getg" => self.cmd_getg(tokens),
            "run" => self.cmd_run(tokens),
            "output" => self.cmd_output(tokens),
            "policy" => self.cmd_policy(tokens),
            "release" => self.cmd_release(tokens),
            "campaign" => self.cmd_campaign(tokens),
            "objective" => self.cmd_objective(tokens),
            "info" => self.cmd_info(tokens),
            "sessions" => self.cmd_sessions(tokens),
            "interact" => self.cmd_interact(tokens),
            _ => self.emit_error(
                "command",
                CliCode::NotFound,
                &format!("unknown command: {}", tokens[0]),
            ),
        }
        false
    }

    fn cmd_help(&self, tokens: &[String]) {
        if tokens.len() == 1 {
            if self.output_mode.is_json() {
                let commands = command_primary_names().join(",");
                self.emit_response(
                    CommandResponse::ok("help", "available commands")
                        .with_field("count", COMMAND_HELP.len())
                        .with_field("commands", commands),
                );
                return;
            }
            println!("Commands:");
            for spec in COMMAND_HELP {
                println!("  {:<16} {}", spec.name, spec.summary);
            }
            println!("Run 'help <command>' for detailed usage.");
            return;
        }

        let topic = tokens[1].to_ascii_lowercase();
        let Some(spec) = find_command_help(&topic) else {
            self.emit_error(
                "help",
                CliCode::NotFound,
                &format!(
                    "unknown command for help: {} (run 'help' to list commands)",
                    tokens[1]
                ),
            );
            return;
        };

        self.emit_response(
            CommandResponse::ok("help", "command help")
                .with_field("command", spec.name)
                .with_field("usage", spec.usage),
        );
        if self.output_mode.is_json() {
            return;
        }

        println!("Description: {}", spec.summary);
        println!("Usage:       {}", spec.usage);
        if !spec.aliases.is_empty() {
            println!("Aliases:     {}", spec.aliases.join(", "));
        }
        if !spec.examples.is_empty() {
            println!("Examples:");
            for example in spec.examples {
                println!("  {}", example);
            }
        }
        if !spec.notes.is_empty() {
            println!("Notes:");
            for note in spec.notes {
                println!("  - {}", note);
            }
        }
    }

    fn cmd_clear(&self) {
        if self.output_mode.is_json() {
            self.emit_ok("clear", "screen cleared");
            return;
        }
        print!("\x1b[2J\x1b[H");
        let _ = io::stdout().flush();
    }

    fn cmd_history(&self) {
        for (idx, entry) in self.history.iter() {
            println!("{:>4}  {}", idx + 1, entry);
        }
    }

    fn cmd_use(&mut self, tokens: &[String]) {
        if tokens.len() < 2 {
            self.emit_error("use", CliCode::Usage, "usage: use <module>");
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
                                self.emit_ok_with_field("use", "module selected", "module", name);
                                return;
                            }
                            Err(err) => {
                                self.emit_error(
                                    "use",
                                    CliCode::Execution,
                                    &format!("module load failed: {err}"),
                                );
                                return;
                            }
                        }
                    }
                }
            }
            self.emit_error(
                "use",
                CliCode::NotFound,
                &format!("module not found: {name}"),
            );
            return;
        };
        self.active = Some(module);
        self.emit_ok_with_field("use", "module selected", "module", name);
    }

    fn cmd_show(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            println!(
                "{}",
                self.palette
                    .warning("Usage: show <modules|options|globals>")
            );
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
            "globals" => {
                self.emit_response(
                    CommandResponse::ok("show", "global settings")
                        .with_field("output_mode", self.output_mode.as_str()),
                );
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
            self.emit_error("set", CliCode::Usage, "usage: set <option> <value>");
            return;
        }
        if self.active.is_none() {
            self.emit_error("set", CliCode::Validation, "no active module");
            return;
        }
        let key = &tokens[1];
        let value = tokens[2..].join(" ");
        let set_result = {
            let module = self.active.as_mut().expect("checked is_some");
            module.options_mut().set(key, &value)
        };
        if let Err(err) = set_result {
            self.emit_error("set", CliCode::Validation, &err);
            return;
        }
        self.emit_response(
            CommandResponse::ok("set", "option updated")
                .with_field("option", key)
                .with_field("value", value),
        );
    }

    fn cmd_get(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            self.emit_error("get", CliCode::Usage, "usage: get <option>");
            return;
        }
        let Some(module) = &self.active else {
            self.emit_error("get", CliCode::Validation, "no active module");
            return;
        };
        let key = &tokens[1];
        let Some(opt) = module.options().get(key) else {
            self.emit_error("get", CliCode::NotFound, &format!("unknown option: {key}"));
            return;
        };
        self.emit_response(
            CommandResponse::ok("get", "option value")
                .with_field("option", &opt.name)
                .with_field("value", opt.value_as_string()),
        );
    }

    fn cmd_setg(&mut self, tokens: &[String]) {
        if tokens.len() < 3 {
            self.emit_error("setg", CliCode::Usage, "usage: setg <key> <value>");
            return;
        }
        let key = tokens[1].to_ascii_lowercase();
        let value = tokens[2..].join(" ");
        match key.as_str() {
            "output_mode" | "output" => {
                let Some(mode) = OutputMode::parse(&value) else {
                    self.emit_error(
                        "setg",
                        CliCode::Validation,
                        "output_mode must be one of: human|json",
                    );
                    return;
                };
                self.output_mode = mode;
                self.emit_response(
                    CommandResponse::ok("setg", "global setting updated")
                        .with_field("key", "output_mode")
                        .with_field("value", mode.as_str()),
                );
            }
            "session_max_pending_bytes" | "session_pending_bytes" => {
                let Ok(parsed) = value.parse::<usize>() else {
                    self.emit_error(
                        "setg",
                        CliCode::Validation,
                        "session_max_pending_bytes must be a positive integer",
                    );
                    return;
                };
                if parsed == 0 {
                    self.emit_error(
                        "setg",
                        CliCode::Validation,
                        "session_max_pending_bytes must be greater than zero",
                    );
                    return;
                }
                self.sessions.set_max_pending_bytes(parsed);
                self.emit_response(
                    CommandResponse::ok("setg", "global setting updated")
                        .with_field("key", "session_max_pending_bytes")
                        .with_field("value", parsed),
                );
            }
            "session_drain_bytes" | "session_read_drain_bytes" => {
                let Ok(parsed) = value.parse::<usize>() else {
                    self.emit_error(
                        "setg",
                        CliCode::Validation,
                        "session_drain_bytes must be a positive integer",
                    );
                    return;
                };
                if parsed == 0 {
                    self.emit_error(
                        "setg",
                        CliCode::Validation,
                        "session_drain_bytes must be greater than zero",
                    );
                    return;
                }
                self.sessions.set_default_drain_bytes(parsed);
                self.emit_response(
                    CommandResponse::ok("setg", "global setting updated")
                        .with_field("key", "session_drain_bytes")
                        .with_field("value", parsed),
                );
            }
            _ => self.emit_error(
                "setg",
                CliCode::NotFound,
                &format!("unknown global key: {key}"),
            ),
        }
    }

    fn cmd_getg(&self, tokens: &[String]) {
        if tokens.len() < 2 {
            self.emit_error("getg", CliCode::Usage, "usage: getg <key>");
            return;
        }
        let key = tokens[1].to_ascii_lowercase();
        match key.as_str() {
            "output_mode" | "output" => {
                self.emit_response(
                    CommandResponse::ok("getg", "global setting")
                        .with_field("key", "output_mode")
                        .with_field("value", self.output_mode.as_str()),
                );
            }
            "session_max_pending_bytes" | "session_pending_bytes" => {
                self.emit_response(
                    CommandResponse::ok("getg", "global setting")
                        .with_field("key", "session_max_pending_bytes")
                        .with_field("value", self.sessions.max_pending_bytes()),
                );
            }
            "session_drain_bytes" | "session_read_drain_bytes" => {
                self.emit_response(
                    CommandResponse::ok("getg", "global setting")
                        .with_field("key", "session_drain_bytes")
                        .with_field("value", self.sessions.default_drain_bytes()),
                );
            }
            _ => self.emit_error(
                "getg",
                CliCode::NotFound,
                &format!("unknown global key: {key}"),
            ),
        }
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
            self.emit_error("run", CliCode::Validation, "no active module");
            return;
        };
        if let Err(err) = module.options().validate() {
            self.emit_error(
                "run",
                CliCode::Validation,
                &format!("option validation failed: {err}"),
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
                self.emit_error(
                    "run",
                    CliCode::Validation,
                    &format!("policy metadata error: {err}"),
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
                self.emit_error(
                    "run",
                    CliCode::PolicyDenied,
                    &format!("policy blocked run: {}", decision.reason),
                );
                return;
            }
            DecisionKind::RequireConfirmation if !explicit_yes => {
                if !self
                    .confirm_intent(&format!("{} [yes/no]: ", decision.reason))
                    .unwrap_or(false)
                {
                    self.emit_error("run", CliCode::PolicyDenied, "run canceled by confirmation");
                    return;
                }
            }
            _ => {}
        }

        let ctx = ModuleContext {
            session_id: self.session_id.0,
        };
        let Some(module) = self.active.as_mut() else {
            self.emit_error("run", CliCode::Validation, "no active module");
            return;
        };
        let module_name = module.metadata().name.clone();
        match module.run(&ctx) {
            Ok(mut result) => {
                if let Some(session) = result.take_session() {
                    let kind = session.kind().to_string();
                    let target = session.target();
                    let id = self.sessions.register(module_name, session);
                    self.emit_response(
                        CommandResponse::ok("run", "module executed; session opened")
                            .with_field("session_id", id)
                            .with_field("session_type", kind)
                            .with_field("target", target),
                    );
                    return;
                }
                if result.success {
                    self.emit_response(
                        CommandResponse::ok("run", "module executed")
                            .with_field("message", result.message),
                    );
                } else {
                    self.emit_error("run", CliCode::Execution, &result.message);
                }
            }
            Err(err) => self.emit_error("run", CliCode::Execution, &format!("module error: {err}")),
        }
    }

    fn cmd_sessions(&mut self, tokens: &[String]) {
        self.sessions.reap_closed();
        if tokens.len() == 1 {
            let snapshots = self.sessions.snapshots();
            if snapshots.is_empty() {
                self.emit_response(
                    CommandResponse::ok("sessions", "no active sessions").with_field("count", 0),
                );
                return;
            }
            if self.output_mode.is_json() {
                let sessions_json = snapshots
                    .iter()
                    .map(|snap| {
                        format!(
                            "{{\"id\":{},\"state\":\"{}\",\"attach\":\"{}\",\"pending_bytes\":{},\"idle_secs\":{},\"type\":\"{}\",\"target\":\"{}\",\"module\":\"{}\"}}",
                            snap.id,
                            if !snap.is_open {
                                "closed".to_string()
                            } else if snap.is_partitioned {
                                format!(
                                    "partitioned({}s,e={})",
                                    snap.partition_age_secs.unwrap_or(0),
                                    snap.consecutive_errors
                                )
                            } else {
                                "open".to_string()
                            },
                            if snap.is_attached { "attached" } else { "bg" },
                            snap.pending_bytes,
                            snap.idle_secs,
                            escape_json(&snap.kind),
                            escape_json(&snap.target),
                            escape_json(&snap.module_name)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{{\"command\":\"sessions\",\"ok\":true,\"code\":\"{}\",\"message\":\"listed sessions\",\"count\":{},\"sessions\":[{}]}}",
                    CliCode::Ok.as_str(),
                    snapshots.len(),
                    sessions_json
                );
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
                    self.emit_error("sessions", CliCode::Usage, "usage: sessions -k <id> [--yes]");
                    return;
                };
                let Ok(id) = id_raw.parse::<u32>() else {
                    self.emit_error("sessions", CliCode::Validation, "session id must be an integer");
                    return;
                };
                let explicit_yes = tokens
                    .iter()
                    .any(|token| token.eq_ignore_ascii_case("--yes") || token.eq_ignore_ascii_case("-y"));
                let decision = self.policy.evaluate(&PolicyRequest::close_session());
                match decision.kind {
                    DecisionKind::Deny => {
                        self.emit_error(
                            "sessions",
                            CliCode::PolicyDenied,
                            &format!("policy blocked session close: {}", decision.reason),
                        );
                        return;
                    }
                    DecisionKind::RequireConfirmation if !explicit_yes => {
                        if !self
                            .confirm_intent(&format!("{} [yes/no]: ", decision.reason))
                            .unwrap_or(false)
                        {
                            self.emit_error("sessions", CliCode::PolicyDenied, "session close canceled");
                            return;
                        }
                    }
                    _ => {}
                }
                match self.sessions.close_and_remove(id) {
                    Ok(true) => self.emit_response(
                        CommandResponse::ok("sessions", "session closed").with_field("session_id", id),
                    ),
                    Ok(false) => {
                        self.emit_error("sessions", CliCode::NotFound, &format!("session {id} not found"))
                    }
                    Err(err) => self.emit_error(
                        "sessions",
                        CliCode::Execution,
                        &format!("failed to close session {id}: {err}"),
                    ),
                }
            }
            "-r" | "--read" => {
                let Some(id_raw) = tokens.get(2) else {
                    self.emit_error("sessions", CliCode::Usage, "usage: sessions -r <id>");
                    return;
                };
                let Ok(id) = id_raw.parse::<u32>() else {
                    self.emit_error("sessions", CliCode::Validation, "session id must be an integer");
                    return;
                };
                if let Err(err) = self.sessions.poll(id) {
                    self.emit_error("sessions", CliCode::Execution, &err.to_string());
                    return;
                }
                match self.sessions.read_buffered(id) {
                    Ok(data) if data.is_empty() => {
                        self.emit_response(
                            CommandResponse::ok("sessions", "session has no buffered output")
                                .with_field("session_id", id)
                                .with_field("bytes", 0),
                        );
                    }
                    Ok(data) => {
                        self.emit_session_output(id, &data);
                    }
                    Err(err) => self.emit_error("sessions", CliCode::Execution, &err.to_string()),
                }
            }
            "-R" | "--read-all" => {
                for outcome in self.sessions.poll_all() {
                    if let Some(err) = outcome.error {
                        if self.output_mode.is_json() {
                            self.emit_response(
                                CommandResponse::err("sessions", CliCode::Execution, &err)
                                    .with_field("session_id", outcome.id)
                                    .with_field("partitioned", outcome.is_partitioned),
                            );
                        } else if outcome.is_partitioned {
                            eprintln!("session {} partitioned: {}", outcome.id, err);
                        } else {
                            eprintln!("session {} poll error: {}", outcome.id, err);
                        }
                    }
                }
                let recovered = self.sessions.recover_partitioned();
                if !recovered.is_empty() {
                    self.emit_response(
                        CommandResponse::ok("sessions", "recovered partitioned sessions")
                            .with_field("count", recovered.len()),
                    );
                }
                let outputs = self.sessions.read_all_background();
                if outputs.is_empty() {
                    self.emit_ok("sessions", "no background output available");
                    return;
                }
                let output_count = outputs.len();
                for (id, bytes) in outputs {
                    if !self.output_mode.is_json() {
                        println!("{}", self.palette.info(&format!("[session {id}]")));
                    }
                    self.emit_session_output(id, &bytes);
                }
                self.emit_response(
                    CommandResponse::ok("sessions", "read buffered output for background sessions")
                        .with_field("count", output_count),
                );
            }
            "-K" | "--kill-all" => {
                let explicit_yes = tokens
                    .iter()
                    .any(|token| token.eq_ignore_ascii_case("--yes") || token.eq_ignore_ascii_case("-y"));
                let decision = self.policy.evaluate(&PolicyRequest::close_all_sessions());
                match decision.kind {
                    DecisionKind::Deny => {
                        self.emit_error(
                            "sessions",
                            CliCode::PolicyDenied,
                            &format!("policy blocked close-all: {}", decision.reason),
                        );
                        return;
                    }
                    DecisionKind::RequireConfirmation if !explicit_yes => {
                        if !self
                            .confirm_intent(&format!("{} [yes/no]: ", decision.reason))
                            .unwrap_or(false)
                        {
                            self.emit_error(
                                "sessions",
                                CliCode::PolicyDenied,
                                "close-all canceled",
                            );
                            return;
                        }
                    }
                    _ => {}
                }

                match self.sessions.close_all() {
                    Ok(count) => self.emit_response(
                        CommandResponse::ok("sessions", "closed sessions")
                            .with_field("count", count),
                    ),
                    Err(err) => self.emit_error(
                        "sessions",
                        CliCode::Execution,
                        &format!("failed to close sessions: {err}"),
                    ),
                }
            }
            _ => self.emit_error(
                "sessions",
                CliCode::Usage,
                "usage: sessions | sessions -k <id> [--yes] | sessions -K [--yes] | sessions -r <id> | sessions -R",
            ),
        }
    }

    fn cmd_output(&mut self, tokens: &[String]) {
        if tokens.len() == 1 {
            self.emit_ok_with_field("output", "output mode", "mode", self.output_mode.as_str());
            return;
        }

        let Some(mode) = OutputMode::parse(&tokens[1]) else {
            self.emit_error("output", CliCode::Usage, "usage: output <human|json>");
            return;
        };

        self.output_mode = mode;
        self.emit_ok_with_field("output", "output mode updated", "mode", mode.as_str());
    }

    fn cmd_policy(&mut self, tokens: &[String]) {
        if tokens.len() == 1 {
            let granted = self.policy.granted_capabilities();
            if self.output_mode.is_json() {
                let caps = granted
                    .iter()
                    .map(|cap| cap.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                self.emit_response(
                    CommandResponse::ok("policy", "policy capabilities")
                        .with_field("enabled_count", granted.len())
                        .with_field("enabled", caps),
                );
                return;
            }
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
            self.emit_error(
                "policy",
                CliCode::Usage,
                "usage: policy <enable|disable> <capability>",
            );
            return;
        }

        let action = tokens[1].to_ascii_lowercase();
        let Some(capability) = Capability::parse(&tokens[2]) else {
            self.emit_error(
                "policy",
                CliCode::Validation,
                &format!("unknown capability: {}", tokens[2]),
            );
            return;
        };

        match action.as_str() {
            "enable" => {
                self.policy.grant(capability);
                self.emit_response(
                    CommandResponse::ok("policy", "capability enabled")
                        .with_field("capability", capability.as_str()),
                );
            }
            "disable" => {
                self.policy.revoke(capability);
                self.emit_response(
                    CommandResponse::ok("policy", "capability disabled")
                        .with_field("capability", capability.as_str()),
                );
            }
            _ => self.emit_error(
                "policy",
                CliCode::Usage,
                "usage: policy <enable|disable> <capability>",
            ),
        }
    }

    fn cmd_release(&mut self, tokens: &[String]) {
        if tokens.len() == 1 {
            self.emit_response(
                CommandResponse::ok("release", "release discipline state")
                    .with_field("schema_version", self.release_state.schema_version)
                    .with_field(
                        "latest_version",
                        self.release_migration_policy.latest_version,
                    )
                    .with_field(
                        "rollback_snapshots",
                        self.release_rollback.list_snapshots().len(),
                    ),
            );
            if !self.output_mode.is_json() {
                println!("Usage:");
                println!("  release check");
                println!("  release matrix");
                println!("  release migrate plan <from> <to>");
                println!("  release migrate apply <to>");
                println!("  release rollback snapshot <label>");
                println!("  release rollback list");
                println!("  release rollback apply <snapshot_id>");
                println!("  release rollback prune <keep_latest>");
            }
            return;
        }

        match tokens[1].to_ascii_lowercase().as_str() {
            "check" => self.cmd_release_check(),
            "matrix" => self.cmd_release_matrix(),
            "migrate" => self.cmd_release_migrate(tokens),
            "rollback" => self.cmd_release_rollback(tokens),
            _ => self.emit_error("release", CliCode::Usage, &release_usage_string()),
        }
    }

    fn cmd_release_check(&mut self) {
        let matrix_report = self
            .build_release_matrix()
            .evaluate(&self.release_compat_policy);
        let docs_root = match std::env::current_dir() {
            Ok(path) => path,
            Err(err) => {
                self.emit_error(
                    "release",
                    CliCode::Io,
                    &format!("failed to resolve workspace root: {err}"),
                );
                return;
            }
        };
        let docs_report = match self.release_doc_gates.evaluate(&docs_root) {
            Ok(report) => report,
            Err(err) => {
                self.emit_error(
                    "release",
                    CliCode::Execution,
                    &format!("documentation gate evaluation failed: {err}"),
                );
                return;
            }
        };

        let migration_path_ok = self
            .release_migration_policy
            .plan(
                self.release_state.schema_version,
                self.release_migration_policy.latest_version,
            )
            .is_ok();
        let rollback_snapshot_ok = self.release_rollback.has_snapshots();
        let docs_usage_ok = docs_report
            .results
            .iter()
            .find(|result| result.name == "release-usage")
            .map(|result| result.passed)
            .unwrap_or(false);

        let mut checklist_status = BTreeMap::new();
        checklist_status.insert(
            "compatibility_matrix".to_string(),
            matrix_report.tests_passed,
        );
        checklist_status.insert("migration_path".to_string(), migration_path_ok);
        checklist_status.insert("rollback_snapshot".to_string(), rollback_snapshot_ok);
        checklist_status.insert("documentation_gates".to_string(), docs_report.all_passed);
        checklist_status.insert("usage_notes".to_string(), docs_usage_ok);

        let checklist_report = self.release_checklist.evaluate(&checklist_status);
        self.emit_response(
            CommandResponse::ok("release", "release readiness evaluated")
                .with_field("ready", checklist_report.ready)
                .with_field("compatibility_ok", matrix_report.tests_passed)
                .with_field("docs_ok", docs_report.all_passed)
                .with_field("migration_path_ok", migration_path_ok)
                .with_field("rollback_snapshot_ok", rollback_snapshot_ok),
        );

        if self.output_mode.is_json() || checklist_report.ready {
            return;
        }

        println!("Blocking checklist items:");
        for failure in checklist_report.failures {
            println!("  - {}: {}", failure.key, failure.description);
        }
    }

    fn cmd_release_matrix(&mut self) {
        let report = self
            .build_release_matrix()
            .evaluate(&self.release_compat_policy);
        self.emit_response(
            CommandResponse::ok("release", "compatibility matrix evaluated")
                .with_field("total_cases", report.total_cases)
                .with_field("passed_cases", report.passed_cases)
                .with_field("failed_cases", report.failed_cases)
                .with_field("tests_passed", report.tests_passed),
        );
        if self.output_mode.is_json() {
            return;
        }

        if report.results.is_empty() {
            println!("No compatibility cases configured.");
            return;
        }

        let headers = ["Case", "Expected", "Actual", "Pass", "Details"];
        let mut rows = Vec::with_capacity(report.results.len());
        let mut widths = [
            headers[0].len(),
            headers[1].len(),
            headers[2].len(),
            headers[3].len(),
            headers[4].len(),
        ];
        for result in report.results {
            let details = if result.failures.is_empty() {
                "-".to_string()
            } else {
                result.failures.join("; ")
            };
            let row = [
                result.case_name,
                bool_word(result.expected_compatible),
                bool_word(result.actual_compatible),
                bool_word(result.test_passed),
                details,
            ];
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

    fn cmd_release_migrate(&mut self, tokens: &[String]) {
        if tokens.len() < 3 {
            self.emit_error("release", CliCode::Usage, &release_usage_string());
            return;
        }

        match tokens[2].to_ascii_lowercase().as_str() {
            "plan" => {
                let (from_version, to_version) = if tokens.len() == 5 {
                    let Ok(from) = tokens[3].parse::<u32>() else {
                        self.emit_error(
                            "release",
                            CliCode::Validation,
                            "from version must be an integer",
                        );
                        return;
                    };
                    let Ok(to) = tokens[4].parse::<u32>() else {
                        self.emit_error(
                            "release",
                            CliCode::Validation,
                            "to version must be an integer",
                        );
                        return;
                    };
                    (from, to)
                } else if tokens.len() == 4 {
                    let Ok(to) = tokens[3].parse::<u32>() else {
                        self.emit_error(
                            "release",
                            CliCode::Validation,
                            "to version must be an integer",
                        );
                        return;
                    };
                    (self.release_state.schema_version, to)
                } else {
                    self.emit_error(
                        "release",
                        CliCode::Usage,
                        "usage: release migrate plan <from> <to> | release migrate plan <to>",
                    );
                    return;
                };

                match self.release_migration_policy.plan(from_version, to_version) {
                    Ok(plan) => self.emit_migration_plan(&plan),
                    Err(err) => {
                        self.emit_error("release", CliCode::Execution, &err.to_string());
                    }
                }
            }
            "apply" => {
                if tokens.len() != 4 {
                    self.emit_error(
                        "release",
                        CliCode::Usage,
                        "usage: release migrate apply <to>",
                    );
                    return;
                }
                let Ok(target_version) = tokens[3].parse::<u32>() else {
                    self.emit_error(
                        "release",
                        CliCode::Validation,
                        "target version must be an integer",
                    );
                    return;
                };

                let from_version = self.release_state.schema_version;
                let plan = match self
                    .release_migration_policy
                    .plan(from_version, target_version)
                {
                    Ok(plan) => plan,
                    Err(err) => {
                        self.emit_error("release", CliCode::Execution, &err.to_string());
                        return;
                    }
                };

                let snapshot = match self.release_rollback.create_snapshot(
                    &format!("pre-migrate-v{}-to-v{}", from_version, target_version),
                    self.release_state.schema_version,
                    &self.release_state.snapshot_payload(),
                    now_secs(),
                ) {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        self.emit_error(
                            "release",
                            CliCode::Execution,
                            &format!("failed to create rollback snapshot: {err}"),
                        );
                        return;
                    }
                };

                match self.release_state.apply_migration_plan(&plan, now_secs()) {
                    Ok(report) => self.emit_response(
                        CommandResponse::ok("release", "migration applied")
                            .with_field("from_version", report.from_version)
                            .with_field("to_version", report.to_version)
                            .with_field("applied_steps", report.applied_steps)
                            .with_field("requires_backup", report.requires_backup)
                            .with_field("rollback_snapshot_id", snapshot.id),
                    ),
                    Err(err) => self.emit_error(
                        "release",
                        CliCode::Execution,
                        &format!("migration apply failed: {err}"),
                    ),
                }
            }
            _ => self.emit_error("release", CliCode::Usage, &release_usage_string()),
        }
    }

    fn cmd_release_rollback(&mut self, tokens: &[String]) {
        if tokens.len() < 3 {
            self.emit_error("release", CliCode::Usage, &release_usage_string());
            return;
        }

        match tokens[2].to_ascii_lowercase().as_str() {
            "snapshot" => {
                if tokens.len() < 4 {
                    self.emit_error(
                        "release",
                        CliCode::Usage,
                        "usage: release rollback snapshot <label>",
                    );
                    return;
                }
                let label = tokens[3..].join(" ");
                match self.release_rollback.create_snapshot(
                    &label,
                    self.release_state.schema_version,
                    &self.release_state.snapshot_payload(),
                    now_secs(),
                ) {
                    Ok(snapshot) => self.emit_response(
                        CommandResponse::ok("release", "rollback snapshot created")
                            .with_field("snapshot_id", snapshot.id)
                            .with_field("schema_version", snapshot.schema_version)
                            .with_field("label", snapshot.label),
                    ),
                    Err(err) => self.emit_error("release", CliCode::Execution, &err.to_string()),
                }
            }
            "list" => {
                let snapshots = self.release_rollback.list_snapshots();
                if snapshots.is_empty() {
                    self.emit_ok("release", "no rollback snapshots available");
                    return;
                }
                self.emit_response(
                    CommandResponse::ok("release", "rollback snapshots listed")
                        .with_field("count", snapshots.len()),
                );
                if self.output_mode.is_json() {
                    return;
                }

                let headers = ["Id", "Schema", "CapturedAt", "Checksum", "Label"];
                let mut widths = [
                    headers[0].len(),
                    headers[1].len(),
                    headers[2].len(),
                    headers[3].len(),
                    headers[4].len(),
                ];
                let mut rows = Vec::with_capacity(snapshots.len());
                for snapshot in snapshots {
                    let row = [
                        snapshot.id.to_string(),
                        snapshot.schema_version.to_string(),
                        snapshot.captured_at.to_string(),
                        snapshot.checksum.to_string(),
                        snapshot.label,
                    ];
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
            "apply" => {
                if tokens.len() != 4 {
                    self.emit_error(
                        "release",
                        CliCode::Usage,
                        "usage: release rollback apply <snapshot_id>",
                    );
                    return;
                }
                let Ok(snapshot_id) = tokens[3].parse::<u64>() else {
                    self.emit_error(
                        "release",
                        CliCode::Validation,
                        "snapshot_id must be an integer",
                    );
                    return;
                };

                match self.release_rollback.restore(snapshot_id) {
                    Ok(restore) => {
                        self.release_state
                            .apply_rollback_restore(&restore, now_secs());
                        self.emit_response(
                            CommandResponse::ok("release", "rollback restore applied")
                                .with_field("snapshot_id", restore.snapshot_id)
                                .with_field("schema_version", restore.schema_version)
                                .with_field("label", restore.label),
                        );
                    }
                    Err(err) => self.emit_error("release", CliCode::Execution, &err.to_string()),
                }
            }
            "prune" => {
                if tokens.len() != 4 {
                    self.emit_error(
                        "release",
                        CliCode::Usage,
                        "usage: release rollback prune <keep_latest>",
                    );
                    return;
                }
                let Ok(keep_latest) = tokens[3].parse::<usize>() else {
                    self.emit_error(
                        "release",
                        CliCode::Validation,
                        "keep_latest must be an integer",
                    );
                    return;
                };
                let removed = self.release_rollback.prune_keep_latest(keep_latest);
                self.emit_response(
                    CommandResponse::ok("release", "rollback snapshots pruned")
                        .with_field("removed", removed)
                        .with_field("remaining", self.release_rollback.list_snapshots().len()),
                );
            }
            _ => self.emit_error("release", CliCode::Usage, &release_usage_string()),
        }
    }

    fn cmd_campaign(&mut self, tokens: &[String]) {
        if tokens.len() < 2 {
            self.emit_error(
                "campaign",
                CliCode::Usage,
                "usage: campaign create <name> [description] | campaign list | campaign show <campaign-id> | campaign status [campaign-id [active|paused|completed|failed]]",
            );
            return;
        }
        match tokens[1].as_str() {
            "create" => self.cmd_campaign_create(tokens),
            "list" => self.cmd_campaign_list(),
            "show" => self.cmd_campaign_show(tokens),
            "status" => self.cmd_campaign_status(tokens),
            _ => self.emit_error(
                "campaign",
                CliCode::Usage,
                "usage: campaign create <name> [description] | campaign list | campaign show <campaign-id> | campaign status [campaign-id [active|paused|completed|failed]]",
            ),
        }
    }

    fn cmd_campaign_create(&mut self, tokens: &[String]) {
        if tokens.len() < 3 {
            self.emit_error(
                "campaign",
                CliCode::Usage,
                "usage: campaign create <name> [description]",
            );
            return;
        }
        let campaign_id = next_campaign_id();
        let name = &tokens[2];
        let description = if tokens.len() > 3 {
            tokens[3..].join(" ")
        } else {
            String::new()
        };
        let now = now_secs();
        let campaign = match Campaign::new_at(campaign_id.clone(), name, &description, now, None) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("campaign", CliCode::Validation, &err.to_string());
                return;
            }
        };
        self.campaigns.insert(campaign_id.clone(), campaign.clone());
        self.emit_response(
            CommandResponse::ok("campaign", "campaign created")
                .with_field("campaign_id", campaign_id.as_str())
                .with_field("name", campaign.name)
                .with_field("status", campaign.status.as_str()),
        );
    }

    fn cmd_campaign_list(&self) {
        if self.campaigns.is_empty() {
            self.emit_response(
                CommandResponse::ok("campaign", "no campaigns").with_field("count", 0),
            );
            return;
        }
        if self.output_mode.is_json() {
            let campaigns_json = self
                .campaigns
                .values()
                .map(|campaign| {
                    format!(
                        "{{\"id\":\"{}\",\"name\":\"{}\",\"status\":\"{}\",\"objective_count\":{},\"created_at\":{}}}",
                        escape_json(campaign.id.as_str()),
                        escape_json(&campaign.name),
                        campaign.status.as_str(),
                        campaign.objective_ids.len(),
                        campaign.created_at
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{{\"command\":\"campaign\",\"ok\":true,\"code\":\"{}\",\"message\":\"listed campaigns\",\"count\":{},\"campaigns\":[{}]}}",
                CliCode::Ok.as_str(),
                self.campaigns.len(),
                campaigns_json
            );
            return;
        }
        self.emit_response(
            CommandResponse::ok("campaign", "listed campaigns")
                .with_field("count", self.campaigns.len()),
        );

        let headers = ["Id", "Status", "Objectives", "Created", "Name"];
        let mut rows = Vec::with_capacity(self.campaigns.len());
        let mut widths = [
            headers[0].len(),
            headers[1].len(),
            headers[2].len(),
            headers[3].len(),
            headers[4].len(),
        ];
        for campaign in self.campaigns.values() {
            let row = [
                campaign.id.as_str().to_string(),
                campaign.status.as_str().to_string(),
                campaign.objective_ids.len().to_string(),
                campaign.created_at.to_string(),
                campaign.name.clone(),
            ];
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

    fn cmd_campaign_show(&self, tokens: &[String]) {
        if tokens.len() != 3 {
            self.emit_error(
                "campaign",
                CliCode::Usage,
                "usage: campaign show <campaign-id>",
            );
            return;
        }
        let campaign_id = match CampaignId::parse(&tokens[2]) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("campaign", CliCode::Validation, &err.to_string());
                return;
            }
        };
        let Some(campaign) = self.campaigns.get(&campaign_id) else {
            self.emit_error(
                "campaign",
                CliCode::NotFound,
                &format!("campaign not found: {}", campaign_id.as_str()),
            );
            return;
        };
        self.emit_response(
            CommandResponse::ok("campaign", "campaign details")
                .with_field("campaign_id", campaign.id.as_str())
                .with_field("name", &campaign.name)
                .with_field("status", campaign.status.as_str())
                .with_field("objective_count", campaign.objective_ids.len()),
        );
        if self.output_mode.is_json() {
            return;
        }
        println!("Description: {}", campaign.description);
        println!("Created At:  {}", campaign.created_at);
        if campaign.objective_ids.is_empty() {
            println!("Objectives:  <none>");
        } else {
            let objectives = campaign
                .objective_ids
                .iter()
                .map(|id| id.as_str().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("Objectives:  {objectives}");
        }
    }

    fn cmd_campaign_status(&mut self, tokens: &[String]) {
        match tokens.len() {
            2 => {
                if self.campaigns.is_empty() {
                    self.emit_response(
                        CommandResponse::ok("campaign", "no campaigns").with_field("count", 0),
                    );
                    return;
                }
                if self.output_mode.is_json() {
                    let statuses = self
                        .campaigns
                        .values()
                        .map(|campaign| {
                            format!(
                                "{{\"campaign_id\":\"{}\",\"status\":\"{}\"}}",
                                escape_json(campaign.id.as_str()),
                                campaign.status.as_str()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{{\"command\":\"campaign\",\"ok\":true,\"code\":\"{}\",\"message\":\"campaign statuses\",\"count\":{},\"statuses\":[{}]}}",
                        CliCode::Ok.as_str(),
                        self.campaigns.len(),
                        statuses
                    );
                    return;
                }
                self.emit_response(
                    CommandResponse::ok("campaign", "campaign statuses")
                        .with_field("count", self.campaigns.len()),
                );
                for campaign in self.campaigns.values() {
                    println!("{} {}", campaign.id.as_str(), campaign.status.as_str());
                }
            }
            3 => {
                let campaign_id = match CampaignId::parse(&tokens[2]) {
                    Ok(value) => value,
                    Err(err) => {
                        self.emit_error("campaign", CliCode::Validation, &err.to_string());
                        return;
                    }
                };
                let Some(campaign) = self.campaigns.get(&campaign_id) else {
                    self.emit_error(
                        "campaign",
                        CliCode::NotFound,
                        &format!("campaign not found: {}", campaign_id.as_str()),
                    );
                    return;
                };
                self.emit_response(
                    CommandResponse::ok("campaign", "campaign status")
                        .with_field("campaign_id", campaign.id.as_str())
                        .with_field("status", campaign.status.as_str()),
                );
            }
            4 => {
                let campaign_id = match CampaignId::parse(&tokens[2]) {
                    Ok(value) => value,
                    Err(err) => {
                        self.emit_error("campaign", CliCode::Validation, &err.to_string());
                        return;
                    }
                };
                let Some(next_status) = parse_campaign_status_token(&tokens[3]) else {
                    self.emit_error(
                        "campaign",
                        CliCode::Validation,
                        "status must be one of: active|paused|completed|failed",
                    );
                    return;
                };
                let (campaign_id_text, from_status, to_status) = {
                    let Some(campaign) = self.campaigns.get_mut(&campaign_id) else {
                        self.emit_error(
                            "campaign",
                            CliCode::NotFound,
                            &format!("campaign not found: {}", campaign_id.as_str()),
                        );
                        return;
                    };
                    let from = campaign.status;
                    if let Err(err) = campaign.transition_status(next_status) {
                        self.emit_error("campaign", CliCode::Validation, &err.to_string());
                        return;
                    }
                    (
                        campaign.id.as_str().to_string(),
                        from.as_str().to_string(),
                        campaign.status.as_str().to_string(),
                    )
                };
                self.emit_response(
                    CommandResponse::ok("campaign", "campaign status updated")
                        .with_field("campaign_id", campaign_id_text)
                        .with_field("from", from_status)
                        .with_field("to", to_status),
                );
            }
            _ => self.emit_error(
                "campaign",
                CliCode::Usage,
                "usage: campaign status [campaign-id [active|paused|completed|failed]]",
            ),
        }
    }

    fn cmd_objective(&mut self, tokens: &[String]) {
        if tokens.len() < 2 {
            self.emit_error(
                "objective",
                CliCode::Usage,
                "usage: objective create <campaign-id> <name> --success <predicate[,predicate...]> [--failure <predicate[,predicate...]>] [--risk <low|medium|high>] [--noise-budget <n>] [--description <text>] | objective link-prereq <objective-id> <prerequisite-id> | objective list [campaign-id] | objective status [objective-id [start|evaluate]]",
            );
            return;
        }
        match tokens[1].as_str() {
            "create" => self.cmd_objective_create(tokens),
            "link-prereq" => self.cmd_objective_link_prereq(tokens),
            "list" => self.cmd_objective_list(tokens),
            "status" => self.cmd_objective_status(tokens),
            _ => self.emit_error(
                "objective",
                CliCode::Usage,
                "usage: objective create <campaign-id> <name> --success <predicate[,predicate...]> [--failure <predicate[,predicate...]>] [--risk <low|medium|high>] [--noise-budget <n>] [--description <text>] | objective link-prereq <objective-id> <prerequisite-id> | objective list [campaign-id] | objective status [objective-id [start|evaluate]]",
            ),
        }
    }

    fn cmd_objective_create(&mut self, tokens: &[String]) {
        if tokens.len() < 5 {
            self.emit_error(
                "objective",
                CliCode::Usage,
                "usage: objective create <campaign-id> <name> --success <predicate[,predicate...]> [--failure <predicate[,predicate...]>] [--risk <low|medium|high>] [--noise-budget <n>] [--description <text>]",
            );
            return;
        }
        let campaign_id = match CampaignId::parse(&tokens[2]) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("objective", CliCode::Validation, &err.to_string());
                return;
            }
        };
        let Some(campaign) = self.campaigns.get(&campaign_id) else {
            self.emit_error(
                "objective",
                CliCode::NotFound,
                &format!("campaign not found: {}", campaign_id.as_str()),
            );
            return;
        };
        if campaign.status.is_terminal() {
            self.emit_error(
                "objective",
                CliCode::Validation,
                "cannot add objectives to terminal campaign",
            );
            return;
        }

        let name = &tokens[3];
        let mut description = String::new();
        let mut risk_level = RiskLevel::Medium;
        let mut noise_budget = None;
        let mut success_criteria = Vec::new();
        let mut failure_criteria = Vec::new();

        let mut idx = 4;
        while idx < tokens.len() {
            match tokens[idx].as_str() {
                "--description" | "-d" => {
                    idx = idx.saturating_add(1);
                    let Some(value) = tokens.get(idx) else {
                        self.emit_error("objective", CliCode::Usage, "usage: --description <text>");
                        return;
                    };
                    description = value.clone();
                }
                "--risk" => {
                    idx = idx.saturating_add(1);
                    let Some(value) = tokens.get(idx) else {
                        self.emit_error("objective", CliCode::Usage, "usage: --risk <level>");
                        return;
                    };
                    let Some(parsed) = parse_risk_level_token(value) else {
                        self.emit_error(
                            "objective",
                            CliCode::Validation,
                            "risk must be one of: low|medium|high",
                        );
                        return;
                    };
                    risk_level = parsed;
                }
                "--noise-budget" => {
                    idx = idx.saturating_add(1);
                    let Some(value) = tokens.get(idx) else {
                        self.emit_error("objective", CliCode::Usage, "usage: --noise-budget <n>");
                        return;
                    };
                    let Ok(parsed) = value.parse::<u32>() else {
                        self.emit_error(
                            "objective",
                            CliCode::Validation,
                            "noise-budget must be a positive integer",
                        );
                        return;
                    };
                    if parsed == 0 {
                        self.emit_error(
                            "objective",
                            CliCode::Validation,
                            "noise-budget must be greater than zero",
                        );
                        return;
                    }
                    noise_budget = Some(parsed);
                }
                "--success" => {
                    idx = idx.saturating_add(1);
                    let Some(value) = tokens.get(idx) else {
                        self.emit_error(
                            "objective",
                            CliCode::Usage,
                            "usage: --success <predicate[,predicate...]>",
                        );
                        return;
                    };
                    match parse_predicates(value) {
                        Ok(parsed) => success_criteria.extend(parsed),
                        Err(err) => {
                            self.emit_error("objective", CliCode::Validation, &err);
                            return;
                        }
                    }
                }
                "--failure" => {
                    idx = idx.saturating_add(1);
                    let Some(value) = tokens.get(idx) else {
                        self.emit_error(
                            "objective",
                            CliCode::Usage,
                            "usage: --failure <predicate[,predicate...]>",
                        );
                        return;
                    };
                    match parse_predicates(value) {
                        Ok(parsed) => failure_criteria.extend(parsed),
                        Err(err) => {
                            self.emit_error("objective", CliCode::Validation, &err);
                            return;
                        }
                    }
                }
                unknown => {
                    self.emit_error(
                        "objective",
                        CliCode::Usage,
                        &format!("unknown argument: {unknown}"),
                    );
                    return;
                }
            }
            idx = idx.saturating_add(1);
        }

        if success_criteria.is_empty() {
            self.emit_error(
                "objective",
                CliCode::Validation,
                "objective requires at least one success predicate (--success)",
            );
            return;
        }

        let objective_id = next_objective_id();
        let objective = match Objective::new_at(
            objective_id.clone(),
            campaign_id.clone(),
            name,
            &description,
            Vec::new(),
            success_criteria,
            failure_criteria,
            risk_level,
            noise_budget,
            now_secs(),
        ) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("objective", CliCode::Validation, &err.to_string());
                return;
            }
        };

        self.objectives
            .insert(objective_id.clone(), objective.clone());
        if let Some(campaign) = self.campaigns.get_mut(&campaign_id) {
            campaign.add_objective(objective_id.clone());
        }

        self.emit_response(
            CommandResponse::ok("objective", "objective created")
                .with_field("objective_id", objective_id.as_str())
                .with_field("campaign_id", campaign_id.as_str())
                .with_field("status", objective.status.as_str())
                .with_field("risk_level", objective.risk_level.as_str()),
        );
    }

    fn cmd_objective_link_prereq(&mut self, tokens: &[String]) {
        if tokens.len() != 4 {
            self.emit_error(
                "objective",
                CliCode::Usage,
                "usage: objective link-prereq <objective-id> <prerequisite-id>",
            );
            return;
        }
        let objective_id = match ObjectiveId::parse(&tokens[2]) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("objective", CliCode::Validation, &err.to_string());
                return;
            }
        };
        let prerequisite_id = match ObjectiveId::parse(&tokens[3]) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("objective", CliCode::Validation, &err.to_string());
                return;
            }
        };
        if objective_id == prerequisite_id {
            self.emit_error(
                "objective",
                CliCode::Validation,
                "objective cannot depend on itself",
            );
            return;
        }

        let Some(objective) = self.objectives.get(&objective_id) else {
            self.emit_error(
                "objective",
                CliCode::NotFound,
                &format!("objective not found: {}", objective_id.as_str()),
            );
            return;
        };
        let Some(prerequisite) = self.objectives.get(&prerequisite_id) else {
            self.emit_error(
                "objective",
                CliCode::NotFound,
                &format!("objective not found: {}", prerequisite_id.as_str()),
            );
            return;
        };
        if objective.campaign_id != prerequisite.campaign_id {
            self.emit_error(
                "objective",
                CliCode::Validation,
                "objective and prerequisite must belong to same campaign",
            );
            return;
        }

        let campaign_id = objective.campaign_id.clone();
        let mut already_linked = false;
        let mut inserted = false;
        if let Some(editable) = self.objectives.get_mut(&objective_id) {
            if editable.prerequisites.contains(&prerequisite_id) {
                already_linked = true;
            } else {
                editable.prerequisites.push(prerequisite_id.clone());
                editable.updated_at = now_secs();
                inserted = true;
            }
        }

        if already_linked {
            self.emit_response(
                CommandResponse::ok("objective", "prerequisite already linked")
                    .with_field("objective_id", objective_id.as_str())
                    .with_field("prerequisite_id", prerequisite_id.as_str()),
            );
            return;
        }

        let validation = self.validate_campaign_objective_graph(&campaign_id);
        if let Err(err) = validation {
            if inserted {
                if let Some(editable) = self.objectives.get_mut(&objective_id) {
                    editable.prerequisites.retain(|id| id != &prerequisite_id);
                    editable.updated_at = now_secs();
                }
            }
            self.emit_error("objective", CliCode::Validation, &err.to_string());
            return;
        }

        self.emit_response(
            CommandResponse::ok("objective", "prerequisite linked")
                .with_field("objective_id", objective_id.as_str())
                .with_field("prerequisite_id", prerequisite_id.as_str()),
        );
    }

    fn cmd_objective_list(&self, tokens: &[String]) {
        if tokens.len() > 3 {
            self.emit_error(
                "objective",
                CliCode::Usage,
                "usage: objective list [campaign-id]",
            );
            return;
        }
        let filter_campaign = if tokens.len() == 3 {
            match CampaignId::parse(&tokens[2]) {
                Ok(value) => Some(value),
                Err(err) => {
                    self.emit_error("objective", CliCode::Validation, &err.to_string());
                    return;
                }
            }
        } else {
            None
        };

        let objectives = self
            .objectives
            .values()
            .filter(|objective| {
                filter_campaign
                    .as_ref()
                    .map(|campaign_id| &objective.campaign_id == campaign_id)
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();

        if objectives.is_empty() {
            self.emit_response(
                CommandResponse::ok("objective", "no objectives")
                    .with_field("count", 0)
                    .with_field(
                        "campaign_id",
                        filter_campaign
                            .as_ref()
                            .map(|id| id.as_str().to_string())
                            .unwrap_or_default(),
                    ),
            );
            return;
        }
        if self.output_mode.is_json() {
            let objectives_json = objectives
                .iter()
                .map(|objective| {
                    format!(
                        "{{\"id\":\"{}\",\"campaign_id\":\"{}\",\"name\":\"{}\",\"status\":\"{}\",\"risk\":\"{}\",\"prerequisites\":{}}}",
                        escape_json(objective.id.as_str()),
                        escape_json(objective.campaign_id.as_str()),
                        escape_json(&objective.name),
                        objective.status.as_str(),
                        objective.risk_level.as_str(),
                        objective.prerequisites.len()
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{{\"command\":\"objective\",\"ok\":true,\"code\":\"{}\",\"message\":\"listed objectives\",\"count\":{},\"objectives\":[{}]}}",
                CliCode::Ok.as_str(),
                objectives.len(),
                objectives_json
            );
            return;
        }
        self.emit_response(
            CommandResponse::ok("objective", "listed objectives")
                .with_field("count", objectives.len()),
        );

        let headers = ["Id", "Campaign", "Status", "Risk", "Prereq", "Name"];
        let mut rows = Vec::with_capacity(objectives.len());
        let mut widths = [
            headers[0].len(),
            headers[1].len(),
            headers[2].len(),
            headers[3].len(),
            headers[4].len(),
            headers[5].len(),
        ];
        for objective in objectives {
            let row = [
                objective.id.as_str().to_string(),
                objective.campaign_id.as_str().to_string(),
                objective.status.as_str().to_string(),
                objective.risk_level.as_str().to_string(),
                objective.prerequisites.len().to_string(),
                objective.name.clone(),
            ];
            for (idx, col) in row.iter().enumerate() {
                widths[idx] = widths[idx].max(col.len());
            }
            rows.push(row);
        }

        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {:<w5$}",
            headers[0],
            headers[1],
            headers[2],
            headers[3],
            headers[4],
            headers[5],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
            w4 = widths[4],
            w5 = widths[5]
        );
        println!(
            "{:-<w0$}  {:-<w1$}  {:-<w2$}  {:-<w3$}  {:-<w4$}  {:-<w5$}",
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
            w5 = widths[5]
        );
        for row in rows {
            println!(
                "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {:<w4$}  {:<w5$}",
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                row[5],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2],
                w3 = widths[3],
                w4 = widths[4],
                w5 = widths[5]
            );
        }
    }

    fn cmd_objective_status(&mut self, tokens: &[String]) {
        match tokens.len() {
            2 => {
                let mut counts = BTreeMap::<&'static str, usize>::new();
                counts.insert("pending", 0);
                counts.insert("eligible", 0);
                counts.insert("in_progress", 0);
                counts.insert("achieved", 0);
                counts.insert("failed", 0);
                for objective in self.objectives.values() {
                    let key = objective.status.as_str();
                    if let Some(counter) = counts.get_mut(key) {
                        *counter = counter.saturating_add(1);
                    }
                }
                self.emit_response(
                    CommandResponse::ok("objective", "objective status counts")
                        .with_field("total", self.objectives.len())
                        .with_field("pending", counts["pending"])
                        .with_field("eligible", counts["eligible"])
                        .with_field("in_progress", counts["in_progress"])
                        .with_field("achieved", counts["achieved"])
                        .with_field("failed", counts["failed"]),
                );
            }
            3 => {
                let objective_id = match ObjectiveId::parse(&tokens[2]) {
                    Ok(value) => value,
                    Err(err) => {
                        self.emit_error("objective", CliCode::Validation, &err.to_string());
                        return;
                    }
                };
                let Some(objective) = self.objectives.get(&objective_id) else {
                    self.emit_error(
                        "objective",
                        CliCode::NotFound,
                        &format!("objective not found: {}", objective_id.as_str()),
                    );
                    return;
                };
                self.emit_response(
                    CommandResponse::ok("objective", "objective status")
                        .with_field("objective_id", objective.id.as_str())
                        .with_field("campaign_id", objective.campaign_id.as_str())
                        .with_field("status", objective.status.as_str()),
                );
            }
            4 => {
                let objective_id = match ObjectiveId::parse(&tokens[2]) {
                    Ok(value) => value,
                    Err(err) => {
                        self.emit_error("objective", CliCode::Validation, &err.to_string());
                        return;
                    }
                };
                match tokens[3].as_str() {
                    "start" => self.cmd_objective_start(objective_id),
                    "evaluate" => self.cmd_objective_evaluate(objective_id),
                    _ => self.emit_error(
                        "objective",
                        CliCode::Usage,
                        "usage: objective status [objective-id [start|evaluate]]",
                    ),
                }
            }
            _ => self.emit_error(
                "objective",
                CliCode::Usage,
                "usage: objective status [objective-id [start|evaluate]]",
            ),
        }
    }

    fn cmd_objective_start(&mut self, objective_id: ObjectiveId) {
        let Some(objective) = self.objectives.get(&objective_id) else {
            self.emit_error(
                "objective",
                CliCode::NotFound,
                &format!("objective not found: {}", objective_id.as_str()),
            );
            return;
        };
        let campaign_id = objective.campaign_id.clone();
        let objective_statuses = self
            .objectives
            .values()
            .filter(|objective| objective.campaign_id == campaign_id)
            .map(|objective| (objective.id.clone(), objective.status))
            .collect::<BTreeMap<_, _>>();

        let Some(editable) = self.objectives.get_mut(&objective_id) else {
            self.emit_error(
                "objective",
                CliCode::NotFound,
                &format!("objective not found: {}", objective_id.as_str()),
            );
            return;
        };
        let mut events = Vec::new();
        let transition = match ObjectiveEvaluationEngine::start_objective(
            editable,
            &objective_statuses,
            now_secs(),
            &mut events,
        ) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("objective", CliCode::Validation, &err.to_string());
                return;
            }
        };
        self.emit_response(
            CommandResponse::ok("objective", "objective started")
                .with_field("objective_id", transition.objective_id.as_str())
                .with_field("from", transition.from.as_str())
                .with_field("to", transition.to.as_str()),
        );
    }

    fn cmd_objective_evaluate(&mut self, objective_id: ObjectiveId) {
        let Some(objective) = self.objectives.get(&objective_id) else {
            self.emit_error(
                "objective",
                CliCode::NotFound,
                &format!("objective not found: {}", objective_id.as_str()),
            );
            return;
        };
        let campaign_id = objective.campaign_id.clone();
        let mut scoped = self
            .objectives
            .iter()
            .filter(|(_, objective)| objective.campaign_id == campaign_id)
            .map(|(id, objective)| (id.clone(), objective.clone()))
            .collect::<BTreeMap<_, _>>();
        let selected = BTreeSet::from([objective_id.clone()]);
        let snapshot = PredicateSnapshot::default();
        let mut events = Vec::new();
        let records = match ObjectiveEvaluationEngine::evaluate_selected(
            &mut scoped,
            &selected,
            &snapshot,
            ObjectiveReevaluationTrigger::ManualRequest,
            now_secs(),
            &mut events,
        ) {
            Ok(value) => value,
            Err(err) => {
                self.emit_error("objective", CliCode::Validation, &err.to_string());
                return;
            }
        };

        for (id, objective) in scoped {
            self.objectives.insert(id, objective);
        }

        let Some(updated) = self.objectives.get(&objective_id) else {
            self.emit_error("objective", CliCode::Execution, "objective evaluate failed");
            return;
        };
        let evaluations = records.len();
        self.emit_response(
            CommandResponse::ok("objective", "objective evaluated")
                .with_field("objective_id", updated.id.as_str())
                .with_field("status", updated.status.as_str())
                .with_field("evaluations", evaluations),
        );
    }

    fn validate_campaign_objective_graph(
        &self,
        campaign_id: &CampaignId,
    ) -> Result<(), corelib::campaign::CampaignModelError> {
        let objectives = self
            .objectives
            .values()
            .filter(|objective| &objective.campaign_id == campaign_id)
            .cloned()
            .collect::<Vec<_>>();
        validate_prerequisite_graph(&objectives)
    }

    fn build_release_matrix(&self) -> CompatibilityMatrix {
        let manifest_min = self.release_compat_policy.module_manifest_versions.min;
        let manifest_max = self.release_compat_policy.module_manifest_versions.max;
        let api_min = self.release_compat_policy.module_api_versions.min;
        let api_max = self.release_compat_policy.module_api_versions.max;
        let control_min = self.release_compat_policy.control_state_versions.min;
        let control_max = self.release_compat_policy.control_state_versions.max;
        let current_control = self.release_state.schema_version;

        CompatibilityMatrix::new(vec![
            CompatibilityCase::new(
                "builtin-current-human",
                "builtin",
                manifest_min,
                api_min,
                current_control,
                "human",
                true,
            )
            .expect("compat-case"),
            CompatibilityCase::new(
                "dynlib-current-json",
                "dynlib",
                manifest_max,
                api_max,
                current_control,
                "json",
                true,
            )
            .expect("compat-case"),
            CompatibilityCase::new(
                "manifest-too-low",
                "builtin",
                manifest_min.saturating_sub(1),
                api_min,
                current_control,
                "human",
                false,
            )
            .expect("compat-case"),
            CompatibilityCase::new(
                "api-too-high",
                "builtin",
                manifest_max,
                api_max.saturating_add(1),
                current_control,
                "human",
                false,
            )
            .expect("compat-case"),
            CompatibilityCase::new(
                "unsupported-runtime",
                "wasm",
                manifest_min,
                api_min,
                current_control,
                "human",
                false,
            )
            .expect("compat-case"),
            CompatibilityCase::new(
                "unsupported-output",
                "builtin",
                manifest_min,
                api_min,
                current_control,
                "xml",
                false,
            )
            .expect("compat-case"),
            CompatibilityCase::new(
                "control-state-too-high",
                "builtin",
                manifest_min,
                api_min,
                control_max.saturating_add(1),
                "human",
                false,
            )
            .expect("compat-case"),
            CompatibilityCase::new(
                "control-state-too-low",
                "builtin",
                manifest_min,
                api_min,
                control_min.saturating_sub(1),
                "human",
                false,
            )
            .expect("compat-case"),
        ])
        .expect("release compatibility matrix")
    }

    fn emit_migration_plan(&self, plan: &MigrationPlan) {
        self.emit_response(
            CommandResponse::ok("release", "migration plan generated")
                .with_field("from_version", plan.start_version)
                .with_field("to_version", plan.target_version)
                .with_field("steps", plan.steps.len())
                .with_field("requires_backup", plan.requires_backup),
        );
        if self.output_mode.is_json() || plan.steps.is_empty() {
            return;
        }

        println!("Planned migration steps:");
        for (idx, step) in plan.steps.iter().enumerate() {
            println!(
                "  {}. {} -> {} [{}|{}|backup={}] {}",
                idx + 1,
                step.from_version,
                step.to_version,
                step.direction.as_str(),
                step.impact.as_str(),
                step.requires_backup,
                step.description
            );
        }
    }

    fn cmd_interact(&mut self, tokens: &[String]) {
        if tokens.len() < 2 {
            self.emit_error("interact", CliCode::Usage, "usage: interact <id>");
            return;
        }
        let Ok(id) = tokens[1].parse::<u32>() else {
            self.emit_error(
                "interact",
                CliCode::Validation,
                "session id must be an integer",
            );
            return;
        };
        if !self.sessions.has(id) {
            self.emit_error(
                "interact",
                CliCode::NotFound,
                &format!("session {id} not found"),
            );
            return;
        }
        self.emit_response(
            CommandResponse::ok("interact", "session attached").with_field("session_id", id),
        );
        if let Err(err) = self.interact_session(id) {
            self.emit_error(
                "interact",
                CliCode::Execution,
                &format!("interact error: {err}"),
            );
        }
    }

    fn interact_session(&mut self, id: u32) -> Result<(), ReplError> {
        self.sessions
            .attach(id)
            .map_err(|e| ReplError::Io(format!("session attach failed: {e}")))?;

        let result = (|| -> Result<(), ReplError> {
            loop {
                if !self.sessions.has(id) {
                    self.emit_response(
                        CommandResponse::ok("interact", "session closed")
                            .with_field("session_id", id),
                    );
                    return Ok(());
                }
                let pending = self.collect_session_output_with_grace(id, 80, 30)?;
                self.emit_session_output(id, &pending);
                let prompt = format!("session({id})> ");
                let completer = ReplCompleter { repl: self };
                let line = read_line(&prompt, &completer, self.history.entries())
                    .map_err(|e| ReplError::Io(e.to_string()))?;
                let Some(line) = line else {
                    self.emit_response(
                        CommandResponse::ok("interact", "session detached")
                            .with_field("session_id", id),
                    );
                    return Ok(());
                };
                let line = line.trim_end();
                if line.is_empty() {
                    continue;
                }
                self.history.add(format!("session({id}) {line}"));
                let lowered = line.to_ascii_lowercase();
                if lowered == "background" || lowered == "bg" {
                    self.emit_response(
                        CommandResponse::ok("interact", "session backgrounded")
                            .with_field("session_id", id),
                    );
                    return Ok(());
                }
                if lowered == "exit" || lowered == "quit" {
                    self.sessions
                        .close_and_remove(id)
                        .map_err(|e| ReplError::Io(format!("session close failed: {e}")))?;
                    self.emit_response(
                        CommandResponse::ok("interact", "session closed")
                            .with_field("session_id", id),
                    );
                    return Ok(());
                }
                let mut payload = line.as_bytes().to_vec();
                payload.push(b'\n');
                self.sessions
                    .write(id, &payload)
                    .map_err(|e| ReplError::Io(format!("session write failed: {e}")))?;
                let response = self.collect_session_output_with_grace(id, 350, 50)?;
                self.emit_session_output(id, &response);
            }
        })();

        if self.sessions.is_attached(id) {
            let _ = self.sessions.detach(id);
        }

        result
    }

    fn collect_session_output_with_grace(
        &mut self,
        id: u32,
        wait_timeout_ms: u64,
        idle_quiet_ms: u64,
    ) -> Result<Vec<u8>, ReplError> {
        let timeout = Duration::from_millis(wait_timeout_ms.max(1));
        let quiet = Duration::from_millis(idle_quiet_ms.max(1));
        let started = Instant::now();
        let mut last_data_at = Instant::now();
        let mut collected = Vec::new();

        loop {
            self.sessions
                .poll(id)
                .map_err(|e| ReplError::Io(format!("session read failed: {e}")))?;
            let chunk = self
                .sessions
                .read_buffered(id)
                .map_err(|e| ReplError::Io(format!("session read failed: {e}")))?;
            if !chunk.is_empty() {
                last_data_at = Instant::now();
                collected.extend_from_slice(&chunk);
            }

            let elapsed = started.elapsed();
            if elapsed >= timeout {
                break;
            }
            if !collected.is_empty() && last_data_at.elapsed() >= quiet {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }

        Ok(collected)
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

    fn emit_response(&self, response: CommandResponse) {
        if self.output_mode.is_json() {
            println!("{}", response.render_json());
            return;
        }
        let rendered = response.render_human();
        if response.ok {
            println!("{}", self.palette.success(&rendered));
        } else {
            println!("{}", self.palette.error(&rendered));
        }
    }

    fn emit_ok(&self, command: &str, message: &str) {
        self.emit_response(CommandResponse::ok(command, message));
    }

    fn emit_ok_with_field(&self, command: &str, message: &str, key: &str, value: impl ToString) {
        self.emit_response(CommandResponse::ok(command, message).with_field(key, value));
    }

    fn emit_error(&self, command: &str, code: CliCode, message: &str) {
        self.emit_response(CommandResponse::err(command, code, message));
    }

    fn emit_session_output(&self, session_id: u32, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.output_mode.is_json() {
            let text = String::from_utf8_lossy(bytes);
            println!(
                "{{\"event\":\"session_output\",\"session_id\":{},\"output\":\"{}\"}}",
                session_id,
                escape_json(&text)
            );
        } else {
            print!("{}", String::from_utf8_lossy(bytes));
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
                "help" => {
                    if token_index == 1 {
                        candidates = help_topic_candidates(current);
                    }
                }
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
                        candidates = ["modules", "options", "globals"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    }
                }
                "setg" => {
                    if token_index == 1 {
                        candidates = global_key_candidates(current);
                    } else if token_index == 2 {
                        if matches!(tokens.get(1), Some(&"output_mode") | Some(&"output")) {
                            candidates = ["human", "json"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                        } else if matches!(
                            tokens.get(1),
                            Some(&"session_max_pending_bytes")
                                | Some(&"session_pending_bytes")
                                | Some(&"session_drain_bytes")
                                | Some(&"session_read_drain_bytes")
                        ) {
                            candidates = ["1024", "4096", "65536"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                        }
                    }
                }
                "getg" => {
                    if token_index == 1 {
                        candidates = global_key_candidates(current);
                    }
                }
                "search" => {
                    candidates = search_flag_candidates(current);
                }
                "run" => {
                    if token_index == 1 {
                        candidates = ["--yes", "-y"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    }
                }
                "output" => {
                    if token_index == 1 {
                        candidates = ["human", "json"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    }
                }
                "policy" => {
                    if token_index == 1 {
                        candidates = ["enable", "disable"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    } else if token_index == 2
                        && matches!(tokens.get(1), Some(&"enable") | Some(&"disable"))
                    {
                        candidates = capability_candidates(current);
                    }
                }
                "clear" | "cls" => {}
                "release" => {
                    if token_index == 1 {
                        candidates = ["check", "matrix", "migrate", "rollback"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    } else if token_index == 2 {
                        if matches!(tokens.get(1), Some(&"migrate")) {
                            candidates = ["plan", "apply"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                        } else if matches!(tokens.get(1), Some(&"rollback")) {
                            candidates = ["snapshot", "list", "apply", "prune"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                        }
                    } else if token_index == 3 {
                        if matches!(tokens.get(1), Some(&"migrate"))
                            && matches!(tokens.get(2), Some(&"plan") | Some(&"apply"))
                        {
                            let current_version = self.release_state.schema_version.to_string();
                            let latest_version =
                                self.release_migration_policy.latest_version.to_string();
                            candidates = vec![current_version, latest_version]
                                .into_iter()
                                .filter(|v| v.starts_with(current))
                                .collect();
                        } else if matches!(tokens.get(1), Some(&"rollback"))
                            && matches!(tokens.get(2), Some(&"apply"))
                        {
                            candidates = release_snapshot_id_candidates(self, current);
                        } else if matches!(tokens.get(1), Some(&"rollback"))
                            && matches!(tokens.get(2), Some(&"prune"))
                        {
                            candidates = ["1", "3", "5"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                        }
                    } else if token_index == 4
                        && matches!(tokens.get(1), Some(&"migrate"))
                        && matches!(tokens.get(2), Some(&"plan"))
                    {
                        let latest_version =
                            self.release_migration_policy.latest_version.to_string();
                        candidates = vec![latest_version]
                            .into_iter()
                            .filter(|v| v.starts_with(current))
                            .collect();
                    }
                }
                "campaign" => {
                    if token_index == 1 {
                        candidates = ["create", "list", "show", "status"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    } else if token_index == 2 {
                        if matches!(tokens.get(1), Some(&"show")) {
                            candidates = campaign_id_candidates(self, current);
                        } else if matches!(tokens.get(1), Some(&"status")) {
                            let mut status_candidates = ["active", "paused", "completed", "failed"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect::<Vec<_>>();
                            let mut id_candidates = campaign_id_candidates(self, current);
                            status_candidates.append(&mut id_candidates);
                            candidates = status_candidates;
                        }
                    } else if token_index == 3 && matches!(tokens.get(1), Some(&"status")) {
                        if tokens
                            .get(2)
                            .and_then(|value| CampaignId::parse(value).ok())
                            .is_some()
                        {
                            candidates = ["active", "paused", "completed", "failed"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                        }
                    }
                }
                "objective" => {
                    if token_index == 1 {
                        candidates = ["create", "link-prereq", "list", "status"]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                    } else if token_index == 2 {
                        if matches!(tokens.get(1), Some(&"create") | Some(&"list")) {
                            candidates = campaign_id_candidates(self, current);
                        } else if matches!(tokens.get(1), Some(&"link-prereq") | Some(&"status")) {
                            candidates = objective_id_candidates(self, current);
                        }
                    } else if token_index == 3 {
                        if matches!(tokens.get(1), Some(&"link-prereq")) {
                            candidates = objective_id_candidates(self, current);
                        } else if matches!(tokens.get(1), Some(&"status")) {
                            if tokens
                                .get(2)
                                .and_then(|value| ObjectiveId::parse(value).ok())
                                .is_some()
                            {
                                candidates = ["start", "evaluate"]
                                    .iter()
                                    .filter(|v| v.starts_with(current))
                                    .map(|v| v.to_string())
                                    .collect();
                            }
                        } else if matches!(tokens.get(1), Some(&"create")) {
                            candidates = [
                                "--success",
                                "--failure",
                                "--risk",
                                "--noise-budget",
                                "--description",
                                "-d",
                            ]
                            .iter()
                            .filter(|v| v.starts_with(current))
                            .map(|v| v.to_string())
                            .collect();
                        }
                    } else if token_index >= 4 && matches!(tokens.get(1), Some(&"create")) {
                        match tokens.get(token_index.saturating_sub(1)) {
                            Some(&"--risk") => {
                                candidates = ["low", "medium", "high"]
                                    .iter()
                                    .filter(|v| v.starts_with(current))
                                    .map(|v| v.to_string())
                                    .collect();
                            }
                            Some(&"--noise-budget") => {
                                candidates = ["1", "10", "100"]
                                    .iter()
                                    .filter(|v| v.starts_with(current))
                                    .map(|v| v.to_string())
                                    .collect();
                            }
                            _ => {
                                candidates = [
                                    "--success",
                                    "--failure",
                                    "--risk",
                                    "--noise-budget",
                                    "--description",
                                    "-d",
                                ]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                            }
                        }
                    }
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
                        } else if matches!(tokens.get(1), Some(&"-K") | Some(&"--kill-all")) {
                            candidates = ["--yes", "-y"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
                        }
                    } else if token_index == 3
                        && matches!(tokens.get(1), Some(&"-k") | Some(&"--kill"))
                    {
                        if tokens
                            .get(2)
                            .and_then(|value| value.parse::<u32>().ok())
                            .is_some()
                        {
                            candidates = ["--yes", "-y"]
                                .iter()
                                .filter(|v| v.starts_with(current))
                                .map(|v| v.to_string())
                                .collect();
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
    command_tokens()
        .into_iter()
        .filter(|cmd| cmd.starts_with(prefix))
        .map(|cmd| cmd.to_string())
        .collect()
}

fn capability_candidates(prefix: &str) -> Vec<String> {
    all_capabilities()
        .iter()
        .map(|cap| cap.as_str().to_string())
        .filter(|cap| cap.starts_with(prefix))
        .collect()
}

fn help_topic_candidates(prefix: &str) -> Vec<String> {
    command_tokens()
        .into_iter()
        .filter(|name| name.starts_with(prefix))
        .map(|name| name.to_string())
        .collect()
}

fn global_key_candidates(prefix: &str) -> Vec<String> {
    [
        "output_mode",
        "output",
        "session_max_pending_bytes",
        "session_pending_bytes",
        "session_drain_bytes",
        "session_read_drain_bytes",
    ]
    .iter()
    .filter(|key| key.starts_with(prefix))
    .map(|key| key.to_string())
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

fn campaign_id_candidates(repl: &Repl, prefix: &str) -> Vec<String> {
    repl.campaigns
        .keys()
        .map(|id| id.as_str().to_string())
        .filter(|id| id.starts_with(prefix))
        .collect()
}

fn objective_id_candidates(repl: &Repl, prefix: &str) -> Vec<String> {
    repl.objectives
        .keys()
        .map(|id| id.as_str().to_string())
        .filter(|id| id.starts_with(prefix))
        .collect()
}

fn release_snapshot_id_candidates(repl: &Repl, prefix: &str) -> Vec<String> {
    repl.release_rollback
        .list_snapshots()
        .into_iter()
        .map(|snapshot| snapshot.id.to_string())
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

fn next_campaign_id() -> CampaignId {
    let left = Id::next().0;
    let right = Id::next().0;
    let hex = format!("{left:016x}{right:016x}");
    let raw = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    CampaignId::parse(&raw).expect("generated campaign id must be valid")
}

fn next_objective_id() -> ObjectiveId {
    let left = Id::next().0;
    let right = Id::next().0;
    let hex = format!("{left:016x}{right:016x}");
    let raw = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    ObjectiveId::parse(&raw).expect("generated objective id must be valid")
}

fn parse_campaign_status_token(raw: &str) -> Option<corelib::campaign::CampaignStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "active" => Some(corelib::campaign::CampaignStatus::Active),
        "paused" => Some(corelib::campaign::CampaignStatus::Paused),
        "completed" => Some(corelib::campaign::CampaignStatus::Completed),
        "failed" => Some(corelib::campaign::CampaignStatus::Failed),
        _ => None,
    }
}

fn parse_risk_level_token(raw: &str) -> Option<RiskLevel> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        _ => None,
    }
}

fn parse_predicates(raw: &str) -> Result<Vec<Predicate>, String> {
    let mut predicates = Vec::new();
    for item in raw.split(',') {
        let token = item.trim();
        if token.is_empty() {
            continue;
        }
        predicates.push(parse_predicate(token)?);
    }
    if predicates.is_empty() {
        return Err("predicate list cannot be empty".to_string());
    }
    Ok(predicates)
}

fn parse_predicate(raw: &str) -> Result<Predicate, String> {
    if let Some(rest) = raw.strip_prefix("finding_exists:") {
        let finding_type = rest.trim();
        if finding_type.is_empty() {
            return Err("finding_exists requires finding type".to_string());
        }
        return Ok(Predicate::FindingExists {
            finding_type: finding_type.to_string(),
        });
    }

    if let Some(rest) = raw.strip_prefix("session_privilege:") {
        let level = match rest.trim().to_ascii_lowercase().as_str() {
            "user" => SessionPrivilegeLevel::User,
            "elevated" => SessionPrivilegeLevel::Elevated,
            "root" => SessionPrivilegeLevel::Root,
            _ => {
                return Err("session_privilege must be one of: user|elevated|root".to_string());
            }
        };
        return Ok(Predicate::SessionPrivilege { level });
    }

    if let Some(rest) = raw.strip_prefix("artifact_tag_match:") {
        let tag = rest.trim();
        if tag.is_empty() {
            return Err("artifact_tag_match requires a tag".to_string());
        }
        return Ok(Predicate::ArtifactTagMatch {
            tag: tag.to_string(),
        });
    }

    if let Some(rest) = raw.strip_prefix("run_succeeded:") {
        let module_name = rest.trim();
        if module_name.is_empty() {
            return Err("run_succeeded requires a module path".to_string());
        }
        return Ok(Predicate::RunSucceeded {
            module_name: module_name.to_string(),
        });
    }

    if let Some(rest) = raw.strip_prefix("custom_metadata_match:") {
        let (key, value) = rest
            .split_once('=')
            .ok_or_else(|| "custom_metadata_match requires key=value".to_string())?;
        let key = key.trim();
        if key.is_empty() {
            return Err("custom_metadata_match requires non-empty key".to_string());
        }
        let value = parse_metadata_value(value.trim());
        return Ok(Predicate::CustomMetadataMatch {
            key: key.to_string(),
            value,
        });
    }

    Err(
        "unsupported predicate format; supported: finding_exists, session_privilege, artifact_tag_match, run_succeeded, custom_metadata_match"
            .to_string(),
    )
}

fn parse_metadata_value(raw: &str) -> MetadataValue {
    match raw.to_ascii_lowercase().as_str() {
        "null" => MetadataValue::Null,
        "true" => MetadataValue::Bool(true),
        "false" => MetadataValue::Bool(false),
        _ => {
            if let Ok(integer) = raw.parse::<i64>() {
                return MetadataValue::Integer(integer);
            }
            MetadataValue::Text(raw.to_string())
        }
    }
}

fn bool_word(value: bool) -> String {
    if value {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn release_usage_string() -> String {
    "usage: release check | release matrix | release migrate plan <from> <to> | release migrate apply <to> | release rollback snapshot <label> | release rollback list | release rollback apply <snapshot_id> | release rollback prune <keep_latest>".to_string()
}

fn command_tokens() -> Vec<&'static str> {
    let mut tokens = Vec::new();
    for spec in COMMAND_HELP {
        tokens.push(spec.name);
        for alias in spec.aliases {
            tokens.push(*alias);
        }
    }
    tokens.sort_unstable();
    tokens.dedup();
    tokens
}

fn command_primary_names() -> Vec<String> {
    COMMAND_HELP
        .iter()
        .map(|spec| spec.name.to_string())
        .collect()
}

fn find_command_help(topic: &str) -> Option<&'static CommandHelpSpec> {
    let normalized = topic.trim().to_ascii_lowercase();
    for spec in COMMAND_HELP {
        if spec.name == normalized {
            return Some(spec);
        }
        for alias in spec.aliases {
            if *alias == normalized {
                return Some(spec);
            }
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_lookup_supports_primary_and_alias_commands() {
        let help = find_command_help("help").expect("help command");
        assert_eq!(help.name, "help");

        let clear_alias = find_command_help("cls").expect("clear alias");
        assert_eq!(clear_alias.name, "clear");

        let exit_alias = find_command_help("quit").expect("exit alias");
        assert_eq!(exit_alias.name, "exit");
    }

    #[test]
    fn help_lookup_rejects_unknown_command() {
        assert!(find_command_help("nonexistent").is_none());
    }

    #[test]
    fn command_tokens_include_core_and_campaign_commands() {
        let commands = command_tokens();
        assert!(commands.contains(&"clear"));
        assert!(commands.contains(&"cls"));
        assert!(commands.contains(&"release"));
        assert!(commands.contains(&"campaign"));
        assert!(commands.contains(&"objective"));
    }

    #[test]
    fn help_topic_candidates_filter_by_prefix() {
        let prefixed = help_topic_candidates("re");
        assert!(prefixed.contains(&"release".to_string()));
        assert!(!prefixed.contains(&"help".to_string()));
    }

    #[test]
    fn predicate_parser_supports_all_contract_variants() {
        let parsed = parse_predicates(
            "finding_exists:shell,session_privilege:root,artifact_tag_match:loot,run_succeeded:exploit/linux/telnet,test",
        );
        assert!(parsed.is_err(), "invalid mixed predicate list should fail");

        assert!(parse_predicate("finding_exists:shell").is_ok());
        assert!(parse_predicate("session_privilege:root").is_ok());
        assert!(parse_predicate("artifact_tag_match:loot").is_ok());
        assert!(parse_predicate("run_succeeded:exploit/linux/telnet").is_ok());
        assert!(parse_predicate("custom_metadata_match:owner=red").is_ok());
    }

    #[test]
    fn completion_suggests_campaign_objective_commands_and_ids() {
        let registry = modules::ModuleRegistryBuilder::new()
            .build()
            .expect("empty registry");
        let mut repl = Repl::new("moonlight".to_string(), registry, None);
        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_id =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective id");
        let mut campaign =
            Campaign::new_at(campaign_id.clone(), "operation", "", 1, None).expect("campaign");
        campaign.add_objective(objective_id.clone());
        repl.campaigns.insert(campaign_id.clone(), campaign);
        let objective = Objective::new_at(
            objective_id.clone(),
            campaign_id.clone(),
            "foothold",
            "",
            vec![],
            vec![Predicate::FindingExists {
                finding_type: "shell".to_string(),
            }],
            vec![],
            RiskLevel::High,
            None,
            1,
        )
        .expect("objective");
        repl.objectives.insert(objective_id.clone(), objective);

        let root = repl.complete("");
        assert!(root.candidates.contains(&"campaign".to_string()));
        assert!(root.candidates.contains(&"objective".to_string()));

        let campaign_sub = repl.complete("campaign ");
        assert!(campaign_sub.candidates.contains(&"create".to_string()));
        assert!(campaign_sub.candidates.contains(&"status".to_string()));

        let campaign_status = repl.complete("campaign status ");
        assert!(campaign_status
            .candidates
            .contains(&campaign_id.as_str().to_string()));

        let objective_status = repl.complete("objective status ");
        assert!(objective_status
            .candidates
            .contains(&objective_id.as_str().to_string()));
    }
}
