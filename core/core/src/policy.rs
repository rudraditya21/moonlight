use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug)]
pub enum PolicyError {
    Validation(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::Validation(msg) => write!(f, "validation error: {msg}"),
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    ExploitExecution,
    PayloadExecution,
    EvasionExecution,
    PublicTargets,
    WideTargetScope,
    BulkSessionControl,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::ExploitExecution => "exploit_execution",
            Capability::PayloadExecution => "payload_execution",
            Capability::EvasionExecution => "evasion_execution",
            Capability::PublicTargets => "public_targets",
            Capability::WideTargetScope => "wide_target_scope",
            Capability::BulkSessionControl => "bulk_session_control",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "exploit_execution" | "exploit" => Some(Capability::ExploitExecution),
            "payload_execution" | "payload" => Some(Capability::PayloadExecution),
            "evasion_execution" | "evasion" => Some(Capability::EvasionExecution),
            "public_targets" | "public" => Some(Capability::PublicTargets),
            "wide_target_scope" | "wide_scope" | "wide" => Some(Capability::WideTargetScope),
            "bulk_session_control" | "bulk_sessions" | "bulk" => {
                Some(Capability::BulkSessionControl)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    ExecuteModule,
    CloseSession,
    CloseAllSessions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleContext {
    pub name: String,
    pub category: String,
    pub rank: String,
    pub tags: Vec<String>,
}

impl ModuleContext {
    pub fn new(
        name: &str,
        category: &str,
        rank: &str,
        tags: Vec<String>,
    ) -> Result<Self, PolicyError> {
        if name.trim().is_empty() {
            return Err(PolicyError::Validation(
                "module name cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            name: name.trim().to_string(),
            category: category.trim().to_ascii_lowercase(),
            rank: rank.trim().to_ascii_lowercase(),
            tags,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub action: PolicyAction,
    pub module: Option<ModuleContext>,
    pub target: Option<String>,
}

impl PolicyRequest {
    pub fn execute_module(module: ModuleContext, target: Option<String>) -> Self {
        Self {
            action: PolicyAction::ExecuteModule,
            module: Some(module),
            target,
        }
    }

    pub fn close_session() -> Self {
        Self {
            action: PolicyAction::CloseSession,
            module: None,
            target: None,
        }
    }

    pub fn close_all_sessions() -> Self {
        Self {
            action: PolicyAction::CloseAllSessions,
            module: None,
            target: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionKind {
    Allow,
    RequireConfirmation,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub kind: DecisionKind,
    pub reason: String,
}

impl PolicyDecision {
    pub fn allow(reason: &str) -> Self {
        Self {
            kind: DecisionKind::Allow,
            reason: reason.to_string(),
        }
    }

    pub fn confirm(reason: &str) -> Self {
        Self {
            kind: DecisionKind::RequireConfirmation,
            reason: reason.to_string(),
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            kind: DecisionKind::Deny,
            reason: reason.to_string(),
        }
    }
}

pub trait PolicyHook: Send + Sync {
    fn evaluate(&self, request: &PolicyRequest, granted: &BTreeSet<Capability>) -> PolicyDecision;
}

#[derive(Debug, Clone)]
pub struct DefaultSafetyPolicy {
    require_confirmation_for_risky_modules: bool,
}

impl Default for DefaultSafetyPolicy {
    fn default() -> Self {
        Self {
            require_confirmation_for_risky_modules: true,
        }
    }
}

impl DefaultSafetyPolicy {
    pub fn evaluate(
        &self,
        request: &PolicyRequest,
        granted: &BTreeSet<Capability>,
    ) -> PolicyDecision {
        match request.action {
            PolicyAction::CloseSession => {
                PolicyDecision::confirm("Closing a live session requires explicit intent")
            }
            PolicyAction::CloseAllSessions => {
                if !granted.contains(&Capability::BulkSessionControl) {
                    return PolicyDecision::deny(
                        "bulk session control blocked: enable capability bulk_session_control",
                    );
                }
                PolicyDecision::confirm(
                    "Closing all sessions is destructive and requires explicit intent",
                )
            }
            PolicyAction::ExecuteModule => self.evaluate_module_execution(request, granted),
        }
    }

    fn evaluate_module_execution(
        &self,
        request: &PolicyRequest,
        granted: &BTreeSet<Capability>,
    ) -> PolicyDecision {
        let Some(module) = &request.module else {
            return PolicyDecision::deny("module execution request missing module metadata");
        };

        match module.category.as_str() {
            "exploit" => {
                if !granted.contains(&Capability::ExploitExecution) {
                    return PolicyDecision::deny(
                        "exploit execution blocked: enable capability exploit_execution",
                    );
                }
            }
            "payload" => {
                if !granted.contains(&Capability::PayloadExecution) {
                    return PolicyDecision::deny(
                        "payload execution blocked: enable capability payload_execution",
                    );
                }
            }
            "evasion" => {
                if !granted.contains(&Capability::EvasionExecution) {
                    return PolicyDecision::deny(
                        "evasion execution blocked: enable capability evasion_execution",
                    );
                }
            }
            _ => {}
        }

        if let Some(target) = request.target.as_deref() {
            let scope = classify_target_scope(target);
            match scope {
                TargetScope::PublicIp | TargetScope::ExternalHostname => {
                    if !granted.contains(&Capability::PublicTargets) {
                        return PolicyDecision::deny(
                            "public target blocked: enable capability public_targets",
                        );
                    }
                    return PolicyDecision::confirm(&format!(
                        "Target '{}' is public; confirm explicit intent",
                        target
                    ));
                }
                TargetScope::CidrWide => {
                    if !granted.contains(&Capability::WideTargetScope) {
                        return PolicyDecision::deny(
                            "wide target scope blocked: enable capability wide_target_scope",
                        );
                    }
                    return PolicyDecision::confirm(&format!(
                        "Target '{}' is wide scope; confirm explicit intent",
                        target
                    ));
                }
                TargetScope::PrivateIp | TargetScope::Loopback | TargetScope::LocalHostname => {}
                TargetScope::Unknown => {
                    return PolicyDecision::confirm(&format!(
                        "Target '{}' cannot be classified; confirm explicit intent",
                        target
                    ));
                }
            }
        }

        if self.require_confirmation_for_risky_modules && is_risky_module(module) {
            return PolicyDecision::confirm(&format!(
                "Module '{}' is high risk (category={}, rank={}); confirm explicit intent",
                module.name, module.category, module.rank
            ));
        }

        PolicyDecision::allow("allowed by default safety policy")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetScope {
    Loopback,
    PrivateIp,
    PublicIp,
    LocalHostname,
    ExternalHostname,
    CidrWide,
    Unknown,
}

fn classify_target_scope(input: &str) -> TargetScope {
    let target = input.trim();
    if target.is_empty() {
        return TargetScope::Unknown;
    }
    if target.contains(',') {
        return TargetScope::CidrWide;
    }
    if let Some((ip_raw, prefix_raw)) = target.split_once('/') {
        let prefix = prefix_raw.parse::<u8>().ok();
        if let Ok(ip) = ip_raw.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    if prefix.unwrap_or(32) < 24 {
                        return TargetScope::CidrWide;
                    }
                    if v4.is_loopback() {
                        return TargetScope::Loopback;
                    }
                    if is_private_v4(&v4) {
                        return TargetScope::PrivateIp;
                    }
                    return TargetScope::PublicIp;
                }
                IpAddr::V6(v6) => {
                    if prefix.unwrap_or(128) < 120 {
                        return TargetScope::CidrWide;
                    }
                    if v6.is_loopback() {
                        return TargetScope::Loopback;
                    }
                    if v6.is_unique_local() {
                        return TargetScope::PrivateIp;
                    }
                    return TargetScope::PublicIp;
                }
            }
        }
        return TargetScope::Unknown;
    }

    if let Ok(ip) = target.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    TargetScope::Loopback
                } else if is_private_v4(&v4) {
                    TargetScope::PrivateIp
                } else {
                    TargetScope::PublicIp
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    TargetScope::Loopback
                } else if v6.is_unique_local() {
                    TargetScope::PrivateIp
                } else {
                    TargetScope::PublicIp
                }
            }
        };
    }

    let lower = target.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".local") {
        return TargetScope::LocalHostname;
    }
    if lower
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return TargetScope::ExternalHostname;
    }

    TargetScope::Unknown
}

fn is_private_v4(v4: &std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 169 && octets[1] == 254)
}

fn is_risky_module(module: &ModuleContext) -> bool {
    matches!(module.category.as_str(), "exploit" | "payload" | "evasion")
        || matches!(module.rank.as_str(), "excellent" | "great")
}

pub struct PolicyEngine {
    granted: BTreeSet<Capability>,
    base: DefaultSafetyPolicy,
    hooks: Vec<Box<dyn PolicyHook>>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            granted: BTreeSet::new(),
            base: DefaultSafetyPolicy::default(),
            hooks: Vec::new(),
        }
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn granted_capabilities(&self) -> Vec<Capability> {
        self.granted.iter().copied().collect()
    }

    pub fn grant(&mut self, capability: Capability) {
        self.granted.insert(capability);
    }

    pub fn revoke(&mut self, capability: Capability) {
        self.granted.remove(&capability);
    }

    pub fn register_hook(&mut self, hook: Box<dyn PolicyHook>) {
        self.hooks.push(hook);
    }

    pub fn evaluate(&self, request: &PolicyRequest) -> PolicyDecision {
        let mut decision = self.base.evaluate(request, &self.granted);
        if matches!(decision.kind, DecisionKind::Deny) {
            return decision;
        }

        for hook in &self.hooks {
            let hook_decision = hook.evaluate(request, &self.granted);
            match hook_decision.kind {
                DecisionKind::Deny => return hook_decision,
                DecisionKind::RequireConfirmation => decision = hook_decision,
                DecisionKind::Allow => {}
            }
        }
        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DenyAllHook;

    impl PolicyHook for DenyAllHook {
        fn evaluate(
            &self,
            _request: &PolicyRequest,
            _granted: &BTreeSet<Capability>,
        ) -> PolicyDecision {
            PolicyDecision::deny("blocked by custom policy hook")
        }
    }

    fn exploit_module() -> ModuleContext {
        ModuleContext::new(
            "exploit/linux/test",
            "exploit",
            "excellent",
            vec!["rce".to_string()],
        )
        .expect("module")
    }

    #[test]
    fn exploit_is_denied_without_explicit_capability() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(&PolicyRequest::execute_module(
            exploit_module(),
            Some("127.0.0.1".to_string()),
        ));
        assert_eq!(decision.kind, DecisionKind::Deny);
    }

    #[test]
    fn private_target_exploit_requires_confirmation_after_capability_grant() {
        let mut engine = PolicyEngine::new();
        engine.grant(Capability::ExploitExecution);
        let decision = engine.evaluate(&PolicyRequest::execute_module(
            exploit_module(),
            Some("10.10.10.5".to_string()),
        ));
        assert_eq!(decision.kind, DecisionKind::RequireConfirmation);
    }

    #[test]
    fn public_target_requires_public_capability() {
        let mut engine = PolicyEngine::new();
        engine.grant(Capability::ExploitExecution);
        let denied = engine.evaluate(&PolicyRequest::execute_module(
            exploit_module(),
            Some("8.8.8.8".to_string()),
        ));
        assert_eq!(denied.kind, DecisionKind::Deny);

        engine.grant(Capability::PublicTargets);
        let confirmed = engine.evaluate(&PolicyRequest::execute_module(
            exploit_module(),
            Some("8.8.8.8".to_string()),
        ));
        assert_eq!(confirmed.kind, DecisionKind::RequireConfirmation);
    }

    #[test]
    fn wide_scope_requires_wide_scope_capability() {
        let mut engine = PolicyEngine::new();
        engine.grant(Capability::ExploitExecution);
        let denied = engine.evaluate(&PolicyRequest::execute_module(
            exploit_module(),
            Some("10.0.0.0/8".to_string()),
        ));
        assert_eq!(denied.kind, DecisionKind::Deny);

        engine.grant(Capability::WideTargetScope);
        let confirmed = engine.evaluate(&PolicyRequest::execute_module(
            exploit_module(),
            Some("10.0.0.0/8".to_string()),
        ));
        assert_eq!(confirmed.kind, DecisionKind::RequireConfirmation);
    }

    #[test]
    fn close_all_sessions_requires_bulk_capability() {
        let mut engine = PolicyEngine::new();
        let denied = engine.evaluate(&PolicyRequest::close_all_sessions());
        assert_eq!(denied.kind, DecisionKind::Deny);

        engine.grant(Capability::BulkSessionControl);
        let confirmed = engine.evaluate(&PolicyRequest::close_all_sessions());
        assert_eq!(confirmed.kind, DecisionKind::RequireConfirmation);
    }

    #[test]
    fn custom_hook_can_deny_without_redesign() {
        let mut engine = PolicyEngine::new();
        engine.grant(Capability::ExploitExecution);
        engine.register_hook(Box::new(DenyAllHook));

        let decision = engine.evaluate(&PolicyRequest::execute_module(
            exploit_module(),
            Some("10.0.0.5".to_string()),
        ));
        assert_eq!(decision.kind, DecisionKind::Deny);
        assert_eq!(decision.reason, "blocked by custom policy hook");
    }
}
