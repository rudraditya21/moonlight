use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::domain;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignModelError {
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    InvalidTransition {
        entity: &'static str,
        from: &'static str,
        to: &'static str,
    },
    Parse {
        reason: &'static str,
    },
    MissingObjective {
        objective_id: ObjectiveId,
    },
    PrerequisiteCycle {
        objective_id: ObjectiveId,
    },
}

impl fmt::Display for CampaignModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CampaignModelError::InvalidField { field, reason } => {
                write!(f, "invalid field {field}: {reason}")
            }
            CampaignModelError::InvalidTransition { entity, from, to } => {
                write!(f, "invalid {entity} transition: {from} -> {to}")
            }
            CampaignModelError::Parse { reason } => write!(f, "parse error: {reason}"),
            CampaignModelError::MissingObjective { objective_id } => {
                write!(
                    f,
                    "objective reference does not exist in campaign graph: {}",
                    objective_id.as_str()
                )
            }
            CampaignModelError::PrerequisiteCycle { objective_id } => {
                write!(
                    f,
                    "objective prerequisite cycle detected near objective {}",
                    objective_id.as_str()
                )
            }
        }
    }
}

impl std::error::Error for CampaignModelError {}

impl CampaignModelError {
    pub const fn code(&self) -> &'static str {
        match self {
            CampaignModelError::InvalidField { .. } => "ML-CAMP-0001",
            CampaignModelError::InvalidTransition { .. } => "ML-CAMP-0002",
            CampaignModelError::MissingObjective { .. } => "ML-CAMP-0003",
            CampaignModelError::PrerequisiteCycle { .. } => "ML-CAMP-0004",
            CampaignModelError::Parse { .. } => "ML-CAMP-0005",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid(String);

impl Uuid {
    pub fn parse(input: &str) -> Result<Self, CampaignModelError> {
        let raw = input.trim();
        if !is_valid_uuid(raw) {
            return Err(CampaignModelError::InvalidField {
                field: "uuid",
                reason: "must be canonical RFC-4122 style UUID",
            });
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CampaignId(Uuid);

impl CampaignId {
    pub fn parse(input: &str) -> Result<Self, CampaignModelError> {
        Ok(Self(Uuid::parse(input)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectiveId(Uuid);

impl ObjectiveId {
    pub fn parse(input: &str) -> Result<Self, CampaignModelError> {
        Ok(Self(Uuid::parse(input)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CampaignStatus {
    Active,
    Paused,
    Completed,
    Failed,
}

impl CampaignStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            CampaignStatus::Active => "active",
            CampaignStatus::Paused => "paused",
            CampaignStatus::Completed => "completed",
            CampaignStatus::Failed => "failed",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (CampaignStatus::Active, CampaignStatus::Paused)
            | (CampaignStatus::Active, CampaignStatus::Completed)
            | (CampaignStatus::Active, CampaignStatus::Failed)
            | (CampaignStatus::Paused, CampaignStatus::Active)
            | (CampaignStatus::Paused, CampaignStatus::Completed)
            | (CampaignStatus::Paused, CampaignStatus::Failed) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, CampaignStatus::Completed | CampaignStatus::Failed)
    }
}

pub const CAMPAIGN_ALLOWED_TRANSITIONS: &[(CampaignStatus, CampaignStatus)] = &[
    (CampaignStatus::Active, CampaignStatus::Paused),
    (CampaignStatus::Active, CampaignStatus::Completed),
    (CampaignStatus::Active, CampaignStatus::Failed),
    (CampaignStatus::Paused, CampaignStatus::Active),
    (CampaignStatus::Paused, CampaignStatus::Completed),
    (CampaignStatus::Paused, CampaignStatus::Failed),
];

pub const CAMPAIGN_FORBIDDEN_TRANSITIONS: &[(CampaignStatus, CampaignStatus)] = &[
    (CampaignStatus::Active, CampaignStatus::Active),
    (CampaignStatus::Paused, CampaignStatus::Paused),
    (CampaignStatus::Completed, CampaignStatus::Active),
    (CampaignStatus::Completed, CampaignStatus::Paused),
    (CampaignStatus::Completed, CampaignStatus::Completed),
    (CampaignStatus::Completed, CampaignStatus::Failed),
    (CampaignStatus::Failed, CampaignStatus::Active),
    (CampaignStatus::Failed, CampaignStatus::Paused),
    (CampaignStatus::Failed, CampaignStatus::Completed),
    (CampaignStatus::Failed, CampaignStatus::Failed),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectiveStatus {
    Pending,
    Eligible,
    InProgress,
    Achieved,
    Failed,
}

impl ObjectiveStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ObjectiveStatus::Pending => "pending",
            ObjectiveStatus::Eligible => "eligible",
            ObjectiveStatus::InProgress => "in_progress",
            ObjectiveStatus::Achieved => "achieved",
            ObjectiveStatus::Failed => "failed",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (ObjectiveStatus::Pending, ObjectiveStatus::Eligible)
            | (ObjectiveStatus::Eligible, ObjectiveStatus::InProgress)
            | (ObjectiveStatus::InProgress, ObjectiveStatus::Achieved)
            | (ObjectiveStatus::InProgress, ObjectiveStatus::Failed) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, ObjectiveStatus::Achieved | ObjectiveStatus::Failed)
    }
}

pub const OBJECTIVE_ALLOWED_TRANSITIONS: &[(ObjectiveStatus, ObjectiveStatus)] = &[
    (ObjectiveStatus::Pending, ObjectiveStatus::Eligible),
    (ObjectiveStatus::Eligible, ObjectiveStatus::InProgress),
    (ObjectiveStatus::InProgress, ObjectiveStatus::Achieved),
    (ObjectiveStatus::InProgress, ObjectiveStatus::Failed),
];

pub const OBJECTIVE_FORBIDDEN_TRANSITIONS: &[(ObjectiveStatus, ObjectiveStatus)] = &[
    (ObjectiveStatus::Pending, ObjectiveStatus::Pending),
    (ObjectiveStatus::Pending, ObjectiveStatus::InProgress),
    (ObjectiveStatus::Pending, ObjectiveStatus::Achieved),
    (ObjectiveStatus::Pending, ObjectiveStatus::Failed),
    (ObjectiveStatus::Eligible, ObjectiveStatus::Pending),
    (ObjectiveStatus::Eligible, ObjectiveStatus::Eligible),
    (ObjectiveStatus::Eligible, ObjectiveStatus::Achieved),
    (ObjectiveStatus::Eligible, ObjectiveStatus::Failed),
    (ObjectiveStatus::InProgress, ObjectiveStatus::Pending),
    (ObjectiveStatus::InProgress, ObjectiveStatus::Eligible),
    (ObjectiveStatus::InProgress, ObjectiveStatus::InProgress),
    (ObjectiveStatus::Achieved, ObjectiveStatus::Pending),
    (ObjectiveStatus::Achieved, ObjectiveStatus::Eligible),
    (ObjectiveStatus::Achieved, ObjectiveStatus::InProgress),
    (ObjectiveStatus::Achieved, ObjectiveStatus::Achieved),
    (ObjectiveStatus::Achieved, ObjectiveStatus::Failed),
    (ObjectiveStatus::Failed, ObjectiveStatus::Pending),
    (ObjectiveStatus::Failed, ObjectiveStatus::Eligible),
    (ObjectiveStatus::Failed, ObjectiveStatus::InProgress),
    (ObjectiveStatus::Failed, ObjectiveStatus::Achieved),
    (ObjectiveStatus::Failed, ObjectiveStatus::Failed),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl RiskLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionPrivilegeLevel {
    User,
    Elevated,
    Root,
}

impl SessionPrivilegeLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionPrivilegeLevel::User => "user",
            SessionPrivilegeLevel::Elevated => "elevated",
            SessionPrivilegeLevel::Root => "root",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MetadataValue {
    Null,
    Bool(bool),
    Integer(i64),
    FloatBits(u64),
    Text(String),
    Array(Vec<MetadataValue>),
    Object(BTreeMap<String, MetadataValue>),
}

impl Eq for MetadataValue {}

impl MetadataValue {
    pub fn stable_encoding(&self) -> String {
        match self {
            MetadataValue::Null => "null".to_string(),
            MetadataValue::Bool(value) => {
                if *value {
                    "bool:true".to_string()
                } else {
                    "bool:false".to_string()
                }
            }
            MetadataValue::Integer(value) => format!("int:{value}"),
            MetadataValue::FloatBits(bits) => format!("float:{bits}"),
            MetadataValue::Text(value) => format!("text:{}", escape_canonical(value)),
            MetadataValue::Array(values) => {
                let joined = values
                    .iter()
                    .map(|v| v.stable_encoding())
                    .collect::<Vec<_>>()
                    .join(",");
                format!("array:[{joined}]")
            }
            MetadataValue::Object(map) => {
                let joined = map
                    .iter()
                    .map(|(k, v)| format!("{}={}", escape_canonical(k), v.stable_encoding()))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("object:{{{joined}}}")
            }
        }
    }

    fn write_wire(&self, out: &mut Vec<u8>) {
        match self {
            MetadataValue::Null => out.push(0),
            MetadataValue::Bool(false) => out.push(1),
            MetadataValue::Bool(true) => out.push(2),
            MetadataValue::Integer(value) => {
                out.push(3);
                out.extend_from_slice(&value.to_be_bytes());
            }
            MetadataValue::FloatBits(bits) => {
                out.push(4);
                out.extend_from_slice(&bits.to_be_bytes());
            }
            MetadataValue::Text(value) => {
                out.push(5);
                write_string(out, value);
            }
            MetadataValue::Array(values) => {
                out.push(6);
                write_u32(out, values.len() as u32);
                for value in values {
                    value.write_wire(out);
                }
            }
            MetadataValue::Object(map) => {
                out.push(7);
                write_u32(out, map.len() as u32);
                for (key, value) in map {
                    write_string(out, key);
                    value.write_wire(out);
                }
            }
        }
    }

    fn read_wire(cursor: &mut WireCursor<'_>) -> Result<Self, CampaignModelError> {
        let tag = cursor.read_u8()?;
        match tag {
            0 => Ok(MetadataValue::Null),
            1 => Ok(MetadataValue::Bool(false)),
            2 => Ok(MetadataValue::Bool(true)),
            3 => Ok(MetadataValue::Integer(cursor.read_i64()?)),
            4 => Ok(MetadataValue::FloatBits(cursor.read_u64()?)),
            5 => Ok(MetadataValue::Text(cursor.read_string()?)),
            6 => {
                let count = cursor.read_u32()? as usize;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(MetadataValue::read_wire(cursor)?);
                }
                Ok(MetadataValue::Array(values))
            }
            7 => {
                let count = cursor.read_u32()? as usize;
                let mut map = BTreeMap::new();
                for _ in 0..count {
                    let key = cursor.read_string()?;
                    if map.contains_key(&key) {
                        return Err(CampaignModelError::Parse {
                            reason: "duplicate metadata object key",
                        });
                    }
                    map.insert(key, MetadataValue::read_wire(cursor)?);
                }
                Ok(MetadataValue::Object(map))
            }
            _ => Err(CampaignModelError::Parse {
                reason: "unknown metadata tag",
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSnapshot {
    pub artifact: domain::Artifact,
    pub tags: BTreeSet<String>,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl ArtifactSnapshot {
    pub fn new(artifact: domain::Artifact) -> Self {
        Self {
            artifact,
            tags: BTreeSet::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.insert(normalize_token(tag));
        self
    }

    pub fn with_metadata(mut self, key: &str, value: MetadataValue) -> Self {
        self.metadata.insert(normalize_token(key), value);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSnapshot {
    pub finding: domain::Finding,
    pub finding_type: String,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl FindingSnapshot {
    pub fn new(finding: domain::Finding, finding_type: &str) -> Result<Self, CampaignModelError> {
        ensure_non_empty(finding_type, "finding_snapshot.finding_type")?;
        Ok(Self {
            finding,
            finding_type: normalize_token(finding_type),
            metadata: BTreeMap::new(),
        })
    }

    pub fn with_metadata(mut self, key: &str, value: MetadataValue) -> Self {
        self.metadata.insert(normalize_token(key), value);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub session: domain::Session,
    pub privilege: Option<SessionPrivilegeLevel>,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl SessionSnapshot {
    pub fn new(session: domain::Session) -> Self {
        Self {
            session,
            privilege: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_privilege(mut self, privilege: SessionPrivilegeLevel) -> Self {
        self.privilege = Some(privilege);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: MetadataValue) -> Self {
        self.metadata.insert(normalize_token(key), value);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSnapshot {
    pub run: domain::Run,
    pub module_name: String,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl RunSnapshot {
    pub fn new(run: domain::Run, module_name: &str) -> Result<Self, CampaignModelError> {
        ensure_non_empty(module_name, "run_snapshot.module_name")?;
        Ok(Self {
            run,
            module_name: normalize_token(module_name),
            metadata: BTreeMap::new(),
        })
    }

    pub fn with_metadata(mut self, key: &str, value: MetadataValue) -> Self {
        self.metadata.insert(normalize_token(key), value);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateSnapshot {
    pub artifacts: Vec<ArtifactSnapshot>,
    pub findings: Vec<FindingSnapshot>,
    pub sessions: Vec<SessionSnapshot>,
    pub runs: Vec<RunSnapshot>,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl PredicateSnapshot {
    pub fn new() -> Self {
        Self {
            artifacts: Vec::new(),
            findings: Vec::new(),
            sessions: Vec::new(),
            runs: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_artifact(mut self, artifact: ArtifactSnapshot) -> Self {
        self.artifacts.push(artifact);
        self
    }

    pub fn with_finding(mut self, finding: FindingSnapshot) -> Self {
        self.findings.push(finding);
        self
    }

    pub fn with_session(mut self, session: SessionSnapshot) -> Self {
        self.sessions.push(session);
        self
    }

    pub fn with_run(mut self, run: RunSnapshot) -> Self {
        self.runs.push(run);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: MetadataValue) -> Self {
        self.metadata.insert(normalize_token(key), value);
        self
    }

    fn contains_metadata_match(&self, key: &str, value: &MetadataValue) -> bool {
        let token = normalize_token(key);
        if self
            .metadata
            .get(&token)
            .is_some_and(|existing| existing == value)
        {
            return true;
        }
        if self
            .artifacts
            .iter()
            .any(|artifact| artifact.metadata.get(&token).is_some_and(|v| v == value))
        {
            return true;
        }
        if self
            .findings
            .iter()
            .any(|finding| finding.metadata.get(&token).is_some_and(|v| v == value))
        {
            return true;
        }
        if self
            .sessions
            .iter()
            .any(|session| session.metadata.get(&token).is_some_and(|v| v == value))
        {
            return true;
        }
        self.runs
            .iter()
            .any(|run| run.metadata.get(&token).is_some_and(|v| v == value))
    }
}

impl Default for PredicateSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    FindingExists { finding_type: String },
    SessionPrivilege { level: SessionPrivilegeLevel },
    ArtifactTagMatch { tag: String },
    RunSucceeded { module_name: String },
    CustomMetadataMatch { key: String, value: MetadataValue },
}

impl Predicate {
    pub fn stable_encoding(&self) -> String {
        match self {
            Predicate::FindingExists { finding_type } => {
                format!("finding_exists:{}", normalize_token(finding_type))
            }
            Predicate::SessionPrivilege { level } => {
                format!("session_privilege:{}", level.as_str())
            }
            Predicate::ArtifactTagMatch { tag } => {
                format!("artifact_tag_match:{}", normalize_token(tag))
            }
            Predicate::RunSucceeded { module_name } => {
                format!("run_succeeded:{}", normalize_token(module_name))
            }
            Predicate::CustomMetadataMatch { key, value } => {
                format!(
                    "custom_metadata_match:{}={}",
                    normalize_token(key),
                    value.stable_encoding()
                )
            }
        }
    }

    pub fn evaluate(&self, view: &PredicateEvaluationView) -> bool {
        match self {
            Predicate::FindingExists { finding_type } => {
                view.finding_types.contains(&normalize_token(finding_type))
            }
            Predicate::SessionPrivilege { level } => view.session_privilege == Some(*level),
            Predicate::ArtifactTagMatch { tag } => {
                view.artifact_tags.contains(&normalize_token(tag))
            }
            Predicate::RunSucceeded { module_name } => view
                .successful_run_modules
                .contains(&normalize_token(module_name)),
            Predicate::CustomMetadataMatch { key, value } => view
                .custom_metadata
                .get(&normalize_token(key))
                .map(|actual| actual == value)
                .unwrap_or(false),
        }
    }

    pub fn evaluate_snapshot(&self, snapshot: &PredicateSnapshot) -> bool {
        match self {
            Predicate::FindingExists { finding_type } => snapshot
                .findings
                .iter()
                .any(|finding| finding.finding_type == normalize_token(finding_type)),
            Predicate::SessionPrivilege { level } => snapshot
                .sessions
                .iter()
                .any(|session| session.privilege == Some(*level)),
            Predicate::ArtifactTagMatch { tag } => {
                let token = normalize_token(tag);
                snapshot
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.tags.contains(&token))
            }
            Predicate::RunSucceeded { module_name } => {
                let token = normalize_token(module_name);
                snapshot.runs.iter().any(|run| {
                    run.module_name == token && run.run.state == domain::RunState::Succeeded
                })
            }
            Predicate::CustomMetadataMatch { key, value } => {
                snapshot.contains_metadata_match(key, value)
            }
        }
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Predicate::FindingExists { finding_type } => {
                out.push(1);
                write_string(&mut out, &normalize_token(finding_type));
            }
            Predicate::SessionPrivilege { level } => {
                out.push(2);
                out.push(match level {
                    SessionPrivilegeLevel::User => 0,
                    SessionPrivilegeLevel::Elevated => 1,
                    SessionPrivilegeLevel::Root => 2,
                });
            }
            Predicate::ArtifactTagMatch { tag } => {
                out.push(3);
                write_string(&mut out, &normalize_token(tag));
            }
            Predicate::RunSucceeded { module_name } => {
                out.push(4);
                write_string(&mut out, &normalize_token(module_name));
            }
            Predicate::CustomMetadataMatch { key, value } => {
                out.push(5);
                write_string(&mut out, &normalize_token(key));
                value.write_wire(&mut out);
            }
        }
        out
    }

    pub fn from_wire_bytes(input: &[u8]) -> Result<Self, CampaignModelError> {
        let mut cursor = WireCursor::new(input);
        let tag = cursor.read_u8()?;
        let predicate = match tag {
            1 => Predicate::FindingExists {
                finding_type: cursor.read_string()?,
            },
            2 => {
                let privilege = cursor.read_u8()?;
                let level = match privilege {
                    0 => SessionPrivilegeLevel::User,
                    1 => SessionPrivilegeLevel::Elevated,
                    2 => SessionPrivilegeLevel::Root,
                    _ => {
                        return Err(CampaignModelError::Parse {
                            reason: "unknown session privilege level tag",
                        });
                    }
                };
                Predicate::SessionPrivilege { level }
            }
            3 => Predicate::ArtifactTagMatch {
                tag: cursor.read_string()?,
            },
            4 => Predicate::RunSucceeded {
                module_name: cursor.read_string()?,
            },
            5 => {
                let key = cursor.read_string()?;
                let value = MetadataValue::read_wire(&mut cursor)?;
                Predicate::CustomMetadataMatch { key, value }
            }
            _ => {
                return Err(CampaignModelError::Parse {
                    reason: "unknown predicate tag",
                });
            }
        };
        cursor.ensure_finished()?;
        Ok(predicate)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectiveEvaluationResult {
    pub prerequisites_satisfied: bool,
    pub success_criteria_satisfied: bool,
    pub failure_criteria_satisfied: bool,
    pub next_status: Option<ObjectiveStatus>,
}

impl ObjectiveEvaluationResult {
    pub const fn no_transition(
        prerequisites_satisfied: bool,
        success_criteria_satisfied: bool,
        failure_criteria_satisfied: bool,
    ) -> Self {
        Self {
            prerequisites_satisfied,
            success_criteria_satisfied,
            failure_criteria_satisfied,
            next_status: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicateEvaluationView {
    pub finding_types: BTreeSet<String>,
    pub session_privilege: Option<SessionPrivilegeLevel>,
    pub artifact_tags: BTreeSet<String>,
    pub successful_run_modules: BTreeSet<String>,
    pub custom_metadata: BTreeMap<String, MetadataValue>,
}

impl PredicateEvaluationView {
    pub fn new() -> Self {
        Self {
            finding_types: BTreeSet::new(),
            session_privilege: None,
            artifact_tags: BTreeSet::new(),
            successful_run_modules: BTreeSet::new(),
            custom_metadata: BTreeMap::new(),
        }
    }

    pub fn with_finding_type(mut self, finding_type: &str) -> Self {
        self.finding_types.insert(normalize_token(finding_type));
        self
    }

    pub fn with_session_privilege(mut self, level: SessionPrivilegeLevel) -> Self {
        self.session_privilege = Some(level);
        self
    }

    pub fn with_artifact_tag(mut self, tag: &str) -> Self {
        self.artifact_tags.insert(normalize_token(tag));
        self
    }

    pub fn with_successful_run(mut self, module_name: &str) -> Self {
        self.successful_run_modules
            .insert(normalize_token(module_name));
        self
    }

    pub fn with_custom_metadata(mut self, key: &str, value: MetadataValue) -> Self {
        self.custom_metadata.insert(normalize_token(key), value);
        self
    }
}

impl Default for PredicateEvaluationView {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Campaign {
    pub id: CampaignId,
    pub name: String,
    pub description: String,
    pub created_at: u64,
    pub status: CampaignStatus,
    pub objective_ids: Vec<ObjectiveId>,
    pub metadata: Option<BTreeMap<String, MetadataValue>>,
}

impl Campaign {
    pub fn new_at(
        id: CampaignId,
        name: &str,
        description: &str,
        created_at: u64,
        metadata: Option<BTreeMap<String, MetadataValue>>,
    ) -> Result<Self, CampaignModelError> {
        ensure_non_empty(name, "campaign.name")?;
        Ok(Self {
            id,
            name: name.trim().to_string(),
            description: description.trim().to_string(),
            created_at,
            status: CampaignStatus::Active,
            objective_ids: Vec::new(),
            metadata,
        })
    }

    pub fn transition_status(&mut self, next: CampaignStatus) -> Result<(), CampaignModelError> {
        if self.status == next {
            return Err(CampaignModelError::InvalidTransition {
                entity: "campaign",
                from: self.status.as_str(),
                to: next.as_str(),
            });
        }
        if !self.status.can_transition_to(next) {
            return Err(CampaignModelError::InvalidTransition {
                entity: "campaign",
                from: self.status.as_str(),
                to: next.as_str(),
            });
        }
        self.status = next;
        Ok(())
    }

    pub fn add_objective(&mut self, objective_id: ObjectiveId) {
        if self.objective_ids.contains(&objective_id) {
            return;
        }
        self.objective_ids.push(objective_id);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objective {
    pub id: ObjectiveId,
    pub campaign_id: CampaignId,
    pub name: String,
    pub description: String,
    pub status: ObjectiveStatus,
    pub prerequisites: Vec<ObjectiveId>,
    pub success_criteria: Vec<Predicate>,
    pub failure_criteria: Vec<Predicate>,
    pub risk_level: RiskLevel,
    pub noise_budget: Option<u32>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Objective {
    #[allow(clippy::too_many_arguments)]
    pub fn new_at(
        id: ObjectiveId,
        campaign_id: CampaignId,
        name: &str,
        description: &str,
        prerequisites: Vec<ObjectiveId>,
        success_criteria: Vec<Predicate>,
        failure_criteria: Vec<Predicate>,
        risk_level: RiskLevel,
        noise_budget: Option<u32>,
        now: u64,
    ) -> Result<Self, CampaignModelError> {
        ensure_non_empty(name, "objective.name")?;
        if success_criteria.is_empty() {
            return Err(CampaignModelError::InvalidField {
                field: "objective.success_criteria",
                reason: "must contain at least one predicate",
            });
        }

        if noise_budget == Some(0) {
            return Err(CampaignModelError::InvalidField {
                field: "objective.noise_budget",
                reason: "must be greater than zero when provided",
            });
        }

        let prerequisites = dedupe_objective_ids(prerequisites);
        if prerequisites.contains(&id) {
            return Err(CampaignModelError::InvalidField {
                field: "objective.prerequisites",
                reason: "cannot include objective id itself",
            });
        }

        Ok(Self {
            id,
            campaign_id,
            name: name.trim().to_string(),
            description: description.trim().to_string(),
            status: ObjectiveStatus::Pending,
            prerequisites,
            success_criteria,
            failure_criteria,
            risk_level,
            noise_budget,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn prerequisites_satisfied(&self, achieved: &BTreeSet<ObjectiveId>) -> bool {
        self.prerequisites
            .iter()
            .all(|prereq| achieved.contains(prereq))
    }

    pub fn success_criteria_satisfied(&self, view: &PredicateEvaluationView) -> bool {
        self.success_criteria
            .iter()
            .all(|predicate| predicate.evaluate(view))
    }

    pub fn success_criteria_satisfied_snapshot(&self, snapshot: &PredicateSnapshot) -> bool {
        self.success_criteria
            .iter()
            .all(|predicate| predicate.evaluate_snapshot(snapshot))
    }

    pub fn failure_criteria_satisfied(&self, view: &PredicateEvaluationView) -> bool {
        self.failure_criteria
            .iter()
            .any(|predicate| predicate.evaluate(view))
    }

    pub fn failure_criteria_satisfied_snapshot(&self, snapshot: &PredicateSnapshot) -> bool {
        self.failure_criteria
            .iter()
            .any(|predicate| predicate.evaluate_snapshot(snapshot))
    }

    pub fn evaluate_transition(
        &self,
        prerequisites_satisfied: bool,
        view: &PredicateEvaluationView,
    ) -> ObjectiveEvaluationResult {
        let success_criteria_satisfied = self.success_criteria_satisfied(view);
        let failure_criteria_satisfied = self.failure_criteria_satisfied(view);

        let next_status = match self.status {
            ObjectiveStatus::Pending if prerequisites_satisfied => Some(ObjectiveStatus::Eligible),
            ObjectiveStatus::InProgress if failure_criteria_satisfied => {
                Some(ObjectiveStatus::Failed)
            }
            ObjectiveStatus::InProgress if success_criteria_satisfied => {
                Some(ObjectiveStatus::Achieved)
            }
            _ => None,
        };

        ObjectiveEvaluationResult {
            prerequisites_satisfied,
            success_criteria_satisfied,
            failure_criteria_satisfied,
            next_status,
        }
    }

    pub fn evaluate_transition_snapshot(
        &self,
        prerequisites_satisfied: bool,
        snapshot: &PredicateSnapshot,
    ) -> ObjectiveEvaluationResult {
        let success_criteria_satisfied = self.success_criteria_satisfied_snapshot(snapshot);
        let failure_criteria_satisfied = self.failure_criteria_satisfied_snapshot(snapshot);

        let next_status = match self.status {
            ObjectiveStatus::Pending if prerequisites_satisfied => Some(ObjectiveStatus::Eligible),
            ObjectiveStatus::InProgress if failure_criteria_satisfied => {
                Some(ObjectiveStatus::Failed)
            }
            ObjectiveStatus::InProgress if success_criteria_satisfied => {
                Some(ObjectiveStatus::Achieved)
            }
            _ => None,
        };

        ObjectiveEvaluationResult {
            prerequisites_satisfied,
            success_criteria_satisfied,
            failure_criteria_satisfied,
            next_status,
        }
    }

    fn transition_to_eligible(
        &mut self,
        prerequisites_satisfied: bool,
        now: u64,
    ) -> Result<(), CampaignModelError> {
        if !prerequisites_satisfied {
            return Err(CampaignModelError::InvalidField {
                field: "objective.prerequisites",
                reason: "all prerequisites must be achieved before eligibility",
            });
        }
        self.transition_status(ObjectiveStatus::Eligible, now)
    }

    fn transition_to_in_progress(&mut self, now: u64) -> Result<(), CampaignModelError> {
        self.transition_status(ObjectiveStatus::InProgress, now)
    }

    fn transition_to_achieved(
        &mut self,
        success_criteria_satisfied: bool,
        now: u64,
    ) -> Result<(), CampaignModelError> {
        if !success_criteria_satisfied {
            return Err(CampaignModelError::InvalidField {
                field: "objective.success_criteria",
                reason: "all success criteria must be satisfied",
            });
        }
        self.transition_status(ObjectiveStatus::Achieved, now)
    }

    fn transition_to_failed(
        &mut self,
        failure_criteria_satisfied: bool,
        now: u64,
    ) -> Result<(), CampaignModelError> {
        if !failure_criteria_satisfied {
            return Err(CampaignModelError::InvalidField {
                field: "objective.failure_criteria",
                reason: "at least one failure criterion must be satisfied",
            });
        }
        self.transition_status(ObjectiveStatus::Failed, now)
    }

    fn transition_status(
        &mut self,
        next: ObjectiveStatus,
        now: u64,
    ) -> Result<(), CampaignModelError> {
        if self.status == next {
            return Err(CampaignModelError::InvalidTransition {
                entity: "objective",
                from: self.status.as_str(),
                to: next.as_str(),
            });
        }
        if !self.status.can_transition_to(next) {
            return Err(CampaignModelError::InvalidTransition {
                entity: "objective",
                from: self.status.as_str(),
                to: next.as_str(),
            });
        }
        self.status = next;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectiveTransitionAudit {
    pub objective_id: ObjectiveId,
    pub from: ObjectiveStatus,
    pub to: ObjectiveStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectiveEvaluationRecord {
    pub objective_id: ObjectiveId,
    pub result: ObjectiveEvaluationResult,
}

pub trait ObjectiveEventHook {
    fn emit(&mut self, payload: CampaignEventPayload);
}

impl ObjectiveEventHook for Vec<CampaignEventPayload> {
    fn emit(&mut self, payload: CampaignEventPayload) {
        self.push(payload);
    }
}

pub struct ObjectiveEvaluationEngine;

impl ObjectiveEvaluationEngine {
    pub fn evaluate_objective<H: ObjectiveEventHook>(
        objective: &mut Objective,
        objective_statuses: &BTreeMap<ObjectiveId, ObjectiveStatus>,
        snapshot: &PredicateSnapshot,
        trigger: ObjectiveReevaluationTrigger,
        now: u64,
        hook: &mut H,
    ) -> Result<ObjectiveEvaluationResult, CampaignModelError> {
        let prerequisites_satisfied = Self::prerequisites_satisfied(objective, objective_statuses)?;
        let success_criteria_satisfied = objective.success_criteria_satisfied_snapshot(snapshot);
        let failure_criteria_satisfied = objective.failure_criteria_satisfied_snapshot(snapshot);

        let mut result = ObjectiveEvaluationResult::no_transition(
            prerequisites_satisfied,
            success_criteria_satisfied,
            failure_criteria_satisfied,
        );
        let from = objective.status;
        let mut resulting_status = from;

        if objective.status == ObjectiveStatus::Pending {
            if prerequisites_satisfied {
                objective.transition_to_eligible(true, now)?;
                result.next_status = Some(ObjectiveStatus::Eligible);
                resulting_status = ObjectiveStatus::Eligible;
                hook.emit(CampaignEventPayload::ObjectiveStatusChanged {
                    campaign_id: objective.campaign_id.clone(),
                    objective_id: objective.id.clone(),
                    from,
                    to: ObjectiveStatus::Eligible,
                    reason: Some("evaluator_prerequisites_satisfied".to_string()),
                });
            }
        } else if objective.status == ObjectiveStatus::InProgress {
            if failure_criteria_satisfied {
                objective.transition_to_failed(true, now)?;
                result.next_status = Some(ObjectiveStatus::Failed);
                resulting_status = ObjectiveStatus::Failed;
                hook.emit(CampaignEventPayload::ObjectiveStatusChanged {
                    campaign_id: objective.campaign_id.clone(),
                    objective_id: objective.id.clone(),
                    from,
                    to: ObjectiveStatus::Failed,
                    reason: Some("evaluator_failure_criteria_satisfied".to_string()),
                });
            } else if success_criteria_satisfied {
                objective.transition_to_achieved(true, now)?;
                result.next_status = Some(ObjectiveStatus::Achieved);
                resulting_status = ObjectiveStatus::Achieved;
                hook.emit(CampaignEventPayload::ObjectiveStatusChanged {
                    campaign_id: objective.campaign_id.clone(),
                    objective_id: objective.id.clone(),
                    from,
                    to: ObjectiveStatus::Achieved,
                    reason: Some("evaluator_success_criteria_satisfied".to_string()),
                });
            }
        }

        hook.emit(CampaignEventPayload::ObjectiveEvaluated {
            campaign_id: objective.campaign_id.clone(),
            objective_id: objective.id.clone(),
            trigger,
            prerequisites_satisfied: result.prerequisites_satisfied,
            success_criteria_satisfied: result.success_criteria_satisfied,
            failure_criteria_satisfied: result.failure_criteria_satisfied,
            resulting_status,
        });

        Ok(result)
    }

    pub fn evaluate_campaign<H: ObjectiveEventHook>(
        campaign_id: &CampaignId,
        objectives: &mut BTreeMap<ObjectiveId, Objective>,
        snapshot: &PredicateSnapshot,
        trigger: ObjectiveReevaluationTrigger,
        now: u64,
        hook: &mut H,
    ) -> Result<Vec<ObjectiveEvaluationRecord>, CampaignModelError> {
        validate_prerequisite_graph(&objectives.values().cloned().collect::<Vec<_>>())?;
        for objective in objectives.values() {
            if &objective.campaign_id != campaign_id {
                return Err(CampaignModelError::InvalidField {
                    field: "objective.campaign_id",
                    reason: "must match evaluation campaign",
                });
            }
        }

        let mut records = Vec::new();
        let max_iterations = objectives.len().saturating_mul(4).max(1);
        for _ in 0..max_iterations {
            let status_index = objectives
                .iter()
                .map(|(id, objective)| (id.clone(), objective.status))
                .collect::<BTreeMap<_, _>>();

            let ordered_ids = objectives.keys().cloned().collect::<Vec<_>>();
            let mut changed = false;

            for objective_id in ordered_ids {
                let objective = objectives.get_mut(&objective_id).ok_or_else(|| {
                    CampaignModelError::MissingObjective {
                        objective_id: objective_id.clone(),
                    }
                })?;

                let result = Self::evaluate_objective(
                    objective,
                    &status_index,
                    snapshot,
                    trigger,
                    now,
                    hook,
                )?;
                changed |= result.next_status.is_some();
                records.push(ObjectiveEvaluationRecord {
                    objective_id,
                    result,
                });
            }

            if !changed {
                return Ok(records);
            }
        }

        Err(CampaignModelError::InvalidField {
            field: "objective.evaluation",
            reason: "evaluation exceeded deterministic iteration budget",
        })
    }

    pub fn start_objective<H: ObjectiveEventHook>(
        objective: &mut Objective,
        objective_statuses: &BTreeMap<ObjectiveId, ObjectiveStatus>,
        now: u64,
        hook: &mut H,
    ) -> Result<ObjectiveTransitionAudit, CampaignModelError> {
        let prerequisites_satisfied = Self::prerequisites_satisfied(objective, objective_statuses)?;
        if !prerequisites_satisfied {
            return Err(CampaignModelError::InvalidField {
                field: "objective.prerequisites",
                reason: "all prerequisites must be achieved before starting objective",
            });
        }

        let from = objective.status;
        objective.transition_to_in_progress(now)?;
        let transition = ObjectiveTransitionAudit {
            objective_id: objective.id.clone(),
            from,
            to: objective.status,
        };
        hook.emit(CampaignEventPayload::ObjectiveStatusChanged {
            campaign_id: objective.campaign_id.clone(),
            objective_id: objective.id.clone(),
            from,
            to: objective.status,
            reason: Some("manual_objective_start".to_string()),
        });
        Ok(transition)
    }

    pub fn prerequisites_satisfied(
        objective: &Objective,
        objective_statuses: &BTreeMap<ObjectiveId, ObjectiveStatus>,
    ) -> Result<bool, CampaignModelError> {
        for prerequisite in &objective.prerequisites {
            let status = objective_statuses.get(prerequisite).ok_or_else(|| {
                CampaignModelError::MissingObjective {
                    objective_id: prerequisite.clone(),
                }
            })?;
            if *status != ObjectiveStatus::Achieved {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CampaignInvariant {
    CampaignNameRequired,
    ObjectiveNameRequired,
    ObjectiveSuccessCriteriaRequired,
    ObjectivePrerequisitesNoSelfReference,
    ObjectiveNoiseBudgetPositiveWhenPresent,
    CampaignStatusStrictTransitions,
    ObjectiveStatusStrictTransitions,
    ObjectiveTerminalStatesNoOutgoing,
    ObjectiveNoSilentStatusChanges,
    CampaignNoSilentStatusChanges,
    ObjectiveEvaluationPureDeterministic,
    ObjectiveEvaluationNoSideEffects,
}

impl CampaignInvariant {
    pub const fn as_str(self) -> &'static str {
        match self {
            CampaignInvariant::CampaignNameRequired => "campaign_name_required",
            CampaignInvariant::ObjectiveNameRequired => "objective_name_required",
            CampaignInvariant::ObjectiveSuccessCriteriaRequired => {
                "objective_success_criteria_required"
            }
            CampaignInvariant::ObjectivePrerequisitesNoSelfReference => {
                "objective_prerequisites_no_self_reference"
            }
            CampaignInvariant::ObjectiveNoiseBudgetPositiveWhenPresent => {
                "objective_noise_budget_positive_when_present"
            }
            CampaignInvariant::CampaignStatusStrictTransitions => {
                "campaign_status_strict_transitions"
            }
            CampaignInvariant::ObjectiveStatusStrictTransitions => {
                "objective_status_strict_transitions"
            }
            CampaignInvariant::ObjectiveTerminalStatesNoOutgoing => {
                "objective_terminal_states_no_outgoing"
            }
            CampaignInvariant::ObjectiveNoSilentStatusChanges => {
                "objective_no_silent_status_changes"
            }
            CampaignInvariant::CampaignNoSilentStatusChanges => "campaign_no_silent_status_changes",
            CampaignInvariant::ObjectiveEvaluationPureDeterministic => {
                "objective_evaluation_pure_deterministic"
            }
            CampaignInvariant::ObjectiveEvaluationNoSideEffects => {
                "objective_evaluation_no_side_effects"
            }
        }
    }
}

pub const CAMPAIGN_INVARIANTS: &[CampaignInvariant] = &[
    CampaignInvariant::CampaignNameRequired,
    CampaignInvariant::ObjectiveNameRequired,
    CampaignInvariant::ObjectiveSuccessCriteriaRequired,
    CampaignInvariant::ObjectivePrerequisitesNoSelfReference,
    CampaignInvariant::ObjectiveNoiseBudgetPositiveWhenPresent,
    CampaignInvariant::CampaignStatusStrictTransitions,
    CampaignInvariant::ObjectiveStatusStrictTransitions,
    CampaignInvariant::ObjectiveTerminalStatesNoOutgoing,
    CampaignInvariant::ObjectiveNoSilentStatusChanges,
    CampaignInvariant::CampaignNoSilentStatusChanges,
    CampaignInvariant::ObjectiveEvaluationPureDeterministic,
    CampaignInvariant::ObjectiveEvaluationNoSideEffects,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayRule {
    AppendOnlyEventLog,
    DeterministicOrderingByEventSequence,
    TransitionValidationBeforeProjectionApply,
    ObjectiveEvaluationIsIdempotent,
    ObjectiveEvaluationIsPure,
    ObjectiveEvaluationHasNoSideEffects,
    ObjectiveRebuildFromEventHistory,
    ObjectiveStateAdvancesOnlyViaRecordedTransitionEvent,
}

impl ReplayRule {
    pub const fn as_str(self) -> &'static str {
        match self {
            ReplayRule::AppendOnlyEventLog => "append_only_event_log",
            ReplayRule::DeterministicOrderingByEventSequence => {
                "deterministic_ordering_by_event_sequence"
            }
            ReplayRule::TransitionValidationBeforeProjectionApply => {
                "transition_validation_before_projection_apply"
            }
            ReplayRule::ObjectiveEvaluationIsIdempotent => "objective_evaluation_is_idempotent",
            ReplayRule::ObjectiveEvaluationIsPure => "objective_evaluation_is_pure",
            ReplayRule::ObjectiveEvaluationHasNoSideEffects => {
                "objective_evaluation_has_no_side_effects"
            }
            ReplayRule::ObjectiveRebuildFromEventHistory => "objective_rebuild_from_event_history",
            ReplayRule::ObjectiveStateAdvancesOnlyViaRecordedTransitionEvent => {
                "objective_state_advances_only_via_recorded_transition_event"
            }
        }
    }
}

pub const REPLAY_RULES: &[ReplayRule] = &[
    ReplayRule::AppendOnlyEventLog,
    ReplayRule::DeterministicOrderingByEventSequence,
    ReplayRule::TransitionValidationBeforeProjectionApply,
    ReplayRule::ObjectiveEvaluationIsIdempotent,
    ReplayRule::ObjectiveEvaluationIsPure,
    ReplayRule::ObjectiveEvaluationHasNoSideEffects,
    ReplayRule::ObjectiveRebuildFromEventHistory,
    ReplayRule::ObjectiveStateAdvancesOnlyViaRecordedTransitionEvent,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectiveReevaluationTrigger {
    ArtifactCreated,
    FindingCreated,
    SessionStateChanged,
    RunCompleted,
    ReplayRecovery,
    ManualRequest,
}

impl ObjectiveReevaluationTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            ObjectiveReevaluationTrigger::ArtifactCreated => "artifact_created",
            ObjectiveReevaluationTrigger::FindingCreated => "finding_created",
            ObjectiveReevaluationTrigger::SessionStateChanged => "session_state_changed",
            ObjectiveReevaluationTrigger::RunCompleted => "run_completed",
            ObjectiveReevaluationTrigger::ReplayRecovery => "replay_recovery",
            ObjectiveReevaluationTrigger::ManualRequest => "manual_request",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignEventPayload {
    CampaignCreated {
        campaign_id: CampaignId,
        name: String,
    },
    CampaignStatusChanged {
        campaign_id: CampaignId,
        from: CampaignStatus,
        to: CampaignStatus,
        reason: Option<String>,
    },
    ObjectiveCreated {
        campaign_id: CampaignId,
        objective_id: ObjectiveId,
        name: String,
        risk_level: RiskLevel,
    },
    ObjectivePrerequisiteLinked {
        campaign_id: CampaignId,
        objective_id: ObjectiveId,
        prerequisite_id: ObjectiveId,
    },
    ObjectiveStatusChanged {
        campaign_id: CampaignId,
        objective_id: ObjectiveId,
        from: ObjectiveStatus,
        to: ObjectiveStatus,
        reason: Option<String>,
    },
    ObjectiveEvaluated {
        campaign_id: CampaignId,
        objective_id: ObjectiveId,
        trigger: ObjectiveReevaluationTrigger,
        prerequisites_satisfied: bool,
        success_criteria_satisfied: bool,
        failure_criteria_satisfied: bool,
        resulting_status: ObjectiveStatus,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CampaignEventType {
    CampaignCreated,
    CampaignStatusChanged,
    ObjectiveCreated,
    ObjectivePrerequisiteLinked,
    ObjectiveStatusChanged,
    ObjectiveEvaluated,
}

impl CampaignEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            CampaignEventType::CampaignCreated => "campaign_created",
            CampaignEventType::CampaignStatusChanged => "campaign_status_changed",
            CampaignEventType::ObjectiveCreated => "objective_created",
            CampaignEventType::ObjectivePrerequisiteLinked => "objective_prerequisite_linked",
            CampaignEventType::ObjectiveStatusChanged => "objective_status_changed",
            CampaignEventType::ObjectiveEvaluated => "objective_evaluated",
        }
    }
}

pub const CAMPAIGN_EVENT_TAXONOMY: &[CampaignEventType] = &[
    CampaignEventType::CampaignCreated,
    CampaignEventType::CampaignStatusChanged,
    CampaignEventType::ObjectiveCreated,
    CampaignEventType::ObjectivePrerequisiteLinked,
    CampaignEventType::ObjectiveStatusChanged,
    CampaignEventType::ObjectiveEvaluated,
];

impl CampaignEventPayload {
    pub const fn event_type(&self) -> CampaignEventType {
        match self {
            CampaignEventPayload::CampaignCreated { .. } => CampaignEventType::CampaignCreated,
            CampaignEventPayload::CampaignStatusChanged { .. } => {
                CampaignEventType::CampaignStatusChanged
            }
            CampaignEventPayload::ObjectiveCreated { .. } => CampaignEventType::ObjectiveCreated,
            CampaignEventPayload::ObjectivePrerequisiteLinked { .. } => {
                CampaignEventType::ObjectivePrerequisiteLinked
            }
            CampaignEventPayload::ObjectiveStatusChanged { .. } => {
                CampaignEventType::ObjectiveStatusChanged
            }
            CampaignEventPayload::ObjectiveEvaluated { .. } => {
                CampaignEventType::ObjectiveEvaluated
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignEvent {
    pub sequence: u64,
    pub occurred_at: u64,
    pub payload: CampaignEventPayload,
}

struct WireCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> WireCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, CampaignModelError> {
        let byte = *self
            .data
            .get(self.offset)
            .ok_or(CampaignModelError::Parse {
                reason: "unexpected end of input",
            })?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], CampaignModelError> {
        if self.offset + N > self.data.len() {
            return Err(CampaignModelError::Parse {
                reason: "unexpected end of input",
            });
        }
        let mut buf = [0u8; N];
        buf.copy_from_slice(&self.data[self.offset..self.offset + N]);
        self.offset += N;
        Ok(buf)
    }

    fn read_u32(&mut self) -> Result<u32, CampaignModelError> {
        Ok(u32::from_be_bytes(self.read_exact::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, CampaignModelError> {
        Ok(u64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_i64(&mut self) -> Result<i64, CampaignModelError> {
        Ok(i64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_string(&mut self) -> Result<String, CampaignModelError> {
        let len = self.read_u32()? as usize;
        if self.offset + len > self.data.len() {
            return Err(CampaignModelError::Parse {
                reason: "string length exceeds input buffer",
            });
        }
        let raw = &self.data[self.offset..self.offset + len];
        self.offset += len;
        String::from_utf8(raw.to_vec()).map_err(|_| CampaignModelError::Parse {
            reason: "invalid utf-8 string",
        })
    }

    fn ensure_finished(&self) -> Result<(), CampaignModelError> {
        if self.offset != self.data.len() {
            return Err(CampaignModelError::Parse {
                reason: "extra bytes at end of input",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Visited,
}

pub fn validate_prerequisite_graph(objectives: &[Objective]) -> Result<(), CampaignModelError> {
    let mut objective_map = BTreeMap::new();
    for objective in objectives {
        let previous = objective_map.insert(objective.id.clone(), objective);
        if previous.is_some() {
            return Err(CampaignModelError::InvalidField {
                field: "objective.id",
                reason: "duplicate objective id in campaign graph",
            });
        }
    }

    for objective in objectives {
        for prerequisite in &objective.prerequisites {
            if !objective_map.contains_key(prerequisite) {
                return Err(CampaignModelError::MissingObjective {
                    objective_id: prerequisite.clone(),
                });
            }
        }
    }

    let mut visit_states = BTreeMap::<ObjectiveId, VisitState>::new();
    for objective_id in objective_map.keys() {
        if visit_states.contains_key(objective_id) {
            continue;
        }
        detect_prerequisite_cycle(objective_id, &objective_map, &mut visit_states)?;
    }
    Ok(())
}

pub fn validate_prerequisite_link(
    objectives: &[Objective],
    objective_id: &ObjectiveId,
    prerequisite_id: &ObjectiveId,
) -> Result<(), CampaignModelError> {
    let mut next_objectives = objectives.to_vec();
    let mut found = false;
    for objective in &mut next_objectives {
        if &objective.id == objective_id {
            found = true;
            if &objective.id == prerequisite_id {
                return Err(CampaignModelError::InvalidField {
                    field: "objective.prerequisites",
                    reason: "cannot include objective id itself",
                });
            }
            if !objective.prerequisites.contains(prerequisite_id) {
                objective.prerequisites.push(prerequisite_id.clone());
            }
            break;
        }
    }

    if !found {
        return Err(CampaignModelError::MissingObjective {
            objective_id: objective_id.clone(),
        });
    }

    validate_prerequisite_graph(&next_objectives)
}

fn detect_prerequisite_cycle(
    objective_id: &ObjectiveId,
    objective_map: &BTreeMap<ObjectiveId, &Objective>,
    visit_states: &mut BTreeMap<ObjectiveId, VisitState>,
) -> Result<(), CampaignModelError> {
    visit_states.insert(objective_id.clone(), VisitState::Visiting);

    let objective =
        objective_map
            .get(objective_id)
            .ok_or_else(|| CampaignModelError::MissingObjective {
                objective_id: objective_id.clone(),
            })?;

    for prerequisite_id in &objective.prerequisites {
        match visit_states.get(prerequisite_id).copied() {
            Some(VisitState::Visiting) => {
                return Err(CampaignModelError::PrerequisiteCycle {
                    objective_id: objective_id.clone(),
                });
            }
            Some(VisitState::Visited) => {}
            None => detect_prerequisite_cycle(prerequisite_id, objective_map, visit_states)?,
        }
    }

    visit_states.insert(objective_id.clone(), VisitState::Visited);
    Ok(())
}

fn dedupe_objective_ids(ids: Vec<ObjectiveId>) -> Vec<ObjectiveId> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for id in ids {
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    out
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), CampaignModelError> {
    if value.trim().is_empty() {
        return Err(CampaignModelError::InvalidField {
            field,
            reason: "cannot be empty",
        });
    }
    Ok(())
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn escape_canonical(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(':', "\\:")
        .replace(',', "\\,")
        .replace('=', "\\=")
}

fn is_valid_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    for (idx, byte) in value.as_bytes().iter().copied().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn campaign_id(seed: &str) -> CampaignId {
        CampaignId::parse(seed).expect("campaign id")
    }

    fn objective_id(seed: &str) -> ObjectiveId {
        ObjectiveId::parse(seed).expect("objective id")
    }

    #[test]
    fn uuid_parser_enforces_canonical_shape() {
        assert!(CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").is_ok());
        assert!(CampaignId::parse("DE305D54-75B4-431B-ADB2-EB6B9E546014").is_ok());
        assert!(CampaignId::parse("de305d5475b4431badb2eb6b9e546014").is_err());
        assert!(CampaignId::parse("not-a-uuid").is_err());
    }

    #[test]
    fn campaign_transition_matrix_is_strict_and_unambiguous() {
        let states = [
            CampaignStatus::Active,
            CampaignStatus::Paused,
            CampaignStatus::Completed,
            CampaignStatus::Failed,
        ];
        for from in states {
            for to in states {
                let expected = CAMPAIGN_ALLOWED_TRANSITIONS
                    .iter()
                    .any(|(f, t)| *f == from && *t == to);
                assert_eq!(from.can_transition_to(to), expected);

                let forbidden = CAMPAIGN_FORBIDDEN_TRANSITIONS
                    .iter()
                    .any(|(f, t)| *f == from && *t == to);
                assert_ne!(
                    expected, forbidden,
                    "transition cannot be both allowed and forbidden"
                );
            }
        }
    }

    #[test]
    fn objective_transition_matrix_is_strict_and_unambiguous() {
        let states = [
            ObjectiveStatus::Pending,
            ObjectiveStatus::Eligible,
            ObjectiveStatus::InProgress,
            ObjectiveStatus::Achieved,
            ObjectiveStatus::Failed,
        ];
        for from in states {
            for to in states {
                let expected = OBJECTIVE_ALLOWED_TRANSITIONS
                    .iter()
                    .any(|(f, t)| *f == from && *t == to);
                assert_eq!(from.can_transition_to(to), expected);

                let forbidden = OBJECTIVE_FORBIDDEN_TRANSITIONS
                    .iter()
                    .any(|(f, t)| *f == from && *t == to);
                assert_ne!(
                    expected, forbidden,
                    "transition cannot be both allowed and forbidden"
                );
            }
        }
    }

    #[test]
    fn no_op_transitions_are_rejected() {
        let mut campaign = Campaign::new_at(
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "Engagement",
            "phase 0",
            42,
            None,
        )
        .expect("campaign");
        assert!(campaign.transition_status(CampaignStatus::Active).is_err());

        let mut objective = Objective::new_at(
            objective_id("7f5f5d5c-f9a9-42dc-a0ef-3d96f5565de8"),
            campaign.id.clone(),
            "Objective A",
            "test no-op",
            vec![],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            42,
        )
        .expect("objective");
        assert!(objective
            .transition_status(ObjectiveStatus::Pending, 43)
            .is_err());

        let transition_err = campaign
            .transition_status(CampaignStatus::Active)
            .expect_err("no-op transition must fail");
        assert_eq!(transition_err.code(), "ML-CAMP-0002");
    }

    #[test]
    fn objective_validates_prerequisite_and_criteria_invariants() {
        let objective = Objective::new_at(
            objective_id("0f8fad5b-d9cb-469f-a165-70867728950e"),
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "Gain foothold",
            "Get first session",
            vec![objective_id("f47ac10b-58cc-4372-a567-0e02b2c3d479")],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Medium,
            Some(100),
            100,
        )
        .expect("objective");

        assert_eq!(objective.status, ObjectiveStatus::Pending);
        assert_eq!(objective.prerequisites.len(), 1);

        let err = Objective::new_at(
            objective_id("f47ac10b-58cc-4372-a567-0e02b2c3d479"),
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "invalid",
            "invalid",
            vec![objective_id("f47ac10b-58cc-4372-a567-0e02b2c3d479")],
            vec![Predicate::ArtifactTagMatch {
                tag: "loot".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            100,
        )
        .expect_err("self prerequisite must fail");
        assert!(
            err.to_string().contains("objective.prerequisites"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn objective_enforces_transition_requirements() {
        let mut objective = Objective::new_at(
            objective_id("7f5f5d5c-f9a9-42dc-a0ef-3d96f5565de8"),
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "Escalate",
            "Get root",
            vec![],
            vec![Predicate::SessionPrivilege {
                level: SessionPrivilegeLevel::Root,
            }],
            vec![Predicate::FindingExists {
                finding_type: "detection".to_string(),
            }],
            RiskLevel::High,
            None,
            10,
        )
        .expect("objective");
        let mut status_index = BTreeMap::from([(objective.id.clone(), ObjectiveStatus::Pending)]);
        let mut events = Vec::<CampaignEventPayload>::new();

        let pending_result = ObjectiveEvaluationEngine::evaluate_objective(
            &mut objective,
            &status_index,
            &PredicateSnapshot::new(),
            ObjectiveReevaluationTrigger::ManualRequest,
            11,
            &mut events,
        )
        .expect("evaluate pending");
        assert_eq!(objective.status, ObjectiveStatus::Eligible);
        assert_eq!(pending_result.next_status, Some(ObjectiveStatus::Eligible));
        assert_eq!(events.len(), 2);

        status_index.insert(objective.id.clone(), objective.status);
        ObjectiveEvaluationEngine::start_objective(&mut objective, &status_index, 12, &mut events)
            .expect("start objective");
        assert_eq!(objective.status, ObjectiveStatus::InProgress);

        let root_snapshot = PredicateSnapshot::new().with_session(
            SessionSnapshot::new(
                domain::Session::new_at(
                    domain::Run::new_at(
                        domain::Workspace::new_at("ws", "test", 1)
                            .expect("workspace")
                            .id,
                        domain::ModuleVersion::new_at(
                            "exploit/linux/example",
                            "1.0.0",
                            1,
                            "entrypoint",
                            "sha256",
                            1,
                        )
                        .expect("module")
                        .id,
                        None,
                        "operator",
                        2,
                    )
                    .expect("run")
                    .id,
                    None,
                    "shell",
                    "127.0.0.1:23",
                    3,
                )
                .expect("session"),
            )
            .with_privilege(SessionPrivilegeLevel::Root),
        );
        status_index.insert(objective.id.clone(), objective.status);
        let complete_result = ObjectiveEvaluationEngine::evaluate_objective(
            &mut objective,
            &status_index,
            &root_snapshot,
            ObjectiveReevaluationTrigger::SessionStateChanged,
            13,
            &mut events,
        )
        .expect("evaluate in progress");
        assert_eq!(objective.status, ObjectiveStatus::Achieved);
        assert_eq!(complete_result.next_status, Some(ObjectiveStatus::Achieved));
    }

    #[test]
    fn evaluator_emits_auditable_transition_events() {
        let mut objective = Objective::new_at(
            objective_id("1f65f5d5-f9a9-42dc-a0ef-3d96f5565de8"),
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "Objective",
            "pending to eligible",
            vec![],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            10,
        )
        .expect("objective");

        let mut events = Vec::<CampaignEventPayload>::new();
        let status_index = BTreeMap::from([(objective.id.clone(), ObjectiveStatus::Pending)]);

        ObjectiveEvaluationEngine::evaluate_objective(
            &mut objective,
            &status_index,
            &PredicateSnapshot::new(),
            ObjectiveReevaluationTrigger::RunCompleted,
            11,
            &mut events,
        )
        .expect("evaluation");

        assert_eq!(events.len(), 2);
        match &events[0] {
            CampaignEventPayload::ObjectiveStatusChanged { from, to, .. } => {
                assert_eq!(*from, ObjectiveStatus::Pending);
                assert_eq!(*to, ObjectiveStatus::Eligible);
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
        match &events[1] {
            CampaignEventPayload::ObjectiveEvaluated {
                trigger,
                resulting_status,
                ..
            } => {
                assert_eq!(*trigger, ObjectiveReevaluationTrigger::RunCompleted);
                assert_eq!(*resulting_status, ObjectiveStatus::Eligible);
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
    }

    #[test]
    fn evaluator_campaign_pass_is_deterministic_and_auditable() {
        let cid = campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014");
        let oid_a = objective_id("0f8fad5b-d9cb-469f-a165-70867728950e");
        let oid_b = objective_id("9b2f4d6a-3aa4-41ba-91ed-6308a58186a1");

        let objective_a = Objective::new_at(
            oid_a.clone(),
            cid.clone(),
            "A",
            "first objective",
            vec![],
            vec![Predicate::SessionPrivilege {
                level: SessionPrivilegeLevel::Root,
            }],
            vec![],
            RiskLevel::Low,
            None,
            1,
        )
        .expect("objective a");
        let objective_b = Objective::new_at(
            oid_b.clone(),
            cid.clone(),
            "B",
            "depends on A",
            vec![oid_a.clone()],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Medium,
            None,
            1,
        )
        .expect("objective b");

        let mut objectives =
            BTreeMap::from([(oid_a.clone(), objective_a), (oid_b.clone(), objective_b)]);
        let mut events_a = Vec::<CampaignEventPayload>::new();
        let records_a = ObjectiveEvaluationEngine::evaluate_campaign(
            &cid,
            &mut objectives,
            &PredicateSnapshot::new(),
            ObjectiveReevaluationTrigger::ManualRequest,
            2,
            &mut events_a,
        )
        .expect("campaign evaluation");

        assert_eq!(objectives[&oid_a].status, ObjectiveStatus::Eligible);
        assert_eq!(objectives[&oid_b].status, ObjectiveStatus::Pending);
        assert!(!records_a.is_empty());

        let mut status_index = objectives
            .iter()
            .map(|(id, objective)| (id.clone(), objective.status))
            .collect::<BTreeMap<_, _>>();
        ObjectiveEvaluationEngine::start_objective(
            objectives.get_mut(&oid_a).expect("objective a"),
            &status_index,
            3,
            &mut events_a,
        )
        .expect("start objective a");
        status_index.insert(oid_a.clone(), ObjectiveStatus::InProgress);

        let root_snapshot = PredicateSnapshot::new().with_session(
            SessionSnapshot::new(
                domain::Session::new_at(
                    domain::Run::new_at(
                        domain::Workspace::new_at("ws", "test", 1)
                            .expect("workspace")
                            .id,
                        domain::ModuleVersion::new_at(
                            "exploit/linux/example",
                            "1.0.0",
                            1,
                            "entrypoint",
                            "sha256",
                            1,
                        )
                        .expect("module")
                        .id,
                        None,
                        "operator",
                        1,
                    )
                    .expect("run")
                    .id,
                    None,
                    "shell",
                    "127.0.0.1:23",
                    1,
                )
                .expect("session"),
            )
            .with_privilege(SessionPrivilegeLevel::Root),
        );

        let mut events_b = Vec::<CampaignEventPayload>::new();
        let records_b = ObjectiveEvaluationEngine::evaluate_campaign(
            &cid,
            &mut objectives,
            &root_snapshot,
            ObjectiveReevaluationTrigger::SessionStateChanged,
            4,
            &mut events_b,
        )
        .expect("campaign re-evaluation");

        assert_eq!(objectives[&oid_a].status, ObjectiveStatus::Achieved);
        assert_eq!(objectives[&oid_b].status, ObjectiveStatus::Eligible);
        assert!(!records_b.is_empty());
        assert!(events_b
            .iter()
            .any(|event| matches!(event, CampaignEventPayload::ObjectiveStatusChanged { .. })));
        assert!(events_b
            .iter()
            .any(|event| matches!(event, CampaignEventPayload::ObjectiveEvaluated { .. })));
    }

    #[test]
    fn predicate_evaluation_is_pure_and_deterministic() {
        let view = PredicateEvaluationView::new()
            .with_finding_type("credential")
            .with_session_privilege(SessionPrivilegeLevel::Root)
            .with_artifact_tag("loot")
            .with_successful_run("exploit/linux/example")
            .with_custom_metadata("owner", MetadataValue::Text("redteam".to_string()));

        let predicates = vec![
            Predicate::FindingExists {
                finding_type: "credential".to_string(),
            },
            Predicate::SessionPrivilege {
                level: SessionPrivilegeLevel::Root,
            },
            Predicate::ArtifactTagMatch {
                tag: "loot".to_string(),
            },
            Predicate::RunSucceeded {
                module_name: "exploit/linux/example".to_string(),
            },
            Predicate::CustomMetadataMatch {
                key: "owner".to_string(),
                value: MetadataValue::Text("redteam".to_string()),
            },
        ];

        for predicate in &predicates {
            let first = predicate.evaluate(&view);
            let second = predicate.evaluate(&view);
            assert_eq!(first, second, "predicate must be deterministic");
            assert!(first, "predicate should match prepared evaluation view");
        }
    }

    #[test]
    fn objective_evaluation_is_deterministic_and_side_effect_free() {
        let objective = Objective::new_at(
            objective_id("7f5f5d5c-f9a9-42dc-a0ef-3d96f5565de8"),
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "Escalate",
            "Get root",
            vec![],
            vec![Predicate::SessionPrivilege {
                level: SessionPrivilegeLevel::Root,
            }],
            vec![Predicate::FindingExists {
                finding_type: "detection".to_string(),
            }],
            RiskLevel::High,
            Some(10),
            10,
        )
        .expect("objective");

        let snapshot = objective.clone();
        let view =
            PredicateEvaluationView::new().with_session_privilege(SessionPrivilegeLevel::Root);
        let first = objective.evaluate_transition(true, &view);
        let second = objective.evaluate_transition(true, &view);
        assert_eq!(first, second);
        assert_eq!(objective, snapshot, "evaluation must not mutate objective");
        assert_eq!(first.next_status, Some(ObjectiveStatus::Eligible));
    }

    #[test]
    fn stable_encoding_is_repeatable() {
        let predicate = Predicate::CustomMetadataMatch {
            key: "risk_profile".to_string(),
            value: MetadataValue::Object(BTreeMap::from([
                ("noise".to_string(), MetadataValue::Integer(2)),
                (
                    "tags".to_string(),
                    MetadataValue::Array(vec![
                        MetadataValue::Text("stealth".to_string()),
                        MetadataValue::Text("lateral".to_string()),
                    ]),
                ),
            ])),
        };
        let a = predicate.stable_encoding();
        let b = predicate.stable_encoding();
        assert_eq!(a, b);
    }

    #[test]
    fn graph_validation_rejects_missing_prerequisites_with_stable_error_code() {
        let objective = Objective::new_at(
            objective_id("0f8fad5b-d9cb-469f-a165-70867728950e"),
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "Objective A",
            "requires unknown objective",
            vec![objective_id("9b2f4d6a-3aa4-41ba-91ed-6308a58186a1")],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            10,
        )
        .expect("objective");

        let err = validate_prerequisite_graph(&[objective]).expect_err("missing reference");
        assert_eq!(err.code(), "ML-CAMP-0003");
    }

    #[test]
    fn graph_validation_rejects_cycles_with_stable_error_code() {
        let campaign_id = campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014");
        let objective_a_id = objective_id("0f8fad5b-d9cb-469f-a165-70867728950e");
        let objective_b_id = objective_id("9b2f4d6a-3aa4-41ba-91ed-6308a58186a1");

        let objective_a = Objective::new_at(
            objective_a_id.clone(),
            campaign_id.clone(),
            "Objective A",
            "depends on B",
            vec![objective_b_id.clone()],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            10,
        )
        .expect("objective A");

        let objective_b = Objective::new_at(
            objective_b_id,
            campaign_id,
            "Objective B",
            "depends on A",
            vec![objective_a_id],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            10,
        )
        .expect("objective B");

        let err = validate_prerequisite_graph(&[objective_a, objective_b]).expect_err("cycle");
        assert_eq!(err.code(), "ML-CAMP-0004");
    }

    #[test]
    fn prerequisite_link_validation_prevents_cycle_creation() {
        let campaign_id = campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014");
        let objective_a_id = objective_id("0f8fad5b-d9cb-469f-a165-70867728950e");
        let objective_b_id = objective_id("9b2f4d6a-3aa4-41ba-91ed-6308a58186a1");

        let objective_a = Objective::new_at(
            objective_a_id.clone(),
            campaign_id.clone(),
            "Objective A",
            "valid",
            vec![],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            10,
        )
        .expect("objective A");

        let objective_b = Objective::new_at(
            objective_b_id.clone(),
            campaign_id,
            "Objective B",
            "depends on A",
            vec![objective_a_id.clone()],
            vec![Predicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            10,
        )
        .expect("objective B");

        let err = validate_prerequisite_link(
            &[objective_a.clone(), objective_b.clone()],
            &objective_a_id,
            &objective_b_id,
        )
        .expect_err("would create A<->B cycle");
        assert_eq!(err.code(), "ML-CAMP-0004");

        let self_ref_err = validate_prerequisite_link(
            &[objective_a, objective_b],
            &objective_a_id,
            &objective_a_id,
        )
        .expect_err("self prereq must fail");
        assert_eq!(self_ref_err.code(), "ML-CAMP-0001");
    }

    #[test]
    fn predicate_wire_serialization_round_trip_is_deterministic() {
        let predicates = vec![
            Predicate::FindingExists {
                finding_type: "credential".to_string(),
            },
            Predicate::SessionPrivilege {
                level: SessionPrivilegeLevel::Elevated,
            },
            Predicate::ArtifactTagMatch {
                tag: "loot".to_string(),
            },
            Predicate::RunSucceeded {
                module_name: "exploit/linux/example".to_string(),
            },
            Predicate::CustomMetadataMatch {
                key: "owner".to_string(),
                value: MetadataValue::Object(BTreeMap::from([
                    (
                        "team".to_string(),
                        MetadataValue::Text("purple".to_string()),
                    ),
                    ("risk".to_string(), MetadataValue::Integer(2)),
                ])),
            },
        ];

        for predicate in predicates {
            let encoded_a = predicate.to_wire_bytes();
            let encoded_b = predicate.to_wire_bytes();
            assert_eq!(encoded_a, encoded_b, "wire bytes must be deterministic");

            let decoded = Predicate::from_wire_bytes(&encoded_a).expect("decode predicate");
            assert_eq!(decoded, predicate);
            assert_eq!(decoded.to_wire_bytes(), encoded_a);
        }
    }

    #[test]
    fn predicate_snapshot_evaluation_is_pure_and_replay_safe() {
        let workspace = domain::Workspace::new_at("ws", "test", 1).expect("workspace");
        let module = domain::ModuleVersion::new_at(
            "exploit/linux/example",
            "1.0.0",
            1,
            "entrypoint",
            "sha256",
            1,
        )
        .expect("module");
        let mut run =
            domain::Run::new_at(workspace.id, module.id, None, "operator", 2).expect("run");
        run.transition_state(domain::RunState::Running, 3)
            .expect("run running");
        run.transition_state(domain::RunState::Succeeded, 4)
            .expect("run succeeded");

        let mut session =
            domain::Session::new_at(run.id, None, "shell", "127.0.0.1:23", 5).expect("session");
        session
            .transition_state(domain::SessionState::Open, 6)
            .expect("session open");

        let mut artifact = domain::Artifact::new_at(
            run.id,
            None,
            Some(session.id),
            domain::ArtifactKind::CommandOutput,
            "cmd-out",
            "memory://1",
            7,
        )
        .expect("artifact");
        artifact
            .transition_state(domain::ArtifactState::Available, 8)
            .expect("artifact available");

        let finding = domain::Finding::new_at(
            run.id,
            None,
            Some(session.id),
            "Credential found",
            "password in config",
            domain::FindingSeverity::High,
            9,
        )
        .expect("finding");

        let snapshot = PredicateSnapshot::new()
            .with_run(
                RunSnapshot::new(run, "exploit/linux/example")
                    .expect("run snapshot")
                    .with_metadata("owner", MetadataValue::Text("red".to_string())),
            )
            .with_session(
                SessionSnapshot::new(session)
                    .with_privilege(SessionPrivilegeLevel::Root)
                    .with_metadata("channel", MetadataValue::Text("pty".to_string())),
            )
            .with_artifact(
                ArtifactSnapshot::new(artifact)
                    .with_tag("loot")
                    .with_metadata("path", MetadataValue::Text("/tmp/loot".to_string())),
            )
            .with_finding(
                FindingSnapshot::new(finding, "credential")
                    .expect("finding snapshot")
                    .with_metadata("source", MetadataValue::Text("procfs".to_string())),
            )
            .with_metadata("owner", MetadataValue::Text("red".to_string()));

        let predicates = vec![
            Predicate::FindingExists {
                finding_type: "credential".to_string(),
            },
            Predicate::SessionPrivilege {
                level: SessionPrivilegeLevel::Root,
            },
            Predicate::ArtifactTagMatch {
                tag: "loot".to_string(),
            },
            Predicate::RunSucceeded {
                module_name: "exploit/linux/example".to_string(),
            },
            Predicate::CustomMetadataMatch {
                key: "owner".to_string(),
                value: MetadataValue::Text("red".to_string()),
            },
            Predicate::CustomMetadataMatch {
                key: "path".to_string(),
                value: MetadataValue::Text("/tmp/loot".to_string()),
            },
        ];

        for predicate in predicates {
            let first = predicate.evaluate_snapshot(&snapshot);
            let second = predicate.evaluate_snapshot(&snapshot);
            assert_eq!(first, second, "evaluation must be deterministic");
            assert!(first, "predicate must match immutable snapshot");
        }
    }

    #[test]
    fn objective_snapshot_evaluation_matches_for_identical_inputs() {
        let objective = Objective::new_at(
            objective_id("7f5f5d5c-f9a9-42dc-a0ef-3d96f5565de8"),
            campaign_id("de305d54-75b4-431b-adb2-eb6b9e546014"),
            "Escalate",
            "Get root",
            vec![],
            vec![Predicate::SessionPrivilege {
                level: SessionPrivilegeLevel::Root,
            }],
            vec![Predicate::FindingExists {
                finding_type: "detection".to_string(),
            }],
            RiskLevel::High,
            None,
            10,
        )
        .expect("objective");

        let workspace = domain::Workspace::new_at("ws", "test", 1).expect("workspace");
        let module = domain::ModuleVersion::new_at(
            "exploit/linux/example",
            "1.0.0",
            1,
            "entrypoint",
            "sha256",
            1,
        )
        .expect("module");
        let run = domain::Run::new_at(workspace.id, module.id, None, "operator", 2).expect("run");
        let session =
            domain::Session::new_at(run.id, None, "shell", "127.0.0.1:23", 3).expect("session");
        let snapshot = PredicateSnapshot::new()
            .with_run(RunSnapshot::new(run, "exploit/linux/example").expect("run snapshot"))
            .with_session(
                SessionSnapshot::new(session).with_privilege(SessionPrivilegeLevel::Root),
            );

        let first = objective.evaluate_transition_snapshot(true, &snapshot);
        let second = objective.evaluate_transition_snapshot(true, &snapshot);
        assert_eq!(first, second);
    }
}
