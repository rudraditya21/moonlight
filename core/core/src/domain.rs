use std::fmt;

use crate::ids::Id;
use crate::time::now_secs;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub Id);

        impl $name {
            pub fn next() -> Self {
                Self(Id::next())
            }
        }
    };
}

define_id!(WorkspaceId);
define_id!(TargetId);
define_id!(ModuleVersionId);
define_id!(RunId);
define_id!(TaskId);
define_id!(SessionId);
define_id!(ArtifactId);
define_id!(FindingId);
define_id!(EventId);
define_id!(CorrelationId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    InvalidTransition {
        entity: &'static str,
        from: &'static str,
        to: &'static str,
    },
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::InvalidField { field, reason } => {
                write!(f, "invalid field {field}: {reason}")
            }
            DomainError::InvalidTransition { entity, from, to } => {
                write!(f, "invalid {entity} transition: {from} -> {to}")
            }
        }
    }
}

impl std::error::Error for DomainError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityKind {
    Workspace,
    Target,
    ModuleVersion,
    Run,
    Task,
    Session,
    Artifact,
    Finding,
    Event,
}

impl EntityKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            EntityKind::Workspace => "workspace",
            EntityKind::Target => "target",
            EntityKind::ModuleVersion => "module_version",
            EntityKind::Run => "run",
            EntityKind::Task => "task",
            EntityKind::Session => "session",
            EntityKind::Artifact => "artifact",
            EntityKind::Finding => "finding",
            EntityKind::Event => "event",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlAction {
    WorkspaceCreate,
    WorkspaceArchive,
    WorkspaceActivate,
    TargetCreate,
    TargetPause,
    TargetActivate,
    TargetRetire,
    ModuleRegister,
    ModuleDeprecate,
    ModuleDisable,
    RunCreate,
    RunStart,
    RunSucceed,
    RunFail,
    RunCancel,
    TaskCreate,
    TaskStart,
    TaskRetry,
    TaskSucceed,
    TaskFail,
    TaskCancel,
    SessionCreate,
    SessionOpen,
    SessionBackground,
    SessionLose,
    SessionClose,
    ArtifactCreate,
    ArtifactPublish,
    ArtifactExpire,
    ArtifactDelete,
    FindingCreate,
    FindingConfirm,
    FindingResolve,
    FindingFalsePositive,
    EventEmit,
    EventPersist,
    EventDeliver,
    EventFail,
}

pub const ALL_CONTROL_ACTIONS: &[ControlAction] = &[
    ControlAction::WorkspaceCreate,
    ControlAction::WorkspaceArchive,
    ControlAction::WorkspaceActivate,
    ControlAction::TargetCreate,
    ControlAction::TargetPause,
    ControlAction::TargetActivate,
    ControlAction::TargetRetire,
    ControlAction::ModuleRegister,
    ControlAction::ModuleDeprecate,
    ControlAction::ModuleDisable,
    ControlAction::RunCreate,
    ControlAction::RunStart,
    ControlAction::RunSucceed,
    ControlAction::RunFail,
    ControlAction::RunCancel,
    ControlAction::TaskCreate,
    ControlAction::TaskStart,
    ControlAction::TaskRetry,
    ControlAction::TaskSucceed,
    ControlAction::TaskFail,
    ControlAction::TaskCancel,
    ControlAction::SessionCreate,
    ControlAction::SessionOpen,
    ControlAction::SessionBackground,
    ControlAction::SessionLose,
    ControlAction::SessionClose,
    ControlAction::ArtifactCreate,
    ControlAction::ArtifactPublish,
    ControlAction::ArtifactExpire,
    ControlAction::ArtifactDelete,
    ControlAction::FindingCreate,
    ControlAction::FindingConfirm,
    ControlAction::FindingResolve,
    ControlAction::FindingFalsePositive,
    ControlAction::EventEmit,
    ControlAction::EventPersist,
    ControlAction::EventDeliver,
    ControlAction::EventFail,
];

pub fn action_entity_changes(action: ControlAction) -> &'static [EntityKind] {
    match action {
        ControlAction::WorkspaceCreate
        | ControlAction::WorkspaceArchive
        | ControlAction::WorkspaceActivate => &[EntityKind::Workspace, EntityKind::Event],
        ControlAction::TargetCreate
        | ControlAction::TargetPause
        | ControlAction::TargetActivate
        | ControlAction::TargetRetire => &[EntityKind::Target, EntityKind::Event],
        ControlAction::ModuleRegister
        | ControlAction::ModuleDeprecate
        | ControlAction::ModuleDisable => &[EntityKind::ModuleVersion, EntityKind::Event],
        ControlAction::RunCreate
        | ControlAction::RunStart
        | ControlAction::RunSucceed
        | ControlAction::RunFail
        | ControlAction::RunCancel => &[EntityKind::Run, EntityKind::Event],
        ControlAction::TaskCreate
        | ControlAction::TaskStart
        | ControlAction::TaskRetry
        | ControlAction::TaskSucceed
        | ControlAction::TaskFail
        | ControlAction::TaskCancel => &[EntityKind::Task, EntityKind::Event],
        ControlAction::SessionCreate
        | ControlAction::SessionOpen
        | ControlAction::SessionBackground
        | ControlAction::SessionLose
        | ControlAction::SessionClose => &[EntityKind::Session, EntityKind::Event],
        ControlAction::ArtifactCreate
        | ControlAction::ArtifactPublish
        | ControlAction::ArtifactExpire
        | ControlAction::ArtifactDelete => &[EntityKind::Artifact, EntityKind::Event],
        ControlAction::FindingCreate
        | ControlAction::FindingConfirm
        | ControlAction::FindingResolve
        | ControlAction::FindingFalsePositive => &[EntityKind::Finding, EntityKind::Event],
        ControlAction::EventEmit
        | ControlAction::EventPersist
        | ControlAction::EventDeliver
        | ControlAction::EventFail => &[EntityKind::Event],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceState {
    Active,
    Archived,
}

impl WorkspaceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            WorkspaceState::Active => "active",
            WorkspaceState::Archived => "archived",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (WorkspaceState::Active, WorkspaceState::Archived) => true,
            (WorkspaceState::Archived, WorkspaceState::Active) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub description: String,
    pub state: WorkspaceState,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Workspace {
    pub fn new(name: &str, description: &str) -> Result<Self, DomainError> {
        Self::new_at(name, description, now_secs())
    }

    pub fn new_at(name: &str, description: &str, now: u64) -> Result<Self, DomainError> {
        ensure_non_empty(name, "workspace.name")?;
        Ok(Self {
            id: WorkspaceId::next(),
            name: name.trim().to_string(),
            description: description.trim().to_string(),
            state: WorkspaceState::Active,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn transition_state(&mut self, next: WorkspaceState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "workspace",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Active,
    Paused,
    Retired,
}

impl TargetState {
    pub const fn as_str(self) -> &'static str {
        match self {
            TargetState::Active => "active",
            TargetState::Paused => "paused",
            TargetState::Retired => "retired",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (TargetState::Active, TargetState::Paused) => true,
            (TargetState::Active, TargetState::Retired) => true,
            (TargetState::Paused, TargetState::Active) => true,
            (TargetState::Paused, TargetState::Retired) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, TargetState::Retired)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: TargetId,
    pub workspace_id: WorkspaceId,
    pub address: String,
    pub tags: Vec<String>,
    pub state: TargetState,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Target {
    pub fn new(workspace_id: WorkspaceId, address: &str) -> Result<Self, DomainError> {
        Self::new_at(workspace_id, address, now_secs())
    }

    pub fn new_at(workspace_id: WorkspaceId, address: &str, now: u64) -> Result<Self, DomainError> {
        ensure_non_empty(address, "target.address")?;
        Ok(Self {
            id: TargetId::next(),
            workspace_id,
            address: address.trim().to_string(),
            tags: Vec::new(),
            state: TargetState::Active,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn transition_state(&mut self, next: TargetState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "target",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleVersionState {
    Registered,
    Deprecated,
    Disabled,
}

impl ModuleVersionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            ModuleVersionState::Registered => "registered",
            ModuleVersionState::Deprecated => "deprecated",
            ModuleVersionState::Disabled => "disabled",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (ModuleVersionState::Registered, ModuleVersionState::Deprecated) => true,
            (ModuleVersionState::Registered, ModuleVersionState::Disabled) => true,
            (ModuleVersionState::Deprecated, ModuleVersionState::Disabled) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, ModuleVersionState::Disabled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleVersion {
    pub id: ModuleVersionId,
    pub module_name: String,
    pub semantic_version: String,
    pub api_version: u16,
    pub entrypoint: String,
    pub digest_sha256: String,
    pub state: ModuleVersionState,
    pub created_at: u64,
    pub updated_at: u64,
}

impl ModuleVersion {
    pub fn new(
        module_name: &str,
        semantic_version: &str,
        api_version: u16,
        entrypoint: &str,
        digest_sha256: &str,
    ) -> Result<Self, DomainError> {
        Self::new_at(
            module_name,
            semantic_version,
            api_version,
            entrypoint,
            digest_sha256,
            now_secs(),
        )
    }

    pub fn new_at(
        module_name: &str,
        semantic_version: &str,
        api_version: u16,
        entrypoint: &str,
        digest_sha256: &str,
        now: u64,
    ) -> Result<Self, DomainError> {
        ensure_non_empty(module_name, "module_version.module_name")?;
        ensure_non_empty(semantic_version, "module_version.semantic_version")?;
        ensure_non_empty(entrypoint, "module_version.entrypoint")?;
        ensure_non_empty(digest_sha256, "module_version.digest_sha256")?;
        if api_version == 0 {
            return Err(DomainError::InvalidField {
                field: "module_version.api_version",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            id: ModuleVersionId::next(),
            module_name: module_name.trim().to_string(),
            semantic_version: semantic_version.trim().to_string(),
            api_version,
            entrypoint: entrypoint.trim().to_string(),
            digest_sha256: digest_sha256.trim().to_string(),
            state: ModuleVersionState::Registered,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn transition_state(
        &mut self,
        next: ModuleVersionState,
        now: u64,
    ) -> Result<(), DomainError> {
        ensure_transition(
            "module_version",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

impl RunState {
    pub const fn as_str(self) -> &'static str {
        match self {
            RunState::Queued => "queued",
            RunState::Running => "running",
            RunState::Succeeded => "succeeded",
            RunState::Failed => "failed",
            RunState::Canceled => "canceled",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (RunState::Queued, RunState::Running) => true,
            (RunState::Queued, RunState::Failed) => true,
            (RunState::Queued, RunState::Canceled) => true,
            (RunState::Running, RunState::Succeeded) => true,
            (RunState::Running, RunState::Failed) => true,
            (RunState::Running, RunState::Canceled) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            RunState::Succeeded | RunState::Failed | RunState::Canceled
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: RunId,
    pub workspace_id: WorkspaceId,
    pub module_version_id: ModuleVersionId,
    pub target_id: Option<TargetId>,
    pub requested_by: String,
    pub state: RunState,
    pub created_at: u64,
    pub queued_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub updated_at: u64,
    pub error: Option<String>,
}

impl Run {
    pub fn new(
        workspace_id: WorkspaceId,
        module_version_id: ModuleVersionId,
        target_id: Option<TargetId>,
        requested_by: &str,
    ) -> Result<Self, DomainError> {
        Self::new_at(
            workspace_id,
            module_version_id,
            target_id,
            requested_by,
            now_secs(),
        )
    }

    pub fn new_at(
        workspace_id: WorkspaceId,
        module_version_id: ModuleVersionId,
        target_id: Option<TargetId>,
        requested_by: &str,
        now: u64,
    ) -> Result<Self, DomainError> {
        ensure_non_empty(requested_by, "run.requested_by")?;
        Ok(Self {
            id: RunId::next(),
            workspace_id,
            module_version_id,
            target_id,
            requested_by: requested_by.trim().to_string(),
            state: RunState::Queued,
            created_at: now,
            queued_at: now,
            started_at: None,
            finished_at: None,
            updated_at: now,
            error: None,
        })
    }

    pub fn transition_state(&mut self, next: RunState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "run",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        if next == RunState::Running && self.started_at.is_none() {
            self.started_at = Some(now);
        }
        if next.is_terminal() {
            self.finished_at = Some(now);
        }
        Ok(())
    }

    pub fn fail_with_error(&mut self, message: &str, now: u64) -> Result<(), DomainError> {
        ensure_non_empty(message, "run.error")?;
        self.error = Some(message.trim().to_string());
        self.transition_state(RunState::Failed, now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Queued,
    Running,
    Retrying,
    Succeeded,
    Failed,
    Canceled,
}

impl TaskState {
    pub const fn as_str(self) -> &'static str {
        match self {
            TaskState::Queued => "queued",
            TaskState::Running => "running",
            TaskState::Retrying => "retrying",
            TaskState::Succeeded => "succeeded",
            TaskState::Failed => "failed",
            TaskState::Canceled => "canceled",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (TaskState::Queued, TaskState::Running) => true,
            (TaskState::Queued, TaskState::Canceled) => true,
            (TaskState::Running, TaskState::Succeeded) => true,
            (TaskState::Running, TaskState::Failed) => true,
            (TaskState::Running, TaskState::Retrying) => true,
            (TaskState::Running, TaskState::Canceled) => true,
            (TaskState::Retrying, TaskState::Queued) => true,
            (TaskState::Retrying, TaskState::Canceled) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Succeeded | TaskState::Failed | TaskState::Canceled
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: TaskId,
    pub run_id: RunId,
    pub name: String,
    pub state: TaskState,
    pub attempt_count: u32,
    pub max_attempts: u32,
    pub created_at: u64,
    pub queued_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub updated_at: u64,
    pub error: Option<String>,
}

impl Task {
    pub fn new(run_id: RunId, name: &str, max_attempts: u32) -> Result<Self, DomainError> {
        Self::new_at(run_id, name, max_attempts, now_secs())
    }

    pub fn new_at(
        run_id: RunId,
        name: &str,
        max_attempts: u32,
        now: u64,
    ) -> Result<Self, DomainError> {
        ensure_non_empty(name, "task.name")?;
        if max_attempts == 0 {
            return Err(DomainError::InvalidField {
                field: "task.max_attempts",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            id: TaskId::next(),
            run_id,
            name: name.trim().to_string(),
            state: TaskState::Queued,
            attempt_count: 0,
            max_attempts,
            created_at: now,
            queued_at: now,
            started_at: None,
            finished_at: None,
            updated_at: now,
            error: None,
        })
    }

    pub fn transition_state(&mut self, next: TaskState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "task",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        if next == TaskState::Running {
            self.attempt_count = self.attempt_count.saturating_add(1);
            if self.attempt_count > self.max_attempts {
                return Err(DomainError::InvalidField {
                    field: "task.attempt_count",
                    reason: "exceeds max_attempts",
                });
            }
            if self.started_at.is_none() {
                self.started_at = Some(now);
            }
        }
        if next == TaskState::Retrying {
            self.error = self.error.take();
        }
        if next == TaskState::Queued {
            self.queued_at = now;
        }
        if next.is_terminal() {
            self.finished_at = Some(now);
        }
        Ok(())
    }

    pub fn fail_with_error(&mut self, message: &str, now: u64) -> Result<(), DomainError> {
        ensure_non_empty(message, "task.error")?;
        self.error = Some(message.trim().to_string());
        self.transition_state(TaskState::Failed, now)
    }

    pub fn retry_with_error(&mut self, message: &str, now: u64) -> Result<(), DomainError> {
        ensure_non_empty(message, "task.error")?;
        self.error = Some(message.trim().to_string());
        self.transition_state(TaskState::Retrying, now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Opening,
    Open,
    Backgrounded,
    Lost,
    Closed,
}

impl SessionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionState::Opening => "opening",
            SessionState::Open => "open",
            SessionState::Backgrounded => "backgrounded",
            SessionState::Lost => "lost",
            SessionState::Closed => "closed",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (SessionState::Opening, SessionState::Open) => true,
            (SessionState::Opening, SessionState::Lost) => true,
            (SessionState::Opening, SessionState::Closed) => true,
            (SessionState::Open, SessionState::Backgrounded) => true,
            (SessionState::Open, SessionState::Lost) => true,
            (SessionState::Open, SessionState::Closed) => true,
            (SessionState::Backgrounded, SessionState::Open) => true,
            (SessionState::Backgrounded, SessionState::Lost) => true,
            (SessionState::Backgrounded, SessionState::Closed) => true,
            (SessionState::Lost, SessionState::Open) => true,
            (SessionState::Lost, SessionState::Closed) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, SessionState::Closed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub run_id: RunId,
    pub task_id: Option<TaskId>,
    pub kind: String,
    pub target: String,
    pub state: SessionState,
    pub created_at: u64,
    pub opened_at: Option<u64>,
    pub closed_at: Option<u64>,
    pub last_activity_at: u64,
    pub updated_at: u64,
}

impl Session {
    pub fn new(
        run_id: RunId,
        task_id: Option<TaskId>,
        kind: &str,
        target: &str,
    ) -> Result<Self, DomainError> {
        Self::new_at(run_id, task_id, kind, target, now_secs())
    }

    pub fn new_at(
        run_id: RunId,
        task_id: Option<TaskId>,
        kind: &str,
        target: &str,
        now: u64,
    ) -> Result<Self, DomainError> {
        ensure_non_empty(kind, "session.kind")?;
        ensure_non_empty(target, "session.target")?;
        Ok(Self {
            id: SessionId::next(),
            run_id,
            task_id,
            kind: kind.trim().to_string(),
            target: target.trim().to_string(),
            state: SessionState::Opening,
            created_at: now,
            opened_at: None,
            closed_at: None,
            last_activity_at: now,
            updated_at: now,
        })
    }

    pub fn transition_state(&mut self, next: SessionState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "session",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        if next == SessionState::Open && self.opened_at.is_none() {
            self.opened_at = Some(now);
        }
        if next.is_terminal() {
            self.closed_at = Some(now);
        }
        Ok(())
    }

    pub fn touch_activity(&mut self, now: u64) {
        self.last_activity_at = now;
        self.updated_at = now;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Pending,
    Available,
    Expired,
    Deleted,
}

impl ArtifactState {
    pub const fn as_str(self) -> &'static str {
        match self {
            ArtifactState::Pending => "pending",
            ArtifactState::Available => "available",
            ArtifactState::Expired => "expired",
            ArtifactState::Deleted => "deleted",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (ArtifactState::Pending, ArtifactState::Available) => true,
            (ArtifactState::Pending, ArtifactState::Deleted) => true,
            (ArtifactState::Available, ArtifactState::Expired) => true,
            (ArtifactState::Available, ArtifactState::Deleted) => true,
            (ArtifactState::Expired, ArtifactState::Deleted) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, ArtifactState::Deleted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Transcript,
    CommandOutput,
    StructuredJson,
    BinaryBlob,
    FileReference,
}

impl ArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Transcript => "transcript",
            ArtifactKind::CommandOutput => "command_output",
            ArtifactKind::StructuredJson => "structured_json",
            ArtifactKind::BinaryBlob => "binary_blob",
            ArtifactKind::FileReference => "file_reference",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub id: ArtifactId,
    pub run_id: RunId,
    pub task_id: Option<TaskId>,
    pub session_id: Option<SessionId>,
    pub kind: ArtifactKind,
    pub name: String,
    pub locator: String,
    pub state: ArtifactState,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Artifact {
    pub fn new(
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        kind: ArtifactKind,
        name: &str,
        locator: &str,
    ) -> Result<Self, DomainError> {
        Self::new_at(run_id, task_id, session_id, kind, name, locator, now_secs())
    }

    pub fn new_at(
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        kind: ArtifactKind,
        name: &str,
        locator: &str,
        now: u64,
    ) -> Result<Self, DomainError> {
        ensure_non_empty(name, "artifact.name")?;
        ensure_non_empty(locator, "artifact.locator")?;
        Ok(Self {
            id: ArtifactId::next(),
            run_id,
            task_id,
            session_id,
            kind,
            name: name.trim().to_string(),
            locator: locator.trim().to_string(),
            state: ArtifactState::Pending,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn transition_state(&mut self, next: ArtifactState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "artifact",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingSeverity::Info => "info",
            FindingSeverity::Low => "low",
            FindingSeverity::Medium => "medium",
            FindingSeverity::High => "high",
            FindingSeverity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingState {
    Open,
    Confirmed,
    Resolved,
    FalsePositive,
}

impl FindingState {
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingState::Open => "open",
            FindingState::Confirmed => "confirmed",
            FindingState::Resolved => "resolved",
            FindingState::FalsePositive => "false_positive",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (FindingState::Open, FindingState::Confirmed) => true,
            (FindingState::Open, FindingState::Resolved) => true,
            (FindingState::Open, FindingState::FalsePositive) => true,
            (FindingState::Confirmed, FindingState::Resolved) => true,
            (FindingState::Confirmed, FindingState::FalsePositive) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, FindingState::Resolved | FindingState::FalsePositive)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: FindingId,
    pub run_id: RunId,
    pub task_id: Option<TaskId>,
    pub session_id: Option<SessionId>,
    pub title: String,
    pub details: String,
    pub severity: FindingSeverity,
    pub state: FindingState,
    pub created_at: u64,
    pub updated_at: u64,
    pub resolved_at: Option<u64>,
}

impl Finding {
    pub fn new(
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        title: &str,
        details: &str,
        severity: FindingSeverity,
    ) -> Result<Self, DomainError> {
        Self::new_at(run_id, task_id, session_id, title, details, severity, now_secs())
    }

    pub fn new_at(
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        title: &str,
        details: &str,
        severity: FindingSeverity,
        now: u64,
    ) -> Result<Self, DomainError> {
        ensure_non_empty(title, "finding.title")?;
        Ok(Self {
            id: FindingId::next(),
            run_id,
            task_id,
            session_id,
            title: title.trim().to_string(),
            details: details.trim().to_string(),
            severity,
            state: FindingState::Open,
            created_at: now,
            updated_at: now,
            resolved_at: None,
        })
    }

    pub fn transition_state(&mut self, next: FindingState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "finding",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        if next.is_terminal() {
            self.resolved_at = Some(now);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    Emitted,
    Persisted,
    Delivered,
    Failed,
}

impl EventState {
    pub const fn as_str(self) -> &'static str {
        match self {
            EventState::Emitted => "emitted",
            EventState::Persisted => "persisted",
            EventState::Delivered => "delivered",
            EventState::Failed => "failed",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (EventState::Emitted, EventState::Persisted) => true,
            (EventState::Emitted, EventState::Failed) => true,
            (EventState::Persisted, EventState::Delivered) => true,
            (EventState::Persisted, EventState::Failed) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, EventState::Delivered | EventState::Failed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: EventId,
    pub correlation_id: CorrelationId,
    pub entity: EntityKind,
    pub action: ControlAction,
    pub message: String,
    pub state: EventState,
    pub created_at: u64,
    pub updated_at: u64,
    pub persisted_at: Option<u64>,
    pub delivered_at: Option<u64>,
}

impl Event {
    pub fn new(
        correlation_id: CorrelationId,
        entity: EntityKind,
        action: ControlAction,
        message: &str,
    ) -> Result<Self, DomainError> {
        Self::new_at(correlation_id, entity, action, message, now_secs())
    }

    pub fn new_at(
        correlation_id: CorrelationId,
        entity: EntityKind,
        action: ControlAction,
        message: &str,
        now: u64,
    ) -> Result<Self, DomainError> {
        ensure_non_empty(message, "event.message")?;
        Ok(Self {
            id: EventId::next(),
            correlation_id,
            entity,
            action,
            message: message.trim().to_string(),
            state: EventState::Emitted,
            created_at: now,
            updated_at: now,
            persisted_at: None,
            delivered_at: None,
        })
    }

    pub fn transition_state(&mut self, next: EventState, now: u64) -> Result<(), DomainError> {
        ensure_transition(
            "event",
            self.state.as_str(),
            next.as_str(),
            self.state.can_transition_to(next),
        )?;
        self.state = next;
        self.updated_at = now;
        if next == EventState::Persisted {
            self.persisted_at = Some(now);
        }
        if next == EventState::Delivered {
            self.delivered_at = Some(now);
        }
        Ok(())
    }
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), DomainError> {
    if value.trim().is_empty() {
        return Err(DomainError::InvalidField {
            field,
            reason: "cannot be empty",
        });
    }
    Ok(())
}

fn ensure_transition(
    entity: &'static str,
    from: &'static str,
    to: &'static str,
    allowed: bool,
) -> Result<(), DomainError> {
    if !allowed {
        return Err(DomainError::InvalidTransition { entity, from, to });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_lifecycle_rejects_ambiguous_transitions() {
        let now = 10;
        let workspace_id = WorkspaceId::next();
        let module_version_id = ModuleVersionId::next();
        let mut run = Run::new_at(workspace_id, module_version_id, None, "operator", now)
            .expect("run");

        assert_eq!(run.state, RunState::Queued);
        run.transition_state(RunState::Running, now + 1)
            .expect("queued->running");
        run.transition_state(RunState::Succeeded, now + 2)
            .expect("running->succeeded");
        assert_eq!(run.finished_at, Some(now + 2));
        assert!(
            run.transition_state(RunState::Running, now + 3).is_err(),
            "terminal states must reject new transitions"
        );
    }

    #[test]
    fn task_retries_respect_max_attempts() {
        let run_id = RunId::next();
        let now = 20;
        let mut task = Task::new_at(run_id, "probe", 1, now).expect("task");

        task.transition_state(TaskState::Running, now + 1)
            .expect("attempt 1");
        task.retry_with_error("temporary timeout", now + 2)
            .expect("mark retry");
        task.transition_state(TaskState::Queued, now + 3)
            .expect("requeue");
        assert!(
            task.transition_state(TaskState::Running, now + 4).is_err(),
            "attempt 2 exceeds max_attempts=1"
        );
    }

    #[test]
    fn session_can_recover_from_lost() {
        let run_id = RunId::next();
        let mut session =
            Session::new_at(run_id, None, "telnet/new-environ", "target:23", 100).expect("session");

        session
            .transition_state(SessionState::Open, 101)
            .expect("opening->open");
        session
            .transition_state(SessionState::Lost, 102)
            .expect("open->lost");
        session
            .transition_state(SessionState::Open, 103)
            .expect("lost->open");
        session.touch_activity(104);
        session
            .transition_state(SessionState::Closed, 105)
            .expect("open->closed");

        assert_eq!(session.closed_at, Some(105));
    }

    #[test]
    fn every_control_action_maps_to_an_entity_change() {
        for action in ALL_CONTROL_ACTIONS {
            let changed = action_entity_changes(*action);
            assert!(
                !changed.is_empty(),
                "action {:?} must map to at least one entity",
                action
            );
        }
    }

    #[test]
    fn event_pipeline_state_is_linear_and_terminal() {
        let correlation = CorrelationId::next();
        let mut event = Event::new_at(
            correlation,
            EntityKind::Run,
            ControlAction::RunStart,
            "run started",
            1000,
        )
        .expect("event");
        event
            .transition_state(EventState::Persisted, 1001)
            .expect("persisted");
        event
            .transition_state(EventState::Delivered, 1002)
            .expect("delivered");
        assert!(
            event.transition_state(EventState::Failed, 1003).is_err(),
            "delivered is terminal"
        );
    }
}
