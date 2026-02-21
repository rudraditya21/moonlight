use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::campaign::{
    CampaignEvent as CampaignAuditEvent, CampaignEventPayload as CampaignPayload, CampaignId,
    CampaignStatus, Objective, ObjectiveId, ObjectiveIngestionDispatch,
    ObjectiveIngestionDispatcher, ObjectiveIngestionEvent, ObjectiveReevaluationTrigger,
    ObjectiveStatus, PredicateSnapshot, RiskLevel,
};
use crate::control::ControlState;
use crate::domain::{
    ArtifactId, CorrelationId, DomainError, EventId, FindingId, ModuleVersionId, Run, RunId,
    RunState, SessionId, TargetId, Task, TaskId, TaskState, WorkspaceId,
};
use crate::ids::Id;
use crate::time::now_secs;

const SNAPSHOT_HEADER: &str = "moonlight-orchestrator:v1";
const AUDIT_HEADER: &str = "moonlight-audit:v1";

#[derive(Debug)]
pub enum OrchestratorError {
    Domain(DomainError),
    Validation(String),
    NotFound(String),
    Storage(String),
    Parse(String),
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrchestratorError::Domain(err) => write!(f, "{err}"),
            OrchestratorError::Validation(msg) => write!(f, "validation error: {msg}"),
            OrchestratorError::NotFound(msg) => write!(f, "not found: {msg}"),
            OrchestratorError::Storage(msg) => write!(f, "storage error: {msg}"),
            OrchestratorError::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl From<DomainError> for OrchestratorError {
    fn from(value: DomainError) -> Self {
        OrchestratorError::Domain(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub workspace_id: WorkspaceId,
    pub module_version_id: ModuleVersionId,
    pub target_id: Option<TargetId>,
    pub requested_by: String,
}

impl RunRequest {
    pub fn new(
        workspace_id: WorkspaceId,
        module_version_id: ModuleVersionId,
        target_id: Option<TargetId>,
        requested_by: &str,
    ) -> Result<Self, OrchestratorError> {
        if requested_by.trim().is_empty() {
            return Err(OrchestratorError::Validation(
                "requested_by cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            workspace_id,
            module_version_id,
            target_id,
            requested_by: requested_by.trim().to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTask {
    pub name: String,
    pub max_attempts: u32,
    pub timeout_ms: u64,
    pub idempotency_key: String,
}

impl PlannedTask {
    pub fn new(
        name: &str,
        max_attempts: u32,
        timeout_ms: u64,
        idempotency_key: &str,
    ) -> Result<Self, OrchestratorError> {
        if name.trim().is_empty() {
            return Err(OrchestratorError::Validation(
                "task name cannot be empty".to_string(),
            ));
        }
        if max_attempts == 0 {
            return Err(OrchestratorError::Validation(
                "max_attempts must be greater than zero".to_string(),
            ));
        }
        if timeout_ms == 0 {
            return Err(OrchestratorError::Validation(
                "timeout_ms must be greater than zero".to_string(),
            ));
        }
        if idempotency_key.trim().is_empty() {
            return Err(OrchestratorError::Validation(
                "idempotency_key cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            name: name.trim().to_string(),
            max_attempts,
            timeout_ms,
            idempotency_key: idempotency_key.trim().to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub tasks: Vec<PlannedTask>,
}

impl RunPlan {
    pub fn new(tasks: Vec<PlannedTask>) -> Result<Self, OrchestratorError> {
        if tasks.is_empty() {
            return Err(OrchestratorError::Validation(
                "run plan must contain at least one task".to_string(),
            ));
        }
        Ok(Self { tasks })
    }
}

pub trait RunPlanner {
    fn plan(&self, request: &RunRequest) -> Result<RunPlan, OrchestratorError>;
}

#[derive(Debug, Clone)]
pub struct StaticRunPlanner {
    plan: RunPlan,
}

impl StaticRunPlanner {
    pub fn new(plan: RunPlan) -> Self {
        Self { plan }
    }
}

impl RunPlanner for StaticRunPlanner {
    fn plan(&self, _request: &RunRequest) -> Result<RunPlan, OrchestratorError> {
        Ok(self.plan.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskExecutionContext {
    pub run_id: RunId,
    pub task_id: TaskId,
    pub task_name: String,
    pub attempt: u32,
    pub timeout_ms: u64,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskExecutionOutcome {
    Success { message: String },
    RetryableError { message: String },
    FatalError { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskExecutionReport {
    pub elapsed_ms: u64,
    pub outcome: TaskExecutionOutcome,
}

pub trait TaskExecutor {
    fn execute(
        &mut self,
        context: &TaskExecutionContext,
    ) -> Result<TaskExecutionReport, OrchestratorError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    Idle,
    Succeeded {
        run_id: RunId,
        task_id: TaskId,
    },
    Requeued {
        run_id: RunId,
        task_id: TaskId,
        reason: String,
    },
    Failed {
        run_id: RunId,
        task_id: TaskId,
        reason: String,
    },
    Canceled {
        run_id: RunId,
        task_id: TaskId,
    },
    Deduplicated {
        run_id: RunId,
        task_id: TaskId,
        source_task_id: TaskId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRecord {
    pub key: String,
    pub run_id: RunId,
    pub task_id: TaskId,
    pub message: String,
    pub completed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScheduledTask {
    task: Task,
    timeout_ms: u64,
    idempotency_key: String,
    cancel_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunExecution {
    run: Run,
    task_order: Vec<TaskId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExecutionSnapshot {
    runs: Vec<RunExecution>,
    tasks: Vec<ScheduledTask>,
    queue: Vec<TaskId>,
    idempotency: Vec<IdempotencyRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrchestratorLimits {
    pub max_pending_tasks: usize,
}

impl Default for OrchestratorLimits {
    fn default() -> Self {
        Self {
            max_pending_tasks: usize::MAX,
        }
    }
}

pub trait SnapshotStore {
    fn load_snapshot(&mut self) -> Result<Option<String>, OrchestratorError>;
    fn save_snapshot(&mut self, snapshot: &str) -> Result<(), OrchestratorError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: EventId,
    pub correlation_id: CorrelationId,
    pub occurred_at: u64,
    pub payload: AuditEventPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventPayload {
    Run(RunEvent),
    Task(TaskEvent),
    Session(SessionEvent),
    Module(ModuleEvent),
    Campaign(CampaignAuditEvent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvent {
    Submitted {
        run_id: RunId,
        workspace_id: WorkspaceId,
        module_version_id: ModuleVersionId,
        target_id: Option<TargetId>,
        requested_by: String,
    },
    StateChanged {
        run_id: RunId,
        from: RunState,
        to: RunState,
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskEvent {
    Created {
        run_id: RunId,
        task_id: TaskId,
        name: String,
        max_attempts: u32,
        timeout_ms: u64,
        idempotency_key: String,
    },
    Started {
        run_id: RunId,
        task_id: TaskId,
        attempt: u32,
    },
    Retried {
        run_id: RunId,
        task_id: TaskId,
        attempt: u32,
        reason: String,
    },
    Succeeded {
        run_id: RunId,
        task_id: TaskId,
        message: Option<String>,
        deduplicated_from: Option<TaskId>,
    },
    Failed {
        run_id: RunId,
        task_id: TaskId,
        reason: String,
    },
    Canceled {
        run_id: RunId,
        task_id: TaskId,
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Opened {
        session_id: SessionId,
        run_id: Option<RunId>,
        session_type: String,
        target: String,
    },
    Attached {
        session_id: SessionId,
        operator: String,
    },
    Detached {
        session_id: SessionId,
        operator: String,
    },
    Backgrounded {
        session_id: SessionId,
    },
    Closed {
        session_id: SessionId,
        reason: Option<String>,
    },
    Reaped {
        session_id: SessionId,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleEvent {
    Discovered {
        module_path: String,
        module_version_id: Option<ModuleVersionId>,
    },
    Validated {
        module_path: String,
        api_version: String,
    },
    ValidationFailed {
        module_path: String,
        reason: String,
    },
    Executed {
        module_path: String,
        run_id: RunId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedRun {
    pub run_id: RunId,
    pub correlation_id: CorrelationId,
    pub workspace_id: WorkspaceId,
    pub module_version_id: ModuleVersionId,
    pub target_id: Option<TargetId>,
    pub requested_by: String,
    pub state: RunState,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub error: Option<String>,
    pub tasks: BTreeMap<TaskId, ReconstructedTask>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedTask {
    pub task_id: TaskId,
    pub name: String,
    pub state: TaskState,
    pub attempt_count: u32,
    pub max_attempts: u32,
    pub timeout_ms: u64,
    pub idempotency_key: String,
    pub error: Option<String>,
    pub deduplicated_from: Option<TaskId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayDiagnostic {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayedObjective {
    pub objective_id: ObjectiveId,
    pub name: Option<String>,
    pub risk_level: Option<RiskLevel>,
    pub status: ObjectiveStatus,
    pub prerequisites: BTreeSet<ObjectiveId>,
    pub evaluation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedCampaign {
    pub campaign_id: CampaignId,
    pub correlation_id: CorrelationId,
    pub sequence_high_watermark: u64,
    pub name: Option<String>,
    pub status: CampaignStatus,
    pub objective_ids: BTreeSet<ObjectiveId>,
    pub objectives: BTreeMap<ObjectiveId, ReplayedObjective>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignReplayReport {
    pub campaign: Option<ReconstructedCampaign>,
    pub diagnostics: Vec<ReplayDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignReplayConsistency {
    pub report: CampaignReplayReport,
    pub consistent: bool,
}

pub trait AuditLogStore {
    fn load_events(&mut self) -> Result<Vec<AuditEvent>, OrchestratorError>;
    fn append_event(&mut self, event: &AuditEvent) -> Result<(), OrchestratorError>;
}

#[derive(Debug, Clone)]
pub struct InMemorySnapshotStore {
    shared: Arc<Mutex<Option<String>>>,
}

impl Default for InMemorySnapshotStore {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(None)),
        }
    }
}

impl InMemorySnapshotStore {
    pub fn from_shared(shared: Arc<Mutex<Option<String>>>) -> Self {
        Self { shared }
    }

    pub fn shared(&self) -> Arc<Mutex<Option<String>>> {
        Arc::clone(&self.shared)
    }
}

impl SnapshotStore for InMemorySnapshotStore {
    fn load_snapshot(&mut self) -> Result<Option<String>, OrchestratorError> {
        self.shared
            .lock()
            .map_err(|_| OrchestratorError::Storage("snapshot lock poisoned".to_string()))
            .map(|v| v.clone())
    }

    fn save_snapshot(&mut self, snapshot: &str) -> Result<(), OrchestratorError> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| OrchestratorError::Storage("snapshot lock poisoned".to_string()))?;
        *guard = Some(snapshot.to_string());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FileSnapshotStore {
    path: PathBuf,
}

impl FileSnapshotStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl SnapshotStore for FileSnapshotStore {
    fn load_snapshot(&mut self) -> Result<Option<String>, OrchestratorError> {
        if !self.path.exists() {
            return Ok(None);
        }
        std::fs::read_to_string(&self.path)
            .map(Some)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }

    fn save_snapshot(&mut self, snapshot: &str) -> Result<(), OrchestratorError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        }
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, snapshot)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        std::fs::rename(&tmp_path, &self.path)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct InMemoryAuditLogStore {
    shared: Arc<Mutex<Vec<AuditEvent>>>,
}

impl Default for InMemoryAuditLogStore {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl InMemoryAuditLogStore {
    pub fn from_shared(shared: Arc<Mutex<Vec<AuditEvent>>>) -> Self {
        Self { shared }
    }

    pub fn shared(&self) -> Arc<Mutex<Vec<AuditEvent>>> {
        Arc::clone(&self.shared)
    }
}

impl AuditLogStore for InMemoryAuditLogStore {
    fn load_events(&mut self) -> Result<Vec<AuditEvent>, OrchestratorError> {
        self.shared
            .lock()
            .map_err(|_| OrchestratorError::Storage("audit lock poisoned".to_string()))
            .map(|events| events.clone())
    }

    fn append_event(&mut self, event: &AuditEvent) -> Result<(), OrchestratorError> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| OrchestratorError::Storage("audit lock poisoned".to_string()))?;
        guard.push(event.clone());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FileAuditLogStore {
    path: PathBuf,
}

impl FileAuditLogStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    fn ensure_header(&self, file: &mut std::fs::File) -> Result<(), OrchestratorError> {
        if file
            .metadata()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?
            .len()
            == 0
        {
            file.write_all(AUDIT_HEADER.as_bytes())
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
            file.write_all(b"\n")
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        }
        Ok(())
    }
}

impl AuditLogStore for FileAuditLogStore {
    fn load_events(&mut self) -> Result<Vec<AuditEvent>, OrchestratorError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        decode_audit_log(&raw)
    }

    fn append_event(&mut self, event: &AuditEvent) -> Result<(), OrchestratorError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        self.ensure_header(&mut file)?;
        file.write_all(encode_audit_event(event).as_bytes())
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        file.write_all(b"\n")
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }
}

pub struct ExecutionOrchestrator<S: SnapshotStore> {
    store: S,
    runs: BTreeMap<RunId, RunExecution>,
    tasks: BTreeMap<TaskId, ScheduledTask>,
    queue: VecDeque<TaskId>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
    limits: OrchestratorLimits,
}

impl<S: SnapshotStore> ExecutionOrchestrator<S> {
    pub fn new(store: S) -> Result<Self, OrchestratorError> {
        Self::with_limits(store, OrchestratorLimits::default())
    }

    pub fn with_limits(store: S, limits: OrchestratorLimits) -> Result<Self, OrchestratorError> {
        let mut this = Self {
            store,
            runs: BTreeMap::new(),
            tasks: BTreeMap::new(),
            queue: VecDeque::new(),
            idempotency: BTreeMap::new(),
            limits,
        };

        if let Some(raw) = this.store.load_snapshot()? {
            let snapshot = decode_snapshot(&raw)?;
            this.apply_snapshot(snapshot)?;
            this.recover_after_restart(now_secs())?;
            this.persist()?;
        }

        Ok(this)
    }

    pub fn submit_with_planner<P: RunPlanner>(
        &mut self,
        request: RunRequest,
        planner: &P,
    ) -> Result<RunId, OrchestratorError> {
        let plan = planner.plan(&request)?;
        self.submit_run(request, plan)
    }

    pub fn submit_run(
        &mut self,
        request: RunRequest,
        plan: RunPlan,
    ) -> Result<RunId, OrchestratorError> {
        if self.queue.len().saturating_add(plan.tasks.len()) > self.limits.max_pending_tasks {
            return Err(OrchestratorError::Validation(format!(
                "queue pressure exceeded: pending={} incoming={} limit={}",
                self.queue.len(),
                plan.tasks.len(),
                self.limits.max_pending_tasks
            )));
        }
        let now = now_secs();
        let run = Run::new_at(
            request.workspace_id,
            request.module_version_id,
            request.target_id,
            &request.requested_by,
            now,
        )?;
        let run_id = run.id;

        let mut run_exec = RunExecution {
            run,
            task_order: Vec::with_capacity(plan.tasks.len()),
        };

        for spec in plan.tasks {
            let task = Task::new_at(run_id, &spec.name, spec.max_attempts, now)?;
            let task_id = task.id;
            self.tasks.insert(
                task_id,
                ScheduledTask {
                    task,
                    timeout_ms: spec.timeout_ms,
                    idempotency_key: spec.idempotency_key,
                    cancel_requested: false,
                },
            );
            self.queue.push_back(task_id);
            run_exec.task_order.push(task_id);
        }

        self.runs.insert(run_id, run_exec);
        self.persist()?;
        Ok(run_id)
    }

    pub fn dispatch_next<E: TaskExecutor>(
        &mut self,
        executor: &mut E,
    ) -> Result<DispatchOutcome, OrchestratorError> {
        let Some(task_id) = self.pop_next_dispatchable_task() else {
            return Ok(DispatchOutcome::Idle);
        };
        let run_id = self.task_run_id(task_id)?;
        let now = now_secs();

        if self.is_run_canceled(run_id)? {
            self.cancel_task_internal(task_id, now)?;
            self.persist()?;
            return Ok(DispatchOutcome::Canceled { run_id, task_id });
        }
        if self.is_task_cancel_requested(task_id)? {
            self.cancel_task_internal(task_id, now)?;
            self.refresh_run_state(run_id, now)?;
            self.persist()?;
            return Ok(DispatchOutcome::Canceled { run_id, task_id });
        }

        self.ensure_run_started(run_id, now)?;
        self.transition_task_to_running(task_id, now)?;
        self.persist()?;

        let idempotency_key = self.task_idempotency_key(task_id)?;
        if let Some(source_task_id) = self.idempotency.get(&idempotency_key).map(|v| v.task_id) {
            self.complete_task_success(task_id, now, None)?;
            self.refresh_run_state(run_id, now)?;
            self.persist()?;
            return Ok(DispatchOutcome::Deduplicated {
                run_id,
                task_id,
                source_task_id,
            });
        }

        let context = self.build_execution_context(task_id)?;
        let report = match executor.execute(&context) {
            Ok(report) => report,
            Err(err) => TaskExecutionReport {
                elapsed_ms: 0,
                outcome: TaskExecutionOutcome::FatalError {
                    message: err.to_string(),
                },
            },
        };

        let timeout_ms = self.task_timeout(task_id)?;
        let outcome = if report.elapsed_ms > timeout_ms {
            TaskExecutionOutcome::RetryableError {
                message: format!(
                    "task timed out after {}ms (limit {}ms)",
                    report.elapsed_ms, timeout_ms
                ),
            }
        } else {
            report.outcome
        };

        match outcome {
            TaskExecutionOutcome::Success { message } => {
                self.complete_task_success(task_id, now, Some(message.clone()))?;
                self.refresh_run_state(run_id, now)?;
                self.persist()?;
                Ok(DispatchOutcome::Succeeded { run_id, task_id })
            }
            TaskExecutionOutcome::RetryableError { message } => {
                if self.can_retry(task_id)? {
                    self.requeue_task(task_id, &message, now)?;
                    self.persist()?;
                    Ok(DispatchOutcome::Requeued {
                        run_id,
                        task_id,
                        reason: message,
                    })
                } else {
                    self.fail_task(task_id, &message, now)?;
                    self.fail_run_and_cancel_remaining(run_id, &message, now)?;
                    self.persist()?;
                    Ok(DispatchOutcome::Failed {
                        run_id,
                        task_id,
                        reason: message,
                    })
                }
            }
            TaskExecutionOutcome::FatalError { message } => {
                self.fail_task(task_id, &message, now)?;
                self.fail_run_and_cancel_remaining(run_id, &message, now)?;
                self.persist()?;
                Ok(DispatchOutcome::Failed {
                    run_id,
                    task_id,
                    reason: message,
                })
            }
        }
    }

    pub fn cancel_run(&mut self, run_id: RunId) -> Result<bool, OrchestratorError> {
        let now = now_secs();
        let Some(run_exec) = self.runs.get_mut(&run_id) else {
            return Err(OrchestratorError::NotFound(format!("run {}", run_id.0 .0)));
        };
        if run_exec.run.state.is_terminal() {
            return Ok(false);
        }
        run_exec.run.transition_state(RunState::Canceled, now)?;
        let task_ids = run_exec.task_order.clone();
        for task_id in task_ids {
            let Some(scheduled) = self.tasks.get_mut(&task_id) else {
                continue;
            };
            match scheduled.task.state {
                TaskState::Queued | TaskState::Retrying => {
                    scheduled.task.transition_state(TaskState::Canceled, now)?
                }
                TaskState::Running => scheduled.cancel_requested = true,
                _ => {}
            }
        }
        self.queue.retain(|task_id| {
            self.tasks
                .get(task_id)
                .map(|task| !task.task.state.is_terminal())
                .unwrap_or(false)
        });
        self.persist()?;
        Ok(true)
    }

    pub fn cancel_task(&mut self, task_id: TaskId) -> Result<bool, OrchestratorError> {
        let run_id = self.task_run_id(task_id)?;
        let now = now_secs();
        let Some(scheduled) = self.tasks.get_mut(&task_id) else {
            return Err(OrchestratorError::NotFound(format!(
                "task {}",
                task_id.0 .0
            )));
        };
        if scheduled.task.state.is_terminal() {
            return Ok(false);
        }
        match scheduled.task.state {
            TaskState::Queued | TaskState::Retrying => {
                scheduled.task.transition_state(TaskState::Canceled, now)?;
                self.queue.retain(|queued| *queued != task_id);
            }
            TaskState::Running => scheduled.cancel_requested = true,
            _ => {}
        }
        self.refresh_run_state(run_id, now)?;
        self.persist()?;
        Ok(true)
    }

    pub fn run_state(&self, run_id: RunId) -> Option<RunState> {
        self.runs.get(&run_id).map(|run| run.run.state)
    }

    pub fn task_state(&self, task_id: TaskId) -> Option<TaskState> {
        self.tasks.get(&task_id).map(|task| task.task.state)
    }

    pub fn task_attempt_count(&self, task_id: TaskId) -> Option<u32> {
        self.tasks.get(&task_id).map(|task| task.task.attempt_count)
    }

    pub fn run_task_ids(&self, run_id: RunId) -> Option<Vec<TaskId>> {
        self.runs.get(&run_id).map(|run| run.task_order.clone())
    }

    pub fn pending_tasks(&self) -> usize {
        self.queue.len()
    }

    pub fn idempotency_record(&self, key: &str) -> Option<&IdempotencyRecord> {
        self.idempotency.get(key)
    }

    fn peek_next_dispatchable_task(&self) -> Option<TaskId> {
        for task_id in &self.queue {
            let Some(task) = self.tasks.get(task_id) else {
                continue;
            };
            if task.task.state != TaskState::Queued {
                continue;
            }
            let run_state = self
                .runs
                .get(&task.task.run_id)
                .map(|run| run.run.state)
                .unwrap_or(RunState::Failed);
            if run_state.is_terminal() {
                continue;
            }
            return Some(*task_id);
        }
        None
    }

    fn pop_next_dispatchable_task(&mut self) -> Option<TaskId> {
        while let Some(task_id) = self.queue.pop_front() {
            let Some(task) = self.tasks.get(&task_id) else {
                continue;
            };
            if task.task.state != TaskState::Queued {
                continue;
            }
            let run_state = self
                .runs
                .get(&task.task.run_id)
                .map(|run| run.run.state)
                .unwrap_or(RunState::Failed);
            if run_state.is_terminal() {
                continue;
            }
            return Some(task_id);
        }
        None
    }

    fn task_run_id(&self, task_id: TaskId) -> Result<RunId, OrchestratorError> {
        self.tasks
            .get(&task_id)
            .map(|task| task.task.run_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))
    }

    fn is_run_canceled(&self, run_id: RunId) -> Result<bool, OrchestratorError> {
        let run = self
            .runs
            .get(&run_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("run {}", run_id.0 .0)))?;
        Ok(run.run.state == RunState::Canceled)
    }

    fn is_task_cancel_requested(&self, task_id: TaskId) -> Result<bool, OrchestratorError> {
        let task = self
            .tasks
            .get(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        Ok(task.cancel_requested)
    }

    fn ensure_run_started(&mut self, run_id: RunId, now: u64) -> Result<(), OrchestratorError> {
        let run_exec = self
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("run {}", run_id.0 .0)))?;
        if run_exec.run.state == RunState::Queued {
            run_exec.run.transition_state(RunState::Running, now)?;
        }
        Ok(())
    }

    fn transition_task_to_running(
        &mut self,
        task_id: TaskId,
        now: u64,
    ) -> Result<(), OrchestratorError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        task.task.transition_state(TaskState::Running, now)?;
        Ok(())
    }

    fn task_timeout(&self, task_id: TaskId) -> Result<u64, OrchestratorError> {
        self.tasks
            .get(&task_id)
            .map(|task| task.timeout_ms)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))
    }

    fn task_idempotency_key(&self, task_id: TaskId) -> Result<String, OrchestratorError> {
        self.tasks
            .get(&task_id)
            .map(|task| task.idempotency_key.clone())
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))
    }

    fn build_execution_context(
        &self,
        task_id: TaskId,
    ) -> Result<TaskExecutionContext, OrchestratorError> {
        let scheduled = self
            .tasks
            .get(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        Ok(TaskExecutionContext {
            run_id: scheduled.task.run_id,
            task_id,
            task_name: scheduled.task.name.clone(),
            attempt: scheduled.task.attempt_count,
            timeout_ms: scheduled.timeout_ms,
            idempotency_key: scheduled.idempotency_key.clone(),
        })
    }

    fn can_retry(&self, task_id: TaskId) -> Result<bool, OrchestratorError> {
        let task = self
            .tasks
            .get(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        Ok(task.task.attempt_count < task.task.max_attempts)
    }

    fn complete_task_success(
        &mut self,
        task_id: TaskId,
        now: u64,
        message: Option<String>,
    ) -> Result<(), OrchestratorError> {
        let scheduled = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        scheduled.task.transition_state(TaskState::Succeeded, now)?;
        if let Some(message) = message {
            self.idempotency.insert(
                scheduled.idempotency_key.clone(),
                IdempotencyRecord {
                    key: scheduled.idempotency_key.clone(),
                    run_id: scheduled.task.run_id,
                    task_id,
                    message,
                    completed_at: now,
                },
            );
        }
        Ok(())
    }

    fn requeue_task(
        &mut self,
        task_id: TaskId,
        message: &str,
        now: u64,
    ) -> Result<(), OrchestratorError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        task.task.retry_with_error(message, now)?;
        task.task.transition_state(TaskState::Queued, now)?;
        self.queue.push_back(task_id);
        Ok(())
    }

    fn fail_task(
        &mut self,
        task_id: TaskId,
        message: &str,
        now: u64,
    ) -> Result<(), OrchestratorError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        task.task.fail_with_error(message, now)?;
        Ok(())
    }

    fn fail_run_and_cancel_remaining(
        &mut self,
        run_id: RunId,
        message: &str,
        now: u64,
    ) -> Result<(), OrchestratorError> {
        {
            let run_exec = self
                .runs
                .get_mut(&run_id)
                .ok_or_else(|| OrchestratorError::NotFound(format!("run {}", run_id.0 .0)))?;
            if !run_exec.run.state.is_terminal() {
                run_exec.run.fail_with_error(message, now)?;
            }
            let task_ids = run_exec.task_order.clone();
            for task_id in task_ids {
                let Some(task) = self.tasks.get_mut(&task_id) else {
                    continue;
                };
                if task.task.state.is_terminal() {
                    continue;
                }
                match task.task.state {
                    TaskState::Queued | TaskState::Retrying => {
                        task.task.transition_state(TaskState::Canceled, now)?
                    }
                    TaskState::Running => task.cancel_requested = true,
                    _ => {}
                }
            }
        }
        self.queue.retain(|task_id| {
            self.tasks
                .get(task_id)
                .map(|task| !task.task.state.is_terminal())
                .unwrap_or(false)
        });
        Ok(())
    }

    fn cancel_task_internal(&mut self, task_id: TaskId, now: u64) -> Result<(), OrchestratorError> {
        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
        if !task.task.state.is_terminal() {
            match task.task.state {
                TaskState::Queued | TaskState::Retrying => {
                    task.task.transition_state(TaskState::Canceled, now)?
                }
                TaskState::Running => task.cancel_requested = true,
                _ => {}
            }
        }
        Ok(())
    }

    fn refresh_run_state(&mut self, run_id: RunId, now: u64) -> Result<(), OrchestratorError> {
        let task_ids = self
            .runs
            .get(&run_id)
            .map(|r| r.task_order.clone())
            .ok_or_else(|| OrchestratorError::NotFound(format!("run {}", run_id.0 .0)))?;

        let mut any_failed = false;
        let mut any_canceled = false;
        let mut all_succeeded = true;
        let mut all_terminal = true;

        for task_id in &task_ids {
            let Some(task) = self.tasks.get(task_id) else {
                continue;
            };
            match task.task.state {
                TaskState::Failed => {
                    any_failed = true;
                    all_succeeded = false;
                }
                TaskState::Canceled => {
                    any_canceled = true;
                    all_succeeded = false;
                }
                TaskState::Succeeded => {}
                _ => {
                    all_terminal = false;
                    all_succeeded = false;
                }
            }
        }

        let run_exec = self
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("run {}", run_id.0 .0)))?;

        if run_exec.run.state.is_terminal() {
            return Ok(());
        }

        if any_failed {
            run_exec
                .run
                .fail_with_error("one or more tasks failed", now)?;
            return Ok(());
        }

        if all_terminal {
            if all_succeeded {
                run_exec.run.transition_state(RunState::Succeeded, now)?;
            } else if any_canceled {
                run_exec.run.transition_state(RunState::Canceled, now)?;
            }
        }

        Ok(())
    }

    fn recover_after_restart(&mut self, now: u64) -> Result<(), OrchestratorError> {
        let task_ids: Vec<TaskId> = self.tasks.keys().cloned().collect();
        for task_id in task_ids {
            let Some(scheduled) = self.tasks.get_mut(&task_id) else {
                continue;
            };
            match scheduled.task.state {
                TaskState::Running => {
                    if scheduled.task.attempt_count >= scheduled.task.max_attempts {
                        scheduled.task.fail_with_error(
                            "recovered after restart: interrupted attempt exceeded retry budget",
                            now,
                        )?;
                    } else {
                        scheduled.task.retry_with_error(
                            "recovered after restart: interrupted task requeued",
                            now,
                        )?;
                        scheduled.task.transition_state(TaskState::Queued, now)?;
                        if !self.queue.contains(&task_id) {
                            self.queue.push_back(task_id);
                        }
                    }
                }
                TaskState::Retrying => {
                    scheduled.task.transition_state(TaskState::Queued, now)?;
                    if !self.queue.contains(&task_id) {
                        self.queue.push_back(task_id);
                    }
                }
                TaskState::Queued => {
                    if !self.queue.contains(&task_id) {
                        self.queue.push_back(task_id);
                    }
                }
                _ => {}
            }
        }

        let run_ids: Vec<RunId> = self.runs.keys().cloned().collect();
        for run_id in run_ids {
            self.refresh_run_state(run_id, now)?;
        }
        Ok(())
    }

    fn apply_snapshot(&mut self, snapshot: ExecutionSnapshot) -> Result<(), OrchestratorError> {
        self.runs.clear();
        self.tasks.clear();
        self.queue.clear();
        self.idempotency.clear();

        for run in snapshot.runs {
            self.runs.insert(run.run.id, run);
        }
        for task in snapshot.tasks {
            self.tasks.insert(task.task.id, task);
        }
        for task_id in snapshot.queue {
            self.queue.push_back(task_id);
        }
        for record in snapshot.idempotency {
            self.idempotency.insert(record.key.clone(), record);
        }
        Ok(())
    }

    fn snapshot(&self) -> ExecutionSnapshot {
        ExecutionSnapshot {
            runs: self.runs.values().cloned().collect(),
            tasks: self.tasks.values().cloned().collect(),
            queue: self.queue.iter().cloned().collect(),
            idempotency: self.idempotency.values().cloned().collect(),
        }
    }

    fn persist(&mut self) -> Result<(), OrchestratorError> {
        let snapshot = self.snapshot();
        let encoded = encode_snapshot(&snapshot);
        self.store.save_snapshot(&encoded)
    }
}

pub struct ObservableExecutionOrchestrator<S: SnapshotStore, A: AuditLogStore> {
    inner: ExecutionOrchestrator<S>,
    audit_store: A,
    run_correlations: BTreeMap<RunId, CorrelationId>,
    campaign_correlations: BTreeMap<CampaignId, CorrelationId>,
    next_campaign_sequence: BTreeMap<CampaignId, u64>,
    campaign_ingestion_dispatchers: BTreeMap<CampaignId, ObjectiveIngestionDispatcher>,
}

impl<S: SnapshotStore, A: AuditLogStore> ObservableExecutionOrchestrator<S, A> {
    pub fn new(store: S, mut audit_store: A) -> Result<Self, OrchestratorError> {
        let inner = ExecutionOrchestrator::new(store)?;
        let mut run_correlations = BTreeMap::new();
        let mut campaign_correlations = BTreeMap::new();
        let mut next_campaign_sequence = BTreeMap::new();
        for event in audit_store.load_events()? {
            if let Some(run_id) = event_run_id(&event.payload) {
                run_correlations
                    .entry(run_id)
                    .or_insert(event.correlation_id);
            }
            if let Some((campaign_id, sequence)) = event_campaign_meta(&event.payload) {
                campaign_correlations
                    .entry(campaign_id.clone())
                    .or_insert(event.correlation_id);
                let candidate_next = sequence.saturating_add(1);
                let entry = next_campaign_sequence.entry(campaign_id).or_insert(1);
                if *entry < candidate_next {
                    *entry = candidate_next;
                }
            }
        }
        for run_id in inner.runs.keys() {
            run_correlations
                .entry(*run_id)
                .or_insert_with(CorrelationId::next);
        }
        Ok(Self {
            inner,
            audit_store,
            run_correlations,
            campaign_correlations,
            next_campaign_sequence,
            campaign_ingestion_dispatchers: BTreeMap::new(),
        })
    }

    pub fn submit_with_planner<P: RunPlanner>(
        &mut self,
        request: RunRequest,
        planner: &P,
    ) -> Result<RunId, OrchestratorError> {
        let plan = planner.plan(&request)?;
        self.submit_run(request, plan)
    }

    pub fn submit_run(
        &mut self,
        request: RunRequest,
        plan: RunPlan,
    ) -> Result<RunId, OrchestratorError> {
        let workspace_id = request.workspace_id;
        let module_version_id = request.module_version_id;
        let target_id = request.target_id;
        let requested_by = request.requested_by.clone();
        let run_id = self.inner.submit_run(request, plan)?;
        let correlation_id = CorrelationId::next();
        self.run_correlations.insert(run_id, correlation_id);
        self.append_event(
            correlation_id,
            AuditEventPayload::Run(RunEvent::Submitted {
                run_id,
                workspace_id,
                module_version_id,
                target_id,
                requested_by,
            }),
        )?;

        let Some(task_ids) = self.inner.run_task_ids(run_id) else {
            return Err(OrchestratorError::NotFound(format!("run {}", run_id.0 .0)));
        };
        for task_id in task_ids {
            let task = self
                .inner
                .tasks
                .get(&task_id)
                .ok_or_else(|| OrchestratorError::NotFound(format!("task {}", task_id.0 .0)))?;
            self.append_event(
                correlation_id,
                AuditEventPayload::Task(TaskEvent::Created {
                    run_id,
                    task_id,
                    name: task.task.name.clone(),
                    max_attempts: task.task.max_attempts,
                    timeout_ms: task.timeout_ms,
                    idempotency_key: task.idempotency_key.clone(),
                }),
            )?;
        }
        Ok(run_id)
    }

    pub fn dispatch_next<E: TaskExecutor>(
        &mut self,
        executor: &mut E,
    ) -> Result<DispatchOutcome, OrchestratorError> {
        let preview_task_id = self.inner.peek_next_dispatchable_task();
        let preview_run_state = preview_task_id
            .and_then(|task_id| self.inner.tasks.get(&task_id))
            .and_then(|scheduled| self.inner.run_state(scheduled.task.run_id));

        let outcome = self.inner.dispatch_next(executor)?;
        if let Some(run_id) = outcome_run_id(&outcome) {
            let correlation_id = self.correlation_for_run_or_create(run_id);
            if let Some(task_id) = outcome_task_id(&outcome) {
                match &outcome {
                    DispatchOutcome::Succeeded { .. }
                    | DispatchOutcome::Requeued { .. }
                    | DispatchOutcome::Failed { .. }
                    | DispatchOutcome::Deduplicated { .. } => {
                        let attempt = self.inner.task_attempt_count(task_id).ok_or_else(|| {
                            OrchestratorError::NotFound(format!("task {}", task_id.0 .0))
                        })?;
                        self.append_event(
                            correlation_id,
                            AuditEventPayload::Task(TaskEvent::Started {
                                run_id,
                                task_id,
                                attempt,
                            }),
                        )?;
                    }
                    _ => {}
                }

                match &outcome {
                    DispatchOutcome::Succeeded { .. } => {
                        let message = self
                            .inner
                            .tasks
                            .get(&task_id)
                            .and_then(|task| self.inner.idempotency.get(&task.idempotency_key))
                            .map(|record| record.message.clone());
                        self.append_event(
                            correlation_id,
                            AuditEventPayload::Task(TaskEvent::Succeeded {
                                run_id,
                                task_id,
                                message,
                                deduplicated_from: None,
                            }),
                        )?;
                    }
                    DispatchOutcome::Requeued { reason, .. } => {
                        let attempt = self.inner.task_attempt_count(task_id).ok_or_else(|| {
                            OrchestratorError::NotFound(format!("task {}", task_id.0 .0))
                        })?;
                        self.append_event(
                            correlation_id,
                            AuditEventPayload::Task(TaskEvent::Retried {
                                run_id,
                                task_id,
                                attempt,
                                reason: reason.clone(),
                            }),
                        )?;
                    }
                    DispatchOutcome::Failed { reason, .. } => {
                        self.append_event(
                            correlation_id,
                            AuditEventPayload::Task(TaskEvent::Failed {
                                run_id,
                                task_id,
                                reason: reason.clone(),
                            }),
                        )?;
                    }
                    DispatchOutcome::Canceled { .. } => {
                        self.append_event(
                            correlation_id,
                            AuditEventPayload::Task(TaskEvent::Canceled {
                                run_id,
                                task_id,
                                reason: Some("task canceled".to_string()),
                            }),
                        )?;
                    }
                    DispatchOutcome::Deduplicated { source_task_id, .. } => {
                        self.append_event(
                            correlation_id,
                            AuditEventPayload::Task(TaskEvent::Succeeded {
                                run_id,
                                task_id,
                                message: Some("deduplicated by idempotency key".to_string()),
                                deduplicated_from: Some(*source_task_id),
                            }),
                        )?;
                    }
                    DispatchOutcome::Idle => {}
                }
            }

            if let Some(before) = preview_run_state {
                let after = self
                    .inner
                    .run_state(run_id)
                    .ok_or_else(|| OrchestratorError::NotFound(format!("run {}", run_id.0 .0)))?;
                self.emit_run_state_delta(run_id, correlation_id, before, after, &outcome)?;
            }
        }
        Ok(outcome)
    }

    pub fn cancel_run(&mut self, run_id: RunId) -> Result<bool, OrchestratorError> {
        let before = self.inner.run_state(run_id);
        let changed = self.inner.cancel_run(run_id)?;
        if !changed {
            return Ok(false);
        }
        let correlation_id = self.correlation_for_run_or_create(run_id);
        if let Some(from) = before {
            self.append_event(
                correlation_id,
                AuditEventPayload::Run(RunEvent::StateChanged {
                    run_id,
                    from,
                    to: RunState::Canceled,
                    reason: Some("operator requested cancellation".to_string()),
                }),
            )?;
        }
        if let Some(task_ids) = self.inner.run_task_ids(run_id) {
            for task_id in task_ids {
                if self.inner.task_state(task_id) == Some(TaskState::Canceled) {
                    self.append_event(
                        correlation_id,
                        AuditEventPayload::Task(TaskEvent::Canceled {
                            run_id,
                            task_id,
                            reason: Some("run canceled".to_string()),
                        }),
                    )?;
                }
            }
        }
        Ok(true)
    }

    pub fn cancel_task(&mut self, task_id: TaskId) -> Result<bool, OrchestratorError> {
        let run_id = self.inner.task_run_id(task_id)?;
        let run_before = self.inner.run_state(run_id);
        let changed = self.inner.cancel_task(task_id)?;
        if !changed {
            return Ok(false);
        }
        let correlation_id = self.correlation_for_run_or_create(run_id);
        self.append_event(
            correlation_id,
            AuditEventPayload::Task(TaskEvent::Canceled {
                run_id,
                task_id,
                reason: Some("operator requested task cancellation".to_string()),
            }),
        )?;
        let run_after = self
            .inner
            .run_state(run_id)
            .ok_or_else(|| OrchestratorError::NotFound(format!("run {}", run_id.0 .0)))?;
        if let Some(before) = run_before {
            if before != run_after {
                self.append_event(
                    correlation_id,
                    AuditEventPayload::Run(RunEvent::StateChanged {
                        run_id,
                        from: before,
                        to: run_after,
                        reason: Some("task cancellation changed run state".to_string()),
                    }),
                )?;
            }
        }
        Ok(true)
    }

    pub fn record_session_event(
        &mut self,
        event: SessionEvent,
        correlation_id: Option<CorrelationId>,
    ) -> Result<CorrelationId, OrchestratorError> {
        let effective = match (&event, correlation_id) {
            (
                SessionEvent::Opened {
                    run_id: Some(run_id),
                    ..
                },
                None,
            ) => self.correlation_for_run_or_create(*run_id),
            (_, Some(value)) => value,
            _ => CorrelationId::next(),
        };
        self.append_event(effective, AuditEventPayload::Session(event))?;
        Ok(effective)
    }

    pub fn record_module_event(
        &mut self,
        event: ModuleEvent,
        correlation_id: Option<CorrelationId>,
    ) -> Result<CorrelationId, OrchestratorError> {
        let effective = match (&event, correlation_id) {
            (ModuleEvent::Executed { run_id, .. }, None) => {
                self.correlation_for_run_or_create(*run_id)
            }
            (_, Some(value)) => value,
            _ => CorrelationId::next(),
        };
        self.append_event(effective, AuditEventPayload::Module(event))?;
        Ok(effective)
    }

    pub fn record_campaign_event(
        &mut self,
        payload: CampaignPayload,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(CorrelationId, u64), OrchestratorError> {
        let campaign_id = payload.campaign_id().clone();
        let effective = match (
            self.campaign_correlations.get(&campaign_id).copied(),
            correlation_id,
        ) {
            (Some(existing), Some(provided)) if existing != provided => {
                return Err(OrchestratorError::Validation(format!(
                    "campaign {} already bound to lineage {} but {} was provided",
                    campaign_id.as_str(),
                    existing.0 .0,
                    provided.0 .0
                )));
            }
            (Some(existing), _) => existing,
            (None, Some(provided)) => {
                self.campaign_correlations
                    .insert(campaign_id.clone(), provided);
                provided
            }
            (None, None) => {
                let generated = CorrelationId::next();
                self.campaign_correlations
                    .insert(campaign_id.clone(), generated);
                generated
            }
        };

        let sequence = *self
            .next_campaign_sequence
            .entry(campaign_id.clone())
            .or_insert(1);
        let occurred_at = now_secs();
        let event = CampaignAuditEvent {
            sequence,
            occurred_at,
            payload,
        };
        self.append_event(effective, AuditEventPayload::Campaign(event))?;
        self.next_campaign_sequence
            .insert(campaign_id, sequence.saturating_add(1));
        Ok((effective, sequence))
    }

    pub fn record_campaign_events<I>(
        &mut self,
        payloads: I,
        correlation_id: Option<CorrelationId>,
    ) -> Result<CorrelationId, OrchestratorError>
    where
        I: IntoIterator<Item = CampaignPayload>,
    {
        let payloads = payloads.into_iter().collect::<Vec<_>>();
        if payloads.is_empty() {
            return Err(OrchestratorError::Validation(
                "campaign payload batch cannot be empty".to_string(),
            ));
        }

        let campaign_id = payloads[0].campaign_id().clone();
        for payload in payloads.iter().skip(1) {
            if payload.campaign_id() != &campaign_id {
                return Err(OrchestratorError::Validation(
                    "all campaign payloads in a batch must belong to one campaign".to_string(),
                ));
            }
        }

        let mut effective = correlation_id;
        for payload in payloads {
            let (lineage, _sequence) = self.record_campaign_event(payload, effective)?;
            effective = Some(lineage);
        }
        Ok(effective.expect("non-empty payload batch must produce lineage"))
    }

    pub fn ingest_artifact_created(
        &mut self,
        campaign_id: CampaignId,
        objectives: &mut BTreeMap<ObjectiveId, Objective>,
        snapshot: &PredicateSnapshot,
        artifact_id: ArtifactId,
        correlation_id: Option<CorrelationId>,
    ) -> Result<ObjectiveIngestionDispatch, OrchestratorError> {
        let event = ObjectiveIngestionEvent::new(
            campaign_id,
            ObjectiveReevaluationTrigger::ArtifactCreated,
            &format!("artifact_created:{}", artifact_id.0 .0),
        )
        .map_err(|err| OrchestratorError::Validation(err.to_string()))?;
        self.ingest_campaign_trigger(event, objectives, snapshot, correlation_id)
    }

    pub fn ingest_finding_created(
        &mut self,
        campaign_id: CampaignId,
        objectives: &mut BTreeMap<ObjectiveId, Objective>,
        snapshot: &PredicateSnapshot,
        finding_id: FindingId,
        correlation_id: Option<CorrelationId>,
    ) -> Result<ObjectiveIngestionDispatch, OrchestratorError> {
        let event = ObjectiveIngestionEvent::new(
            campaign_id,
            ObjectiveReevaluationTrigger::FindingCreated,
            &format!("finding_created:{}", finding_id.0 .0),
        )
        .map_err(|err| OrchestratorError::Validation(err.to_string()))?;
        self.ingest_campaign_trigger(event, objectives, snapshot, correlation_id)
    }

    pub fn ingest_session_state_changed(
        &mut self,
        campaign_id: CampaignId,
        objectives: &mut BTreeMap<ObjectiveId, Objective>,
        snapshot: &PredicateSnapshot,
        session_id: SessionId,
        run_id: Option<RunId>,
        correlation_id: Option<CorrelationId>,
    ) -> Result<ObjectiveIngestionDispatch, OrchestratorError> {
        let propagated = correlation_id.or(run_id.and_then(|id| self.correlation_id_for_run(id)));
        let event = ObjectiveIngestionEvent::new(
            campaign_id,
            ObjectiveReevaluationTrigger::SessionStateChanged,
            &format!("session_state_changed:{}", session_id.0 .0),
        )
        .map_err(|err| OrchestratorError::Validation(err.to_string()))?;
        self.ingest_campaign_trigger(event, objectives, snapshot, propagated)
    }

    pub fn ingest_run_completed(
        &mut self,
        campaign_id: CampaignId,
        objectives: &mut BTreeMap<ObjectiveId, Objective>,
        snapshot: &PredicateSnapshot,
        run_id: RunId,
        correlation_id: Option<CorrelationId>,
    ) -> Result<ObjectiveIngestionDispatch, OrchestratorError> {
        let propagated = correlation_id.or(self.correlation_id_for_run(run_id));
        let event = ObjectiveIngestionEvent::new(
            campaign_id,
            ObjectiveReevaluationTrigger::RunCompleted,
            &format!("run_completed:{}", run_id.0 .0),
        )
        .map_err(|err| OrchestratorError::Validation(err.to_string()))?;
        self.ingest_campaign_trigger(event, objectives, snapshot, propagated)
    }

    pub fn load_audit_events(&mut self) -> Result<Vec<AuditEvent>, OrchestratorError> {
        self.audit_store.load_events()
    }

    pub fn correlation_id_for_run(&self, run_id: RunId) -> Option<CorrelationId> {
        self.run_correlations.get(&run_id).copied()
    }

    pub fn correlation_id_for_campaign(&self, campaign_id: &CampaignId) -> Option<CorrelationId> {
        self.campaign_correlations.get(campaign_id).copied()
    }

    fn ingest_campaign_trigger(
        &mut self,
        event: ObjectiveIngestionEvent,
        objectives: &mut BTreeMap<ObjectiveId, Objective>,
        snapshot: &PredicateSnapshot,
        correlation_id: Option<CorrelationId>,
    ) -> Result<ObjectiveIngestionDispatch, OrchestratorError> {
        if objectives
            .values()
            .any(|objective| objective.campaign_id != event.campaign_id)
        {
            return Err(OrchestratorError::Validation(
                "all objectives must belong to ingestion campaign".to_string(),
            ));
        }

        let dispatcher = self
            .campaign_ingestion_dispatchers
            .entry(event.campaign_id.clone())
            .or_default();
        let dispatch = dispatcher
            .dispatch(&event, objectives, snapshot, now_secs())
            .map_err(|err| OrchestratorError::Validation(err.to_string()))?;

        if dispatch.emitted_events.is_empty() {
            return Ok(dispatch);
        }

        let _ = self.record_campaign_events(dispatch.emitted_events.clone(), correlation_id)?;
        Ok(dispatch)
    }

    pub fn reconstruct_run_from_history(
        &mut self,
        run_id: RunId,
    ) -> Result<Option<ReconstructedRun>, OrchestratorError> {
        let events = self.audit_store.load_events()?;
        Ok(reconstruct_run_from_events(&events, run_id))
    }

    pub fn reconstruct_campaign_from_history(
        &mut self,
        campaign_id: &CampaignId,
    ) -> Result<CampaignReplayReport, OrchestratorError> {
        let events = self.audit_store.load_events()?;
        Ok(reconstruct_campaign_from_events(&events, campaign_id))
    }

    pub fn replay_campaign_consistency(
        &mut self,
        campaign_id: &CampaignId,
        snapshot: &ControlState,
    ) -> Result<CampaignReplayConsistency, OrchestratorError> {
        let report = self.reconstruct_campaign_from_history(campaign_id)?;
        let diagnostics = compare_campaign_replay_to_snapshot(&report, snapshot, campaign_id);
        let mut merged = report.diagnostics.clone();
        merged.extend(diagnostics);
        let consistent = merged.is_empty();
        Ok(CampaignReplayConsistency {
            report: CampaignReplayReport {
                campaign: report.campaign,
                diagnostics: merged,
            },
            consistent,
        })
    }

    pub fn run_state(&self, run_id: RunId) -> Option<RunState> {
        self.inner.run_state(run_id)
    }

    pub fn task_state(&self, task_id: TaskId) -> Option<TaskState> {
        self.inner.task_state(task_id)
    }

    pub fn task_attempt_count(&self, task_id: TaskId) -> Option<u32> {
        self.inner.task_attempt_count(task_id)
    }

    pub fn run_task_ids(&self, run_id: RunId) -> Option<Vec<TaskId>> {
        self.inner.run_task_ids(run_id)
    }

    pub fn pending_tasks(&self) -> usize {
        self.inner.pending_tasks()
    }

    pub fn idempotency_record(&self, key: &str) -> Option<&IdempotencyRecord> {
        self.inner.idempotency_record(key)
    }

    fn correlation_for_run_or_create(&mut self, run_id: RunId) -> CorrelationId {
        *self
            .run_correlations
            .entry(run_id)
            .or_insert_with(CorrelationId::next)
    }

    fn append_event(
        &mut self,
        correlation_id: CorrelationId,
        payload: AuditEventPayload,
    ) -> Result<(), OrchestratorError> {
        self.audit_store.append_event(&AuditEvent {
            id: EventId::next(),
            correlation_id,
            occurred_at: now_secs(),
            payload,
        })
    }

    fn emit_run_state_delta(
        &mut self,
        run_id: RunId,
        correlation_id: CorrelationId,
        before: RunState,
        after: RunState,
        outcome: &DispatchOutcome,
    ) -> Result<(), OrchestratorError> {
        if before == after {
            return Ok(());
        }

        if before == RunState::Queued && after.is_terminal() {
            self.append_event(
                correlation_id,
                AuditEventPayload::Run(RunEvent::StateChanged {
                    run_id,
                    from: RunState::Queued,
                    to: RunState::Running,
                    reason: None,
                }),
            )?;
            self.append_event(
                correlation_id,
                AuditEventPayload::Run(RunEvent::StateChanged {
                    run_id,
                    from: RunState::Running,
                    to: after,
                    reason: outcome_reason(outcome),
                }),
            )?;
            return Ok(());
        }

        self.append_event(
            correlation_id,
            AuditEventPayload::Run(RunEvent::StateChanged {
                run_id,
                from: before,
                to: after,
                reason: outcome_reason(outcome),
            }),
        )
    }
}

fn encode_snapshot(snapshot: &ExecutionSnapshot) -> String {
    let mut out = String::new();
    out.push_str(SNAPSHOT_HEADER);
    out.push('\n');

    for run in &snapshot.runs {
        let task_ids = run
            .task_order
            .iter()
            .map(|id| id.0 .0.to_string())
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(
            "run|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            run.run.id.0 .0,
            run.run.workspace_id.0 .0,
            run.run.module_version_id.0 .0,
            encode_opt_u64(run.run.target_id.map(|id| id.0 .0)),
            encode_hex(&run.run.requested_by),
            run_state_to_str(run.run.state),
            run.run.created_at,
            run.run.queued_at,
            encode_opt_u64(run.run.started_at),
            encode_opt_u64(run.run.finished_at),
            run.run.updated_at,
            encode_opt_string(run.run.error.as_deref()),
            task_ids
        ));
    }

    for task in &snapshot.tasks {
        out.push_str(&format!(
            "task|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            task.task.id.0 .0,
            task.task.run_id.0 .0,
            encode_hex(&task.task.name),
            task_state_to_str(task.task.state),
            task.task.attempt_count,
            task.task.max_attempts,
            task.task.created_at,
            task.task.queued_at,
            encode_opt_u64(task.task.started_at),
            encode_opt_u64(task.task.finished_at),
            task.task.updated_at,
            encode_opt_string(task.task.error.as_deref()),
            task.timeout_ms,
            encode_hex(&task.idempotency_key),
            if task.cancel_requested { 1 } else { 0 }
        ));
    }

    let queue = snapshot
        .queue
        .iter()
        .map(|id| id.0 .0.to_string())
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!("queue|{}\n", queue));

    for idem in &snapshot.idempotency {
        out.push_str(&format!(
            "idem|{}|{}|{}|{}|{}\n",
            encode_hex(&idem.key),
            idem.run_id.0 .0,
            idem.task_id.0 .0,
            encode_hex(&idem.message),
            idem.completed_at
        ));
    }

    out
}

fn decode_snapshot(input: &str) -> Result<ExecutionSnapshot, OrchestratorError> {
    let mut lines = input.lines();
    let Some(header) = lines.next() else {
        return Err(OrchestratorError::Parse("empty snapshot".to_string()));
    };
    if header != SNAPSHOT_HEADER {
        return Err(OrchestratorError::Parse(format!(
            "unsupported snapshot header '{}'",
            header
        )));
    }

    let mut runs = Vec::new();
    let mut tasks = Vec::new();
    let mut queue = Vec::new();
    let mut idempotency = Vec::new();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        match parts.first().copied().unwrap_or_default() {
            "run" => {
                if parts.len() != 14 {
                    return Err(OrchestratorError::Parse(format!(
                        "invalid run record '{}'",
                        line
                    )));
                }
                let run_id = RunId(Id(parse_u64(parts[1])?));
                let workspace_id = WorkspaceId(Id(parse_u64(parts[2])?));
                let module_version_id = ModuleVersionId(Id(parse_u64(parts[3])?));
                let target_id = parse_opt_u64(parts[4])?.map(|v| TargetId(Id(v)));
                let requested_by = decode_hex(parts[5])?;
                let state = parse_run_state(parts[6])?;
                let created_at = parse_u64(parts[7])?;
                let queued_at = parse_u64(parts[8])?;
                let started_at = parse_opt_u64(parts[9])?;
                let finished_at = parse_opt_u64(parts[10])?;
                let updated_at = parse_u64(parts[11])?;
                let error = decode_opt_string(parts[12])?;
                let task_order = parse_id_list(parts[13])?
                    .into_iter()
                    .map(|id| TaskId(Id(id)))
                    .collect::<Vec<_>>();

                runs.push(RunExecution {
                    run: Run {
                        id: run_id,
                        workspace_id,
                        module_version_id,
                        target_id,
                        requested_by,
                        state,
                        created_at,
                        queued_at,
                        started_at,
                        finished_at,
                        updated_at,
                        error,
                    },
                    task_order,
                });
            }
            "task" => {
                if parts.len() != 16 {
                    return Err(OrchestratorError::Parse(format!(
                        "invalid task record '{}'",
                        line
                    )));
                }
                let task_id = TaskId(Id(parse_u64(parts[1])?));
                let run_id = RunId(Id(parse_u64(parts[2])?));
                let name = decode_hex(parts[3])?;
                let state = parse_task_state(parts[4])?;
                let attempt_count = parse_u32(parts[5])?;
                let max_attempts = parse_u32(parts[6])?;
                let created_at = parse_u64(parts[7])?;
                let queued_at = parse_u64(parts[8])?;
                let started_at = parse_opt_u64(parts[9])?;
                let finished_at = parse_opt_u64(parts[10])?;
                let updated_at = parse_u64(parts[11])?;
                let error = decode_opt_string(parts[12])?;
                let timeout_ms = parse_u64(parts[13])?;
                let idempotency_key = decode_hex(parts[14])?;
                let cancel_requested = parse_u64(parts[15])? != 0;
                tasks.push(ScheduledTask {
                    task: Task {
                        id: task_id,
                        run_id,
                        name,
                        state,
                        attempt_count,
                        max_attempts,
                        created_at,
                        queued_at,
                        started_at,
                        finished_at,
                        updated_at,
                        error,
                    },
                    timeout_ms,
                    idempotency_key,
                    cancel_requested,
                });
            }
            "queue" => {
                if parts.len() != 2 {
                    return Err(OrchestratorError::Parse(format!(
                        "invalid queue record '{}'",
                        line
                    )));
                }
                queue = parse_id_list(parts[1])?
                    .into_iter()
                    .map(|id| TaskId(Id(id)))
                    .collect();
            }
            "idem" => {
                if parts.len() != 6 {
                    return Err(OrchestratorError::Parse(format!(
                        "invalid idempotency record '{}'",
                        line
                    )));
                }
                idempotency.push(IdempotencyRecord {
                    key: decode_hex(parts[1])?,
                    run_id: RunId(Id(parse_u64(parts[2])?)),
                    task_id: TaskId(Id(parse_u64(parts[3])?)),
                    message: decode_hex(parts[4])?,
                    completed_at: parse_u64(parts[5])?,
                });
            }
            other => {
                return Err(OrchestratorError::Parse(format!(
                    "unknown snapshot record '{}'",
                    other
                )));
            }
        }
    }

    Ok(ExecutionSnapshot {
        runs,
        tasks,
        queue,
        idempotency,
    })
}

fn encode_audit_event(event: &AuditEvent) -> String {
    let mut parts = vec![
        "event".to_string(),
        event.id.0 .0.to_string(),
        event.correlation_id.0 .0.to_string(),
        event.occurred_at.to_string(),
    ];

    match &event.payload {
        AuditEventPayload::Run(RunEvent::Submitted {
            run_id,
            workspace_id,
            module_version_id,
            target_id,
            requested_by,
        }) => {
            parts.push("run_submitted".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(workspace_id.0 .0.to_string());
            parts.push(module_version_id.0 .0.to_string());
            parts.push(encode_opt_u64(target_id.map(|id| id.0 .0)));
            parts.push(encode_hex(requested_by));
        }
        AuditEventPayload::Run(RunEvent::StateChanged {
            run_id,
            from,
            to,
            reason,
        }) => {
            parts.push("run_state_changed".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(run_state_to_str(*from).to_string());
            parts.push(run_state_to_str(*to).to_string());
            parts.push(encode_opt_string(reason.as_deref()));
        }
        AuditEventPayload::Task(TaskEvent::Created {
            run_id,
            task_id,
            name,
            max_attempts,
            timeout_ms,
            idempotency_key,
        }) => {
            parts.push("task_created".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(task_id.0 .0.to_string());
            parts.push(encode_hex(name));
            parts.push(max_attempts.to_string());
            parts.push(timeout_ms.to_string());
            parts.push(encode_hex(idempotency_key));
        }
        AuditEventPayload::Task(TaskEvent::Started {
            run_id,
            task_id,
            attempt,
        }) => {
            parts.push("task_started".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(task_id.0 .0.to_string());
            parts.push(attempt.to_string());
        }
        AuditEventPayload::Task(TaskEvent::Retried {
            run_id,
            task_id,
            attempt,
            reason,
        }) => {
            parts.push("task_retried".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(task_id.0 .0.to_string());
            parts.push(attempt.to_string());
            parts.push(encode_hex(reason));
        }
        AuditEventPayload::Task(TaskEvent::Succeeded {
            run_id,
            task_id,
            message,
            deduplicated_from,
        }) => {
            parts.push("task_succeeded".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(task_id.0 .0.to_string());
            parts.push(encode_opt_string(message.as_deref()));
            parts.push(encode_opt_u64(deduplicated_from.map(|id| id.0 .0)));
        }
        AuditEventPayload::Task(TaskEvent::Failed {
            run_id,
            task_id,
            reason,
        }) => {
            parts.push("task_failed".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(task_id.0 .0.to_string());
            parts.push(encode_hex(reason));
        }
        AuditEventPayload::Task(TaskEvent::Canceled {
            run_id,
            task_id,
            reason,
        }) => {
            parts.push("task_canceled".to_string());
            parts.push(run_id.0 .0.to_string());
            parts.push(task_id.0 .0.to_string());
            parts.push(encode_opt_string(reason.as_deref()));
        }
        AuditEventPayload::Session(SessionEvent::Opened {
            session_id,
            run_id,
            session_type,
            target,
        }) => {
            parts.push("session_opened".to_string());
            parts.push(session_id.0 .0.to_string());
            parts.push(encode_opt_u64(run_id.map(|id| id.0 .0)));
            parts.push(encode_hex(session_type));
            parts.push(encode_hex(target));
        }
        AuditEventPayload::Session(SessionEvent::Attached {
            session_id,
            operator,
        }) => {
            parts.push("session_attached".to_string());
            parts.push(session_id.0 .0.to_string());
            parts.push(encode_hex(operator));
        }
        AuditEventPayload::Session(SessionEvent::Detached {
            session_id,
            operator,
        }) => {
            parts.push("session_detached".to_string());
            parts.push(session_id.0 .0.to_string());
            parts.push(encode_hex(operator));
        }
        AuditEventPayload::Session(SessionEvent::Backgrounded { session_id }) => {
            parts.push("session_backgrounded".to_string());
            parts.push(session_id.0 .0.to_string());
        }
        AuditEventPayload::Session(SessionEvent::Closed { session_id, reason }) => {
            parts.push("session_closed".to_string());
            parts.push(session_id.0 .0.to_string());
            parts.push(encode_opt_string(reason.as_deref()));
        }
        AuditEventPayload::Session(SessionEvent::Reaped { session_id, reason }) => {
            parts.push("session_reaped".to_string());
            parts.push(session_id.0 .0.to_string());
            parts.push(encode_hex(reason));
        }
        AuditEventPayload::Module(ModuleEvent::Discovered {
            module_path,
            module_version_id,
        }) => {
            parts.push("module_discovered".to_string());
            parts.push(encode_hex(module_path));
            parts.push(encode_opt_u64(module_version_id.map(|id| id.0 .0)));
        }
        AuditEventPayload::Module(ModuleEvent::Validated {
            module_path,
            api_version,
        }) => {
            parts.push("module_validated".to_string());
            parts.push(encode_hex(module_path));
            parts.push(encode_hex(api_version));
        }
        AuditEventPayload::Module(ModuleEvent::ValidationFailed {
            module_path,
            reason,
        }) => {
            parts.push("module_validation_failed".to_string());
            parts.push(encode_hex(module_path));
            parts.push(encode_hex(reason));
        }
        AuditEventPayload::Module(ModuleEvent::Executed {
            module_path,
            run_id,
        }) => {
            parts.push("module_executed".to_string());
            parts.push(encode_hex(module_path));
            parts.push(run_id.0 .0.to_string());
        }
        AuditEventPayload::Campaign(event) => match &event.payload {
            CampaignPayload::CampaignCreated { campaign_id, name } => {
                parts.push("campaign_created".to_string());
                parts.push(event.sequence.to_string());
                parts.push(campaign_id.as_str().to_string());
                parts.push(encode_hex(name));
            }
            CampaignPayload::CampaignStatusChanged {
                campaign_id,
                from,
                to,
                reason,
            } => {
                parts.push("campaign_status_changed".to_string());
                parts.push(event.sequence.to_string());
                parts.push(campaign_id.as_str().to_string());
                parts.push(from.as_str().to_string());
                parts.push(to.as_str().to_string());
                parts.push(encode_opt_string(reason.as_deref()));
            }
            CampaignPayload::ObjectiveCreated {
                campaign_id,
                objective_id,
                name,
                risk_level,
            } => {
                parts.push("objective_created".to_string());
                parts.push(event.sequence.to_string());
                parts.push(campaign_id.as_str().to_string());
                parts.push(objective_id.as_str().to_string());
                parts.push(encode_hex(name));
                parts.push(risk_level.as_str().to_string());
            }
            CampaignPayload::ObjectivePrereqLinked {
                campaign_id,
                objective_id,
                prerequisite_id,
            } => {
                parts.push("objective_prereq_linked".to_string());
                parts.push(event.sequence.to_string());
                parts.push(campaign_id.as_str().to_string());
                parts.push(objective_id.as_str().to_string());
                parts.push(prerequisite_id.as_str().to_string());
            }
            CampaignPayload::ObjectiveStatusChanged {
                campaign_id,
                objective_id,
                from,
                to,
                reason,
            } => {
                parts.push("objective_status_changed".to_string());
                parts.push(event.sequence.to_string());
                parts.push(campaign_id.as_str().to_string());
                parts.push(objective_id.as_str().to_string());
                parts.push(from.as_str().to_string());
                parts.push(to.as_str().to_string());
                parts.push(encode_opt_string(reason.as_deref()));
            }
            CampaignPayload::ObjectiveEvaluated {
                campaign_id,
                objective_id,
                trigger,
                prerequisites_satisfied,
                success_criteria_satisfied,
                failure_criteria_satisfied,
                resulting_status,
            } => {
                parts.push("objective_evaluated".to_string());
                parts.push(event.sequence.to_string());
                parts.push(campaign_id.as_str().to_string());
                parts.push(objective_id.as_str().to_string());
                parts.push(trigger.as_str().to_string());
                parts.push(if *prerequisites_satisfied { "1" } else { "0" }.to_string());
                parts.push(
                    if *success_criteria_satisfied {
                        "1"
                    } else {
                        "0"
                    }
                    .to_string(),
                );
                parts.push(
                    if *failure_criteria_satisfied {
                        "1"
                    } else {
                        "0"
                    }
                    .to_string(),
                );
                parts.push(resulting_status.as_str().to_string());
            }
        },
    }
    parts.join("|")
}

fn decode_audit_log(input: &str) -> Result<Vec<AuditEvent>, OrchestratorError> {
    let mut lines = input.lines();
    let Some(header) = lines.next() else {
        return Err(OrchestratorError::Parse("empty audit log".to_string()));
    };
    if header != AUDIT_HEADER {
        return Err(OrchestratorError::Parse(format!(
            "unsupported audit header '{}'",
            header
        )));
    }

    let mut events = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        events.push(decode_audit_event(line)?);
    }
    Ok(events)
}

fn decode_audit_event(line: &str) -> Result<AuditEvent, OrchestratorError> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 5 || parts[0] != "event" {
        return Err(OrchestratorError::Parse(format!(
            "invalid audit event '{}'",
            line
        )));
    }
    let event_id = EventId(Id(parse_u64(parts[1])?));
    let correlation_id = CorrelationId(Id(parse_u64(parts[2])?));
    let occurred_at = parse_u64(parts[3])?;
    let event_kind = parts[4];
    let payload = match event_kind {
        "run_submitted" => {
            if parts.len() != 10 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid run_submitted event '{}'",
                    line
                )));
            }
            AuditEventPayload::Run(RunEvent::Submitted {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                workspace_id: WorkspaceId(Id(parse_u64(parts[6])?)),
                module_version_id: ModuleVersionId(Id(parse_u64(parts[7])?)),
                target_id: parse_opt_u64(parts[8])?.map(|id| TargetId(Id(id))),
                requested_by: decode_hex(parts[9])?,
            })
        }
        "run_state_changed" => {
            if parts.len() != 9 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid run_state_changed event '{}'",
                    line
                )));
            }
            AuditEventPayload::Run(RunEvent::StateChanged {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                from: parse_run_state(parts[6])?,
                to: parse_run_state(parts[7])?,
                reason: decode_opt_string(parts[8])?,
            })
        }
        "task_created" => {
            if parts.len() != 11 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid task_created event '{}'",
                    line
                )));
            }
            AuditEventPayload::Task(TaskEvent::Created {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                task_id: TaskId(Id(parse_u64(parts[6])?)),
                name: decode_hex(parts[7])?,
                max_attempts: parse_u32(parts[8])?,
                timeout_ms: parse_u64(parts[9])?,
                idempotency_key: decode_hex(parts[10])?,
            })
        }
        "task_started" => {
            if parts.len() != 8 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid task_started event '{}'",
                    line
                )));
            }
            AuditEventPayload::Task(TaskEvent::Started {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                task_id: TaskId(Id(parse_u64(parts[6])?)),
                attempt: parse_u32(parts[7])?,
            })
        }
        "task_retried" => {
            if parts.len() != 9 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid task_retried event '{}'",
                    line
                )));
            }
            AuditEventPayload::Task(TaskEvent::Retried {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                task_id: TaskId(Id(parse_u64(parts[6])?)),
                attempt: parse_u32(parts[7])?,
                reason: decode_hex(parts[8])?,
            })
        }
        "task_succeeded" => {
            if parts.len() != 9 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid task_succeeded event '{}'",
                    line
                )));
            }
            AuditEventPayload::Task(TaskEvent::Succeeded {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                task_id: TaskId(Id(parse_u64(parts[6])?)),
                message: decode_opt_string(parts[7])?,
                deduplicated_from: parse_opt_u64(parts[8])?.map(|id| TaskId(Id(id))),
            })
        }
        "task_failed" => {
            if parts.len() != 8 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid task_failed event '{}'",
                    line
                )));
            }
            AuditEventPayload::Task(TaskEvent::Failed {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                task_id: TaskId(Id(parse_u64(parts[6])?)),
                reason: decode_hex(parts[7])?,
            })
        }
        "task_canceled" => {
            if parts.len() != 8 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid task_canceled event '{}'",
                    line
                )));
            }
            AuditEventPayload::Task(TaskEvent::Canceled {
                run_id: RunId(Id(parse_u64(parts[5])?)),
                task_id: TaskId(Id(parse_u64(parts[6])?)),
                reason: decode_opt_string(parts[7])?,
            })
        }
        "session_opened" => {
            if parts.len() != 9 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid session_opened event '{}'",
                    line
                )));
            }
            AuditEventPayload::Session(SessionEvent::Opened {
                session_id: SessionId(Id(parse_u64(parts[5])?)),
                run_id: parse_opt_u64(parts[6])?.map(|id| RunId(Id(id))),
                session_type: decode_hex(parts[7])?,
                target: decode_hex(parts[8])?,
            })
        }
        "session_attached" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid session_attached event '{}'",
                    line
                )));
            }
            AuditEventPayload::Session(SessionEvent::Attached {
                session_id: SessionId(Id(parse_u64(parts[5])?)),
                operator: decode_hex(parts[6])?,
            })
        }
        "session_detached" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid session_detached event '{}'",
                    line
                )));
            }
            AuditEventPayload::Session(SessionEvent::Detached {
                session_id: SessionId(Id(parse_u64(parts[5])?)),
                operator: decode_hex(parts[6])?,
            })
        }
        "session_backgrounded" => {
            if parts.len() != 6 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid session_backgrounded event '{}'",
                    line
                )));
            }
            AuditEventPayload::Session(SessionEvent::Backgrounded {
                session_id: SessionId(Id(parse_u64(parts[5])?)),
            })
        }
        "session_closed" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid session_closed event '{}'",
                    line
                )));
            }
            AuditEventPayload::Session(SessionEvent::Closed {
                session_id: SessionId(Id(parse_u64(parts[5])?)),
                reason: decode_opt_string(parts[6])?,
            })
        }
        "session_reaped" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid session_reaped event '{}'",
                    line
                )));
            }
            AuditEventPayload::Session(SessionEvent::Reaped {
                session_id: SessionId(Id(parse_u64(parts[5])?)),
                reason: decode_hex(parts[6])?,
            })
        }
        "module_discovered" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid module_discovered event '{}'",
                    line
                )));
            }
            AuditEventPayload::Module(ModuleEvent::Discovered {
                module_path: decode_hex(parts[5])?,
                module_version_id: parse_opt_u64(parts[6])?.map(|id| ModuleVersionId(Id(id))),
            })
        }
        "module_validated" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid module_validated event '{}'",
                    line
                )));
            }
            AuditEventPayload::Module(ModuleEvent::Validated {
                module_path: decode_hex(parts[5])?,
                api_version: decode_hex(parts[6])?,
            })
        }
        "module_validation_failed" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid module_validation_failed event '{}'",
                    line
                )));
            }
            AuditEventPayload::Module(ModuleEvent::ValidationFailed {
                module_path: decode_hex(parts[5])?,
                reason: decode_hex(parts[6])?,
            })
        }
        "module_executed" => {
            if parts.len() != 7 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid module_executed event '{}'",
                    line
                )));
            }
            AuditEventPayload::Module(ModuleEvent::Executed {
                module_path: decode_hex(parts[5])?,
                run_id: RunId(Id(parse_u64(parts[6])?)),
            })
        }
        "campaign_created" => {
            if parts.len() != 8 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid campaign_created event '{}'",
                    line
                )));
            }
            AuditEventPayload::Campaign(CampaignAuditEvent {
                sequence: parse_u64(parts[5])?,
                occurred_at,
                payload: CampaignPayload::CampaignCreated {
                    campaign_id: parse_campaign_id(parts[6])?,
                    name: decode_hex(parts[7])?,
                },
            })
        }
        "campaign_status_changed" => {
            if parts.len() != 10 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid campaign_status_changed event '{}'",
                    line
                )));
            }
            AuditEventPayload::Campaign(CampaignAuditEvent {
                sequence: parse_u64(parts[5])?,
                occurred_at,
                payload: CampaignPayload::CampaignStatusChanged {
                    campaign_id: parse_campaign_id(parts[6])?,
                    from: parse_campaign_status(parts[7])?,
                    to: parse_campaign_status(parts[8])?,
                    reason: decode_opt_string(parts[9])?,
                },
            })
        }
        "objective_created" => {
            if parts.len() != 10 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid objective_created event '{}'",
                    line
                )));
            }
            AuditEventPayload::Campaign(CampaignAuditEvent {
                sequence: parse_u64(parts[5])?,
                occurred_at,
                payload: CampaignPayload::ObjectiveCreated {
                    campaign_id: parse_campaign_id(parts[6])?,
                    objective_id: parse_objective_id(parts[7])?,
                    name: decode_hex(parts[8])?,
                    risk_level: parse_risk_level(parts[9])?,
                },
            })
        }
        "objective_prereq_linked" => {
            if parts.len() != 9 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid objective_prereq_linked event '{}'",
                    line
                )));
            }
            AuditEventPayload::Campaign(CampaignAuditEvent {
                sequence: parse_u64(parts[5])?,
                occurred_at,
                payload: CampaignPayload::ObjectivePrereqLinked {
                    campaign_id: parse_campaign_id(parts[6])?,
                    objective_id: parse_objective_id(parts[7])?,
                    prerequisite_id: parse_objective_id(parts[8])?,
                },
            })
        }
        "objective_status_changed" => {
            if parts.len() != 11 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid objective_status_changed event '{}'",
                    line
                )));
            }
            AuditEventPayload::Campaign(CampaignAuditEvent {
                sequence: parse_u64(parts[5])?,
                occurred_at,
                payload: CampaignPayload::ObjectiveStatusChanged {
                    campaign_id: parse_campaign_id(parts[6])?,
                    objective_id: parse_objective_id(parts[7])?,
                    from: parse_objective_status(parts[8])?,
                    to: parse_objective_status(parts[9])?,
                    reason: decode_opt_string(parts[10])?,
                },
            })
        }
        "objective_evaluated" => {
            if parts.len() != 13 {
                return Err(OrchestratorError::Parse(format!(
                    "invalid objective_evaluated event '{}'",
                    line
                )));
            }
            AuditEventPayload::Campaign(CampaignAuditEvent {
                sequence: parse_u64(parts[5])?,
                occurred_at,
                payload: CampaignPayload::ObjectiveEvaluated {
                    campaign_id: parse_campaign_id(parts[6])?,
                    objective_id: parse_objective_id(parts[7])?,
                    trigger: parse_objective_trigger(parts[8])?,
                    prerequisites_satisfied: parse_bool_01(parts[9])?,
                    success_criteria_satisfied: parse_bool_01(parts[10])?,
                    failure_criteria_satisfied: parse_bool_01(parts[11])?,
                    resulting_status: parse_objective_status(parts[12])?,
                },
            })
        }
        _ => {
            return Err(OrchestratorError::Parse(format!(
                "unknown audit event kind '{}'",
                event_kind
            )));
        }
    };

    Ok(AuditEvent {
        id: event_id,
        correlation_id,
        occurred_at,
        payload,
    })
}

fn event_run_id(payload: &AuditEventPayload) -> Option<RunId> {
    match payload {
        AuditEventPayload::Run(RunEvent::Submitted { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Run(RunEvent::StateChanged { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Task(TaskEvent::Created { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Task(TaskEvent::Started { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Task(TaskEvent::Retried { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Task(TaskEvent::Succeeded { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Task(TaskEvent::Failed { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Task(TaskEvent::Canceled { run_id, .. }) => Some(*run_id),
        AuditEventPayload::Session(SessionEvent::Opened {
            run_id: Some(run_id),
            ..
        }) => Some(*run_id),
        AuditEventPayload::Module(ModuleEvent::Executed { run_id, .. }) => Some(*run_id),
        _ => None,
    }
}

fn event_campaign_meta(payload: &AuditEventPayload) -> Option<(CampaignId, u64)> {
    match payload {
        AuditEventPayload::Campaign(event) => {
            Some((event.payload.campaign_id().clone(), event.sequence))
        }
        _ => None,
    }
}

fn outcome_run_id(outcome: &DispatchOutcome) -> Option<RunId> {
    match outcome {
        DispatchOutcome::Succeeded { run_id, .. } => Some(*run_id),
        DispatchOutcome::Requeued { run_id, .. } => Some(*run_id),
        DispatchOutcome::Failed { run_id, .. } => Some(*run_id),
        DispatchOutcome::Canceled { run_id, .. } => Some(*run_id),
        DispatchOutcome::Deduplicated { run_id, .. } => Some(*run_id),
        DispatchOutcome::Idle => None,
    }
}

fn outcome_task_id(outcome: &DispatchOutcome) -> Option<TaskId> {
    match outcome {
        DispatchOutcome::Succeeded { task_id, .. } => Some(*task_id),
        DispatchOutcome::Requeued { task_id, .. } => Some(*task_id),
        DispatchOutcome::Failed { task_id, .. } => Some(*task_id),
        DispatchOutcome::Canceled { task_id, .. } => Some(*task_id),
        DispatchOutcome::Deduplicated { task_id, .. } => Some(*task_id),
        DispatchOutcome::Idle => None,
    }
}

fn outcome_reason(outcome: &DispatchOutcome) -> Option<String> {
    match outcome {
        DispatchOutcome::Requeued { reason, .. } => Some(reason.clone()),
        DispatchOutcome::Failed { reason, .. } => Some(reason.clone()),
        DispatchOutcome::Canceled { .. } => Some("task canceled".to_string()),
        _ => None,
    }
}

fn reconstruct_run_from_events(events: &[AuditEvent], run_id: RunId) -> Option<ReconstructedRun> {
    let mut reconstructed: Option<ReconstructedRun> = None;

    for event in events {
        match &event.payload {
            AuditEventPayload::Run(RunEvent::Submitted {
                run_id: event_run_id,
                workspace_id,
                module_version_id,
                target_id,
                requested_by,
            }) if *event_run_id == run_id => {
                reconstructed = Some(ReconstructedRun {
                    run_id,
                    correlation_id: event.correlation_id,
                    workspace_id: *workspace_id,
                    module_version_id: *module_version_id,
                    target_id: *target_id,
                    requested_by: requested_by.clone(),
                    state: RunState::Queued,
                    created_at: event.occurred_at,
                    started_at: None,
                    finished_at: None,
                    error: None,
                    tasks: BTreeMap::new(),
                });
            }
            AuditEventPayload::Run(RunEvent::StateChanged {
                run_id: event_run_id,
                to,
                reason,
                ..
            }) if *event_run_id == run_id => {
                let Some(run) = reconstructed.as_mut() else {
                    continue;
                };
                run.state = *to;
                if *to == RunState::Running && run.started_at.is_none() {
                    run.started_at = Some(event.occurred_at);
                }
                if to.is_terminal() {
                    if run.started_at.is_none() {
                        run.started_at = Some(event.occurred_at);
                    }
                    run.finished_at = Some(event.occurred_at);
                }
                if *to == RunState::Failed {
                    run.error = reason.clone();
                } else if *to == RunState::Succeeded {
                    run.error = None;
                }
            }
            AuditEventPayload::Task(TaskEvent::Created {
                run_id: event_run_id,
                task_id,
                name,
                max_attempts,
                timeout_ms,
                idempotency_key,
            }) if *event_run_id == run_id => {
                let Some(run) = reconstructed.as_mut() else {
                    continue;
                };
                run.tasks.insert(
                    *task_id,
                    ReconstructedTask {
                        task_id: *task_id,
                        name: name.clone(),
                        state: TaskState::Queued,
                        attempt_count: 0,
                        max_attempts: *max_attempts,
                        timeout_ms: *timeout_ms,
                        idempotency_key: idempotency_key.clone(),
                        error: None,
                        deduplicated_from: None,
                    },
                );
            }
            AuditEventPayload::Task(TaskEvent::Started {
                run_id: event_run_id,
                task_id,
                attempt,
            }) if *event_run_id == run_id => {
                let Some(run) = reconstructed.as_mut() else {
                    continue;
                };
                if let Some(task) = run.tasks.get_mut(task_id) {
                    task.state = TaskState::Running;
                    task.attempt_count = *attempt;
                    task.error = None;
                }
            }
            AuditEventPayload::Task(TaskEvent::Retried {
                run_id: event_run_id,
                task_id,
                attempt,
                reason,
            }) if *event_run_id == run_id => {
                let Some(run) = reconstructed.as_mut() else {
                    continue;
                };
                if let Some(task) = run.tasks.get_mut(task_id) {
                    task.state = TaskState::Queued;
                    task.attempt_count = *attempt;
                    task.error = Some(reason.clone());
                }
            }
            AuditEventPayload::Task(TaskEvent::Succeeded {
                run_id: event_run_id,
                task_id,
                deduplicated_from,
                ..
            }) if *event_run_id == run_id => {
                let Some(run) = reconstructed.as_mut() else {
                    continue;
                };
                if let Some(task) = run.tasks.get_mut(task_id) {
                    task.state = TaskState::Succeeded;
                    task.error = None;
                    task.deduplicated_from = *deduplicated_from;
                }
            }
            AuditEventPayload::Task(TaskEvent::Failed {
                run_id: event_run_id,
                task_id,
                reason,
            }) if *event_run_id == run_id => {
                let Some(run) = reconstructed.as_mut() else {
                    continue;
                };
                if let Some(task) = run.tasks.get_mut(task_id) {
                    task.state = TaskState::Failed;
                    task.error = Some(reason.clone());
                }
            }
            AuditEventPayload::Task(TaskEvent::Canceled {
                run_id: event_run_id,
                task_id,
                reason,
            }) if *event_run_id == run_id => {
                let Some(run) = reconstructed.as_mut() else {
                    continue;
                };
                if let Some(task) = run.tasks.get_mut(task_id) {
                    task.state = TaskState::Canceled;
                    task.error = reason.clone();
                }
            }
            _ => {}
        }
    }

    reconstructed
}

fn reconstruct_campaign_from_events(
    events: &[AuditEvent],
    campaign_id: &CampaignId,
) -> CampaignReplayReport {
    let mut diagnostics = Vec::<ReplayDiagnostic>::new();
    let mut reconstructed: Option<ReconstructedCampaign> = None;

    for event in events {
        let AuditEventPayload::Campaign(campaign_event) = &event.payload else {
            continue;
        };
        let payload_campaign_id = campaign_event.payload.campaign_id();
        if payload_campaign_id != campaign_id {
            continue;
        }

        let Some(campaign) = reconstructed.as_mut() else {
            reconstructed = Some(ReconstructedCampaign {
                campaign_id: campaign_id.clone(),
                correlation_id: event.correlation_id,
                sequence_high_watermark: 0,
                name: None,
                status: CampaignStatus::Active,
                objective_ids: BTreeSet::new(),
                objectives: BTreeMap::new(),
            });
            continue;
        };

        if campaign.correlation_id != event.correlation_id {
            diagnostics.push(ReplayDiagnostic {
                code: "ML-REPLAY-0001",
                message: format!(
                    "campaign {} has mixed lineage correlations {} and {}",
                    campaign_id.as_str(),
                    campaign.correlation_id.0 .0,
                    event.correlation_id.0 .0
                ),
            });
        }
    }

    for event in events {
        let AuditEventPayload::Campaign(campaign_event) = &event.payload else {
            continue;
        };
        let payload_campaign_id = campaign_event.payload.campaign_id();
        if payload_campaign_id != campaign_id {
            continue;
        }
        let Some(campaign) = reconstructed.as_mut() else {
            continue;
        };

        let expected_next = campaign.sequence_high_watermark.saturating_add(1);
        if campaign_event.sequence != expected_next {
            diagnostics.push(ReplayDiagnostic {
                code: "ML-REPLAY-0002",
                message: format!(
                    "campaign {} sequence mismatch: expected {}, found {}",
                    campaign_id.as_str(),
                    expected_next,
                    campaign_event.sequence
                ),
            });
        }
        campaign.sequence_high_watermark = campaign_event.sequence;

        match &campaign_event.payload {
            CampaignPayload::CampaignCreated { name, .. } => {
                if campaign.name.is_some() {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0003",
                        message: format!(
                            "campaign {} contains duplicate CampaignCreated event",
                            campaign_id.as_str()
                        ),
                    });
                }
                campaign.name = Some(name.clone());
                campaign.status = CampaignStatus::Active;
            }
            CampaignPayload::CampaignStatusChanged { from, to, .. } => {
                if campaign.status != *from {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0004",
                        message: format!(
                            "campaign {} status mismatch during replay: event from={} but current={}",
                            campaign_id.as_str(),
                            from.as_str(),
                            campaign.status.as_str()
                        ),
                    });
                }
                if !campaign.status.can_transition_to(*to) {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0005",
                        message: format!(
                            "campaign {} invalid transition during replay: {} -> {}",
                            campaign_id.as_str(),
                            campaign.status.as_str(),
                            to.as_str()
                        ),
                    });
                }
                campaign.status = *to;
            }
            CampaignPayload::ObjectiveCreated {
                objective_id,
                name,
                risk_level,
                ..
            } => {
                campaign.objective_ids.insert(objective_id.clone());
                let entry = campaign
                    .objectives
                    .entry(objective_id.clone())
                    .or_insert_with(|| ReplayedObjective {
                        objective_id: objective_id.clone(),
                        name: None,
                        risk_level: None,
                        status: ObjectiveStatus::Pending,
                        prerequisites: BTreeSet::new(),
                        evaluation_count: 0,
                    });
                entry.name = Some(name.clone());
                entry.risk_level = Some(*risk_level);
            }
            CampaignPayload::ObjectivePrereqLinked {
                objective_id,
                prerequisite_id,
                ..
            } => {
                campaign.objective_ids.insert(objective_id.clone());
                campaign.objective_ids.insert(prerequisite_id.clone());
                let entry = campaign
                    .objectives
                    .entry(objective_id.clone())
                    .or_insert_with(|| ReplayedObjective {
                        objective_id: objective_id.clone(),
                        name: None,
                        risk_level: None,
                        status: ObjectiveStatus::Pending,
                        prerequisites: BTreeSet::new(),
                        evaluation_count: 0,
                    });
                entry.prerequisites.insert(prerequisite_id.clone());
            }
            CampaignPayload::ObjectiveStatusChanged {
                objective_id,
                from,
                to,
                ..
            } => {
                let entry = campaign
                    .objectives
                    .entry(objective_id.clone())
                    .or_insert_with(|| ReplayedObjective {
                        objective_id: objective_id.clone(),
                        name: None,
                        risk_level: None,
                        status: ObjectiveStatus::Pending,
                        prerequisites: BTreeSet::new(),
                        evaluation_count: 0,
                    });
                if entry.status != *from {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0006",
                        message: format!(
                            "objective {} status mismatch during replay: event from={} current={}",
                            objective_id.as_str(),
                            from.as_str(),
                            entry.status.as_str()
                        ),
                    });
                }
                if !entry.status.can_transition_to(*to) {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0007",
                        message: format!(
                            "objective {} invalid transition during replay: {} -> {}",
                            objective_id.as_str(),
                            entry.status.as_str(),
                            to.as_str()
                        ),
                    });
                }
                entry.status = *to;
                campaign.objective_ids.insert(objective_id.clone());
            }
            CampaignPayload::ObjectiveEvaluated {
                objective_id,
                prerequisites_satisfied,
                success_criteria_satisfied,
                failure_criteria_satisfied,
                resulting_status,
                ..
            } => {
                let entry = campaign
                    .objectives
                    .entry(objective_id.clone())
                    .or_insert_with(|| ReplayedObjective {
                        objective_id: objective_id.clone(),
                        name: None,
                        risk_level: None,
                        status: ObjectiveStatus::Pending,
                        prerequisites: BTreeSet::new(),
                        evaluation_count: 0,
                    });
                entry.evaluation_count = entry.evaluation_count.saturating_add(1);

                if entry.status != *resulting_status {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0008",
                        message: format!(
                            "objective {} evaluated status mismatch: replay={} event={}",
                            objective_id.as_str(),
                            entry.status.as_str(),
                            resulting_status.as_str()
                        ),
                    });
                }
                if *resulting_status == ObjectiveStatus::Eligible && !*prerequisites_satisfied {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0009",
                        message: format!(
                            "objective {} marked eligible without prerequisite satisfaction",
                            objective_id.as_str()
                        ),
                    });
                }
                if *resulting_status == ObjectiveStatus::Achieved && !*success_criteria_satisfied {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0010",
                        message: format!(
                            "objective {} marked achieved without success criteria",
                            objective_id.as_str()
                        ),
                    });
                }
                if *resulting_status == ObjectiveStatus::Failed && !*failure_criteria_satisfied {
                    diagnostics.push(ReplayDiagnostic {
                        code: "ML-REPLAY-0011",
                        message: format!(
                            "objective {} marked failed without failure criteria",
                            objective_id.as_str()
                        ),
                    });
                }

                campaign.objective_ids.insert(objective_id.clone());
            }
        }
    }

    if reconstructed.is_none() {
        diagnostics.push(ReplayDiagnostic {
            code: "ML-REPLAY-0012",
            message: format!(
                "campaign {} not found in audit event history",
                campaign_id.as_str()
            ),
        });
    }

    CampaignReplayReport {
        campaign: reconstructed,
        diagnostics,
    }
}

fn compare_campaign_replay_to_snapshot(
    report: &CampaignReplayReport,
    snapshot: &ControlState,
    campaign_id: &CampaignId,
) -> Vec<ReplayDiagnostic> {
    let mut diagnostics = Vec::new();
    let Some(replayed) = report.campaign.as_ref() else {
        diagnostics.push(ReplayDiagnostic {
            code: "ML-REPLAY-0013",
            message: format!(
                "cannot compare snapshot for campaign {} because replay produced no campaign state",
                campaign_id.as_str()
            ),
        });
        return diagnostics;
    };

    let Some(snapshot_campaign) = snapshot.campaigns.get(campaign_id) else {
        diagnostics.push(ReplayDiagnostic {
            code: "ML-REPLAY-0014",
            message: format!(
                "snapshot missing campaign {} while replay produced one",
                campaign_id.as_str()
            ),
        });
        return diagnostics;
    };

    if replayed.status != snapshot_campaign.status {
        diagnostics.push(ReplayDiagnostic {
            code: "ML-REPLAY-0015",
            message: format!(
                "campaign {} status mismatch replay={} snapshot={}",
                campaign_id.as_str(),
                replayed.status.as_str(),
                snapshot_campaign.status.as_str()
            ),
        });
    }

    let snapshot_objective_ids = snapshot_campaign
        .objective_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if replayed.objective_ids != snapshot_objective_ids {
        diagnostics.push(ReplayDiagnostic {
            code: "ML-REPLAY-0016",
            message: format!(
                "campaign {} objective id set mismatch replay={} snapshot={}",
                campaign_id.as_str(),
                replayed.objective_ids.len(),
                snapshot_objective_ids.len()
            ),
        });
    }

    for objective_id in &replayed.objective_ids {
        let Some(snapshot_objective) = snapshot.objectives.get(objective_id) else {
            diagnostics.push(ReplayDiagnostic {
                code: "ML-REPLAY-0017",
                message: format!(
                    "snapshot missing objective {} present in replay for campaign {}",
                    objective_id.as_str(),
                    campaign_id.as_str()
                ),
            });
            continue;
        };
        if snapshot_objective.campaign_id != *campaign_id {
            diagnostics.push(ReplayDiagnostic {
                code: "ML-REPLAY-0018",
                message: format!(
                    "snapshot objective {} belongs to campaign {} instead of {}",
                    objective_id.as_str(),
                    snapshot_objective.campaign_id.as_str(),
                    campaign_id.as_str()
                ),
            });
        }
        let Some(replayed_objective) = replayed.objectives.get(objective_id) else {
            diagnostics.push(ReplayDiagnostic {
                code: "ML-REPLAY-0019",
                message: format!(
                    "replay missing objective {} listed in replay objective id set",
                    objective_id.as_str()
                ),
            });
            continue;
        };
        if replayed_objective.status != snapshot_objective.status {
            diagnostics.push(ReplayDiagnostic {
                code: "ML-REPLAY-0020",
                message: format!(
                    "objective {} status mismatch replay={} snapshot={}",
                    objective_id.as_str(),
                    replayed_objective.status.as_str(),
                    snapshot_objective.status.as_str()
                ),
            });
        }
    }

    for objective in snapshot.objectives.values() {
        if &objective.campaign_id != campaign_id {
            continue;
        }
        if !replayed.objective_ids.contains(&objective.id) {
            diagnostics.push(ReplayDiagnostic {
                code: "ML-REPLAY-0021",
                message: format!(
                    "snapshot objective {} for campaign {} missing from replay",
                    objective.id.as_str(),
                    campaign_id.as_str()
                ),
            });
        }
    }

    diagnostics
}

fn parse_u64(input: &str) -> Result<u64, OrchestratorError> {
    input
        .parse::<u64>()
        .map_err(|_| OrchestratorError::Parse(format!("invalid u64 '{}'", input)))
}

fn parse_u32(input: &str) -> Result<u32, OrchestratorError> {
    input
        .parse::<u32>()
        .map_err(|_| OrchestratorError::Parse(format!("invalid u32 '{}'", input)))
}

fn parse_opt_u64(input: &str) -> Result<Option<u64>, OrchestratorError> {
    if input == "-" {
        return Ok(None);
    }
    parse_u64(input).map(Some)
}

fn parse_id_list(input: &str) -> Result<Vec<u64>, OrchestratorError> {
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    input
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(parse_u64)
        .collect()
}

fn encode_opt_u64(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn encode_opt_string(value: Option<&str>) -> String {
    value.map(encode_hex).unwrap_or_else(|| "-".to_string())
}

fn decode_opt_string(value: &str) -> Result<Option<String>, OrchestratorError> {
    if value == "-" {
        return Ok(None);
    }
    decode_hex(value).map(Some)
}

fn encode_hex(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input.as_bytes() {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn decode_hex(input: &str) -> Result<String, OrchestratorError> {
    if input.len() % 2 != 0 {
        return Err(OrchestratorError::Parse("invalid hex length".to_string()));
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    let data = input.as_bytes();
    let mut i = 0;
    while i < data.len() {
        let hi = hex_to_nibble(data[i])?;
        let lo = hex_to_nibble(data[i + 1])?;
        bytes.push((hi << 4) | lo);
        i += 2;
    }
    String::from_utf8(bytes)
        .map_err(|_| OrchestratorError::Parse("invalid utf-8 in hex".to_string()))
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn hex_to_nibble(value: u8) -> Result<u8, OrchestratorError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(OrchestratorError::Parse(
            "invalid hex character".to_string(),
        )),
    }
}

fn run_state_to_str(state: RunState) -> &'static str {
    state.as_str()
}

fn parse_run_state(state: &str) -> Result<RunState, OrchestratorError> {
    match state {
        "queued" => Ok(RunState::Queued),
        "running" => Ok(RunState::Running),
        "succeeded" => Ok(RunState::Succeeded),
        "failed" => Ok(RunState::Failed),
        "canceled" => Ok(RunState::Canceled),
        _ => Err(OrchestratorError::Parse(format!(
            "invalid run state '{}'",
            state
        ))),
    }
}

fn task_state_to_str(state: TaskState) -> &'static str {
    state.as_str()
}

fn parse_task_state(state: &str) -> Result<TaskState, OrchestratorError> {
    match state {
        "queued" => Ok(TaskState::Queued),
        "running" => Ok(TaskState::Running),
        "retrying" => Ok(TaskState::Retrying),
        "succeeded" => Ok(TaskState::Succeeded),
        "failed" => Ok(TaskState::Failed),
        "canceled" => Ok(TaskState::Canceled),
        _ => Err(OrchestratorError::Parse(format!(
            "invalid task state '{}'",
            state
        ))),
    }
}

fn parse_bool_01(input: &str) -> Result<bool, OrchestratorError> {
    match input {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(OrchestratorError::Parse(format!(
            "invalid boolean flag '{}' (expected 0 or 1)",
            input
        ))),
    }
}

fn parse_campaign_id(input: &str) -> Result<CampaignId, OrchestratorError> {
    CampaignId::parse(input).map_err(|err| {
        OrchestratorError::Parse(format!("invalid campaign id '{}': {}", input, err))
    })
}

fn parse_objective_id(input: &str) -> Result<ObjectiveId, OrchestratorError> {
    ObjectiveId::parse(input).map_err(|err| {
        OrchestratorError::Parse(format!("invalid objective id '{}': {}", input, err))
    })
}

fn parse_campaign_status(input: &str) -> Result<CampaignStatus, OrchestratorError> {
    match input {
        "active" => Ok(CampaignStatus::Active),
        "paused" => Ok(CampaignStatus::Paused),
        "completed" => Ok(CampaignStatus::Completed),
        "failed" => Ok(CampaignStatus::Failed),
        _ => Err(OrchestratorError::Parse(format!(
            "invalid campaign status '{}'",
            input
        ))),
    }
}

fn parse_objective_status(input: &str) -> Result<ObjectiveStatus, OrchestratorError> {
    match input {
        "pending" => Ok(ObjectiveStatus::Pending),
        "eligible" => Ok(ObjectiveStatus::Eligible),
        "in_progress" => Ok(ObjectiveStatus::InProgress),
        "achieved" => Ok(ObjectiveStatus::Achieved),
        "failed" => Ok(ObjectiveStatus::Failed),
        _ => Err(OrchestratorError::Parse(format!(
            "invalid objective status '{}'",
            input
        ))),
    }
}

fn parse_risk_level(input: &str) -> Result<RiskLevel, OrchestratorError> {
    match input {
        "low" => Ok(RiskLevel::Low),
        "medium" => Ok(RiskLevel::Medium),
        "high" => Ok(RiskLevel::High),
        _ => Err(OrchestratorError::Parse(format!(
            "invalid risk level '{}'",
            input
        ))),
    }
}

fn parse_objective_trigger(input: &str) -> Result<ObjectiveReevaluationTrigger, OrchestratorError> {
    match input {
        "artifact_created" => Ok(ObjectiveReevaluationTrigger::ArtifactCreated),
        "finding_created" => Ok(ObjectiveReevaluationTrigger::FindingCreated),
        "session_state_changed" => Ok(ObjectiveReevaluationTrigger::SessionStateChanged),
        "run_completed" => Ok(ObjectiveReevaluationTrigger::RunCompleted),
        "replay_recovery" => Ok(ObjectiveReevaluationTrigger::ReplayRecovery),
        "manual_request" => Ok(ObjectiveReevaluationTrigger::ManualRequest),
        _ => Err(OrchestratorError::Parse(format!(
            "invalid objective trigger '{}'",
            input
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::campaign::Predicate as CampaignPredicate;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Behavior {
        AlwaysSuccess,
        RetryOnce,
        TimeoutOnce,
    }

    #[derive(Debug, Default)]
    struct DeterministicExecutor {
        behavior: BTreeMap<String, Behavior>,
        calls_by_key: BTreeMap<String, u32>,
        side_effects_by_key: BTreeMap<String, u32>,
        observed_keys: Vec<String>,
    }

    impl DeterministicExecutor {
        fn with_behavior(mut self, key: &str, behavior: Behavior) -> Self {
            self.behavior.insert(key.to_string(), behavior);
            self
        }
    }

    impl TaskExecutor for DeterministicExecutor {
        fn execute(
            &mut self,
            context: &TaskExecutionContext,
        ) -> Result<TaskExecutionReport, OrchestratorError> {
            self.observed_keys.push(context.idempotency_key.clone());
            let attempts = self
                .calls_by_key
                .entry(context.idempotency_key.clone())
                .or_insert(0);
            *attempts += 1;

            // Simulate idempotent side effects at the executor boundary:
            // first call for key applies effect, retries for same key do not.
            self.side_effects_by_key
                .entry(context.idempotency_key.clone())
                .or_insert(1);

            let behavior = self
                .behavior
                .get(&context.idempotency_key)
                .copied()
                .unwrap_or(Behavior::AlwaysSuccess);

            let report = match behavior {
                Behavior::AlwaysSuccess => TaskExecutionReport {
                    elapsed_ms: 1,
                    outcome: TaskExecutionOutcome::Success {
                        message: "ok".to_string(),
                    },
                },
                Behavior::RetryOnce => {
                    if *attempts == 1 {
                        TaskExecutionReport {
                            elapsed_ms: 1,
                            outcome: TaskExecutionOutcome::RetryableError {
                                message: "temporary failure".to_string(),
                            },
                        }
                    } else {
                        TaskExecutionReport {
                            elapsed_ms: 1,
                            outcome: TaskExecutionOutcome::Success {
                                message: "ok-after-retry".to_string(),
                            },
                        }
                    }
                }
                Behavior::TimeoutOnce => {
                    if *attempts == 1 {
                        TaskExecutionReport {
                            elapsed_ms: context.timeout_ms + 10,
                            outcome: TaskExecutionOutcome::Success {
                                message: "late-success".to_string(),
                            },
                        }
                    } else {
                        TaskExecutionReport {
                            elapsed_ms: 1,
                            outcome: TaskExecutionOutcome::Success {
                                message: "ok-after-timeout".to_string(),
                            },
                        }
                    }
                }
            };
            Ok(report)
        }
    }

    fn basic_request() -> RunRequest {
        RunRequest::new(
            WorkspaceId::next(),
            ModuleVersionId::next(),
            Some(TargetId::next()),
            "operator",
        )
        .expect("request")
    }

    #[test]
    fn planner_and_dispatcher_follow_deterministic_lifecycle() {
        let store = InMemorySnapshotStore::default();
        let mut orchestrator = ExecutionOrchestrator::new(store).expect("new");
        let planner = StaticRunPlanner::new(
            RunPlan::new(vec![
                PlannedTask::new("task-1", 2, 1000, "k1").expect("t1"),
                PlannedTask::new("task-2", 2, 1000, "k2").expect("t2"),
            ])
            .expect("plan"),
        );
        let run_id = orchestrator
            .submit_with_planner(basic_request(), &planner)
            .expect("submit");
        assert_eq!(orchestrator.run_state(run_id), Some(RunState::Queued));

        let mut executor = DeterministicExecutor::default();
        let first = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(first, DispatchOutcome::Succeeded { .. }));
        assert_eq!(orchestrator.run_state(run_id), Some(RunState::Running));

        let second = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(second, DispatchOutcome::Succeeded { .. }));
        assert_eq!(orchestrator.run_state(run_id), Some(RunState::Succeeded));

        let idle = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert_eq!(idle, DispatchOutcome::Idle);
    }

    #[test]
    fn timeout_and_retry_semantics_are_enforced() {
        let store = InMemorySnapshotStore::default();
        let mut orchestrator = ExecutionOrchestrator::new(store).expect("new");
        let run_id = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("timeout-task", 2, 5, "timeout-key").expect("planned")
                ])
                .expect("plan"),
            )
            .expect("submit");
        let task_id = orchestrator.run_task_ids(run_id).expect("tasks")[0];

        let mut executor =
            DeterministicExecutor::default().with_behavior("timeout-key", Behavior::TimeoutOnce);
        let first = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(first, DispatchOutcome::Requeued { .. }));
        assert_eq!(orchestrator.task_state(task_id), Some(TaskState::Queued));
        assert_eq!(orchestrator.task_attempt_count(task_id), Some(1));

        let second = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(second, DispatchOutcome::Succeeded { .. }));
        assert_eq!(orchestrator.run_state(run_id), Some(RunState::Succeeded));
        assert_eq!(orchestrator.task_attempt_count(task_id), Some(2));
    }

    #[test]
    fn cancel_semantics_are_deterministic() {
        let store = InMemorySnapshotStore::default();
        let mut orchestrator = ExecutionOrchestrator::new(store).expect("new");
        let run_id = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("a", 2, 100, "cancel-a").expect("a"),
                    PlannedTask::new("b", 2, 100, "cancel-b").expect("b"),
                ])
                .expect("plan"),
            )
            .expect("submit");

        assert!(orchestrator.cancel_run(run_id).expect("cancel"));
        assert_eq!(orchestrator.run_state(run_id), Some(RunState::Canceled));
        for task_id in orchestrator.run_task_ids(run_id).expect("tasks") {
            assert_eq!(orchestrator.task_state(task_id), Some(TaskState::Canceled));
        }

        let mut executor = DeterministicExecutor::default();
        assert_eq!(
            orchestrator.dispatch_next(&mut executor).expect("dispatch"),
            DispatchOutcome::Idle
        );
    }

    #[test]
    fn idempotency_deduplicates_across_runs() {
        let store = InMemorySnapshotStore::default();
        let mut orchestrator = ExecutionOrchestrator::new(store).expect("new");
        let mut executor = DeterministicExecutor::default();

        let run_1 = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("seed", 2, 100, "shared-key").expect("seed")
                ])
                .expect("plan"),
            )
            .expect("submit");
        let first = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(first, DispatchOutcome::Succeeded { .. }));
        assert_eq!(orchestrator.run_state(run_1), Some(RunState::Succeeded));
        assert_eq!(executor.calls_by_key.get("shared-key"), Some(&1));

        let run_2 = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("dedup", 2, 100, "shared-key").expect("dedup")
                ])
                .expect("plan"),
            )
            .expect("submit");
        let second = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(second, DispatchOutcome::Deduplicated { .. }));
        assert_eq!(orchestrator.run_state(run_2), Some(RunState::Succeeded));
        assert_eq!(executor.calls_by_key.get("shared-key"), Some(&1));
    }

    #[test]
    fn restart_recovery_requeues_inflight_tasks() {
        let now = now_secs();
        let run_id = RunId(Id(500));
        let task_id = TaskId(Id(600));
        let workspace_id = WorkspaceId(Id(700));
        let module_version_id = ModuleVersionId(Id(800));
        let snapshot = ExecutionSnapshot {
            runs: vec![RunExecution {
                run: Run {
                    id: run_id,
                    workspace_id,
                    module_version_id,
                    target_id: None,
                    requested_by: "operator".to_string(),
                    state: RunState::Running,
                    created_at: now,
                    queued_at: now,
                    started_at: Some(now),
                    finished_at: None,
                    updated_at: now,
                    error: None,
                },
                task_order: vec![task_id],
            }],
            tasks: vec![ScheduledTask {
                task: Task {
                    id: task_id,
                    run_id,
                    name: "recovered".to_string(),
                    state: TaskState::Running,
                    attempt_count: 1,
                    max_attempts: 3,
                    created_at: now,
                    queued_at: now,
                    started_at: Some(now),
                    finished_at: None,
                    updated_at: now,
                    error: None,
                },
                timeout_ms: 100,
                idempotency_key: "recovered-key".to_string(),
                cancel_requested: false,
            }],
            queue: Vec::new(),
            idempotency: Vec::new(),
        };

        let encoded = encode_snapshot(&snapshot);
        let shared = Arc::new(Mutex::new(Some(encoded)));
        let store = InMemorySnapshotStore::from_shared(Arc::clone(&shared));
        let mut orchestrator = ExecutionOrchestrator::new(store).expect("new");

        assert_eq!(orchestrator.task_state(task_id), Some(TaskState::Queued));
        let mut executor = DeterministicExecutor::default();
        let outcome = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(outcome, DispatchOutcome::Succeeded { .. }));
        assert_eq!(orchestrator.run_state(run_id), Some(RunState::Succeeded));
    }

    #[test]
    fn retries_do_not_duplicate_side_effects_beyond_idempotency_contract() {
        let store = InMemorySnapshotStore::default();
        let mut orchestrator = ExecutionOrchestrator::new(store).expect("new");
        let run_id = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("retry", 2, 100, "retry-key").expect("retry")
                ])
                .expect("plan"),
            )
            .expect("submit");
        let mut executor =
            DeterministicExecutor::default().with_behavior("retry-key", Behavior::RetryOnce);

        let first = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(first, DispatchOutcome::Requeued { .. }));
        let second = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(second, DispatchOutcome::Succeeded { .. }));
        assert_eq!(orchestrator.run_state(run_id), Some(RunState::Succeeded));

        let observed = executor
            .observed_keys
            .iter()
            .filter(|k| k.as_str() == "retry-key")
            .count();
        assert_eq!(
            observed, 2,
            "expected two attempts with same idempotency key"
        );
        assert_eq!(
            executor.side_effects_by_key.get("retry-key"),
            Some(&1),
            "executor side effect should occur once for same idempotency key"
        );
    }

    #[test]
    fn queue_pressure_rejects_new_runs_beyond_limit() {
        let store = InMemorySnapshotStore::default();
        let mut orchestrator = ExecutionOrchestrator::with_limits(
            store,
            OrchestratorLimits {
                max_pending_tasks: 1,
            },
        )
        .expect("new");

        orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![PlannedTask::new("first", 1, 100, "k1").expect("task")])
                    .expect("plan"),
            )
            .expect("submit first");

        let err = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![PlannedTask::new("second", 1, 100, "k2").expect("task")])
                    .expect("plan"),
            )
            .expect_err("queue limit should reject second run");
        assert!(
            err.to_string().contains("queue pressure exceeded"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn observable_orchestrator_emits_typed_events_with_shared_correlation_id() {
        let snapshot_store = InMemorySnapshotStore::default();
        let audit_store = InMemoryAuditLogStore::default();
        let mut orchestrator =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");

        let run_id = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("evt", 2, 100, "evt-key").expect("task")
                ])
                .expect("plan"),
            )
            .expect("submit");
        let mut executor = DeterministicExecutor::default();
        let outcome = orchestrator.dispatch_next(&mut executor).expect("dispatch");
        assert!(matches!(outcome, DispatchOutcome::Succeeded { .. }));

        let events = orchestrator.load_audit_events().expect("events");
        assert_eq!(events.len(), 6, "expected deterministic audit event count");

        let run_correlation = events
            .iter()
            .find_map(|event| match &event.payload {
                AuditEventPayload::Run(RunEvent::Submitted {
                    run_id: event_run_id,
                    ..
                }) if *event_run_id == run_id => Some(event.correlation_id),
                _ => None,
            })
            .expect("run submitted event correlation");

        for event in &events {
            match &event.payload {
                AuditEventPayload::Run(RunEvent::Submitted {
                    run_id: event_run_id,
                    ..
                })
                | AuditEventPayload::Run(RunEvent::StateChanged {
                    run_id: event_run_id,
                    ..
                }) if *event_run_id == run_id => {
                    assert_eq!(event.correlation_id, run_correlation);
                }
                AuditEventPayload::Task(TaskEvent::Created {
                    run_id: event_run_id,
                    ..
                })
                | AuditEventPayload::Task(TaskEvent::Started {
                    run_id: event_run_id,
                    ..
                })
                | AuditEventPayload::Task(TaskEvent::Retried {
                    run_id: event_run_id,
                    ..
                })
                | AuditEventPayload::Task(TaskEvent::Succeeded {
                    run_id: event_run_id,
                    ..
                })
                | AuditEventPayload::Task(TaskEvent::Failed {
                    run_id: event_run_id,
                    ..
                })
                | AuditEventPayload::Task(TaskEvent::Canceled {
                    run_id: event_run_id,
                    ..
                }) if *event_run_id == run_id => {
                    assert_eq!(event.correlation_id, run_correlation);
                }
                _ => {}
            }
        }

        let reconstructed = orchestrator
            .reconstruct_run_from_history(run_id)
            .expect("reconstruct")
            .expect("run");
        assert_eq!(reconstructed.state, RunState::Succeeded);
        assert_eq!(reconstructed.tasks.len(), 1);
        let task = reconstructed.tasks.values().next().expect("task");
        assert_eq!(task.state, TaskState::Succeeded);
    }

    #[test]
    fn audit_file_store_is_append_only_and_replayable() {
        let path = std::env::temp_dir().join(format!("moonlight-audit-{}.log", Id::next().0));
        let mut store = FileAuditLogStore::new(&path);
        let event_a = AuditEvent {
            id: EventId::next(),
            correlation_id: CorrelationId::next(),
            occurred_at: now_secs(),
            payload: AuditEventPayload::Module(ModuleEvent::Discovered {
                module_path: "exploit/linux/test".to_string(),
                module_version_id: None,
            }),
        };
        let event_b = AuditEvent {
            id: EventId::next(),
            correlation_id: CorrelationId::next(),
            occurred_at: now_secs(),
            payload: AuditEventPayload::Session(SessionEvent::Backgrounded {
                session_id: SessionId::next(),
            }),
        };

        store.append_event(&event_a).expect("append-a");
        store.append_event(&event_b).expect("append-b");

        let raw = std::fs::read_to_string(&path).expect("raw");
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines[0], AUDIT_HEADER);
        assert_eq!(lines.len(), 3, "header + two appended events");

        let events = store.load_events().expect("load");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload, event_a.payload);
        assert_eq!(events[1].payload, event_b.payload);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn run_reconstruction_works_after_restart_from_event_history() {
        let snapshot_shared = Arc::new(Mutex::new(None));
        let audit_shared = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));

        let run_id = {
            let snapshot_store = InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared));
            let audit_store = InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared));
            let mut orchestrator =
                ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");
            let run_id = orchestrator
                .submit_run(
                    basic_request(),
                    RunPlan::new(vec![
                        PlannedTask::new("retry", 2, 100, "restart-retry").expect("task")
                    ])
                    .expect("plan"),
                )
                .expect("submit");
            let mut executor = DeterministicExecutor::default()
                .with_behavior("restart-retry", Behavior::RetryOnce);
            let first = orchestrator
                .dispatch_next(&mut executor)
                .expect("dispatch-1");
            assert!(matches!(first, DispatchOutcome::Requeued { .. }));
            let second = orchestrator
                .dispatch_next(&mut executor)
                .expect("dispatch-2");
            assert!(matches!(second, DispatchOutcome::Succeeded { .. }));
            run_id
        };

        let snapshot_store = InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared));
        let audit_store = InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared));
        let mut recovered =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("recover");
        let run = recovered
            .reconstruct_run_from_history(run_id)
            .expect("reconstruct")
            .expect("run");
        assert_eq!(run.state, RunState::Succeeded);
        let task = run.tasks.values().next().expect("task");
        assert_eq!(task.attempt_count, 2);
        assert_eq!(task.state, TaskState::Succeeded);
    }

    #[test]
    fn session_and_module_events_reuse_run_correlation_when_available() {
        let snapshot_store = InMemorySnapshotStore::default();
        let audit_store = InMemoryAuditLogStore::default();
        let mut orchestrator =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");

        let run_id = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("evt", 1, 100, "corr-key").expect("task")
                ])
                .expect("plan"),
            )
            .expect("submit");
        let run_correlation = orchestrator
            .correlation_id_for_run(run_id)
            .expect("run correlation");

        let session_corr = orchestrator
            .record_session_event(
                SessionEvent::Opened {
                    session_id: SessionId::next(),
                    run_id: Some(run_id),
                    session_type: "telnet/new-environ".to_string(),
                    target: "target:23".to_string(),
                },
                None,
            )
            .expect("session event");
        assert_eq!(session_corr, run_correlation);

        let module_corr = orchestrator
            .record_module_event(
                ModuleEvent::Executed {
                    module_path: "exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass"
                        .to_string(),
                    run_id,
                },
                None,
            )
            .expect("module event");
        assert_eq!(module_corr, run_correlation);
    }

    #[test]
    fn campaign_events_use_single_lineage_and_gapless_sequence() {
        let snapshot_shared = Arc::new(Mutex::new(None));
        let audit_shared = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_a =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective a");
        let objective_b =
            ObjectiveId::parse("9b2f4d6a-3aa4-41ba-91ed-6308a58186a1").expect("objective b");

        let first_lineage = {
            let snapshot_store = InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared));
            let audit_store = InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared));
            let mut orchestrator =
                ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");

            let (lineage, seq1) = orchestrator
                .record_campaign_event(
                    CampaignPayload::CampaignCreated {
                        campaign_id: campaign_id.clone(),
                        name: "operation".to_string(),
                    },
                    None,
                )
                .expect("campaign create");
            assert_eq!(seq1, 1);

            let (lineage2, seq2) = orchestrator
                .record_campaign_event(
                    CampaignPayload::ObjectiveCreated {
                        campaign_id: campaign_id.clone(),
                        objective_id: objective_a.clone(),
                        name: "initial access".to_string(),
                        risk_level: RiskLevel::Medium,
                    },
                    None,
                )
                .expect("objective create");
            assert_eq!(lineage2, lineage);
            assert_eq!(seq2, 2);

            let (lineage3, seq3) = orchestrator
                .record_campaign_event(
                    CampaignPayload::ObjectivePrereqLinked {
                        campaign_id: campaign_id.clone(),
                        objective_id: objective_b.clone(),
                        prerequisite_id: objective_a.clone(),
                    },
                    None,
                )
                .expect("prereq link");
            assert_eq!(lineage3, lineage);
            assert_eq!(seq3, 3);

            let explicit_mismatch = CorrelationId::next();
            let err = orchestrator
                .record_campaign_event(
                    CampaignPayload::CampaignStatusChanged {
                        campaign_id: campaign_id.clone(),
                        from: CampaignStatus::Active,
                        to: CampaignStatus::Paused,
                        reason: None,
                    },
                    Some(explicit_mismatch),
                )
                .expect_err("lineage mismatch must fail");
            assert!(
                err.to_string().contains("already bound to lineage"),
                "unexpected error: {err}"
            );

            lineage
        };

        let snapshot_store = InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared));
        let audit_store = InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared));
        let mut recovered =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("recover");
        let (lineage_after_restart, seq4) = recovered
            .record_campaign_event(
                CampaignPayload::ObjectiveStatusChanged {
                    campaign_id: campaign_id.clone(),
                    objective_id: objective_a,
                    from: ObjectiveStatus::Eligible,
                    to: ObjectiveStatus::InProgress,
                    reason: Some("operator start".to_string()),
                },
                None,
            )
            .expect("status change");
        assert_eq!(lineage_after_restart, first_lineage);
        assert_eq!(seq4, 4);

        let events = recovered.load_audit_events().expect("events");
        let campaign_events = events
            .iter()
            .filter_map(|event| match &event.payload {
                AuditEventPayload::Campaign(campaign_event) => {
                    Some((event.correlation_id, campaign_event.sequence))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(campaign_events.len(), 4);
        for (idx, (correlation, sequence)) in campaign_events.iter().enumerate() {
            assert_eq!(*correlation, first_lineage);
            assert_eq!(*sequence, (idx as u64) + 1);
        }
    }

    #[test]
    fn campaign_events_round_trip_in_file_audit_log() {
        let path =
            std::env::temp_dir().join(format!("moonlight-campaign-audit-{}.log", Id::next().0));
        let mut store = FileAuditLogStore::new(&path);
        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_id =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective");

        let event = AuditEvent {
            id: EventId::next(),
            correlation_id: CorrelationId::next(),
            occurred_at: now_secs(),
            payload: AuditEventPayload::Campaign(CampaignAuditEvent {
                sequence: 7,
                occurred_at: now_secs(),
                payload: CampaignPayload::ObjectiveEvaluated {
                    campaign_id,
                    objective_id,
                    trigger: ObjectiveReevaluationTrigger::RunCompleted,
                    prerequisites_satisfied: true,
                    success_criteria_satisfied: true,
                    failure_criteria_satisfied: false,
                    resulting_status: ObjectiveStatus::Achieved,
                },
            }),
        };

        store.append_event(&event).expect("append");
        let loaded = store.load_events().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].payload, event.payload);
        assert_eq!(loaded[0].correlation_id, event.correlation_id);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ingestion_run_completed_propagates_correlation_and_deduplicates() {
        let snapshot_store = InMemorySnapshotStore::default();
        let audit_store = InMemoryAuditLogStore::default();
        let mut orchestrator =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");

        let run_id = orchestrator
            .submit_run(
                basic_request(),
                RunPlan::new(vec![
                    PlannedTask::new("evt", 1, 100, "ingest-run").expect("task")
                ])
                .expect("plan"),
            )
            .expect("submit");
        let run_correlation = orchestrator
            .correlation_id_for_run(run_id)
            .expect("run correlation");

        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_id =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective id");
        let mut objective = Objective::new_at(
            objective_id.clone(),
            campaign_id.clone(),
            "run objective",
            "run completion should satisfy",
            vec![],
            vec![CampaignPredicate::RunSucceeded {
                module_name: "exploit/linux/example".to_string(),
            }],
            vec![],
            RiskLevel::Medium,
            None,
            1,
        )
        .expect("objective");
        objective.status = ObjectiveStatus::InProgress;
        let mut objectives = BTreeMap::from([(objective_id, objective)]);

        let workspace = crate::domain::Workspace::new_at("ws", "test", 1).expect("workspace");
        let module = crate::domain::ModuleVersion::new_at(
            "exploit/linux/example",
            "1.0.0",
            1,
            "entrypoint",
            "sha256",
            1,
        )
        .expect("module");
        let mut run =
            crate::domain::Run::new_at(workspace.id, module.id, None, "operator", 2).expect("run");
        run.transition_state(RunState::Running, 3).expect("running");
        run.transition_state(RunState::Succeeded, 4)
            .expect("succeeded");
        let snapshot = PredicateSnapshot::new().with_run(
            crate::campaign::RunSnapshot::new(run, "exploit/linux/example").expect("run snapshot"),
        );

        let first = orchestrator
            .ingest_run_completed(
                campaign_id.clone(),
                &mut objectives,
                &snapshot,
                run_id,
                None,
            )
            .expect("first ingestion");
        assert!(!first.skipped_duplicate);
        assert!(!first.emitted_events.is_empty());
        assert_eq!(
            orchestrator.correlation_id_for_campaign(&campaign_id),
            Some(run_correlation)
        );

        let second = orchestrator
            .ingest_run_completed(
                campaign_id.clone(),
                &mut objectives,
                &snapshot,
                run_id,
                None,
            )
            .expect("duplicate ingestion");
        assert!(second.skipped_duplicate);
        assert!(second.emitted_events.is_empty());

        let campaign_event_count = orchestrator
            .load_audit_events()
            .expect("events")
            .into_iter()
            .filter(|event| matches!(event.payload, AuditEventPayload::Campaign(_)))
            .count();
        assert_eq!(campaign_event_count, first.emitted_events.len());
        assert_eq!(
            objectives.values().next().expect("objective").status,
            ObjectiveStatus::Achieved
        );
    }

    #[test]
    fn ingestion_artifact_finding_session_triggers_evaluate_relevant_objectives() {
        let snapshot_store = InMemorySnapshotStore::default();
        let audit_store = InMemoryAuditLogStore::default();
        let mut orchestrator =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");

        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_artifact =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective");
        let objective_finding =
            ObjectiveId::parse("9b2f4d6a-3aa4-41ba-91ed-6308a58186a1").expect("objective");
        let objective_session =
            ObjectiveId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("objective");

        let mut obj_a = Objective::new_at(
            objective_artifact.clone(),
            campaign_id.clone(),
            "artifact objective",
            "artifact trigger",
            vec![],
            vec![CampaignPredicate::ArtifactTagMatch {
                tag: "loot".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            1,
        )
        .expect("objective");
        obj_a.status = ObjectiveStatus::InProgress;

        let mut obj_b = Objective::new_at(
            objective_finding.clone(),
            campaign_id.clone(),
            "finding objective",
            "finding trigger",
            vec![],
            vec![CampaignPredicate::FindingExists {
                finding_type: "credential".to_string(),
            }],
            vec![],
            RiskLevel::Low,
            None,
            1,
        )
        .expect("objective");
        obj_b.status = ObjectiveStatus::InProgress;

        let mut obj_c = Objective::new_at(
            objective_session.clone(),
            campaign_id.clone(),
            "session objective",
            "session trigger",
            vec![],
            vec![CampaignPredicate::SessionPrivilege {
                level: crate::campaign::SessionPrivilegeLevel::Root,
            }],
            vec![],
            RiskLevel::Low,
            None,
            1,
        )
        .expect("objective");
        obj_c.status = ObjectiveStatus::InProgress;

        let mut objectives = BTreeMap::from([
            (objective_artifact.clone(), obj_a),
            (objective_finding.clone(), obj_b),
            (objective_session.clone(), obj_c),
        ]);

        let workspace = crate::domain::Workspace::new_at("ws", "test", 1).expect("workspace");
        let module = crate::domain::ModuleVersion::new_at(
            "exploit/linux/example",
            "1.0.0",
            1,
            "entrypoint",
            "sha256",
            1,
        )
        .expect("module");
        let run =
            crate::domain::Run::new_at(workspace.id, module.id, None, "operator", 2).expect("run");
        let session = crate::domain::Session::new_at(run.id, None, "shell", "127.0.0.1:23", 3)
            .expect("session");
        let artifact = crate::domain::Artifact::new_at(
            run.id,
            None,
            Some(session.id),
            crate::domain::ArtifactKind::CommandOutput,
            "loot",
            "memory://loot",
            4,
        )
        .expect("artifact");
        let finding = crate::domain::Finding::new_at(
            run.id,
            None,
            Some(session.id),
            "Credential",
            "found secret",
            crate::domain::FindingSeverity::High,
            5,
        )
        .expect("finding");

        let snapshot = PredicateSnapshot::new()
            .with_artifact(crate::campaign::ArtifactSnapshot::new(artifact).with_tag("loot"))
            .with_finding(
                crate::campaign::FindingSnapshot::new(finding, "credential").expect("snapshot"),
            )
            .with_session(
                crate::campaign::SessionSnapshot::new(session)
                    .with_privilege(crate::campaign::SessionPrivilegeLevel::Root),
            );

        orchestrator
            .ingest_artifact_created(
                campaign_id.clone(),
                &mut objectives,
                &snapshot,
                ArtifactId::next(),
                None,
            )
            .expect("artifact trigger");
        orchestrator
            .ingest_finding_created(
                campaign_id.clone(),
                &mut objectives,
                &snapshot,
                FindingId::next(),
                None,
            )
            .expect("finding trigger");
        orchestrator
            .ingest_session_state_changed(
                campaign_id.clone(),
                &mut objectives,
                &snapshot,
                SessionId::next(),
                None,
                None,
            )
            .expect("session trigger");

        assert_eq!(
            objectives[&objective_artifact].status,
            ObjectiveStatus::Achieved
        );
        assert_eq!(
            objectives[&objective_finding].status,
            ObjectiveStatus::Achieved
        );
        assert_eq!(
            objectives[&objective_session].status,
            ObjectiveStatus::Achieved
        );
    }

    #[test]
    fn campaign_cold_replay_reconstructs_identical_objective_outcomes() {
        let snapshot_shared = Arc::new(Mutex::new(None));
        let audit_shared = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_id =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective id");

        {
            let snapshot_store = InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared));
            let audit_store = InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared));
            let mut orchestrator =
                ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");

            orchestrator
                .record_campaign_events(
                    vec![
                        CampaignPayload::CampaignCreated {
                            campaign_id: campaign_id.clone(),
                            name: "operation".to_string(),
                        },
                        CampaignPayload::ObjectiveCreated {
                            campaign_id: campaign_id.clone(),
                            objective_id: objective_id.clone(),
                            name: "escalate".to_string(),
                            risk_level: RiskLevel::High,
                        },
                        CampaignPayload::ObjectiveStatusChanged {
                            campaign_id: campaign_id.clone(),
                            objective_id: objective_id.clone(),
                            from: ObjectiveStatus::Pending,
                            to: ObjectiveStatus::Eligible,
                            reason: Some("prerequisites".to_string()),
                        },
                        CampaignPayload::ObjectiveStatusChanged {
                            campaign_id: campaign_id.clone(),
                            objective_id: objective_id.clone(),
                            from: ObjectiveStatus::Eligible,
                            to: ObjectiveStatus::InProgress,
                            reason: Some("operator start".to_string()),
                        },
                        CampaignPayload::ObjectiveStatusChanged {
                            campaign_id: campaign_id.clone(),
                            objective_id: objective_id.clone(),
                            from: ObjectiveStatus::InProgress,
                            to: ObjectiveStatus::Achieved,
                            reason: Some("criteria met".to_string()),
                        },
                        CampaignPayload::ObjectiveEvaluated {
                            campaign_id: campaign_id.clone(),
                            objective_id: objective_id.clone(),
                            trigger: ObjectiveReevaluationTrigger::RunCompleted,
                            prerequisites_satisfied: true,
                            success_criteria_satisfied: true,
                            failure_criteria_satisfied: false,
                            resulting_status: ObjectiveStatus::Achieved,
                        },
                    ],
                    None,
                )
                .expect("record campaign events");

            let report = orchestrator
                .reconstruct_campaign_from_history(&campaign_id)
                .expect("replay");
            assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
            let campaign = report.campaign.expect("campaign");
            assert_eq!(campaign.objective_ids.len(), 1);
            assert_eq!(
                campaign
                    .objectives
                    .get(&objective_id)
                    .expect("objective")
                    .status,
                ObjectiveStatus::Achieved
            );
        }

        let snapshot_store = InMemorySnapshotStore::from_shared(Arc::clone(&snapshot_shared));
        let audit_store = InMemoryAuditLogStore::from_shared(Arc::clone(&audit_shared));
        let mut recovered =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("recover");
        let replay = recovered
            .reconstruct_campaign_from_history(&campaign_id)
            .expect("replay");
        assert!(replay.diagnostics.is_empty(), "{:?}", replay.diagnostics);
        let campaign = replay.campaign.expect("campaign");
        assert_eq!(
            campaign
                .objectives
                .get(&objective_id)
                .expect("objective")
                .status,
            ObjectiveStatus::Achieved
        );
    }

    #[test]
    fn campaign_replay_consistency_reports_snapshot_mismatches() {
        let snapshot_store = InMemorySnapshotStore::default();
        let audit_store = InMemoryAuditLogStore::default();
        let mut orchestrator =
            ObservableExecutionOrchestrator::new(snapshot_store, audit_store).expect("new");

        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_id =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective id");

        orchestrator
            .record_campaign_events(
                vec![
                    CampaignPayload::CampaignCreated {
                        campaign_id: campaign_id.clone(),
                        name: "operation".to_string(),
                    },
                    CampaignPayload::ObjectiveCreated {
                        campaign_id: campaign_id.clone(),
                        objective_id: objective_id.clone(),
                        name: "escalate".to_string(),
                        risk_level: RiskLevel::High,
                    },
                    CampaignPayload::ObjectiveEvaluated {
                        campaign_id: campaign_id.clone(),
                        objective_id: objective_id.clone(),
                        trigger: ObjectiveReevaluationTrigger::ManualRequest,
                        prerequisites_satisfied: true,
                        success_criteria_satisfied: false,
                        failure_criteria_satisfied: false,
                        resulting_status: ObjectiveStatus::Pending,
                    },
                ],
                None,
            )
            .expect("record events");

        let mut snapshot = ControlState::default();
        let mut campaign =
            crate::campaign::Campaign::new_at(campaign_id.clone(), "operation", "", 1, None)
                .expect("campaign");
        campaign.add_objective(objective_id.clone());
        let mut objective = crate::campaign::Objective::new_at(
            objective_id,
            campaign_id.clone(),
            "escalate",
            "",
            vec![],
            vec![crate::campaign::Predicate::RunSucceeded {
                module_name: "exploit/linux/example".to_string(),
            }],
            vec![],
            RiskLevel::High,
            None,
            1,
        )
        .expect("objective");
        objective.status = ObjectiveStatus::Failed;
        snapshot.campaigns.insert(campaign_id.clone(), campaign);
        snapshot
            .objectives
            .insert(objective.id.clone(), objective.clone());

        let consistency = orchestrator
            .replay_campaign_consistency(&campaign_id, &snapshot)
            .expect("consistency");
        assert!(!consistency.consistent);
        assert!(consistency
            .report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "ML-REPLAY-0020"));
    }

    #[test]
    fn campaign_replay_emits_diagnostics_for_invalid_event_sequences() {
        let mut store = InMemoryAuditLogStore::default();
        let campaign_id =
            CampaignId::parse("de305d54-75b4-431b-adb2-eb6b9e546014").expect("campaign id");
        let objective_id =
            ObjectiveId::parse("0f8fad5b-d9cb-469f-a165-70867728950e").expect("objective id");
        let correlation = CorrelationId::next();

        store
            .append_event(&AuditEvent {
                id: EventId::next(),
                correlation_id: correlation,
                occurred_at: now_secs(),
                payload: AuditEventPayload::Campaign(CampaignAuditEvent {
                    sequence: 1,
                    occurred_at: now_secs(),
                    payload: CampaignPayload::CampaignCreated {
                        campaign_id: campaign_id.clone(),
                        name: "operation".to_string(),
                    },
                }),
            })
            .expect("append 1");
        store
            .append_event(&AuditEvent {
                id: EventId::next(),
                correlation_id: CorrelationId::next(),
                occurred_at: now_secs(),
                payload: AuditEventPayload::Campaign(CampaignAuditEvent {
                    sequence: 3,
                    occurred_at: now_secs(),
                    payload: CampaignPayload::ObjectiveEvaluated {
                        campaign_id: campaign_id.clone(),
                        objective_id,
                        trigger: ObjectiveReevaluationTrigger::ManualRequest,
                        prerequisites_satisfied: false,
                        success_criteria_satisfied: false,
                        failure_criteria_satisfied: false,
                        resulting_status: ObjectiveStatus::Achieved,
                    },
                }),
            })
            .expect("append 2");

        let snapshot_store = InMemorySnapshotStore::default();
        let mut orchestrator =
            ObservableExecutionOrchestrator::new(snapshot_store, store).expect("new");
        let report = orchestrator
            .reconstruct_campaign_from_history(&campaign_id)
            .expect("replay");
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "ML-REPLAY-0001"));
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "ML-REPLAY-0002"));
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "ML-REPLAY-0010"));
    }
}
