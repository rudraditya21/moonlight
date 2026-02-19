use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::domain::{
    DomainError, ModuleVersionId, Run, RunId, RunState, TargetId, Task, TaskId, TaskState,
    WorkspaceId,
};
use crate::ids::Id;
use crate::time::now_secs;

const SNAPSHOT_HEADER: &str = "moonlight-orchestrator:v1";

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

pub trait SnapshotStore {
    fn load_snapshot(&mut self) -> Result<Option<String>, OrchestratorError>;
    fn save_snapshot(&mut self, snapshot: &str) -> Result<(), OrchestratorError>;
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

pub struct ExecutionOrchestrator<S: SnapshotStore> {
    store: S,
    runs: BTreeMap<RunId, RunExecution>,
    tasks: BTreeMap<TaskId, ScheduledTask>,
    queue: VecDeque<TaskId>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
}

impl<S: SnapshotStore> ExecutionOrchestrator<S> {
    pub fn new(store: S) -> Result<Self, OrchestratorError> {
        let mut this = Self {
            store,
            runs: BTreeMap::new(),
            tasks: BTreeMap::new(),
            queue: VecDeque::new(),
            idempotency: BTreeMap::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
