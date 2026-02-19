use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::domain::{
    Artifact, ArtifactId, ArtifactKind, ArtifactState, CorrelationId, DomainError, ModuleVersionId,
    Run, RunId, RunState, Session, SessionId, SessionState, TargetId, Task, TaskId, TaskState,
    WorkspaceId,
};
use crate::ids::Id;
use crate::time::now_secs;

const CONTROL_STATE_HEADER: &str = "moonlight-control-state:v1";
const CONTROL_COMMIT_LOG_HEADER: &str = "moonlight-control-commit-log:v1";

#[derive(Debug)]
pub enum ControlStateError {
    Domain(DomainError),
    Validation(String),
    NotFound(String),
    Storage(String),
    Parse(String),
}

impl fmt::Display for ControlStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlStateError::Domain(err) => write!(f, "{err}"),
            ControlStateError::Validation(msg) => write!(f, "validation error: {msg}"),
            ControlStateError::NotFound(msg) => write!(f, "not found: {msg}"),
            ControlStateError::Storage(msg) => write!(f, "storage error: {msg}"),
            ControlStateError::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for ControlStateError {}

impl From<DomainError> for ControlStateError {
    fn from(value: DomainError) -> Self {
        ControlStateError::Domain(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlState {
    pub runs: BTreeMap<RunId, Run>,
    pub tasks: BTreeMap<TaskId, Task>,
    pub sessions: BTreeMap<SessionId, Session>,
    pub artifacts: BTreeMap<ArtifactId, Artifact>,
    pub applied_transactions: BTreeSet<u64>,
}

impl ControlState {
    pub fn tasks_for_run(&self, run_id: RunId) -> Vec<&Task> {
        self.tasks
            .values()
            .filter(|task| task.run_id == run_id)
            .collect()
    }

    pub fn sessions_for_run(&self, run_id: RunId) -> Vec<&Session> {
        self.sessions
            .values()
            .filter(|session| session.run_id == run_id)
            .collect()
    }

    pub fn artifacts_for_run(&self, run_id: RunId) -> Vec<&Artifact> {
        self.artifacts
            .values()
            .filter(|artifact| artifact.run_id == run_id)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMutation {
    UpsertRun(Run),
    UpsertTask(Task),
    UpsertSession(Session),
    UpsertArtifact(Artifact),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlTransaction {
    pub id: u64,
    pub correlation_id: Option<CorrelationId>,
    pub occurred_at: u64,
    pub mutations: Vec<ControlMutation>,
}

impl ControlTransaction {
    pub fn new(
        mutations: Vec<ControlMutation>,
        correlation_id: Option<CorrelationId>,
        occurred_at: u64,
    ) -> Result<Self, ControlStateError> {
        if mutations.is_empty() {
            return Err(ControlStateError::Validation(
                "transaction must contain at least one mutation".to_string(),
            ));
        }
        Ok(Self {
            id: Id::next().0,
            correlation_id,
            occurred_at,
            mutations,
        })
    }

    fn apply_to_state(&self, state: &mut ControlState) -> Result<(), ControlStateError> {
        if state.applied_transactions.contains(&self.id) {
            return Ok(());
        }

        let mut candidate = state.clone();
        for mutation in &self.mutations {
            apply_mutation(&mut candidate, mutation)?;
        }
        candidate.applied_transactions.insert(self.id);
        *state = candidate;
        Ok(())
    }
}

fn apply_mutation(
    state: &mut ControlState,
    mutation: &ControlMutation,
) -> Result<(), ControlStateError> {
    match mutation {
        ControlMutation::UpsertRun(run) => {
            state.runs.insert(run.id, run.clone());
        }
        ControlMutation::UpsertTask(task) => {
            if !state.runs.contains_key(&task.run_id) {
                return Err(ControlStateError::Validation(format!(
                    "task {} references missing run {}",
                    task.id.0 .0, task.run_id.0 .0
                )));
            }
            state.tasks.insert(task.id, task.clone());
        }
        ControlMutation::UpsertSession(session) => {
            if !state.runs.contains_key(&session.run_id) {
                return Err(ControlStateError::Validation(format!(
                    "session {} references missing run {}",
                    session.id.0 .0, session.run_id.0 .0
                )));
            }
            if let Some(task_id) = session.task_id {
                let task = state.tasks.get(&task_id).ok_or_else(|| {
                    ControlStateError::Validation(format!(
                        "session {} references missing task {}",
                        session.id.0 .0, task_id.0 .0
                    ))
                })?;
                if task.run_id != session.run_id {
                    return Err(ControlStateError::Validation(format!(
                        "session {} task {} belongs to run {} but session run is {}",
                        session.id.0 .0, task_id.0 .0, task.run_id.0 .0, session.run_id.0 .0
                    )));
                }
            }
            state.sessions.insert(session.id, session.clone());
        }
        ControlMutation::UpsertArtifact(artifact) => {
            if !state.runs.contains_key(&artifact.run_id) {
                return Err(ControlStateError::Validation(format!(
                    "artifact {} references missing run {}",
                    artifact.id.0 .0, artifact.run_id.0 .0
                )));
            }
            if let Some(task_id) = artifact.task_id {
                let task = state.tasks.get(&task_id).ok_or_else(|| {
                    ControlStateError::Validation(format!(
                        "artifact {} references missing task {}",
                        artifact.id.0 .0, task_id.0 .0
                    ))
                })?;
                if task.run_id != artifact.run_id {
                    return Err(ControlStateError::Validation(format!(
                        "artifact {} task {} belongs to run {} but artifact run is {}",
                        artifact.id.0 .0, task_id.0 .0, task.run_id.0 .0, artifact.run_id.0 .0
                    )));
                }
            }
            if let Some(session_id) = artifact.session_id {
                let session = state.sessions.get(&session_id).ok_or_else(|| {
                    ControlStateError::Validation(format!(
                        "artifact {} references missing session {}",
                        artifact.id.0 .0, session_id.0 .0
                    ))
                })?;
                if session.run_id != artifact.run_id {
                    return Err(ControlStateError::Validation(format!(
                        "artifact {} session {} belongs to run {} but artifact run is {}",
                        artifact.id.0 .0,
                        session_id.0 .0,
                        session.run_id.0 .0,
                        artifact.run_id.0 .0
                    )));
                }
                if let Some(task_id) = artifact.task_id {
                    if session.task_id != Some(task_id) {
                        return Err(ControlStateError::Validation(format!(
                            "artifact {} has task {} but session {} task is {:?}",
                            artifact.id.0 .0,
                            task_id.0 .0,
                            session_id.0 .0,
                            session.task_id.map(|id| id.0 .0)
                        )));
                    }
                }
            }
            state.artifacts.insert(artifact.id, artifact.clone());
        }
    }
    Ok(())
}

pub trait TransactionalStateStore {
    fn load_state(&mut self) -> Result<ControlState, ControlStateError>;
    fn apply_transaction(&mut self, tx: &ControlTransaction) -> Result<(), ControlStateError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryTransactionalStateStore {
    state: ControlState,
    journal: Vec<ControlTransaction>,
}

impl InMemoryTransactionalStateStore {
    pub fn journal(&self) -> &[ControlTransaction] {
        &self.journal
    }
}

impl TransactionalStateStore for InMemoryTransactionalStateStore {
    fn load_state(&mut self) -> Result<ControlState, ControlStateError> {
        Ok(self.state.clone())
    }

    fn apply_transaction(&mut self, tx: &ControlTransaction) -> Result<(), ControlStateError> {
        let mut candidate = self.state.clone();
        tx.apply_to_state(&mut candidate)?;
        self.state = candidate;
        self.journal.push(tx.clone());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FileTransactionalStateStore {
    path: PathBuf,
    state: ControlState,
}

impl FileTransactionalStateStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, ControlStateError> {
        let path = path.as_ref().to_path_buf();
        let state = load_commit_log(&path)?;
        Ok(Self { path, state })
    }

    fn append_commit(
        &self,
        tx: &ControlTransaction,
        state: &ControlState,
    ) -> Result<(), ControlStateError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ControlStateError::Storage(e.to_string()))?;
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| ControlStateError::Storage(e.to_string()))?;

        if file
            .metadata()
            .map_err(|e| ControlStateError::Storage(e.to_string()))?
            .len()
            == 0
        {
            file.write_all(CONTROL_COMMIT_LOG_HEADER.as_bytes())
                .map_err(|e| ControlStateError::Storage(e.to_string()))?;
            file.write_all(b"\n")
                .map_err(|e| ControlStateError::Storage(e.to_string()))?;
        }

        let encoded_state = encode_hex(&encode_control_state(state));
        let line = format!(
            "commit|{}|{}|{}|{}\n",
            tx.id,
            encode_opt_u64(tx.correlation_id.map(|id| id.0 .0)),
            tx.occurred_at,
            encoded_state
        );
        file.write_all(line.as_bytes())
            .map_err(|e| ControlStateError::Storage(e.to_string()))?;
        file.sync_all()
            .map_err(|e| ControlStateError::Storage(e.to_string()))
    }
}

impl TransactionalStateStore for FileTransactionalStateStore {
    fn load_state(&mut self) -> Result<ControlState, ControlStateError> {
        Ok(self.state.clone())
    }

    fn apply_transaction(&mut self, tx: &ControlTransaction) -> Result<(), ControlStateError> {
        let mut candidate = self.state.clone();
        tx.apply_to_state(&mut candidate)?;
        self.append_commit(tx, &candidate)?;
        self.state = candidate;
        Ok(())
    }
}

fn load_commit_log(path: &Path) -> Result<ControlState, ControlStateError> {
    if !path.exists() {
        return Ok(ControlState::default());
    }

    let raw =
        std::fs::read_to_string(path).map_err(|e| ControlStateError::Storage(e.to_string()))?;
    let lines: Vec<&str> = raw.lines().collect();
    if lines.is_empty() {
        return Err(ControlStateError::Parse("empty commit log".to_string()));
    }
    if lines[0] != CONTROL_COMMIT_LOG_HEADER {
        return Err(ControlStateError::Parse(format!(
            "unsupported commit log header '{}'",
            lines[0]
        )));
    }

    let mut state = ControlState::default();
    for (idx, line) in lines.iter().enumerate().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        match decode_commit_line(line) {
            Ok((tx_id, decoded_state)) => {
                state = decoded_state;
                state.applied_transactions.insert(tx_id);
            }
            Err(err) => {
                if idx == lines.len() - 1 {
                    break;
                }
                return Err(err);
            }
        }
    }

    Ok(state)
}

fn decode_commit_line(line: &str) -> Result<(u64, ControlState), ControlStateError> {
    let parts: Vec<&str> = line.splitn(5, '|').collect();
    if parts.len() != 5 || parts[0] != "commit" {
        return Err(ControlStateError::Parse(format!(
            "invalid commit record '{}'",
            line
        )));
    }
    let tx_id = parse_u64(parts[1])?;
    let _correlation = parse_opt_u64(parts[2])?;
    let _occurred_at = parse_u64(parts[3])?;
    let state_raw = decode_hex(parts[4])?;
    let state = decode_control_state(&state_raw)?;
    Ok((tx_id, state))
}

pub trait ArtifactStorage {
    fn write_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<String, ControlStateError>;
    fn read_bytes(&self, locator: &str) -> Result<Vec<u8>, ControlStateError>;
    fn delete(&mut self, locator: &str) -> Result<(), ControlStateError>;
    fn exists(&self, locator: &str) -> bool;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryArtifactStorage {
    blobs: BTreeMap<String, Vec<u8>>,
}

impl ArtifactStorage for InMemoryArtifactStorage {
    fn write_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<String, ControlStateError> {
        let locator = format!("{}-{}", Id::next().0, sanitize_name(name));
        self.blobs.insert(locator.clone(), bytes.to_vec());
        Ok(locator)
    }

    fn read_bytes(&self, locator: &str) -> Result<Vec<u8>, ControlStateError> {
        self.blobs
            .get(locator)
            .cloned()
            .ok_or_else(|| ControlStateError::NotFound(format!("artifact locator {}", locator)))
    }

    fn delete(&mut self, locator: &str) -> Result<(), ControlStateError> {
        self.blobs.remove(locator);
        Ok(())
    }

    fn exists(&self, locator: &str) -> bool {
        self.blobs.contains_key(locator)
    }
}

#[derive(Debug, Clone)]
pub struct FileArtifactStorage {
    root: PathBuf,
}

impl FileArtifactStorage {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn path_for(&self, locator: &str) -> PathBuf {
        self.root.join(locator)
    }
}

impl ArtifactStorage for FileArtifactStorage {
    fn write_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<String, ControlStateError> {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| ControlStateError::Storage(e.to_string()))?;
        let locator = format!("{}-{}", Id::next().0, sanitize_name(name));
        let path = self.path_for(&locator);
        let mut file =
            std::fs::File::create(&path).map_err(|e| ControlStateError::Storage(e.to_string()))?;
        file.write_all(bytes)
            .map_err(|e| ControlStateError::Storage(e.to_string()))?;
        file.sync_all()
            .map_err(|e| ControlStateError::Storage(e.to_string()))?;
        Ok(locator)
    }

    fn read_bytes(&self, locator: &str) -> Result<Vec<u8>, ControlStateError> {
        std::fs::read(self.path_for(locator)).map_err(|e| ControlStateError::Storage(e.to_string()))
    }

    fn delete(&mut self, locator: &str) -> Result<(), ControlStateError> {
        let path = self.path_for(locator);
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(path).map_err(|e| ControlStateError::Storage(e.to_string()))
    }

    fn exists(&self, locator: &str) -> bool {
        self.path_for(locator).exists()
    }
}

fn sanitize_name(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        return "artifact.bin".to_string();
    }
    out
}

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub transcript_ttl_secs: u64,
    pub result_ttl_secs: u64,
    pub binary_blob_ttl_secs: u64,
    pub expired_grace_secs: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            transcript_ttl_secs: 30 * 24 * 60 * 60,
            result_ttl_secs: 30 * 24 * 60 * 60,
            binary_blob_ttl_secs: 90 * 24 * 60 * 60,
            expired_grace_secs: 7 * 24 * 60 * 60,
        }
    }
}

impl RetentionPolicy {
    pub fn ttl_for_kind(&self, kind: ArtifactKind) -> u64 {
        match kind {
            ArtifactKind::Transcript => self.transcript_ttl_secs,
            ArtifactKind::CommandOutput | ArtifactKind::StructuredJson => self.result_ttl_secs,
            ArtifactKind::BinaryBlob | ArtifactKind::FileReference => self.binary_blob_ttl_secs,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub expired: Vec<ArtifactId>,
    pub deleted: Vec<ArtifactId>,
}

pub struct ControlPlane<S: TransactionalStateStore, A: ArtifactStorage> {
    state_store: S,
    artifact_storage: A,
}

impl<S: TransactionalStateStore, A: ArtifactStorage> ControlPlane<S, A> {
    pub fn new(state_store: S, artifact_storage: A) -> Self {
        Self {
            state_store,
            artifact_storage,
        }
    }

    pub fn state(&mut self) -> Result<ControlState, ControlStateError> {
        self.state_store.load_state()
    }

    pub fn record_run(
        &mut self,
        run: Run,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(), ControlStateError> {
        let tx = ControlTransaction::new(
            vec![ControlMutation::UpsertRun(run)],
            correlation_id,
            now_secs(),
        )?;
        self.state_store.apply_transaction(&tx)
    }

    pub fn record_task(
        &mut self,
        task: Task,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(), ControlStateError> {
        let tx = ControlTransaction::new(
            vec![ControlMutation::UpsertTask(task)],
            correlation_id,
            now_secs(),
        )?;
        self.state_store.apply_transaction(&tx)
    }

    pub fn record_session(
        &mut self,
        session: Session,
        correlation_id: Option<CorrelationId>,
    ) -> Result<(), ControlStateError> {
        let tx = ControlTransaction::new(
            vec![ControlMutation::UpsertSession(session)],
            correlation_id,
            now_secs(),
        )?;
        self.state_store.apply_transaction(&tx)
    }

    pub fn archive_transcript(
        &mut self,
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        name: &str,
        transcript: &[u8],
        correlation_id: Option<CorrelationId>,
    ) -> Result<Artifact, ControlStateError> {
        self.archive_artifact(
            run_id,
            task_id,
            session_id,
            ArtifactKind::Transcript,
            name,
            transcript,
            correlation_id,
        )
    }

    pub fn archive_result(
        &mut self,
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        name: &str,
        result: &[u8],
        correlation_id: Option<CorrelationId>,
    ) -> Result<Artifact, ControlStateError> {
        self.archive_artifact(
            run_id,
            task_id,
            session_id,
            ArtifactKind::CommandOutput,
            name,
            result,
            correlation_id,
        )
    }

    pub fn archive_structured_json(
        &mut self,
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        name: &str,
        json_payload: &str,
        correlation_id: Option<CorrelationId>,
    ) -> Result<Artifact, ControlStateError> {
        self.archive_artifact(
            run_id,
            task_id,
            session_id,
            ArtifactKind::StructuredJson,
            name,
            json_payload.as_bytes(),
            correlation_id,
        )
    }

    pub fn read_artifact(&self, locator: &str) -> Result<Vec<u8>, ControlStateError> {
        self.artifact_storage.read_bytes(locator)
    }

    pub fn artifact_exists(&self, locator: &str) -> bool {
        self.artifact_storage.exists(locator)
    }

    pub fn apply_retention(
        &mut self,
        now: u64,
        policy: &RetentionPolicy,
        correlation_id: Option<CorrelationId>,
    ) -> Result<RetentionReport, ControlStateError> {
        let state = self.state_store.load_state()?;
        let mut report = RetentionReport::default();
        let mut mutations = Vec::new();
        let mut pending_delete_locators = Vec::new();

        for artifact in state.artifacts.values() {
            match artifact.state {
                ArtifactState::Available => {
                    let ttl = policy.ttl_for_kind(artifact.kind);
                    if now.saturating_sub(artifact.updated_at) >= ttl {
                        let mut expired = artifact.clone();
                        expired.transition_state(ArtifactState::Expired, now)?;
                        report.expired.push(expired.id);
                        mutations.push(ControlMutation::UpsertArtifact(expired));
                    }
                }
                ArtifactState::Expired => {
                    if now.saturating_sub(artifact.updated_at) >= policy.expired_grace_secs {
                        let mut deleted = artifact.clone();
                        deleted.transition_state(ArtifactState::Deleted, now)?;
                        pending_delete_locators.push(deleted.locator.clone());
                        report.deleted.push(deleted.id);
                        mutations.push(ControlMutation::UpsertArtifact(deleted));
                    }
                }
                ArtifactState::Pending | ArtifactState::Deleted => {}
            }
        }

        if !mutations.is_empty() {
            let tx = ControlTransaction::new(mutations, correlation_id, now)?;
            self.state_store.apply_transaction(&tx)?;
        }

        let mut delete_errors = Vec::new();
        for locator in pending_delete_locators {
            if let Err(err) = self.artifact_storage.delete(&locator) {
                delete_errors.push(format!("{locator}: {err}"));
            }
        }
        if !delete_errors.is_empty() {
            return Err(ControlStateError::Storage(format!(
                "failed deleting one or more artifacts: {}",
                delete_errors.join(", ")
            )));
        }

        Ok(report)
    }

    fn archive_artifact(
        &mut self,
        run_id: RunId,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
        kind: ArtifactKind,
        name: &str,
        bytes: &[u8],
        correlation_id: Option<CorrelationId>,
    ) -> Result<Artifact, ControlStateError> {
        let now = now_secs();
        let locator = self.artifact_storage.write_bytes(name, bytes)?;

        let mut artifact =
            Artifact::new_at(run_id, task_id, session_id, kind, name, &locator, now)?;
        artifact.transition_state(ArtifactState::Available, now)?;

        let tx = ControlTransaction::new(
            vec![ControlMutation::UpsertArtifact(artifact.clone())],
            correlation_id,
            now,
        )?;

        if let Err(err) = self.state_store.apply_transaction(&tx) {
            let _ = self.artifact_storage.delete(&locator);
            return Err(err);
        }

        Ok(artifact)
    }
}

fn encode_control_state(state: &ControlState) -> String {
    let mut out = String::new();
    out.push_str(CONTROL_STATE_HEADER);
    out.push('\n');

    for run in state.runs.values() {
        out.push_str(&format!(
            "run|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            run.id.0 .0,
            run.workspace_id.0 .0,
            run.module_version_id.0 .0,
            encode_opt_u64(run.target_id.map(|id| id.0 .0)),
            encode_hex(&run.requested_by),
            run_state_to_str(run.state),
            run.created_at,
            run.queued_at,
            encode_opt_u64(run.started_at),
            encode_opt_u64(run.finished_at),
            run.updated_at,
            encode_opt_string(run.error.as_deref()),
        ));
    }

    for task in state.tasks.values() {
        out.push_str(&format!(
            "task|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            task.id.0 .0,
            task.run_id.0 .0,
            encode_hex(&task.name),
            task_state_to_str(task.state),
            task.attempt_count,
            task.max_attempts,
            task.created_at,
            task.queued_at,
            encode_opt_u64(task.started_at),
            encode_opt_u64(task.finished_at),
            task.updated_at,
            encode_opt_string(task.error.as_deref()),
        ));
    }

    for session in state.sessions.values() {
        out.push_str(&format!(
            "session|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            session.id.0 .0,
            session.run_id.0 .0,
            encode_opt_u64(session.task_id.map(|id| id.0 .0)),
            encode_hex(&session.kind),
            encode_hex(&session.target),
            session_state_to_str(session.state),
            session.created_at,
            encode_opt_u64(session.opened_at),
            encode_opt_u64(session.closed_at),
            session.last_activity_at,
            session.updated_at,
        ));
    }

    for artifact in state.artifacts.values() {
        out.push_str(&format!(
            "artifact|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            artifact.id.0 .0,
            artifact.run_id.0 .0,
            encode_opt_u64(artifact.task_id.map(|id| id.0 .0)),
            encode_opt_u64(artifact.session_id.map(|id| id.0 .0)),
            artifact_kind_to_str(artifact.kind),
            encode_hex(&artifact.name),
            encode_hex(&artifact.locator),
            artifact_state_to_str(artifact.state),
            artifact.created_at,
            artifact.updated_at,
        ));
    }

    let tx_ids = state
        .applied_transactions
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!("txids|{}\n", tx_ids));

    out
}

fn decode_control_state(input: &str) -> Result<ControlState, ControlStateError> {
    let mut lines = input.lines();
    let Some(header) = lines.next() else {
        return Err(ControlStateError::Parse("empty control state".to_string()));
    };
    if header != CONTROL_STATE_HEADER {
        return Err(ControlStateError::Parse(format!(
            "unsupported control state header '{}'",
            header
        )));
    }

    let mut state = ControlState::default();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        match parts.first().copied().unwrap_or_default() {
            "run" => {
                if parts.len() != 13 {
                    return Err(ControlStateError::Parse(format!(
                        "invalid run record '{}'",
                        line
                    )));
                }
                let run = Run {
                    id: RunId(Id(parse_u64(parts[1])?)),
                    workspace_id: WorkspaceId(Id(parse_u64(parts[2])?)),
                    module_version_id: ModuleVersionId(Id(parse_u64(parts[3])?)),
                    target_id: parse_opt_u64(parts[4])?.map(|v| TargetId(Id(v))),
                    requested_by: decode_hex(parts[5])?,
                    state: parse_run_state(parts[6])?,
                    created_at: parse_u64(parts[7])?,
                    queued_at: parse_u64(parts[8])?,
                    started_at: parse_opt_u64(parts[9])?,
                    finished_at: parse_opt_u64(parts[10])?,
                    updated_at: parse_u64(parts[11])?,
                    error: decode_opt_string(parts[12])?,
                };
                state.runs.insert(run.id, run);
            }
            "task" => {
                if parts.len() != 13 {
                    return Err(ControlStateError::Parse(format!(
                        "invalid task record '{}'",
                        line
                    )));
                }
                let task = Task {
                    id: TaskId(Id(parse_u64(parts[1])?)),
                    run_id: RunId(Id(parse_u64(parts[2])?)),
                    name: decode_hex(parts[3])?,
                    state: parse_task_state(parts[4])?,
                    attempt_count: parse_u32(parts[5])?,
                    max_attempts: parse_u32(parts[6])?,
                    created_at: parse_u64(parts[7])?,
                    queued_at: parse_u64(parts[8])?,
                    started_at: parse_opt_u64(parts[9])?,
                    finished_at: parse_opt_u64(parts[10])?,
                    updated_at: parse_u64(parts[11])?,
                    error: decode_opt_string(parts[12])?,
                };
                state.tasks.insert(task.id, task);
            }
            "session" => {
                if parts.len() != 12 {
                    return Err(ControlStateError::Parse(format!(
                        "invalid session record '{}'",
                        line
                    )));
                }
                let session = Session {
                    id: SessionId(Id(parse_u64(parts[1])?)),
                    run_id: RunId(Id(parse_u64(parts[2])?)),
                    task_id: parse_opt_u64(parts[3])?.map(|v| TaskId(Id(v))),
                    kind: decode_hex(parts[4])?,
                    target: decode_hex(parts[5])?,
                    state: parse_session_state(parts[6])?,
                    created_at: parse_u64(parts[7])?,
                    opened_at: parse_opt_u64(parts[8])?,
                    closed_at: parse_opt_u64(parts[9])?,
                    last_activity_at: parse_u64(parts[10])?,
                    updated_at: parse_u64(parts[11])?,
                };
                state.sessions.insert(session.id, session);
            }
            "artifact" => {
                if parts.len() != 11 {
                    return Err(ControlStateError::Parse(format!(
                        "invalid artifact record '{}'",
                        line
                    )));
                }
                let artifact = Artifact {
                    id: ArtifactId(Id(parse_u64(parts[1])?)),
                    run_id: RunId(Id(parse_u64(parts[2])?)),
                    task_id: parse_opt_u64(parts[3])?.map(|v| TaskId(Id(v))),
                    session_id: parse_opt_u64(parts[4])?.map(|v| SessionId(Id(v))),
                    kind: parse_artifact_kind(parts[5])?,
                    name: decode_hex(parts[6])?,
                    locator: decode_hex(parts[7])?,
                    state: parse_artifact_state(parts[8])?,
                    created_at: parse_u64(parts[9])?,
                    updated_at: parse_u64(parts[10])?,
                };
                state.artifacts.insert(artifact.id, artifact);
            }
            "txids" => {
                if parts.len() != 2 {
                    return Err(ControlStateError::Parse(format!(
                        "invalid txids record '{}'",
                        line
                    )));
                }
                for tx_id in parse_id_list(parts[1])? {
                    state.applied_transactions.insert(tx_id);
                }
            }
            other => {
                return Err(ControlStateError::Parse(format!(
                    "unknown control state record '{}'",
                    other
                )));
            }
        }
    }

    Ok(state)
}

fn parse_u64(input: &str) -> Result<u64, ControlStateError> {
    input
        .parse::<u64>()
        .map_err(|_| ControlStateError::Parse(format!("invalid u64 '{}'", input)))
}

fn parse_u32(input: &str) -> Result<u32, ControlStateError> {
    input
        .parse::<u32>()
        .map_err(|_| ControlStateError::Parse(format!("invalid u32 '{}'", input)))
}

fn parse_opt_u64(input: &str) -> Result<Option<u64>, ControlStateError> {
    if input == "-" {
        return Ok(None);
    }
    parse_u64(input).map(Some)
}

fn parse_id_list(input: &str) -> Result<Vec<u64>, ControlStateError> {
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

fn decode_opt_string(value: &str) -> Result<Option<String>, ControlStateError> {
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

fn decode_hex(input: &str) -> Result<String, ControlStateError> {
    if input.len() % 2 != 0 {
        return Err(ControlStateError::Parse("invalid hex length".to_string()));
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
        .map_err(|_| ControlStateError::Parse("invalid utf-8 in hex".to_string()))
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn hex_to_nibble(value: u8) -> Result<u8, ControlStateError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ControlStateError::Parse(
            "invalid hex character".to_string(),
        )),
    }
}

fn run_state_to_str(state: RunState) -> &'static str {
    state.as_str()
}

fn parse_run_state(state: &str) -> Result<RunState, ControlStateError> {
    match state {
        "queued" => Ok(RunState::Queued),
        "running" => Ok(RunState::Running),
        "succeeded" => Ok(RunState::Succeeded),
        "failed" => Ok(RunState::Failed),
        "canceled" => Ok(RunState::Canceled),
        _ => Err(ControlStateError::Parse(format!(
            "invalid run state '{}'",
            state
        ))),
    }
}

fn task_state_to_str(state: TaskState) -> &'static str {
    state.as_str()
}

fn parse_task_state(state: &str) -> Result<TaskState, ControlStateError> {
    match state {
        "queued" => Ok(TaskState::Queued),
        "running" => Ok(TaskState::Running),
        "retrying" => Ok(TaskState::Retrying),
        "succeeded" => Ok(TaskState::Succeeded),
        "failed" => Ok(TaskState::Failed),
        "canceled" => Ok(TaskState::Canceled),
        _ => Err(ControlStateError::Parse(format!(
            "invalid task state '{}'",
            state
        ))),
    }
}

fn session_state_to_str(state: SessionState) -> &'static str {
    state.as_str()
}

fn parse_session_state(state: &str) -> Result<SessionState, ControlStateError> {
    match state {
        "opening" => Ok(SessionState::Opening),
        "open" => Ok(SessionState::Open),
        "backgrounded" => Ok(SessionState::Backgrounded),
        "lost" => Ok(SessionState::Lost),
        "closed" => Ok(SessionState::Closed),
        _ => Err(ControlStateError::Parse(format!(
            "invalid session state '{}'",
            state
        ))),
    }
}

fn artifact_state_to_str(state: ArtifactState) -> &'static str {
    state.as_str()
}

fn parse_artifact_state(state: &str) -> Result<ArtifactState, ControlStateError> {
    match state {
        "pending" => Ok(ArtifactState::Pending),
        "available" => Ok(ArtifactState::Available),
        "expired" => Ok(ArtifactState::Expired),
        "deleted" => Ok(ArtifactState::Deleted),
        _ => Err(ControlStateError::Parse(format!(
            "invalid artifact state '{}'",
            state
        ))),
    }
}

fn artifact_kind_to_str(kind: ArtifactKind) -> &'static str {
    kind.as_str()
}

fn parse_artifact_kind(kind: &str) -> Result<ArtifactKind, ControlStateError> {
    match kind {
        "transcript" => Ok(ArtifactKind::Transcript),
        "command_output" => Ok(ArtifactKind::CommandOutput),
        "structured_json" => Ok(ArtifactKind::StructuredJson),
        "binary_blob" => Ok(ArtifactKind::BinaryBlob),
        "file_reference" => Ok(ArtifactKind::FileReference),
        _ => Err(ControlStateError::Parse(format!(
            "invalid artifact kind '{}'",
            kind
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_run(now: u64) -> Run {
        Run::new_at(
            WorkspaceId::next(),
            ModuleVersionId::next(),
            Some(TargetId::next()),
            "operator",
            now,
        )
        .expect("run")
    }

    #[test]
    fn transaction_is_atomic_on_validation_failure() {
        let mut store = InMemoryTransactionalStateStore::default();
        let now = now_secs();
        let run = build_run(now);
        let bad_task = Task::new_at(RunId::next(), "bad", 1, now).expect("bad task");

        let tx = ControlTransaction::new(
            vec![
                ControlMutation::UpsertRun(run),
                ControlMutation::UpsertTask(bad_task),
            ],
            None,
            now,
        )
        .expect("tx");

        assert!(store.apply_transaction(&tx).is_err());
        let state = store.load_state().expect("state");
        assert!(state.runs.is_empty());
        assert!(state.tasks.is_empty());
        assert!(store.journal().is_empty());
    }

    #[test]
    fn artifacts_are_linked_to_run_task_and_session() {
        let mut plane = ControlPlane::new(
            InMemoryTransactionalStateStore::default(),
            InMemoryArtifactStorage::default(),
        );

        let now = now_secs();
        let run = build_run(now);
        let task = Task::new_at(run.id, "collect", 2, now).expect("task");
        let session = Session::new_at(
            run.id,
            Some(task.id),
            "telnet/new-environ",
            "target:23",
            now,
        )
        .expect("session");

        plane.record_run(run.clone(), None).expect("run");
        plane.record_task(task.clone(), None).expect("task");
        plane
            .record_session(session.clone(), None)
            .expect("session");

        let artifact = plane
            .archive_result(
                run.id,
                Some(task.id),
                Some(session.id),
                "id.txt",
                b"uid=0(root)",
                None,
            )
            .expect("archive");

        let state = plane.state().expect("state");
        let persisted = state.artifacts.get(&artifact.id).expect("artifact");
        assert_eq!(persisted.run_id, run.id);
        assert_eq!(persisted.task_id, Some(task.id));
        assert_eq!(persisted.session_id, Some(session.id));
        assert_eq!(persisted.state, ArtifactState::Available);
    }

    #[test]
    fn retention_expires_then_deletes_artifacts() {
        let mut plane = ControlPlane::new(
            InMemoryTransactionalStateStore::default(),
            InMemoryArtifactStorage::default(),
        );

        let now = now_secs();
        let run = build_run(now);
        plane.record_run(run.clone(), None).expect("run");

        let artifact = plane
            .archive_transcript(run.id, None, None, "shell.log", b"whoami\nroot\n", None)
            .expect("transcript");

        let policy = RetentionPolicy {
            transcript_ttl_secs: 1,
            result_ttl_secs: 60,
            binary_blob_ttl_secs: 60,
            expired_grace_secs: 3,
        };

        let report_1 = plane
            .apply_retention(artifact.updated_at + 2, &policy, None)
            .expect("retention-1");
        assert_eq!(report_1.expired, vec![artifact.id]);
        assert!(report_1.deleted.is_empty());
        assert!(plane.artifact_exists(&artifact.locator));

        let state_1 = plane.state().expect("state-1");
        assert_eq!(
            state_1.artifacts.get(&artifact.id).map(|a| a.state),
            Some(ArtifactState::Expired)
        );

        let report_2 = plane
            .apply_retention(artifact.updated_at + 10, &policy, None)
            .expect("retention-2");
        assert_eq!(report_2.deleted, vec![artifact.id]);
        assert!(!plane.artifact_exists(&artifact.locator));

        let state_2 = plane.state().expect("state-2");
        assert_eq!(
            state_2.artifacts.get(&artifact.id).map(|a| a.state),
            Some(ArtifactState::Deleted)
        );
    }

    #[test]
    fn file_store_recovers_state_and_artifacts_after_restart() {
        let base = std::env::temp_dir().join(format!("moonlight-phase6-{}", Id::next().0));
        let log_path = base.join("control.log");
        let artifacts_root = base.join("artifacts");

        let run = {
            let mut plane = ControlPlane::new(
                FileTransactionalStateStore::new(&log_path).expect("state store"),
                FileArtifactStorage::new(&artifacts_root),
            );

            let now = now_secs();
            let run = build_run(now);
            let task = Task::new_at(run.id, "enumerate", 1, now).expect("task");
            let session = Session::new_at(
                run.id,
                Some(task.id),
                "telnet/new-environ",
                "target:23",
                now,
            )
            .expect("session");

            plane.record_run(run.clone(), None).expect("run");
            plane.record_task(task.clone(), None).expect("task");
            plane.record_session(session, None).expect("session");

            plane
                .archive_transcript(
                    run.id,
                    Some(task.id),
                    Some(SessionId::next()),
                    "session.log",
                    b"id\nuid=0(root)",
                    None,
                )
                .expect_err("invalid session reference should fail and rollback blob");

            let transcript = plane
                .archive_transcript(
                    run.id,
                    Some(task.id),
                    None,
                    "session.log",
                    b"id\nuid=0(root)",
                    None,
                )
                .expect("transcript");
            assert!(plane.artifact_exists(&transcript.locator));
            run
        };

        {
            let mut recovered = ControlPlane::new(
                FileTransactionalStateStore::new(&log_path).expect("reload store"),
                FileArtifactStorage::new(&artifacts_root),
            );
            let state = recovered.state().expect("state");
            assert!(state.runs.contains_key(&run.id));
            assert_eq!(state.tasks_for_run(run.id).len(), 1);
            assert_eq!(state.artifacts_for_run(run.id).len(), 1);
            let artifact = state.artifacts_for_run(run.id)[0];
            let bytes = recovered
                .read_artifact(&artifact.locator)
                .expect("read artifact");
            assert_eq!(bytes, b"id\nuid=0(root)");
        }

        let _ = std::fs::remove_dir_all(base);
    }
}
