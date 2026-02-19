use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::domain::{RunId, TaskId};
use crate::ids::Id;
use crate::time::now_secs;

const LEASE_SNAPSHOT_HEADER: &str = "moonlight-worker-leases:v1";

#[derive(Debug)]
pub enum ReliabilityError {
    Validation(String),
    NotFound(String),
    Storage(String),
    Parse(String),
}

impl fmt::Display for ReliabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReliabilityError::Validation(msg) => write!(f, "validation error: {msg}"),
            ReliabilityError::NotFound(msg) => write!(f, "not found: {msg}"),
            ReliabilityError::Storage(msg) => write!(f, "storage error: {msg}"),
            ReliabilityError::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for ReliabilityError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerLease {
    pub worker_id: String,
    pub acquired_at: u64,
    pub last_heartbeat_at: u64,
    pub lease_secs: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskClaim {
    pub task_id: TaskId,
    pub run_id: RunId,
    pub worker_id: String,
    pub leased_at: u64,
    pub lease_expires_at: u64,
    pub attempt_count: u32,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimAction {
    Requeue,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimDecision {
    pub task_id: TaskId,
    pub run_id: RunId,
    pub worker_id: String,
    pub action: ReclaimAction,
    pub reason: String,
}

pub trait LeaseStore {
    fn load_snapshot(&mut self) -> Result<Option<String>, ReliabilityError>;
    fn save_snapshot(&mut self, snapshot: &str) -> Result<(), ReliabilityError>;
}

#[derive(Debug, Clone)]
pub struct InMemoryLeaseStore {
    shared: Arc<Mutex<Option<String>>>,
}

impl Default for InMemoryLeaseStore {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(None)),
        }
    }
}

impl InMemoryLeaseStore {
    pub fn from_shared(shared: Arc<Mutex<Option<String>>>) -> Self {
        Self { shared }
    }

    pub fn shared(&self) -> Arc<Mutex<Option<String>>> {
        Arc::clone(&self.shared)
    }
}

impl LeaseStore for InMemoryLeaseStore {
    fn load_snapshot(&mut self) -> Result<Option<String>, ReliabilityError> {
        self.shared
            .lock()
            .map_err(|_| ReliabilityError::Storage("lease lock poisoned".to_string()))
            .map(|value| value.clone())
    }

    fn save_snapshot(&mut self, snapshot: &str) -> Result<(), ReliabilityError> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| ReliabilityError::Storage("lease lock poisoned".to_string()))?;
        *guard = Some(snapshot.to_string());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FileLeaseStore {
    path: PathBuf,
}

impl FileLeaseStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl LeaseStore for FileLeaseStore {
    fn load_snapshot(&mut self) -> Result<Option<String>, ReliabilityError> {
        if !self.path.exists() {
            return Ok(None);
        }
        std::fs::read_to_string(&self.path)
            .map(Some)
            .map_err(|e| ReliabilityError::Storage(e.to_string()))
    }

    fn save_snapshot(&mut self, snapshot: &str) -> Result<(), ReliabilityError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ReliabilityError::Storage(e.to_string()))?;
        }
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, snapshot)
            .map_err(|e| ReliabilityError::Storage(e.to_string()))?;
        std::fs::rename(&tmp_path, &self.path).map_err(|e| ReliabilityError::Storage(e.to_string()))
    }
}

pub struct WorkerLeaseRegistry<S: LeaseStore> {
    store: S,
    leases: BTreeMap<String, WorkerLease>,
    claims: BTreeMap<TaskId, TaskClaim>,
}

impl<S: LeaseStore> WorkerLeaseRegistry<S> {
    pub fn new(store: S) -> Result<Self, ReliabilityError> {
        let mut registry = Self {
            store,
            leases: BTreeMap::new(),
            claims: BTreeMap::new(),
        };
        if let Some(raw) = registry.store.load_snapshot()? {
            let snapshot = decode_snapshot(&raw)?;
            registry.leases = snapshot.leases;
            registry.claims = snapshot.claims;
            registry.recover_expired(now_secs())?;
            registry.persist()?;
        }
        Ok(registry)
    }

    pub fn acquire_or_renew(
        &mut self,
        worker_id: &str,
        lease_secs: u64,
        now: u64,
    ) -> Result<WorkerLease, ReliabilityError> {
        validate_worker_input(worker_id, lease_secs)?;
        let worker_id = worker_id.trim().to_string();
        let lease = self
            .leases
            .entry(worker_id.clone())
            .and_modify(|existing| {
                existing.last_heartbeat_at = now;
                existing.lease_secs = lease_secs;
                existing.expires_at = now.saturating_add(lease_secs);
            })
            .or_insert_with(|| WorkerLease {
                worker_id: worker_id.clone(),
                acquired_at: now,
                last_heartbeat_at: now,
                lease_secs,
                expires_at: now.saturating_add(lease_secs),
            })
            .clone();
        self.persist()?;
        Ok(lease)
    }

    pub fn heartbeat(&mut self, worker_id: &str, now: u64) -> Result<bool, ReliabilityError> {
        let Some(lease) = self.leases.get_mut(worker_id.trim()) else {
            return Ok(false);
        };
        lease.last_heartbeat_at = now;
        lease.expires_at = now.saturating_add(lease.lease_secs);

        for claim in self.claims.values_mut() {
            if claim.worker_id == worker_id.trim() {
                claim.leased_at = now;
                claim.lease_expires_at = now.saturating_add(lease.lease_secs);
            }
        }

        self.persist()?;
        Ok(true)
    }

    pub fn has_valid_lease(&self, worker_id: &str, now: u64) -> bool {
        self.leases
            .get(worker_id.trim())
            .map(|lease| lease.expires_at > now)
            .unwrap_or(false)
    }

    pub fn claim_task(
        &mut self,
        worker_id: &str,
        run_id: RunId,
        task_id: TaskId,
        attempt_count: u32,
        max_attempts: u32,
        now: u64,
    ) -> Result<TaskClaim, ReliabilityError> {
        if max_attempts == 0 {
            return Err(ReliabilityError::Validation(
                "max_attempts must be greater than zero".to_string(),
            ));
        }
        let worker_id = worker_id.trim();
        if worker_id.is_empty() {
            return Err(ReliabilityError::Validation(
                "worker_id cannot be empty".to_string(),
            ));
        }

        let Some(lease) = self.leases.get(worker_id) else {
            return Err(ReliabilityError::NotFound(format!("worker {}", worker_id)));
        };
        if lease.expires_at <= now {
            return Err(ReliabilityError::Validation(format!(
                "worker {} lease expired",
                worker_id
            )));
        }
        if self.claims.contains_key(&task_id) {
            return Err(ReliabilityError::Validation(format!(
                "task {} already claimed",
                task_id.0 .0
            )));
        }

        let claim = TaskClaim {
            task_id,
            run_id,
            worker_id: worker_id.to_string(),
            leased_at: now,
            lease_expires_at: now.saturating_add(lease.lease_secs),
            attempt_count,
            max_attempts,
        };
        self.claims.insert(task_id, claim.clone());
        self.persist()?;
        Ok(claim)
    }

    pub fn release_task(
        &mut self,
        worker_id: &str,
        task_id: TaskId,
    ) -> Result<bool, ReliabilityError> {
        let Some(claim) = self.claims.get(&task_id) else {
            return Ok(false);
        };
        if claim.worker_id != worker_id.trim() {
            return Err(ReliabilityError::Validation(format!(
                "task {} is leased by {}, not {}",
                task_id.0 .0,
                claim.worker_id,
                worker_id.trim()
            )));
        }
        self.claims.remove(&task_id);
        self.persist()?;
        Ok(true)
    }

    pub fn recover_expired(&mut self, now: u64) -> Result<Vec<ReclaimDecision>, ReliabilityError> {
        let mut expired_workers = Vec::new();
        for (worker_id, lease) in &self.leases {
            if lease.expires_at <= now {
                expired_workers.push(worker_id.clone());
            }
        }

        let mut decisions = Vec::new();
        let mut remove_claim_ids = Vec::new();
        for (task_id, claim) in &self.claims {
            if expired_workers
                .iter()
                .any(|worker_id| worker_id == &claim.worker_id)
                || claim.lease_expires_at <= now
            {
                let action = if claim.attempt_count < claim.max_attempts {
                    ReclaimAction::Requeue
                } else {
                    ReclaimAction::Fail
                };
                decisions.push(ReclaimDecision {
                    task_id: *task_id,
                    run_id: claim.run_id,
                    worker_id: claim.worker_id.clone(),
                    action,
                    reason: "worker lease expired during task execution".to_string(),
                });
                remove_claim_ids.push(*task_id);
            }
        }

        for task_id in remove_claim_ids {
            self.claims.remove(&task_id);
        }
        for worker_id in expired_workers {
            self.leases.remove(&worker_id);
        }

        if !decisions.is_empty() {
            self.persist()?;
        }

        Ok(decisions)
    }

    pub fn active_claims(&self) -> Vec<TaskClaim> {
        self.claims.values().cloned().collect()
    }

    pub fn leases(&self) -> Vec<WorkerLease> {
        self.leases.values().cloned().collect()
    }

    fn persist(&mut self) -> Result<(), ReliabilityError> {
        let encoded = encode_snapshot(&LeaseSnapshot {
            leases: self.leases.clone(),
            claims: self.claims.clone(),
        });
        self.store.save_snapshot(&encoded)
    }
}

#[derive(Debug, Clone, Default)]
struct LeaseSnapshot {
    leases: BTreeMap<String, WorkerLease>,
    claims: BTreeMap<TaskId, TaskClaim>,
}

fn validate_worker_input(worker_id: &str, lease_secs: u64) -> Result<(), ReliabilityError> {
    if worker_id.trim().is_empty() {
        return Err(ReliabilityError::Validation(
            "worker_id cannot be empty".to_string(),
        ));
    }
    if lease_secs == 0 {
        return Err(ReliabilityError::Validation(
            "lease_secs must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn encode_snapshot(snapshot: &LeaseSnapshot) -> String {
    let mut out = String::new();
    out.push_str(LEASE_SNAPSHOT_HEADER);
    out.push('\n');

    for lease in snapshot.leases.values() {
        out.push_str(&format!(
            "lease|{}|{}|{}|{}|{}\n",
            encode_hex(&lease.worker_id),
            lease.acquired_at,
            lease.last_heartbeat_at,
            lease.lease_secs,
            lease.expires_at,
        ));
    }

    for claim in snapshot.claims.values() {
        out.push_str(&format!(
            "claim|{}|{}|{}|{}|{}|{}|{}\n",
            claim.task_id.0 .0,
            claim.run_id.0 .0,
            encode_hex(&claim.worker_id),
            claim.leased_at,
            claim.lease_expires_at,
            claim.attempt_count,
            claim.max_attempts,
        ));
    }

    out
}

fn decode_snapshot(raw: &str) -> Result<LeaseSnapshot, ReliabilityError> {
    let mut lines = raw.lines();
    let Some(header) = lines.next() else {
        return Err(ReliabilityError::Parse("empty lease snapshot".to_string()));
    };
    if header != LEASE_SNAPSHOT_HEADER {
        return Err(ReliabilityError::Parse(format!(
            "unsupported lease snapshot header '{}'",
            header
        )));
    }

    let mut snapshot = LeaseSnapshot::default();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        match parts.first().copied().unwrap_or_default() {
            "lease" => {
                if parts.len() != 6 {
                    return Err(ReliabilityError::Parse(format!(
                        "invalid lease record '{}'",
                        line
                    )));
                }
                let lease = WorkerLease {
                    worker_id: decode_hex(parts[1])?,
                    acquired_at: parse_u64(parts[2])?,
                    last_heartbeat_at: parse_u64(parts[3])?,
                    lease_secs: parse_u64(parts[4])?,
                    expires_at: parse_u64(parts[5])?,
                };
                snapshot.leases.insert(lease.worker_id.clone(), lease);
            }
            "claim" => {
                if parts.len() != 8 {
                    return Err(ReliabilityError::Parse(format!(
                        "invalid claim record '{}'",
                        line
                    )));
                }
                let claim = TaskClaim {
                    task_id: TaskId(Id(parse_u64(parts[1])?)),
                    run_id: RunId(Id(parse_u64(parts[2])?)),
                    worker_id: decode_hex(parts[3])?,
                    leased_at: parse_u64(parts[4])?,
                    lease_expires_at: parse_u64(parts[5])?,
                    attempt_count: parse_u32(parts[6])?,
                    max_attempts: parse_u32(parts[7])?,
                };
                snapshot.claims.insert(claim.task_id, claim);
            }
            kind => {
                return Err(ReliabilityError::Parse(format!(
                    "unknown lease snapshot record '{}'",
                    kind
                )));
            }
        }
    }

    Ok(snapshot)
}

fn parse_u64(input: &str) -> Result<u64, ReliabilityError> {
    input
        .parse::<u64>()
        .map_err(|_| ReliabilityError::Parse(format!("invalid u64 '{}'", input)))
}

fn parse_u32(input: &str) -> Result<u32, ReliabilityError> {
    input
        .parse::<u32>()
        .map_err(|_| ReliabilityError::Parse(format!("invalid u32 '{}'", input)))
}

fn encode_hex(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input.as_bytes() {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn decode_hex(input: &str) -> Result<String, ReliabilityError> {
    if input.len() % 2 != 0 {
        return Err(ReliabilityError::Parse("invalid hex length".to_string()));
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
        .map_err(|_| ReliabilityError::Parse("invalid utf-8 in hex".to_string()))
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn hex_to_nibble(value: u8) -> Result<u8, ReliabilityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ReliabilityError::Parse("invalid hex character".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_registry_persists_across_restart() {
        let shared = Arc::new(Mutex::new(None));
        let now = now_secs();

        {
            let store = InMemoryLeaseStore::from_shared(Arc::clone(&shared));
            let mut registry = WorkerLeaseRegistry::new(store).expect("new");
            registry
                .acquire_or_renew("worker-a", 60, now)
                .expect("acquire");
            registry
                .claim_task("worker-a", RunId(Id(11)), TaskId(Id(22)), 1, 3, now)
                .expect("claim");
            assert_eq!(registry.leases().len(), 1);
            assert_eq!(registry.active_claims().len(), 1);
        }

        {
            let store = InMemoryLeaseStore::from_shared(Arc::clone(&shared));
            let registry = WorkerLeaseRegistry::new(store).expect("reload");
            assert_eq!(registry.leases().len(), 1);
            assert_eq!(registry.active_claims().len(), 1);
            assert_eq!(registry.active_claims()[0].worker_id, "worker-a");
        }
    }

    #[test]
    fn expired_claims_are_reclaimed_with_retry_or_fail_decisions() {
        let store = InMemoryLeaseStore::default();
        let now = now_secs();
        let mut registry = WorkerLeaseRegistry::new(store).expect("new");

        registry
            .acquire_or_renew("worker-a", 1, now)
            .expect("acquire");
        registry
            .claim_task("worker-a", RunId(Id(1)), TaskId(Id(101)), 1, 3, now)
            .expect("claim retry");
        registry
            .claim_task("worker-a", RunId(Id(1)), TaskId(Id(102)), 3, 3, now)
            .expect("claim fail");

        let decisions = registry.recover_expired(now + 2).expect("recover");
        assert_eq!(decisions.len(), 2);

        let retry = decisions
            .iter()
            .find(|decision| decision.task_id == TaskId(Id(101)))
            .expect("retry decision");
        assert_eq!(retry.action, ReclaimAction::Requeue);

        let fail = decisions
            .iter()
            .find(|decision| decision.task_id == TaskId(Id(102)))
            .expect("fail decision");
        assert_eq!(fail.action, ReclaimAction::Fail);

        assert!(registry.active_claims().is_empty());
        assert!(registry.leases().is_empty());
    }

    #[test]
    fn heartbeat_extends_worker_and_claim_lease_windows() {
        let store = InMemoryLeaseStore::default();
        let now = now_secs();
        let mut registry = WorkerLeaseRegistry::new(store).expect("new");

        registry
            .acquire_or_renew("worker-a", 5, now)
            .expect("acquire");
        registry
            .claim_task("worker-a", RunId(Id(1)), TaskId(Id(7)), 1, 2, now)
            .expect("claim");

        assert!(registry.heartbeat("worker-a", now + 3).expect("heartbeat"));
        let claims = registry.active_claims();
        assert_eq!(claims.len(), 1);
        assert!(claims[0].lease_expires_at >= now + 8);
    }

    #[test]
    fn file_store_survives_restarts_and_fault_recovery() {
        let path = std::env::temp_dir().join(format!("moonlight-lease-{}.log", Id::next().0));
        let now = now_secs();

        {
            let store = FileLeaseStore::new(&path);
            let mut registry = WorkerLeaseRegistry::new(store).expect("new");
            registry
                .acquire_or_renew("worker-a", 1, now)
                .expect("acquire");
            registry
                .claim_task("worker-a", RunId(Id(91)), TaskId(Id(92)), 1, 2, now)
                .expect("claim");
        }

        {
            let store = FileLeaseStore::new(&path);
            let mut registry = WorkerLeaseRegistry::new(store).expect("reload");
            assert_eq!(registry.active_claims().len(), 1);
            let decisions = registry.recover_expired(now + 2).expect("recover");
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].action, ReclaimAction::Requeue);
            assert!(registry.active_claims().is_empty());
        }

        let _ = std::fs::remove_file(path);
    }
}
