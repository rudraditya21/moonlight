use std::collections::{BTreeMap, VecDeque};

use corelib::time::now_secs;
use modules::{ModuleError, ModuleSession};

const DEFAULT_STALE_TIMEOUT_SECS: u64 = 30 * 60;
const DEFAULT_MAX_PENDING_BYTES: usize = 1024 * 1024;
const DEFAULT_READ_DRAIN_BYTES: usize = 64 * 1024;
const DEFAULT_PARTITION_ERROR_THRESHOLD: u32 = 3;
const DEFAULT_PARTITION_GRACE_SECS: u64 = 5 * 60;

#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub id: u32,
    pub module_name: String,
    pub kind: String,
    pub target: String,
    pub is_open: bool,
    pub is_attached: bool,
    pub is_partitioned: bool,
    pub partition_age_secs: Option<u64>,
    pub consecutive_errors: u32,
    pub pending_bytes: usize,
    pub idle_secs: u64,
}

#[derive(Debug, Clone)]
pub struct SessionPollOutcome {
    pub id: u32,
    pub bytes_read: usize,
    pub is_partitioned: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub enum SessionManagerError {
    NotFound(u32),
    AlreadyAttached(u32),
    NotAttached(u32),
    Closed(u32),
    Module(ModuleError),
}

impl std::fmt::Display for SessionManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionManagerError::NotFound(id) => write!(f, "session {id} not found"),
            SessionManagerError::AlreadyAttached(id) => {
                write!(f, "session {id} is already attached")
            }
            SessionManagerError::NotAttached(id) => write!(f, "session {id} is not attached"),
            SessionManagerError::Closed(id) => write!(f, "session {id} is closed"),
            SessionManagerError::Module(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SessionManagerError {}

impl From<ModuleError> for SessionManagerError {
    fn from(value: ModuleError) -> Self {
        SessionManagerError::Module(value)
    }
}

pub struct SessionEntry {
    id: u32,
    module_name: String,
    kind: String,
    target: String,
    handle: Box<dyn ModuleSession>,
    attached: bool,
    last_activity_at: u64,
    consecutive_errors: u32,
    partitioned_since: Option<u64>,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
}

impl SessionEntry {
    fn new(id: u32, module_name: String, session: Box<dyn ModuleSession>, now: u64) -> Self {
        let kind = session.kind().to_string();
        let target = session.target();
        Self {
            id,
            module_name,
            kind,
            target,
            handle: session,
            attached: false,
            last_activity_at: now,
            consecutive_errors: 0,
            partitioned_since: None,
            pending: VecDeque::new(),
            pending_bytes: 0,
        }
    }

    pub fn is_open(&self) -> bool {
        self.handle.is_open()
    }

    pub fn is_attached(&self) -> bool {
        self.attached
    }

    pub fn is_partitioned(&self) -> bool {
        self.partitioned_since.is_some()
    }

    pub fn partition_age_secs(&self, now: u64) -> Option<u64> {
        self.partitioned_since
            .map(|since| now.saturating_sub(since))
    }

    pub fn write(&mut self, input: &[u8], now: u64) -> Result<(), ModuleError> {
        if self.is_partitioned() {
            return Err(ModuleError::Execution(
                "session is partitioned; waiting for recovery".to_string(),
            ));
        }
        self.handle.write(input).map(|_| {
            self.mark_poll_success(now);
        })
    }

    pub fn poll(
        &mut self,
        now: u64,
        max_pending_bytes: usize,
        partition_error_threshold: u32,
    ) -> Result<usize, ModuleError> {
        match self.handle.read() {
            Ok(data) => {
                let bytes = data.len();
                if bytes > 0 {
                    self.last_activity_at = now;
                    self.enqueue_pending(data, max_pending_bytes);
                }
                self.mark_poll_success(now);
                Ok(bytes)
            }
            Err(err) => {
                self.mark_poll_error(now, partition_error_threshold);
                Err(err)
            }
        }
    }

    pub fn close(&mut self) -> Result<(), ModuleError> {
        self.attached = false;
        self.handle.close()
    }

    pub fn idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_activity_at)
    }

    pub fn is_stale(&self, now: u64, stale_timeout_secs: u64) -> bool {
        self.idle_secs(now) >= stale_timeout_secs
    }

    pub fn attach(&mut self, now: u64) -> Result<(), SessionManagerError> {
        if !self.is_open() {
            return Err(SessionManagerError::Closed(self.id));
        }
        if self.attached {
            return Err(SessionManagerError::AlreadyAttached(self.id));
        }
        self.attached = true;
        self.mark_poll_success(now);
        Ok(())
    }

    pub fn detach(&mut self, now: u64) -> Result<(), SessionManagerError> {
        if !self.attached {
            return Err(SessionManagerError::NotAttached(self.id));
        }
        self.attached = false;
        self.mark_poll_success(now);
        Ok(())
    }

    pub fn enqueue_pending(&mut self, mut chunk: Vec<u8>, max_pending_bytes: usize) {
        if chunk.is_empty() {
            return;
        }
        if chunk.len() > max_pending_bytes {
            let keep_from = chunk.len().saturating_sub(max_pending_bytes);
            chunk = chunk.split_off(keep_from);
        }
        while self.pending_bytes + chunk.len() > max_pending_bytes {
            let Some(oldest) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes = self.pending_bytes.saturating_sub(oldest.len());
        }
        self.pending_bytes += chunk.len();
        self.pending.push_back(chunk);
    }

    pub fn drain_pending(&mut self, max_bytes: usize) -> Vec<u8> {
        if max_bytes == 0 || self.pending.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        while out.len() < max_bytes {
            let Some(mut chunk) = self.pending.pop_front() else {
                break;
            };
            let remaining = max_bytes.saturating_sub(out.len());
            if chunk.len() <= remaining {
                self.pending_bytes = self.pending_bytes.saturating_sub(chunk.len());
                out.extend_from_slice(&chunk);
                continue;
            }
            out.extend_from_slice(&chunk[..remaining]);
            let tail = chunk.split_off(remaining);
            self.pending.push_front(tail);
            self.pending_bytes = self.pending_bytes.saturating_sub(remaining);
            break;
        }
        out
    }

    fn enforce_pending_limit(&mut self, max_pending_bytes: usize) {
        let cap = max_pending_bytes.max(1);
        if self.pending_bytes <= cap {
            return;
        }
        let mut merged = Vec::with_capacity(self.pending_bytes);
        while let Some(chunk) = self.pending.pop_front() {
            merged.extend_from_slice(&chunk);
        }
        if merged.len() > cap {
            let keep_from = merged.len().saturating_sub(cap);
            merged = merged.split_off(keep_from);
        }
        self.pending_bytes = merged.len();
        if !merged.is_empty() {
            self.pending.push_back(merged);
        }
    }

    fn mark_poll_success(&mut self, now: u64) {
        self.last_activity_at = now;
        self.consecutive_errors = 0;
        self.partitioned_since = None;
    }

    fn mark_poll_error(&mut self, now: u64, threshold: u32) {
        self.consecutive_errors = self.consecutive_errors.saturating_add(1);
        if self.consecutive_errors >= threshold.max(1) && self.partitioned_since.is_none() {
            self.partitioned_since = Some(now);
        }
    }
}

pub struct SessionManager {
    next_id: u32,
    entries: BTreeMap<u32, SessionEntry>,
    stale_timeout_secs: u64,
    max_pending_bytes: usize,
    default_drain_bytes: usize,
    partition_error_threshold: u32,
    partition_grace_secs: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_STALE_TIMEOUT_SECS, DEFAULT_MAX_PENDING_BYTES)
    }

    pub fn with_config(stale_timeout_secs: u64, max_pending_bytes: usize) -> Self {
        Self::with_fault_config(
            stale_timeout_secs,
            max_pending_bytes,
            DEFAULT_PARTITION_ERROR_THRESHOLD,
            DEFAULT_PARTITION_GRACE_SECS,
        )
    }

    pub fn with_fault_config(
        stale_timeout_secs: u64,
        max_pending_bytes: usize,
        partition_error_threshold: u32,
        partition_grace_secs: u64,
    ) -> Self {
        Self {
            next_id: 1,
            entries: BTreeMap::new(),
            stale_timeout_secs,
            max_pending_bytes: max_pending_bytes.max(1),
            default_drain_bytes: DEFAULT_READ_DRAIN_BYTES,
            partition_error_threshold: partition_error_threshold.max(1),
            partition_grace_secs,
        }
    }

    pub fn register(&mut self, module_name: String, session: Box<dyn ModuleSession>) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let now = now_secs();
        self.entries
            .insert(id, SessionEntry::new(id, module_name, session, now));
        id
    }

    pub fn has(&self, id: u32) -> bool {
        self.entries.contains_key(&id)
    }

    pub fn max_pending_bytes(&self) -> usize {
        self.max_pending_bytes
    }

    pub fn set_max_pending_bytes(&mut self, max_pending_bytes: usize) {
        self.max_pending_bytes = max_pending_bytes.max(1);
        for entry in self.entries.values_mut() {
            entry.enforce_pending_limit(self.max_pending_bytes);
        }
    }

    pub fn default_drain_bytes(&self) -> usize {
        self.default_drain_bytes
    }

    pub fn set_default_drain_bytes(&mut self, default_drain_bytes: usize) {
        self.default_drain_bytes = default_drain_bytes.max(1);
    }

    pub fn is_attached(&self, id: u32) -> bool {
        self.entries
            .get(&id)
            .map(|entry| entry.attached)
            .unwrap_or(false)
    }

    pub fn attach(&mut self, id: u32) -> Result<(), SessionManagerError> {
        let now = now_secs();
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(SessionManagerError::NotFound(id))?;
        entry.attach(now)
    }

    pub fn detach(&mut self, id: u32) -> Result<(), SessionManagerError> {
        let now = now_secs();
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(SessionManagerError::NotFound(id))?;
        entry.detach(now)
    }

    pub fn snapshots(&self) -> Vec<SessionSnapshot> {
        let now = now_secs();
        self.entries
            .values()
            .map(|entry| SessionSnapshot {
                id: entry.id,
                module_name: entry.module_name.clone(),
                kind: entry.kind.clone(),
                target: entry.target.clone(),
                is_open: entry.is_open(),
                is_attached: entry.is_attached(),
                is_partitioned: entry.is_partitioned(),
                partition_age_secs: entry.partition_age_secs(now),
                consecutive_errors: entry.consecutive_errors,
                pending_bytes: entry.pending_bytes,
                idle_secs: now.saturating_sub(entry.last_activity_at),
            })
            .collect()
    }

    pub fn write(&mut self, id: u32, input: &[u8]) -> Result<(), SessionManagerError> {
        let now = now_secs();
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(SessionManagerError::NotFound(id))?;
        if !entry.is_open() {
            return Err(SessionManagerError::Closed(id));
        }
        entry.write(input, now)?;
        Ok(())
    }

    pub fn poll(&mut self, id: u32) -> Result<usize, SessionManagerError> {
        let now = now_secs();
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(SessionManagerError::NotFound(id))?;
        if !entry.is_open() {
            return Ok(0);
        }
        let bytes = entry.poll(now, self.max_pending_bytes, self.partition_error_threshold)?;
        Ok(bytes)
    }

    pub fn poll_all(&mut self) -> Vec<SessionPollOutcome> {
        let ids: Vec<u32> = self.entries.keys().copied().collect();
        let mut outcomes = Vec::with_capacity(ids.len());
        for id in ids {
            match self.poll(id) {
                Ok(bytes) => outcomes.push(SessionPollOutcome {
                    id,
                    bytes_read: bytes,
                    is_partitioned: self
                        .entries
                        .get(&id)
                        .map(|entry| entry.is_partitioned())
                        .unwrap_or(false),
                    error: None,
                }),
                Err(err) => outcomes.push(SessionPollOutcome {
                    id,
                    bytes_read: 0,
                    is_partitioned: self
                        .entries
                        .get(&id)
                        .map(|entry| entry.is_partitioned())
                        .unwrap_or(false),
                    error: Some(err.to_string()),
                }),
            }
        }
        outcomes
    }

    pub fn read_buffered(&mut self, id: u32) -> Result<Vec<u8>, SessionManagerError> {
        self.read_buffered_limited(id, self.default_drain_bytes)
    }

    pub fn read_buffered_limited(
        &mut self,
        id: u32,
        max_bytes: usize,
    ) -> Result<Vec<u8>, SessionManagerError> {
        let now = now_secs();
        let entry = self
            .entries
            .get_mut(&id)
            .ok_or(SessionManagerError::NotFound(id))?;
        let chunk = entry.drain_pending(max_bytes);
        if !chunk.is_empty() {
            entry.last_activity_at = now;
        }
        Ok(chunk)
    }

    pub fn read_all_background(&mut self) -> Vec<(u32, Vec<u8>)> {
        let ids: Vec<u32> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| (!entry.attached).then_some(*id))
            .collect();
        let mut out = Vec::new();
        for id in ids {
            if let Ok(data) = self.read_buffered(id) {
                if !data.is_empty() {
                    out.push((id, data));
                }
            }
        }
        out
    }

    pub fn close_and_remove(&mut self, id: u32) -> Result<bool, SessionManagerError> {
        let Some(mut entry) = self.entries.remove(&id) else {
            return Ok(false);
        };
        entry.close()?;
        Ok(true)
    }

    pub fn close_all(&mut self) -> Result<usize, SessionManagerError> {
        let ids: Vec<u32> = self.entries.keys().copied().collect();
        let mut closed = 0usize;
        for id in ids {
            if self.close_and_remove(id)? {
                closed += 1;
            }
        }
        Ok(closed)
    }

    pub fn reap_closed(&mut self) -> usize {
        let ids: Vec<u32> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| if entry.is_open() { None } else { Some(*id) })
            .collect();
        let count = ids.len();
        for id in ids {
            self.entries.remove(&id);
        }
        count
    }

    pub fn reap_stale(&mut self) -> Vec<u32> {
        let now = now_secs();
        let stale_ids: Vec<u32> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                if !entry.is_open() || entry.attached || entry.is_partitioned() {
                    return None;
                }
                if entry.is_stale(now, self.stale_timeout_secs) {
                    return Some(*id);
                }
                None
            })
            .collect();
        let mut reaped = Vec::with_capacity(stale_ids.len());
        for id in stale_ids {
            if let Some(mut entry) = self.entries.remove(&id) {
                let _ = entry.close();
                reaped.push(id);
            }
        }
        reaped
    }

    pub fn recover_partitioned(&mut self) -> Vec<u32> {
        let ids: Vec<u32> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                if entry.is_open() && entry.is_partitioned() {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let mut recovered = Vec::new();
        for id in ids {
            if self.poll(id).is_ok()
                && self
                    .entries
                    .get(&id)
                    .map(|entry| !entry.is_partitioned())
                    .unwrap_or(false)
            {
                recovered.push(id);
            }
        }
        recovered
    }

    pub fn reap_partitioned(&mut self) -> Vec<u32> {
        let now = now_secs();
        let ids: Vec<u32> = self
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                if entry.attached || !entry.is_partitioned() {
                    return None;
                }
                let age = entry.partition_age_secs(now).unwrap_or(0);
                if age >= self.partition_grace_secs {
                    return Some(*id);
                }
                None
            })
            .collect();

        let mut reaped = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(mut entry) = self.entries.remove(&id) {
                let _ = entry.close();
                reaped.push(id);
            }
        }
        reaped
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corelib::performance::{PerformanceBudget, PerformanceSample};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    struct DummySession {
        open: bool,
        pending_reads: VecDeque<Result<Vec<u8>, ModuleError>>,
        writes: Vec<Vec<u8>>,
    }

    impl DummySession {
        fn new() -> Self {
            Self {
                open: true,
                pending_reads: VecDeque::new(),
                writes: Vec::new(),
            }
        }
    }

    impl ModuleSession for DummySession {
        fn kind(&self) -> &'static str {
            "dummy"
        }

        fn target(&self) -> String {
            "127.0.0.1:0".to_string()
        }

        fn is_open(&self) -> bool {
            self.open
        }

        fn write(&mut self, input: &[u8]) -> Result<(), ModuleError> {
            self.writes.push(input.to_vec());
            Ok(())
        }

        fn read(&mut self) -> Result<Vec<u8>, ModuleError> {
            self.pending_reads
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()))
        }

        fn close(&mut self) -> Result<(), ModuleError> {
            self.open = false;
            Ok(())
        }
    }

    #[test]
    fn manager_registers_and_closes() {
        let mut manager = SessionManager::new();
        let id = manager.register("aux/test".to_string(), Box::new(DummySession::new()));
        assert_eq!(id, 1);
        assert_eq!(manager.snapshots().len(), 1);
        let closed = manager.close_and_remove(id).expect("close");
        assert!(closed);
        assert!(manager.snapshots().is_empty());
    }

    #[test]
    fn manager_attach_detach_flow() {
        let mut manager = SessionManager::new();
        let id = manager.register("aux/test".to_string(), Box::new(DummySession::new()));
        manager.attach(id).expect("attach");
        assert!(manager.is_attached(id));
        manager.detach(id).expect("detach");
        assert!(!manager.is_attached(id));
    }

    #[test]
    fn manager_multiplex_poll_and_buffer_reads() {
        let mut manager = SessionManager::new();
        let mut a = DummySession::new();
        a.pending_reads.push_back(Ok(b"alpha".to_vec()));
        let mut b = DummySession::new();
        b.pending_reads.push_back(Ok(b"beta".to_vec()));
        let a_id = manager.register("aux/a".to_string(), Box::new(a));
        let b_id = manager.register("aux/b".to_string(), Box::new(b));

        let outcomes = manager.poll_all();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(manager.read_buffered(a_id).expect("read a"), b"alpha");
        assert_eq!(manager.read_buffered(b_id).expect("read b"), b"beta");
    }

    #[test]
    fn manager_reaps_stale_background_sessions() {
        let mut manager = SessionManager::with_config(0, 1024);
        let stale_id = manager.register("aux/a".to_string(), Box::new(DummySession::new()));
        let attached_id = manager.register("aux/b".to_string(), Box::new(DummySession::new()));
        manager.attach(attached_id).expect("attach");

        let reaped = manager.reap_stale();
        assert_eq!(reaped, vec![stale_id]);
        assert!(!manager.has(stale_id));
        assert!(manager.has(attached_id));
    }

    #[test]
    fn manager_detects_and_recovers_partitioned_sessions() {
        let mut manager = SessionManager::with_fault_config(30, 1024, 2, 300);
        let mut flaky = DummySession::new();
        flaky
            .pending_reads
            .push_back(Err(ModuleError::Execution("network timeout".to_string())));
        flaky
            .pending_reads
            .push_back(Err(ModuleError::Execution("network timeout".to_string())));
        flaky.pending_reads.push_back(Ok(b"recovered".to_vec()));

        let id = manager.register("aux/flaky".to_string(), Box::new(flaky));

        let first = manager.poll(id);
        assert!(first.is_err());
        assert!(!manager.snapshots()[0].is_partitioned);

        let second = manager.poll(id);
        assert!(second.is_err());
        assert!(manager.snapshots()[0].is_partitioned);

        let recovered = manager.recover_partitioned();
        assert_eq!(recovered, vec![id]);
        assert!(!manager.snapshots()[0].is_partitioned);
        assert_eq!(manager.read_buffered(id).expect("read"), b"recovered");
    }

    #[test]
    fn manager_reaps_partitioned_sessions_after_grace_period() {
        let mut manager = SessionManager::with_fault_config(30, 1024, 1, 0);
        let mut flaky = DummySession::new();
        flaky
            .pending_reads
            .push_back(Err(ModuleError::Execution("partition".to_string())));
        let id = manager.register("aux/flaky".to_string(), Box::new(flaky));

        let poll = manager.poll(id);
        assert!(poll.is_err());
        assert!(manager.snapshots()[0].is_partitioned);

        let reaped = manager.reap_partitioned();
        assert_eq!(reaped, vec![id]);
        assert!(!manager.has(id));
    }

    #[test]
    fn manager_tunes_backpressure_limit_and_trims_existing_buffers() {
        let mut manager = SessionManager::with_config(30, 64);
        let mut session = DummySession::new();
        session.pending_reads.push_back(Ok((0u8..80u8).collect()));
        let id = manager.register("aux/buffer".to_string(), Box::new(session));

        manager.poll(id).expect("poll");
        let before = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.id == id)
            .expect("snapshot");
        assert_eq!(before.pending_bytes, 64);

        manager.set_max_pending_bytes(16);
        assert_eq!(manager.max_pending_bytes(), 16);
        manager.set_default_drain_bytes(8);
        assert_eq!(manager.default_drain_bytes(), 8);

        let after = manager
            .snapshots()
            .into_iter()
            .find(|snapshot| snapshot.id == id)
            .expect("snapshot");
        assert_eq!(after.pending_bytes, 16);
        let drained = manager.read_buffered(id).expect("drain");
        assert_eq!(drained.len(), 8);
        assert_eq!(drained, (64u8..72u8).collect::<Vec<u8>>());
    }

    #[test]
    fn concurrent_session_polling_meets_scale_budget() {
        const SESSION_COUNT: usize = 96;
        const CHUNKS_PER_SESSION: usize = 20;
        const CHUNK_SIZE: usize = 256;
        const WORKERS: usize = 6;

        let mut manager = SessionManager::with_config(30, 4096);
        let mut ids = Vec::with_capacity(SESSION_COUNT);
        for session_idx in 0..SESSION_COUNT {
            let mut session = DummySession::new();
            for chunk_idx in 0..CHUNKS_PER_SESSION {
                let value = ((session_idx + chunk_idx) % 255) as u8;
                session.pending_reads.push_back(Ok(vec![value; CHUNK_SIZE]));
            }
            ids.push(manager.register("aux/load".to_string(), Box::new(session)));
        }

        let manager = Arc::new(Mutex::new(manager));
        let started = Instant::now();
        let mut workers = Vec::with_capacity(WORKERS);

        for worker_idx in 0..WORKERS {
            let manager = Arc::clone(&manager);
            let worker_ids: Vec<u32> = ids
                .iter()
                .copied()
                .enumerate()
                .filter_map(|(idx, id)| (idx % WORKERS == worker_idx).then_some(id))
                .collect();
            workers.push(thread::spawn(move || {
                let mut drained = 0u64;
                let mut operations = 0u64;
                let mut latencies = Vec::<u64>::new();

                for _ in 0..CHUNKS_PER_SESSION {
                    for id in &worker_ids {
                        let call_started = Instant::now();
                        let bytes = {
                            let mut guard = manager.lock().expect("lock");
                            guard.poll(*id).expect("poll");
                            guard.read_buffered_limited(*id, CHUNK_SIZE).expect("read")
                        };
                        if !bytes.is_empty() {
                            drained = drained.saturating_add(bytes.len() as u64);
                            operations = operations.saturating_add(1);
                            latencies.push(call_started.elapsed().as_millis() as u64);
                        }
                    }
                }
                (drained, operations, latencies)
            }));
        }

        let mut total_drained = 0u64;
        let mut total_operations = 0u64;
        let mut latencies_ms = Vec::<u64>::new();
        for worker in workers {
            let (drained, operations, mut worker_latencies) = worker.join().expect("worker");
            total_drained = total_drained.saturating_add(drained);
            total_operations = total_operations.saturating_add(operations);
            latencies_ms.append(&mut worker_latencies);
        }
        let elapsed_ms = started.elapsed().as_millis() as u64;

        let expected_bytes = (SESSION_COUNT * CHUNKS_PER_SESSION * CHUNK_SIZE) as u64;
        assert_eq!(total_drained, expected_bytes);
        assert_eq!(
            total_operations,
            (SESSION_COUNT * CHUNKS_PER_SESSION) as u64
        );

        let snapshots = manager.lock().expect("lock").snapshots();
        for snapshot in snapshots {
            assert_eq!(snapshot.pending_bytes, 0);
            assert!(snapshot.is_open);
        }

        let budget =
            PerformanceBudget::new("session_manager_concurrent_poll", 30_000, 150, Some(25));
        let evaluation = budget.evaluate(&PerformanceSample {
            operations: total_operations,
            total_elapsed_ms: elapsed_ms,
            latencies_ms,
        });
        assert!(
            evaluation.passed,
            "session load regression gate failed: {:?}",
            evaluation.failures
        );
    }
}
