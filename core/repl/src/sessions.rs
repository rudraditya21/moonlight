use std::collections::{BTreeMap, VecDeque};

use corelib::time::now_secs;
use modules::{ModuleError, ModuleSession};

const DEFAULT_STALE_TIMEOUT_SECS: u64 = 30 * 60;
const DEFAULT_MAX_PENDING_BYTES: usize = 1024 * 1024;
const DEFAULT_READ_DRAIN_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub id: u32,
    pub module_name: String,
    pub kind: String,
    pub target: String,
    pub is_open: bool,
    pub is_attached: bool,
    pub pending_bytes: usize,
    pub idle_secs: u64,
}

#[derive(Debug, Clone)]
pub struct SessionPollOutcome {
    pub id: u32,
    pub bytes_read: usize,
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

    pub fn write(&mut self, input: &[u8], now: u64) -> Result<(), ModuleError> {
        self.handle.write(input).map(|_| {
            self.last_activity_at = now;
        })
    }

    pub fn poll(&mut self, now: u64, max_pending_bytes: usize) -> Result<usize, ModuleError> {
        let data = self.handle.read()?;
        let bytes = data.len();
        if bytes > 0 {
            self.last_activity_at = now;
            self.enqueue_pending(data, max_pending_bytes);
        }
        Ok(bytes)
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
        self.last_activity_at = now;
        Ok(())
    }

    pub fn detach(&mut self, now: u64) -> Result<(), SessionManagerError> {
        if !self.attached {
            return Err(SessionManagerError::NotAttached(self.id));
        }
        self.attached = false;
        self.last_activity_at = now;
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
}

pub struct SessionManager {
    next_id: u32,
    entries: BTreeMap<u32, SessionEntry>,
    stale_timeout_secs: u64,
    max_pending_bytes: usize,
    default_drain_bytes: usize,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::with_config(DEFAULT_STALE_TIMEOUT_SECS, DEFAULT_MAX_PENDING_BYTES)
    }

    pub fn with_config(stale_timeout_secs: u64, max_pending_bytes: usize) -> Self {
        Self {
            next_id: 1,
            entries: BTreeMap::new(),
            stale_timeout_secs,
            max_pending_bytes: max_pending_bytes.max(1),
            default_drain_bytes: DEFAULT_READ_DRAIN_BYTES,
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
        let bytes = entry.poll(now, self.max_pending_bytes)?;
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
                    error: None,
                }),
                Err(err) => outcomes.push(SessionPollOutcome {
                    id,
                    bytes_read: 0,
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
                if !entry.is_open() || entry.attached {
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
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummySession {
        open: bool,
        pending_reads: VecDeque<Vec<u8>>,
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
            Ok(self.pending_reads.pop_front().unwrap_or_default())
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
        a.pending_reads.push_back(b"alpha".to_vec());
        let mut b = DummySession::new();
        b.pending_reads.push_back(b"beta".to_vec());
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
}
