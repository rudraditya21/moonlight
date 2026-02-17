use std::collections::BTreeMap;

use modules::{ModuleError, ModuleSession};

#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub id: u32,
    pub module_name: String,
    pub kind: String,
    pub target: String,
    pub is_open: bool,
}

pub struct SessionEntry {
    id: u32,
    module_name: String,
    kind: String,
    target: String,
    handle: Box<dyn ModuleSession>,
}

impl SessionEntry {
    pub fn is_open(&self) -> bool {
        self.handle.is_open()
    }

    pub fn write(&mut self, input: &[u8]) -> Result<(), ModuleError> {
        self.handle.write(input)
    }

    pub fn read(&mut self) -> Result<Vec<u8>, ModuleError> {
        self.handle.read()
    }

    pub fn close(&mut self) -> Result<(), ModuleError> {
        self.handle.close()
    }
}

pub struct SessionManager {
    next_id: u32,
    entries: BTreeMap<u32, SessionEntry>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            entries: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, module_name: String, session: Box<dyn ModuleSession>) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let kind = session.kind().to_string();
        let target = session.target();
        self.entries.insert(
            id,
            SessionEntry {
                id,
                module_name,
                kind,
                target,
                handle: session,
            },
        );
        id
    }

    pub fn snapshots(&self) -> Vec<SessionSnapshot> {
        self.entries
            .values()
            .map(|entry| SessionSnapshot {
                id: entry.id,
                module_name: entry.module_name.clone(),
                kind: entry.kind.clone(),
                target: entry.target.clone(),
                is_open: entry.is_open(),
            })
            .collect()
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut SessionEntry> {
        self.entries.get_mut(&id)
    }

    pub fn close_and_remove(&mut self, id: u32) -> Result<bool, ModuleError> {
        let Some(mut entry) = self.entries.remove(&id) else {
            return Ok(false);
        };
        entry.close()?;
        Ok(true)
    }

    pub fn close_all(&mut self) -> Result<usize, ModuleError> {
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
        buf: Vec<u8>,
    }

    impl DummySession {
        fn new() -> Self {
            Self {
                open: true,
                buf: Vec::new(),
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
            self.buf.extend_from_slice(input);
            Ok(())
        }

        fn read(&mut self) -> Result<Vec<u8>, ModuleError> {
            Ok(std::mem::take(&mut self.buf))
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
}
