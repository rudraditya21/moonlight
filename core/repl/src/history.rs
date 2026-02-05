#[derive(Debug, Clone)]
pub struct History {
    entries: Vec<String>,
    max_entries: usize,
}

impl History {
    pub fn new(max_entries: usize) -> Self {
        History {
            entries: Vec::new(),
            max_entries,
        }
    }

    pub fn add(&mut self, entry: String) {
        if entry.trim().is_empty() {
            return;
        }
        if self.entries.len() == self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, &String)> {
        self.entries.iter().enumerate()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
