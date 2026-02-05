use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Timeout {
    duration: Duration,
}

impl Timeout {
    pub fn from_millis(ms: u64) -> Self {
        Timeout {
            duration: Duration::from_millis(ms),
        }
    }

    pub fn from_secs(secs: u64) -> Self {
        Timeout {
            duration: Duration::from_secs(secs),
        }
    }

    pub fn as_duration(&self) -> Duration {
        self.duration
    }
}
