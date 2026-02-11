use corelib::error::{CoreError, CoreResult};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(5),
            write: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub base_delay: Duration,
    pub backoff_factor: f64,
    pub jitter: f64,
}

impl RetryPolicy {
    pub fn new(max_attempts: usize, base_delay: Duration) -> CoreResult<Self> {
        if max_attempts == 0 {
            return Err(CoreError::Parse("max_attempts must be > 0".to_string()));
        }
        Ok(Self {
            max_attempts,
            base_delay,
            backoff_factor: 2.0,
            jitter: 0.1,
        })
    }

    pub fn delay_for_attempt(&self, attempt: usize, seed: u64) -> Duration {
        let pow = (attempt.saturating_sub(1)) as u32;
        let base = self
            .base_delay
            .mul_f64(self.backoff_factor.powi(pow as i32));
        if self.jitter <= 0.0 {
            return base;
        }
        let jitter = pseudo_random_f64(seed) * self.jitter * base.as_secs_f64();
        Duration::from_secs_f64(base.as_secs_f64() + jitter)
    }
}

#[derive(Debug, Clone)]
pub struct Negotiation<T: Copy + Eq> {
    pub client: Vec<T>,
    pub server: Vec<T>,
}

impl<T: Copy + Eq> Negotiation<T> {
    pub fn pick_first_common(&self) -> CoreResult<T> {
        for client in &self.client {
            if self.server.contains(client) {
                return Ok(*client);
            }
        }
        Err(CoreError::Message("no common option".to_string()))
    }
}

fn pseudo_random_f64(seed: u64) -> f64 {
    let mut x = seed ^ 0x9e3779b97f4a7c15;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let value = x.wrapping_mul(0x2545f4914f6cdd1d);
    (value as f64) / (u64::MAX as f64)
}
