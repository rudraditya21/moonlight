#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceBudget {
    pub name: String,
    pub max_total_ms: u64,
    pub min_throughput_ops_per_sec: u64,
    pub max_p95_latency_ms: Option<u64>,
}

impl PerformanceBudget {
    pub fn new(
        name: &str,
        max_total_ms: u64,
        min_throughput_ops_per_sec: u64,
        max_p95_latency_ms: Option<u64>,
    ) -> Self {
        Self {
            name: name.to_string(),
            max_total_ms,
            min_throughput_ops_per_sec,
            max_p95_latency_ms,
        }
    }

    pub fn evaluate(&self, sample: &PerformanceSample) -> PerformanceEvaluation {
        let throughput = if sample.total_elapsed_ms == 0 {
            sample.operations
        } else {
            sample
                .operations
                .saturating_mul(1000)
                .saturating_div(sample.total_elapsed_ms)
        };
        let p95_latency_ms = sample.p95_latency_ms();

        let mut failures = Vec::new();
        if sample.total_elapsed_ms > self.max_total_ms {
            failures.push(format!(
                "total elapsed {}ms exceeded budget {}ms",
                sample.total_elapsed_ms, self.max_total_ms
            ));
        }
        if throughput < self.min_throughput_ops_per_sec {
            failures.push(format!(
                "throughput {} ops/s below budget {} ops/s",
                throughput, self.min_throughput_ops_per_sec
            ));
        }
        if let (Some(actual), Some(max)) = (p95_latency_ms, self.max_p95_latency_ms) {
            if actual > max {
                failures.push(format!(
                    "p95 latency {}ms exceeded budget {}ms",
                    actual, max
                ));
            }
        }

        PerformanceEvaluation {
            budget_name: self.name.clone(),
            passed: failures.is_empty(),
            throughput_ops_per_sec: throughput,
            p95_latency_ms,
            failures,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceSample {
    pub operations: u64,
    pub total_elapsed_ms: u64,
    pub latencies_ms: Vec<u64>,
}

impl PerformanceSample {
    pub fn p95_latency_ms(&self) -> Option<u64> {
        percentile(&self.latencies_ms, 95)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerformanceEvaluation {
    pub budget_name: String,
    pub passed: bool,
    pub throughput_ops_per_sec: u64,
    pub p95_latency_ms: Option<u64>,
    pub failures: Vec<String>,
}

fn percentile(values: &[u64], percentile: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let p = percentile.min(100);
    let idx = ((p as f64 / 100.0) * (sorted.len().saturating_sub(1) as f64)).round() as usize;
    sorted.get(idx).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_passes_when_sample_meets_budget() {
        let budget = PerformanceBudget::new("dispatch", 5_000, 100, Some(100));
        let sample = PerformanceSample {
            operations: 1_000,
            total_elapsed_ms: 2_000,
            latencies_ms: vec![1, 2, 3, 50, 80],
        };
        let evaluation = budget.evaluate(&sample);
        assert!(evaluation.passed);
        assert!(evaluation.failures.is_empty());
    }

    #[test]
    fn evaluation_reports_failures_for_regression_gate() {
        let budget = PerformanceBudget::new("dispatch", 100, 5_000, Some(10));
        let sample = PerformanceSample {
            operations: 100,
            total_elapsed_ms: 2_000,
            latencies_ms: vec![20, 30, 40, 50],
        };
        let evaluation = budget.evaluate(&sample);
        assert!(!evaluation.passed);
        assert!(!evaluation.failures.is_empty());
    }
}
