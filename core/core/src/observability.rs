use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::control::ControlStateError;
use crate::domain::{CorrelationId, RunId, SessionId, TaskId};
use crate::error::CoreError;
use crate::ids::Id;
use crate::orchestrator::OrchestratorError;
use crate::time::{now_millis, now_secs};

const STRUCTURED_LOG_HEADER: &str = "moonlight-structured-log:v1";

#[derive(Debug)]
pub enum ObservabilityError {
    Validation(String),
    NotFound(String),
    Storage(String),
    Parse(String),
}

impl fmt::Display for ObservabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservabilityError::Validation(msg) => write!(f, "validation error: {msg}"),
            ObservabilityError::NotFound(msg) => write!(f, "not found: {msg}"),
            ObservabilityError::Storage(msg) => write!(f, "storage error: {msg}"),
            ObservabilityError::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for ObservabilityError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TelemetryLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl TelemetryLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            TelemetryLevel::Error => "error",
            TelemetryLevel::Warn => "warn",
            TelemetryLevel::Info => "info",
            TelemetryLevel::Debug => "debug",
            TelemetryLevel::Trace => "trace",
        }
    }
}

fn parse_telemetry_level(raw: &str) -> Result<TelemetryLevel, ObservabilityError> {
    match raw {
        "error" => Ok(TelemetryLevel::Error),
        "warn" => Ok(TelemetryLevel::Warn),
        "info" => Ok(TelemetryLevel::Info),
        "debug" => Ok(TelemetryLevel::Debug),
        "trace" => Ok(TelemetryLevel::Trace),
        _ => Err(ObservabilityError::Parse(format!(
            "invalid telemetry level '{}'",
            raw
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCategory {
    Validation,
    NotFound,
    Storage,
    Parse,
    Timeout,
    Cancellation,
    Internal,
}

impl ErrorCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::Validation => "validation",
            ErrorCategory::NotFound => "not_found",
            ErrorCategory::Storage => "storage",
            ErrorCategory::Parse => "parse",
            ErrorCategory::Timeout => "timeout",
            ErrorCategory::Cancellation => "cancellation",
            ErrorCategory::Internal => "internal",
        }
    }
}

fn parse_error_category(raw: &str) -> Result<ErrorCategory, ObservabilityError> {
    match raw {
        "validation" => Ok(ErrorCategory::Validation),
        "not_found" => Ok(ErrorCategory::NotFound),
        "storage" => Ok(ErrorCategory::Storage),
        "parse" => Ok(ErrorCategory::Parse),
        "timeout" => Ok(ErrorCategory::Timeout),
        "cancellation" => Ok(ErrorCategory::Cancellation),
        "internal" => Ok(ErrorCategory::Internal),
        _ => Err(ObservabilityError::Parse(format!(
            "invalid error category '{}'",
            raw
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    CoreIo,
    CoreParse,
    CoreMessage,
    OrchestratorValidation,
    OrchestratorNotFound,
    OrchestratorStorage,
    OrchestratorParse,
    OrchestratorDomain,
    ControlValidation,
    ControlNotFound,
    ControlStorage,
    ControlParse,
    ControlDomain,
    ObservabilityValidation,
    ObservabilityStorage,
    ObservabilityParse,
    ExecutionTimeout,
    ExecutionCanceled,
    Unknown,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::CoreIo => "ML-CORE-0001",
            ErrorCode::CoreParse => "ML-CORE-0002",
            ErrorCode::CoreMessage => "ML-CORE-0003",
            ErrorCode::OrchestratorValidation => "ML-ORCH-0001",
            ErrorCode::OrchestratorNotFound => "ML-ORCH-0002",
            ErrorCode::OrchestratorStorage => "ML-ORCH-0003",
            ErrorCode::OrchestratorParse => "ML-ORCH-0004",
            ErrorCode::OrchestratorDomain => "ML-ORCH-0005",
            ErrorCode::ControlValidation => "ML-CTRL-0001",
            ErrorCode::ControlNotFound => "ML-CTRL-0002",
            ErrorCode::ControlStorage => "ML-CTRL-0003",
            ErrorCode::ControlParse => "ML-CTRL-0004",
            ErrorCode::ControlDomain => "ML-CTRL-0005",
            ErrorCode::ObservabilityValidation => "ML-OBS-0001",
            ErrorCode::ObservabilityStorage => "ML-OBS-0002",
            ErrorCode::ObservabilityParse => "ML-OBS-0003",
            ErrorCode::ExecutionTimeout => "ML-EXEC-0001",
            ErrorCode::ExecutionCanceled => "ML-EXEC-0002",
            ErrorCode::Unknown => "ML-GEN-0001",
        }
    }

    pub const fn default_category(self) -> ErrorCategory {
        match self {
            ErrorCode::CoreIo | ErrorCode::OrchestratorStorage | ErrorCode::ControlStorage => {
                ErrorCategory::Storage
            }
            ErrorCode::CoreParse | ErrorCode::OrchestratorParse | ErrorCode::ControlParse => {
                ErrorCategory::Parse
            }
            ErrorCode::OrchestratorValidation
            | ErrorCode::ControlValidation
            | ErrorCode::ObservabilityValidation => ErrorCategory::Validation,
            ErrorCode::OrchestratorNotFound | ErrorCode::ControlNotFound => ErrorCategory::NotFound,
            ErrorCode::ExecutionTimeout => ErrorCategory::Timeout,
            ErrorCode::ExecutionCanceled => ErrorCategory::Cancellation,
            ErrorCode::CoreMessage
            | ErrorCode::OrchestratorDomain
            | ErrorCode::ControlDomain
            | ErrorCode::ObservabilityStorage
            | ErrorCode::ObservabilityParse
            | ErrorCode::Unknown => ErrorCategory::Internal,
        }
    }
}

fn parse_error_code(raw: &str) -> Result<ErrorCode, ObservabilityError> {
    match raw {
        "ML-CORE-0001" => Ok(ErrorCode::CoreIo),
        "ML-CORE-0002" => Ok(ErrorCode::CoreParse),
        "ML-CORE-0003" => Ok(ErrorCode::CoreMessage),
        "ML-ORCH-0001" => Ok(ErrorCode::OrchestratorValidation),
        "ML-ORCH-0002" => Ok(ErrorCode::OrchestratorNotFound),
        "ML-ORCH-0003" => Ok(ErrorCode::OrchestratorStorage),
        "ML-ORCH-0004" => Ok(ErrorCode::OrchestratorParse),
        "ML-ORCH-0005" => Ok(ErrorCode::OrchestratorDomain),
        "ML-CTRL-0001" => Ok(ErrorCode::ControlValidation),
        "ML-CTRL-0002" => Ok(ErrorCode::ControlNotFound),
        "ML-CTRL-0003" => Ok(ErrorCode::ControlStorage),
        "ML-CTRL-0004" => Ok(ErrorCode::ControlParse),
        "ML-CTRL-0005" => Ok(ErrorCode::ControlDomain),
        "ML-OBS-0001" => Ok(ErrorCode::ObservabilityValidation),
        "ML-OBS-0002" => Ok(ErrorCode::ObservabilityStorage),
        "ML-OBS-0003" => Ok(ErrorCode::ObservabilityParse),
        "ML-EXEC-0001" => Ok(ErrorCode::ExecutionTimeout),
        "ML-EXEC-0002" => Ok(ErrorCode::ExecutionCanceled),
        "ML-GEN-0001" => Ok(ErrorCode::Unknown),
        _ => Err(ObservabilityError::Parse(format!(
            "invalid error code '{}'",
            raw
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxonomyError {
    pub code: ErrorCode,
    pub category: ErrorCategory,
    pub message: String,
    pub correlation_id: Option<CorrelationId>,
    pub run_id: Option<RunId>,
    pub task_id: Option<TaskId>,
    pub session_id: Option<SessionId>,
}

impl TaxonomyError {
    pub fn new(code: ErrorCode, message: &str) -> Result<Self, ObservabilityError> {
        if message.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "taxonomy error message cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            code,
            category: code.default_category(),
            message: message.trim().to_string(),
            correlation_id: None,
            run_id: None,
            task_id: None,
            session_id: None,
        })
    }

    pub fn with_context(
        mut self,
        correlation_id: Option<CorrelationId>,
        run_id: Option<RunId>,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
    ) -> Self {
        self.correlation_id = correlation_id;
        self.run_id = run_id;
        self.task_id = task_id;
        self.session_id = session_id;
        self
    }

    pub fn from_core(err: &CoreError) -> Self {
        match err {
            CoreError::Io(inner) => Self {
                code: ErrorCode::CoreIo,
                category: ErrorCategory::Storage,
                message: inner.to_string(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            CoreError::Parse(msg) => Self {
                code: ErrorCode::CoreParse,
                category: ErrorCategory::Parse,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            CoreError::Message(msg) => Self {
                code: ErrorCode::CoreMessage,
                category: ErrorCategory::Internal,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
        }
    }

    pub fn from_orchestrator(err: &OrchestratorError) -> Self {
        match err {
            OrchestratorError::Validation(msg) => Self {
                code: ErrorCode::OrchestratorValidation,
                category: ErrorCategory::Validation,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            OrchestratorError::NotFound(msg) => Self {
                code: ErrorCode::OrchestratorNotFound,
                category: ErrorCategory::NotFound,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            OrchestratorError::Storage(msg) => Self {
                code: ErrorCode::OrchestratorStorage,
                category: ErrorCategory::Storage,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            OrchestratorError::Parse(msg) => Self {
                code: ErrorCode::OrchestratorParse,
                category: ErrorCategory::Parse,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            OrchestratorError::Domain(err) => Self {
                code: ErrorCode::OrchestratorDomain,
                category: ErrorCategory::Internal,
                message: err.to_string(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
        }
    }

    pub fn from_control(err: &ControlStateError) -> Self {
        match err {
            ControlStateError::Validation(msg) => Self {
                code: ErrorCode::ControlValidation,
                category: ErrorCategory::Validation,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            ControlStateError::NotFound(msg) => Self {
                code: ErrorCode::ControlNotFound,
                category: ErrorCategory::NotFound,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            ControlStateError::Storage(msg) => Self {
                code: ErrorCode::ControlStorage,
                category: ErrorCategory::Storage,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            ControlStateError::Parse(msg) => Self {
                code: ErrorCode::ControlParse,
                category: ErrorCategory::Parse,
                message: msg.clone(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
            ControlStateError::Domain(err) => Self {
                code: ErrorCode::ControlDomain,
                category: ErrorCategory::Internal,
                message: err.to_string(),
                correlation_id: None,
                run_id: None,
                task_id: None,
                session_id: None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLogRecord {
    pub id: u64,
    pub timestamp_ms: u128,
    pub level: TelemetryLevel,
    pub component: String,
    pub message: String,
    pub correlation_id: Option<CorrelationId>,
    pub run_id: Option<RunId>,
    pub task_id: Option<TaskId>,
    pub session_id: Option<SessionId>,
    pub error_code: Option<ErrorCode>,
    pub error_category: Option<ErrorCategory>,
    pub fields: BTreeMap<String, String>,
}

impl StructuredLogRecord {
    pub fn new(
        level: TelemetryLevel,
        component: &str,
        message: &str,
    ) -> Result<Self, ObservabilityError> {
        if component.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "log component cannot be empty".to_string(),
            ));
        }
        if message.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "log message cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            id: Id::next().0,
            timestamp_ms: now_millis(),
            level,
            component: component.trim().to_string(),
            message: message.trim().to_string(),
            correlation_id: None,
            run_id: None,
            task_id: None,
            session_id: None,
            error_code: None,
            error_category: None,
            fields: BTreeMap::new(),
        })
    }

    pub fn with_context(
        mut self,
        correlation_id: Option<CorrelationId>,
        run_id: Option<RunId>,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
    ) -> Self {
        self.correlation_id = correlation_id;
        self.run_id = run_id;
        self.task_id = task_id;
        self.session_id = session_id;
        self
    }

    pub fn with_error(mut self, code: ErrorCode) -> Self {
        self.error_code = Some(code);
        self.error_category = Some(code.default_category());
        self
    }

    pub fn field(mut self, key: &str, value: &str) -> Result<Self, ObservabilityError> {
        if key.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "field key cannot be empty".to_string(),
            ));
        }
        self.fields
            .insert(key.trim().to_string(), value.trim().to_string());
        Ok(self)
    }
}

pub trait StructuredLogStore {
    fn append(&mut self, record: &StructuredLogRecord) -> Result<(), ObservabilityError>;
    fn load(&mut self) -> Result<Vec<StructuredLogRecord>, ObservabilityError>;
}

#[derive(Debug, Clone)]
pub struct InMemoryStructuredLogStore {
    shared: Arc<Mutex<Vec<StructuredLogRecord>>>,
}

impl Default for InMemoryStructuredLogStore {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl InMemoryStructuredLogStore {
    pub fn from_shared(shared: Arc<Mutex<Vec<StructuredLogRecord>>>) -> Self {
        Self { shared }
    }
}

impl StructuredLogStore for InMemoryStructuredLogStore {
    fn append(&mut self, record: &StructuredLogRecord) -> Result<(), ObservabilityError> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| ObservabilityError::Storage("structured log lock poisoned".to_string()))?;
        guard.push(record.clone());
        Ok(())
    }

    fn load(&mut self) -> Result<Vec<StructuredLogRecord>, ObservabilityError> {
        self.shared
            .lock()
            .map_err(|_| ObservabilityError::Storage("structured log lock poisoned".to_string()))
            .map(|records| records.clone())
    }
}

#[derive(Debug, Clone)]
pub struct FileStructuredLogStore {
    path: PathBuf,
}

impl FileStructuredLogStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    fn ensure_header(file: &mut std::fs::File) -> Result<(), ObservabilityError> {
        if file
            .metadata()
            .map_err(|e| ObservabilityError::Storage(e.to_string()))?
            .len()
            == 0
        {
            file.write_all(STRUCTURED_LOG_HEADER.as_bytes())
                .map_err(|e| ObservabilityError::Storage(e.to_string()))?;
            file.write_all(b"\n")
                .map_err(|e| ObservabilityError::Storage(e.to_string()))?;
        }
        Ok(())
    }
}

impl StructuredLogStore for FileStructuredLogStore {
    fn append(&mut self, record: &StructuredLogRecord) -> Result<(), ObservabilityError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ObservabilityError::Storage(e.to_string()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| ObservabilityError::Storage(e.to_string()))?;
        Self::ensure_header(&mut file)?;
        let encoded = encode_log_record(record);
        file.write_all(encoded.as_bytes())
            .map_err(|e| ObservabilityError::Storage(e.to_string()))?;
        file.write_all(b"\n")
            .map_err(|e| ObservabilityError::Storage(e.to_string()))
    }

    fn load(&mut self) -> Result<Vec<StructuredLogRecord>, ObservabilityError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|e| ObservabilityError::Storage(e.to_string()))?;
        decode_log_records(&raw)
    }
}

fn encode_log_record(record: &StructuredLogRecord) -> String {
    let encoded_fields = record
        .fields
        .iter()
        .map(|(k, v)| format!("{}={}", encode_hex(k), encode_hex(v)))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "log|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        record.id,
        record.timestamp_ms,
        record.level.as_str(),
        encode_hex(&record.component),
        encode_hex(&record.message),
        encode_opt_u64(record.correlation_id.map(|id| id.0 .0)),
        encode_opt_u64(record.run_id.map(|id| id.0 .0)),
        encode_opt_u64(record.task_id.map(|id| id.0 .0)),
        encode_opt_u64(record.session_id.map(|id| id.0 .0)),
        record
            .error_code
            .map(|code| code.as_str().to_string())
            .unwrap_or_else(|| "-".to_string()),
        record
            .error_category
            .map(|category| category.as_str().to_string())
            .unwrap_or_else(|| "-".to_string()),
        encoded_fields,
    )
}

fn decode_log_records(raw: &str) -> Result<Vec<StructuredLogRecord>, ObservabilityError> {
    let mut lines = raw.lines();
    let Some(header) = lines.next() else {
        return Err(ObservabilityError::Parse(
            "empty structured log".to_string(),
        ));
    };
    if header != STRUCTURED_LOG_HEADER {
        return Err(ObservabilityError::Parse(format!(
            "unsupported structured log header '{}'",
            header
        )));
    }

    let mut records = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        records.push(decode_log_record(line)?);
    }
    Ok(records)
}

fn decode_log_record(line: &str) -> Result<StructuredLogRecord, ObservabilityError> {
    let parts: Vec<&str> = line.splitn(13, '|').collect();
    if parts.len() != 13 || parts[0] != "log" {
        return Err(ObservabilityError::Parse(format!(
            "invalid structured log record '{}'",
            line
        )));
    }
    let mut fields = BTreeMap::new();
    if !parts[12].is_empty() {
        for item in parts[12].split(',') {
            if item.trim().is_empty() {
                continue;
            }
            let kv: Vec<&str> = item.splitn(2, '=').collect();
            if kv.len() != 2 {
                return Err(ObservabilityError::Parse(format!(
                    "invalid structured field '{}'",
                    item
                )));
            }
            fields.insert(decode_hex(kv[0])?, decode_hex(kv[1])?);
        }
    }

    Ok(StructuredLogRecord {
        id: parse_u64(parts[1])?,
        timestamp_ms: parse_u128(parts[2])?,
        level: parse_telemetry_level(parts[3])?,
        component: decode_hex(parts[4])?,
        message: decode_hex(parts[5])?,
        correlation_id: parse_opt_u64(parts[6])?.map(|id| CorrelationId(Id(id))),
        run_id: parse_opt_u64(parts[7])?.map(|id| RunId(Id(id))),
        task_id: parse_opt_u64(parts[8])?.map(|id| TaskId(Id(id))),
        session_id: parse_opt_u64(parts[9])?.map(|id| SessionId(Id(id))),
        error_code: if parts[10] == "-" {
            None
        } else {
            Some(parse_error_code(parts[10])?)
        },
        error_category: if parts[11] == "-" {
            None
        } else {
            Some(parse_error_category(parts[11])?)
        },
        fields,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricKey {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

impl Eq for MetricKey {}

impl Ord for MetricKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.canonical().cmp(&other.canonical())
    }
}

impl PartialOrd for MetricKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl MetricKey {
    pub fn new(name: &str) -> Result<Self, ObservabilityError> {
        if name.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "metric name cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            name: name.trim().to_string(),
            labels: BTreeMap::new(),
        })
    }

    pub fn with_label(mut self, key: &str, value: &str) -> Result<Self, ObservabilityError> {
        if key.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "metric label key cannot be empty".to_string(),
            ));
        }
        self.labels
            .insert(key.trim().to_string(), value.trim().to_string());
        Ok(self)
    }

    pub fn canonical(&self) -> String {
        if self.labels.is_empty() {
            return self.name.clone();
        }
        let labels = self
            .labels
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}|{}", self.name, labels)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CounterMetric {
    pub key: MetricKey,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GaugeMetric {
    pub key: MetricKey,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistogramMetric {
    pub key: MetricKey,
    pub count: usize,
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub p50: Option<u64>,
    pub p95: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OperationSummary {
    pub operations_total: u64,
    pub errors_total: u64,
    pub availability_percent: f64,
    pub error_rate_percent: f64,
    pub p95_latency_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricsDashboardSnapshot {
    pub captured_at: u64,
    pub counters: Vec<CounterMetric>,
    pub gauges: Vec<GaugeMetric>,
    pub histograms: Vec<HistogramMetric>,
    pub operation_summary: Option<OperationSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationOutcome {
    Success,
    Error,
    Timeout,
    Canceled,
}

impl OperationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            OperationOutcome::Success => "success",
            OperationOutcome::Error => "error",
            OperationOutcome::Timeout => "timeout",
            OperationOutcome::Canceled => "canceled",
        }
    }

    pub const fn is_error(self) -> bool {
        !matches!(self, OperationOutcome::Success)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MetricsRegistry {
    counters: BTreeMap<MetricKey, u64>,
    gauges: BTreeMap<MetricKey, f64>,
    histograms: BTreeMap<MetricKey, Vec<u64>>,
}

impl MetricsRegistry {
    pub fn increment_counter(&mut self, key: MetricKey, by: u64) {
        let entry = self.counters.entry(key).or_insert(0);
        *entry = entry.saturating_add(by);
    }

    pub fn set_gauge(&mut self, key: MetricKey, value: f64) {
        self.gauges.insert(key, value);
    }

    pub fn observe_histogram(&mut self, key: MetricKey, value: u64) {
        self.histograms.entry(key).or_default().push(value);
    }

    pub fn record_operation(
        &mut self,
        component: &str,
        outcome: OperationOutcome,
        latency_ms: u64,
    ) -> Result<(), ObservabilityError> {
        let total = MetricKey::new("operations_total")?.with_label("component", component)?;
        let errors =
            MetricKey::new("operation_errors_total")?.with_label("component", component)?;
        let by_outcome = MetricKey::new("operations_by_outcome_total")?
            .with_label("component", component)?
            .with_label("outcome", outcome.as_str())?;
        let latency = MetricKey::new("operation_latency_ms")?.with_label("component", component)?;

        self.increment_counter(total, 1);
        self.increment_counter(by_outcome, 1);
        if outcome.is_error() {
            self.increment_counter(errors, 1);
        }
        self.observe_histogram(latency, latency_ms);
        Ok(())
    }

    pub fn dashboard_snapshot(&self) -> MetricsDashboardSnapshot {
        let counters = self
            .counters
            .iter()
            .map(|(key, value)| CounterMetric {
                key: key.clone(),
                value: *value,
            })
            .collect::<Vec<_>>();

        let gauges = self
            .gauges
            .iter()
            .map(|(key, value)| GaugeMetric {
                key: key.clone(),
                value: *value,
            })
            .collect::<Vec<_>>();

        let histograms = self
            .histograms
            .iter()
            .map(|(key, values)| {
                let mut sorted = values.clone();
                sorted.sort_unstable();
                HistogramMetric {
                    key: key.clone(),
                    count: sorted.len(),
                    min: sorted.first().copied(),
                    max: sorted.last().copied(),
                    p50: percentile(&sorted, 50),
                    p95: percentile(&sorted, 95),
                }
            })
            .collect::<Vec<_>>();

        let operation_summary = self.derive_operation_summary();
        MetricsDashboardSnapshot {
            captured_at: now_secs(),
            counters,
            gauges,
            histograms,
            operation_summary,
        }
    }

    fn derive_operation_summary(&self) -> Option<OperationSummary> {
        let total = self
            .counters
            .iter()
            .filter(|(key, _)| key.name == "operations_total")
            .map(|(_, value)| *value)
            .sum::<u64>();

        if total == 0 {
            return None;
        }

        let errors = self
            .counters
            .iter()
            .filter(|(key, _)| key.name == "operation_errors_total")
            .map(|(_, value)| *value)
            .sum::<u64>();

        let mut latency_values = Vec::new();
        for (key, values) in &self.histograms {
            if key.name == "operation_latency_ms" {
                latency_values.extend(values.iter().copied());
            }
        }
        latency_values.sort_unstable();

        let availability_percent =
            ((total.saturating_sub(errors)) as f64 / total as f64 * 100.0).clamp(0.0, 100.0);
        let error_rate_percent = (errors as f64 / total as f64 * 100.0).clamp(0.0, 100.0);

        Some(OperationSummary {
            operations_total: total,
            errors_total: errors,
            availability_percent,
            error_rate_percent,
            p95_latency_ms: percentile(&latency_values, 95),
        })
    }
}

fn percentile(sorted_values: &[u64], percentile: usize) -> Option<u64> {
    if sorted_values.is_empty() {
        return None;
    }
    let p = percentile.min(100);
    let idx =
        ((p as f64 / 100.0) * (sorted_values.len().saturating_sub(1) as f64)).round() as usize;
    sorted_values.get(idx).copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TraceId(pub u64);

impl TraceId {
    pub fn next() -> Self {
        Self(Id::next().0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpanId(pub u64);

impl SpanId {
    pub fn next() -> Self {
        Self(Id::next().0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    Ok,
    Error,
    Timeout,
    Canceled,
}

impl SpanStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            SpanStatus::Ok => "ok",
            SpanStatus::Error => "error",
            SpanStatus::Timeout => "timeout",
            SpanStatus::Canceled => "canceled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpanStartRequest {
    pub trace_id: Option<TraceId>,
    pub parent_span_id: Option<SpanId>,
    pub operation: String,
    pub component: String,
    pub correlation_id: Option<CorrelationId>,
    pub run_id: Option<RunId>,
    pub task_id: Option<TaskId>,
    pub session_id: Option<SessionId>,
    pub attributes: BTreeMap<String, String>,
}

impl SpanStartRequest {
    pub fn new(operation: &str, component: &str) -> Result<Self, ObservabilityError> {
        if operation.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "span operation cannot be empty".to_string(),
            ));
        }
        if component.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "span component cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            trace_id: None,
            parent_span_id: None,
            operation: operation.trim().to_string(),
            component: component.trim().to_string(),
            correlation_id: None,
            run_id: None,
            task_id: None,
            session_id: None,
            attributes: BTreeMap::new(),
        })
    }

    pub fn with_trace(mut self, trace_id: TraceId, parent_span_id: Option<SpanId>) -> Self {
        self.trace_id = Some(trace_id);
        self.parent_span_id = parent_span_id;
        self
    }

    pub fn with_context(
        mut self,
        correlation_id: Option<CorrelationId>,
        run_id: Option<RunId>,
        task_id: Option<TaskId>,
        session_id: Option<SessionId>,
    ) -> Self {
        self.correlation_id = correlation_id;
        self.run_id = run_id;
        self.task_id = task_id;
        self.session_id = session_id;
        self
    }

    pub fn with_attribute(mut self, key: &str, value: &str) -> Result<Self, ObservabilityError> {
        if key.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "span attribute key cannot be empty".to_string(),
            ));
        }
        self.attributes
            .insert(key.trim().to_string(), value.trim().to_string());
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedSpan {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
    pub operation: String,
    pub component: String,
    pub status: SpanStatus,
    pub correlation_id: Option<CorrelationId>,
    pub run_id: Option<RunId>,
    pub task_id: Option<TaskId>,
    pub session_id: Option<SessionId>,
    pub error_code: Option<ErrorCode>,
    pub start_ms: u128,
    pub end_ms: u128,
    pub duration_ms: u64,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct ActiveSpan {
    trace_id: TraceId,
    span_id: SpanId,
    parent_span_id: Option<SpanId>,
    operation: String,
    component: String,
    correlation_id: Option<CorrelationId>,
    run_id: Option<RunId>,
    task_id: Option<TaskId>,
    session_id: Option<SessionId>,
    started_ms: u128,
    attributes: BTreeMap<String, String>,
}

#[derive(Debug, Default, Clone)]
pub struct TraceCollector {
    active: HashMap<SpanId, ActiveSpan>,
    completed: Vec<CompletedSpan>,
}

impl TraceCollector {
    pub fn start_span(&mut self, request: SpanStartRequest) -> (TraceId, SpanId) {
        let trace_id = request.trace_id.unwrap_or_else(TraceId::next);
        let span_id = SpanId::next();
        self.active.insert(
            span_id,
            ActiveSpan {
                trace_id,
                span_id,
                parent_span_id: request.parent_span_id,
                operation: request.operation,
                component: request.component,
                correlation_id: request.correlation_id,
                run_id: request.run_id,
                task_id: request.task_id,
                session_id: request.session_id,
                started_ms: now_millis(),
                attributes: request.attributes,
            },
        );
        (trace_id, span_id)
    }

    pub fn finish_span(
        &mut self,
        span_id: SpanId,
        status: SpanStatus,
        error_code: Option<ErrorCode>,
        additional_attributes: BTreeMap<String, String>,
    ) -> Result<CompletedSpan, ObservabilityError> {
        let Some(mut active) = self.active.remove(&span_id) else {
            return Err(ObservabilityError::NotFound(format!("span {}", span_id.0)));
        };

        for (k, v) in additional_attributes {
            active.attributes.insert(k, v);
        }

        let end_ms = now_millis();
        let duration_ms = end_ms.saturating_sub(active.started_ms) as u64;
        let completed = CompletedSpan {
            trace_id: active.trace_id,
            span_id: active.span_id,
            parent_span_id: active.parent_span_id,
            operation: active.operation,
            component: active.component,
            status,
            correlation_id: active.correlation_id,
            run_id: active.run_id,
            task_id: active.task_id,
            session_id: active.session_id,
            error_code,
            start_ms: active.started_ms,
            end_ms,
            duration_ms,
            attributes: active.attributes,
        };
        self.completed.push(completed.clone());
        Ok(completed)
    }

    pub fn completed_spans(&self) -> &[CompletedSpan] {
        &self.completed
    }

    pub fn active_span_count(&self) -> usize {
        self.active.len()
    }
}

#[derive(Debug, Clone)]
pub enum SloIndicator {
    AvailabilityPercent { minimum_percent: f64 },
    ErrorRatePercent { maximum_percent: f64 },
    LatencyP95Ms { maximum_ms: u64 },
}

#[derive(Debug, Clone)]
pub struct SloDefinition {
    pub id: String,
    pub description: String,
    pub window_secs: u64,
    pub indicator: SloIndicator,
}

impl SloDefinition {
    pub fn new(
        id: &str,
        description: &str,
        window_secs: u64,
        indicator: SloIndicator,
    ) -> Result<Self, ObservabilityError> {
        if id.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "slo id cannot be empty".to_string(),
            ));
        }
        if description.trim().is_empty() {
            return Err(ObservabilityError::Validation(
                "slo description cannot be empty".to_string(),
            ));
        }
        if window_secs == 0 {
            return Err(ObservabilityError::Validation(
                "slo window_secs must be > 0".to_string(),
            ));
        }
        Ok(Self {
            id: id.trim().to_string(),
            description: description.trim().to_string(),
            window_secs,
            indicator,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SloEvaluation {
    pub id: String,
    pub compliant: bool,
    pub target: String,
    pub observed: String,
    pub breach_reason: Option<String>,
}

pub struct SloEvaluator;

impl SloEvaluator {
    pub fn evaluate_all(
        definitions: &[SloDefinition],
        dashboard: &MetricsDashboardSnapshot,
    ) -> Vec<SloEvaluation> {
        definitions
            .iter()
            .map(|def| Self::evaluate(def, dashboard))
            .collect()
    }

    pub fn evaluate(
        definition: &SloDefinition,
        dashboard: &MetricsDashboardSnapshot,
    ) -> SloEvaluation {
        let Some(summary) = &dashboard.operation_summary else {
            return SloEvaluation {
                id: definition.id.clone(),
                compliant: false,
                target: "telemetry required".to_string(),
                observed: "missing operation metrics".to_string(),
                breach_reason: Some("insufficient telemetry for SLO evaluation".to_string()),
            };
        };

        match definition.indicator {
            SloIndicator::AvailabilityPercent { minimum_percent } => {
                let observed = summary.availability_percent;
                let compliant = observed >= minimum_percent;
                SloEvaluation {
                    id: definition.id.clone(),
                    compliant,
                    target: format!(">= {:.2}%", minimum_percent),
                    observed: format!("{:.2}%", observed),
                    breach_reason: if compliant {
                        None
                    } else {
                        Some(format!(
                            "availability dropped to {:.2}% (errors={}, total={})",
                            observed, summary.errors_total, summary.operations_total
                        ))
                    },
                }
            }
            SloIndicator::ErrorRatePercent { maximum_percent } => {
                let observed = summary.error_rate_percent;
                let compliant = observed <= maximum_percent;
                SloEvaluation {
                    id: definition.id.clone(),
                    compliant,
                    target: format!("<= {:.2}%", maximum_percent),
                    observed: format!("{:.2}%", observed),
                    breach_reason: if compliant {
                        None
                    } else {
                        Some(format!(
                            "error rate is {:.2}% (errors={}, total={})",
                            observed, summary.errors_total, summary.operations_total
                        ))
                    },
                }
            }
            SloIndicator::LatencyP95Ms { maximum_ms } => {
                let observed = summary.p95_latency_ms;
                let compliant = observed.map(|ms| ms <= maximum_ms).unwrap_or(false);
                SloEvaluation {
                    id: definition.id.clone(),
                    compliant,
                    target: format!("p95 <= {}ms", maximum_ms),
                    observed: observed
                        .map(|ms| format!("p95={}ms", ms))
                        .unwrap_or_else(|| "p95=missing".to_string()),
                    breach_reason: if compliant {
                        None
                    } else {
                        Some(format!(
                            "latency p95 exceeded threshold (p95={})",
                            observed
                                .map(|ms| format!("{}ms", ms))
                                .unwrap_or_else(|| "missing".to_string())
                        ))
                    },
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorCodeCount {
    pub code: ErrorCode,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowSpan {
    pub operation: String,
    pub component: String,
    pub duration_ms: u64,
    pub span_id: SpanId,
    pub trace_id: TraceId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryTriageReport {
    pub error_counts: Vec<ErrorCodeCount>,
    pub slow_spans: Vec<SlowSpan>,
    pub top_failing_components: Vec<(String, u64)>,
}

pub fn triage_report(
    logs: &[StructuredLogRecord],
    spans: &[CompletedSpan],
    dashboard: &MetricsDashboardSnapshot,
    slow_span_threshold_ms: u64,
) -> TelemetryTriageReport {
    let mut error_counts = BTreeMap::<ErrorCode, usize>::new();
    for log in logs {
        if let Some(code) = log.error_code {
            *error_counts.entry(code).or_insert(0) += 1;
        }
    }
    let mut error_counts = error_counts
        .into_iter()
        .map(|(code, count)| ErrorCodeCount { code, count })
        .collect::<Vec<_>>();
    error_counts.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(a.code.as_str().cmp(b.code.as_str()))
    });

    let mut slow_spans = spans
        .iter()
        .filter(|span| span.duration_ms >= slow_span_threshold_ms)
        .map(|span| SlowSpan {
            operation: span.operation.clone(),
            component: span.component.clone(),
            duration_ms: span.duration_ms,
            span_id: span.span_id,
            trace_id: span.trace_id,
        })
        .collect::<Vec<_>>();
    slow_spans.sort_by(|a, b| b.duration_ms.cmp(&a.duration_ms));

    let mut components = Vec::new();
    for counter in &dashboard.counters {
        if counter.key.name != "operation_errors_total" {
            continue;
        }
        if let Some(component) = counter.key.labels.get("component") {
            components.push((component.clone(), counter.value));
        }
    }
    components.sort_by(|a, b| b.1.cmp(&a.1));

    TelemetryTriageReport {
        error_counts,
        slow_spans,
        top_failing_components: components,
    }
}

fn parse_u64(input: &str) -> Result<u64, ObservabilityError> {
    input
        .parse::<u64>()
        .map_err(|_| ObservabilityError::Parse(format!("invalid u64 '{}'", input)))
}

fn parse_u128(input: &str) -> Result<u128, ObservabilityError> {
    input
        .parse::<u128>()
        .map_err(|_| ObservabilityError::Parse(format!("invalid u128 '{}'", input)))
}

fn parse_opt_u64(input: &str) -> Result<Option<u64>, ObservabilityError> {
    if input == "-" {
        return Ok(None);
    }
    parse_u64(input).map(Some)
}

fn encode_opt_u64(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn encode_hex(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input.as_bytes() {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn decode_hex(input: &str) -> Result<String, ObservabilityError> {
    if input.len() % 2 != 0 {
        return Err(ObservabilityError::Parse("invalid hex length".to_string()));
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
        .map_err(|_| ObservabilityError::Parse("invalid utf-8 in hex".to_string()))
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => '0',
    }
}

fn hex_to_nibble(value: u8) -> Result<u8, ObservabilityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ObservabilityError::Parse(
            "invalid hex character".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_logs_are_machine_parseable_and_contextual() {
        let path = std::env::temp_dir().join(format!("moonlight-structured-{}.log", Id::next().0));
        let mut store = FileStructuredLogStore::new(&path);

        let record = StructuredLogRecord::new(TelemetryLevel::Error, "orchestrator", "task failed")
            .expect("record")
            .with_context(
                Some(CorrelationId::next()),
                Some(RunId::next()),
                Some(TaskId::next()),
                None,
            )
            .with_error(ErrorCode::OrchestratorValidation)
            .field("attempt", "2")
            .expect("field")
            .field("idempotency_key", "abc")
            .expect("field");

        store.append(&record).expect("append");
        let records = store.load().expect("load");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].component, "orchestrator");
        assert_eq!(
            records[0].error_code,
            Some(ErrorCode::OrchestratorValidation)
        );
        assert_eq!(records[0].fields.get("attempt"), Some(&"2".to_string()));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn metrics_dashboard_and_traces_capture_reliability_and_latency() {
        let mut metrics = MetricsRegistry::default();
        metrics
            .record_operation("orchestrator", OperationOutcome::Success, 40)
            .expect("op");
        metrics
            .record_operation("orchestrator", OperationOutcome::Error, 150)
            .expect("op");
        metrics
            .record_operation("orchestrator", OperationOutcome::Timeout, 500)
            .expect("op");

        let snapshot = metrics.dashboard_snapshot();
        let summary = snapshot.operation_summary.expect("summary");
        assert_eq!(summary.operations_total, 3);
        assert_eq!(summary.errors_total, 2);
        assert!(summary.error_rate_percent > 60.0);
        assert!(summary.p95_latency_ms.expect("p95") >= 150);

        let mut traces = TraceCollector::default();
        let (trace_id, span_id) = traces.start_span(
            SpanStartRequest::new("dispatch", "orchestrator")
                .expect("start")
                .with_context(Some(CorrelationId::next()), Some(RunId::next()), None, None),
        );
        let completed = traces
            .finish_span(
                span_id,
                SpanStatus::Error,
                Some(ErrorCode::ExecutionTimeout),
                BTreeMap::new(),
            )
            .expect("finish");
        assert_eq!(completed.trace_id, trace_id);
        assert_eq!(completed.status, SpanStatus::Error);
        assert_eq!(completed.error_code, Some(ErrorCode::ExecutionTimeout));
    }

    #[test]
    fn error_taxonomy_exposes_stable_codes_for_control_plane_errors() {
        let core_err = CoreError::Parse("bad config".to_string());
        let mapped = TaxonomyError::from_core(&core_err);
        assert_eq!(mapped.code, ErrorCode::CoreParse);
        assert_eq!(mapped.code.as_str(), "ML-CORE-0002");

        let orch_err = OrchestratorError::NotFound("run 1".to_string());
        let mapped = TaxonomyError::from_orchestrator(&orch_err);
        assert_eq!(mapped.code, ErrorCode::OrchestratorNotFound);
        assert_eq!(mapped.code.as_str(), "ML-ORCH-0002");

        let ctrl_err = ControlStateError::Storage("disk full".to_string());
        let mapped = TaxonomyError::from_control(&ctrl_err);
        assert_eq!(mapped.code, ErrorCode::ControlStorage);
        assert_eq!(mapped.category, ErrorCategory::Storage);
    }

    #[test]
    fn slo_evaluator_and_triage_report_detect_breaches_and_root_causes() {
        let mut metrics = MetricsRegistry::default();
        for _ in 0..90 {
            metrics
                .record_operation("session", OperationOutcome::Success, 30)
                .expect("op");
        }
        for _ in 0..10 {
            metrics
                .record_operation("session", OperationOutcome::Error, 800)
                .expect("op");
        }
        let dashboard = metrics.dashboard_snapshot();

        let slos = vec![
            SloDefinition::new(
                "availability",
                "session availability",
                3600,
                SloIndicator::AvailabilityPercent {
                    minimum_percent: 99.0,
                },
            )
            .expect("slo"),
            SloDefinition::new(
                "error-rate",
                "session error rate",
                3600,
                SloIndicator::ErrorRatePercent {
                    maximum_percent: 1.0,
                },
            )
            .expect("slo"),
            SloDefinition::new(
                "latency",
                "session latency p95",
                3600,
                SloIndicator::LatencyP95Ms { maximum_ms: 200 },
            )
            .expect("slo"),
        ];

        let evaluations = SloEvaluator::evaluate_all(&slos, &dashboard);
        assert_eq!(evaluations.len(), 3);
        assert!(evaluations.iter().all(|e| !e.compliant));

        let logs = vec![
            StructuredLogRecord::new(TelemetryLevel::Error, "session", "timeout")
                .expect("log")
                .with_error(ErrorCode::ExecutionTimeout),
            StructuredLogRecord::new(TelemetryLevel::Error, "session", "timeout")
                .expect("log")
                .with_error(ErrorCode::ExecutionTimeout),
        ];

        let mut traces = TraceCollector::default();
        let (_, span_id) =
            traces.start_span(SpanStartRequest::new("interact", "session").expect("span"));
        let mut attrs = BTreeMap::new();
        attrs.insert("remote".to_string(), "target:23".to_string());
        let _ = traces
            .finish_span(
                span_id,
                SpanStatus::Timeout,
                Some(ErrorCode::ExecutionTimeout),
                attrs,
            )
            .expect("finish");

        let triage = triage_report(&logs, traces.completed_spans(), &dashboard, 0);
        assert_eq!(triage.error_counts.len(), 1);
        assert_eq!(triage.error_counts[0].code, ErrorCode::ExecutionTimeout);
        assert!(!triage.slow_spans.is_empty());
        assert!(!triage.top_failing_components.is_empty());
    }
}
