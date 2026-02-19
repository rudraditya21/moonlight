use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::Path;

#[derive(Debug)]
pub enum ReleaseError {
    Validation(String),
    NotFound(String),
    Storage(String),
    Parse(String),
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseError::Validation(msg) => write!(f, "validation error: {msg}"),
            ReleaseError::NotFound(msg) => write!(f, "not found: {msg}"),
            ReleaseError::Storage(msg) => write!(f, "storage error: {msg}"),
            ReleaseError::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for ReleaseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionWindow {
    pub min: u32,
    pub max: u32,
}

impl VersionWindow {
    pub fn new(min: u32, max: u32) -> Result<Self, ReleaseError> {
        if min == 0 {
            return Err(ReleaseError::Validation(
                "version window minimum must be greater than zero".to_string(),
            ));
        }
        if min > max {
            return Err(ReleaseError::Validation(
                "version window minimum cannot exceed maximum".to_string(),
            ));
        }
        Ok(Self { min, max })
    }

    pub fn contains(&self, version: u32) -> bool {
        (self.min..=self.max).contains(&version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseCompatibilityPolicy {
    pub module_manifest_versions: VersionWindow,
    pub module_api_versions: VersionWindow,
    pub control_state_versions: VersionWindow,
    pub output_modes: Vec<String>,
    pub runtimes: Vec<String>,
}

impl ReleaseCompatibilityPolicy {
    pub fn new(
        module_manifest_versions: VersionWindow,
        module_api_versions: VersionWindow,
        control_state_versions: VersionWindow,
        output_modes: Vec<String>,
        runtimes: Vec<String>,
    ) -> Result<Self, ReleaseError> {
        if output_modes.is_empty() {
            return Err(ReleaseError::Validation(
                "at least one output mode is required".to_string(),
            ));
        }
        if runtimes.is_empty() {
            return Err(ReleaseError::Validation(
                "at least one runtime is required".to_string(),
            ));
        }

        let output_modes = normalize_unique(output_modes, "output mode")?;
        let runtimes = normalize_unique(runtimes, "runtime")?;

        Ok(Self {
            module_manifest_versions,
            module_api_versions,
            control_state_versions,
            output_modes,
            runtimes,
        })
    }

    pub fn default_control_plane() -> Self {
        Self::new(
            VersionWindow::new(1, 1).expect("fixed window"),
            VersionWindow::new(1, 1).expect("fixed window"),
            VersionWindow::new(1, 3).expect("fixed window"),
            vec!["human".to_string(), "json".to_string()],
            vec!["builtin".to_string(), "dynlib".to_string()],
        )
        .expect("default control-plane compatibility policy")
    }

    pub fn supports_output_mode(&self, mode: &str) -> bool {
        let normalized = normalize_token(mode);
        self.output_modes.iter().any(|value| value == &normalized)
    }

    pub fn supports_runtime(&self, runtime: &str) -> bool {
        let normalized = normalize_token(runtime);
        self.runtimes.iter().any(|value| value == &normalized)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityCase {
    pub name: String,
    pub runtime: String,
    pub module_manifest_version: u32,
    pub module_api_version: u32,
    pub control_state_version: u32,
    pub output_mode: String,
    pub expect_compatible: bool,
}

impl CompatibilityCase {
    pub fn new(
        name: &str,
        runtime: &str,
        module_manifest_version: u32,
        module_api_version: u32,
        control_state_version: u32,
        output_mode: &str,
        expect_compatible: bool,
    ) -> Result<Self, ReleaseError> {
        if name.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "compatibility case name cannot be empty".to_string(),
            ));
        }
        if runtime.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "compatibility case runtime cannot be empty".to_string(),
            ));
        }
        if output_mode.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "compatibility case output_mode cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            name: name.trim().to_string(),
            runtime: normalize_token(runtime),
            module_manifest_version,
            module_api_version,
            control_state_version,
            output_mode: normalize_token(output_mode),
            expect_compatible,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityCaseResult {
    pub case_name: String,
    pub expected_compatible: bool,
    pub actual_compatible: bool,
    pub test_passed: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityMatrixReport {
    pub total_cases: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
    pub tests_passed: bool,
    pub results: Vec<CompatibilityCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityMatrix {
    cases: Vec<CompatibilityCase>,
}

impl CompatibilityMatrix {
    pub fn new(cases: Vec<CompatibilityCase>) -> Result<Self, ReleaseError> {
        if cases.is_empty() {
            return Err(ReleaseError::Validation(
                "compatibility matrix requires at least one test case".to_string(),
            ));
        }
        Ok(Self { cases })
    }

    pub fn cases(&self) -> &[CompatibilityCase] {
        &self.cases
    }

    pub fn evaluate(&self, policy: &ReleaseCompatibilityPolicy) -> CompatibilityMatrixReport {
        let mut results = Vec::with_capacity(self.cases.len());
        let mut passed_cases = 0usize;

        for case in &self.cases {
            let failures = evaluate_compatibility_case(policy, case);
            let actual_compatible = failures.is_empty();
            let test_passed = actual_compatible == case.expect_compatible;
            if test_passed {
                passed_cases = passed_cases.saturating_add(1);
            }
            results.push(CompatibilityCaseResult {
                case_name: case.name.clone(),
                expected_compatible: case.expect_compatible,
                actual_compatible,
                test_passed,
                failures,
            });
        }

        let total_cases = results.len();
        let failed_cases = total_cases.saturating_sub(passed_cases);
        CompatibilityMatrixReport {
            total_cases,
            passed_cases,
            failed_cases,
            tests_passed: failed_cases == 0,
            results,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationImpact {
    Compatible,
    RequiresDowntime,
    Breaking,
}

impl MigrationImpact {
    pub fn as_str(self) -> &'static str {
        match self {
            MigrationImpact::Compatible => "compatible",
            MigrationImpact::RequiresDowntime => "requires_downtime",
            MigrationImpact::Breaking => "breaking",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationDirection {
    Forward,
    Rollback,
}

impl MigrationDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            MigrationDirection::Forward => "forward",
            MigrationDirection::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStepDefinition {
    pub from_version: u32,
    pub to_version: u32,
    pub description: String,
    pub impact: MigrationImpact,
    pub reversible: bool,
    pub requires_backup: bool,
}

impl MigrationStepDefinition {
    pub fn new(
        from_version: u32,
        to_version: u32,
        description: &str,
        impact: MigrationImpact,
        reversible: bool,
        requires_backup: bool,
    ) -> Result<Self, ReleaseError> {
        if from_version == 0 || to_version == 0 {
            return Err(ReleaseError::Validation(
                "migration versions must be greater than zero".to_string(),
            ));
        }
        if from_version == to_version {
            return Err(ReleaseError::Validation(
                "migration step cannot have identical from/to versions".to_string(),
            ));
        }
        if description.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "migration description cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            from_version,
            to_version,
            description: description.trim().to_string(),
            impact,
            reversible,
            requires_backup,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMigrationStep {
    pub from_version: u32,
    pub to_version: u32,
    pub description: String,
    pub impact: MigrationImpact,
    pub direction: MigrationDirection,
    pub requires_backup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub start_version: u32,
    pub target_version: u32,
    pub steps: Vec<PlannedMigrationStep>,
    pub requires_backup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPolicy {
    pub supported_min_version: u32,
    pub latest_version: u32,
    pub steps: Vec<MigrationStepDefinition>,
}

impl MigrationPolicy {
    pub fn new(
        supported_min_version: u32,
        latest_version: u32,
        steps: Vec<MigrationStepDefinition>,
    ) -> Result<Self, ReleaseError> {
        if supported_min_version == 0 || latest_version == 0 {
            return Err(ReleaseError::Validation(
                "migration policy versions must be greater than zero".to_string(),
            ));
        }
        if supported_min_version > latest_version {
            return Err(ReleaseError::Validation(
                "supported_min_version cannot exceed latest_version".to_string(),
            ));
        }

        let mut seen = BTreeSet::new();
        for step in &steps {
            let from_ok =
                step.from_version >= supported_min_version && step.from_version <= latest_version;
            let to_ok =
                step.to_version >= supported_min_version && step.to_version <= latest_version;
            if !from_ok || !to_ok {
                return Err(ReleaseError::Validation(format!(
                    "migration step {} -> {} is outside supported range {}..={}",
                    step.from_version, step.to_version, supported_min_version, latest_version
                )));
            }
            if !seen.insert((step.from_version, step.to_version)) {
                return Err(ReleaseError::Validation(format!(
                    "duplicate migration step {} -> {}",
                    step.from_version, step.to_version
                )));
            }
        }

        Ok(Self {
            supported_min_version,
            latest_version,
            steps,
        })
    }

    pub fn default_control_plane() -> Self {
        let steps = vec![
            MigrationStepDefinition::new(
                1,
                2,
                "Move run/task execution metadata into deterministic status envelopes.",
                MigrationImpact::RequiresDowntime,
                true,
                true,
            )
            .expect("valid step"),
            MigrationStepDefinition::new(
                2,
                3,
                "Add artifact-retention index and session transcript linkage records.",
                MigrationImpact::Compatible,
                true,
                false,
            )
            .expect("valid step"),
        ];
        Self::new(1, 3, steps).expect("default migration policy")
    }

    pub fn plan(
        &self,
        start_version: u32,
        target_version: u32,
    ) -> Result<MigrationPlan, ReleaseError> {
        if start_version < self.supported_min_version || start_version > self.latest_version {
            return Err(ReleaseError::Validation(format!(
                "start version {} is outside supported range {}..={}",
                start_version, self.supported_min_version, self.latest_version
            )));
        }
        if target_version < self.supported_min_version || target_version > self.latest_version {
            return Err(ReleaseError::Validation(format!(
                "target version {} is outside supported range {}..={}",
                target_version, self.supported_min_version, self.latest_version
            )));
        }

        if start_version == target_version {
            return Ok(MigrationPlan {
                start_version,
                target_version,
                steps: Vec::new(),
                requires_backup: false,
            });
        }

        let mut queue = VecDeque::new();
        let mut seen = BTreeSet::new();
        let mut previous: BTreeMap<u32, (u32, usize, MigrationDirection)> = BTreeMap::new();
        queue.push_back(start_version);
        seen.insert(start_version);

        while let Some(current) = queue.pop_front() {
            for (index, step) in self.steps.iter().enumerate() {
                if step.from_version == current {
                    let next = step.to_version;
                    if seen.insert(next) {
                        previous.insert(next, (current, index, MigrationDirection::Forward));
                        if next == target_version {
                            queue.clear();
                            break;
                        }
                        queue.push_back(next);
                    }
                }
                if step.reversible && step.to_version == current {
                    let next = step.from_version;
                    if seen.insert(next) {
                        previous.insert(next, (current, index, MigrationDirection::Rollback));
                        if next == target_version {
                            queue.clear();
                            break;
                        }
                        queue.push_back(next);
                    }
                }
            }
        }

        if !previous.contains_key(&target_version) {
            return Err(ReleaseError::NotFound(format!(
                "no migration path found from version {} to {}",
                start_version, target_version
            )));
        }

        let mut steps = Vec::new();
        let mut cursor = target_version;
        while cursor != start_version {
            let Some((prev_version, step_index, direction)) = previous.get(&cursor).copied() else {
                return Err(ReleaseError::Parse(
                    "migration graph traversal failed to reconstruct plan".to_string(),
                ));
            };
            let step = self.steps.get(step_index).ok_or_else(|| {
                ReleaseError::Parse("migration step index out of range".to_string())
            })?;
            steps.push(PlannedMigrationStep {
                from_version: prev_version,
                to_version: cursor,
                description: step.description.clone(),
                impact: step.impact,
                direction,
                requires_backup: step.requires_backup || direction == MigrationDirection::Rollback,
            });
            cursor = prev_version;
        }
        steps.reverse();

        let requires_backup = steps.iter().any(|step| step.requires_backup);
        Ok(MigrationPlan {
            start_version,
            target_version,
            steps,
            requires_backup,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigrationRecord {
    pub from_version: u32,
    pub to_version: u32,
    pub direction: MigrationDirection,
    pub applied_at: u64,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationExecutionReport {
    pub from_version: u32,
    pub to_version: u32,
    pub applied_steps: usize,
    pub requires_backup: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedControlState {
    pub schema_version: u32,
    migration_history: Vec<AppliedMigrationRecord>,
}

impl VersionedControlState {
    pub fn new(schema_version: u32) -> Result<Self, ReleaseError> {
        if schema_version == 0 {
            return Err(ReleaseError::Validation(
                "schema_version must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            schema_version,
            migration_history: Vec::new(),
        })
    }

    pub fn migration_history(&self) -> &[AppliedMigrationRecord] {
        &self.migration_history
    }

    pub fn apply_migration_plan(
        &mut self,
        plan: &MigrationPlan,
        applied_at: u64,
    ) -> Result<MigrationExecutionReport, ReleaseError> {
        if self.schema_version != plan.start_version {
            return Err(ReleaseError::Validation(format!(
                "cannot apply migration plan from {} when current version is {}",
                plan.start_version, self.schema_version
            )));
        }

        for step in &plan.steps {
            if self.schema_version != step.from_version {
                return Err(ReleaseError::Parse(format!(
                    "migration sequence mismatch: expected current {}, found {}",
                    step.from_version, self.schema_version
                )));
            }
            self.schema_version = step.to_version;
            self.migration_history.push(AppliedMigrationRecord {
                from_version: step.from_version,
                to_version: step.to_version,
                direction: step.direction,
                applied_at,
                note: step.description.clone(),
            });
        }

        Ok(MigrationExecutionReport {
            from_version: plan.start_version,
            to_version: plan.target_version,
            applied_steps: plan.steps.len(),
            requires_backup: plan.requires_backup,
        })
    }

    pub fn snapshot_payload(&self) -> String {
        format!(
            "schema_version={};history_count={}",
            self.schema_version,
            self.migration_history.len()
        )
    }

    pub fn apply_rollback_restore(&mut self, restore: &RollbackRestore, restored_at: u64) {
        let previous = self.schema_version;
        self.schema_version = restore.schema_version;
        self.migration_history.push(AppliedMigrationRecord {
            from_version: previous,
            to_version: restore.schema_version,
            direction: MigrationDirection::Rollback,
            applied_at: restored_at,
            note: format!(
                "restored snapshot {} ({})",
                restore.snapshot_id, restore.label
            ),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackSnapshot {
    pub id: u64,
    pub label: String,
    pub captured_at: u64,
    pub schema_version: u32,
    pub payload: String,
    pub checksum: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackRestore {
    pub snapshot_id: u64,
    pub label: String,
    pub schema_version: u32,
    pub payload: String,
    pub checksum: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackRegistry {
    next_id: u64,
    snapshots: BTreeMap<u64, RollbackSnapshot>,
}

impl Default for RollbackRegistry {
    fn default() -> Self {
        Self {
            next_id: 1,
            snapshots: BTreeMap::new(),
        }
    }
}

impl RollbackRegistry {
    pub fn create_snapshot(
        &mut self,
        label: &str,
        schema_version: u32,
        payload: &str,
        captured_at: u64,
    ) -> Result<RollbackSnapshot, ReleaseError> {
        if label.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "rollback snapshot label cannot be empty".to_string(),
            ));
        }
        if schema_version == 0 {
            return Err(ReleaseError::Validation(
                "rollback snapshot schema_version must be greater than zero".to_string(),
            ));
        }

        let snapshot = RollbackSnapshot {
            id: self.next_id,
            label: label.trim().to_string(),
            captured_at,
            schema_version,
            payload: payload.to_string(),
            checksum: checksum_fnv1a(payload),
        };
        self.snapshots.insert(snapshot.id, snapshot.clone());
        self.next_id = self.next_id.saturating_add(1);
        Ok(snapshot)
    }

    pub fn list_snapshots(&self) -> Vec<RollbackSnapshot> {
        self.snapshots.values().rev().cloned().collect::<Vec<_>>()
    }

    pub fn has_snapshots(&self) -> bool {
        !self.snapshots.is_empty()
    }

    pub fn restore(&self, snapshot_id: u64) -> Result<RollbackRestore, ReleaseError> {
        let snapshot = self
            .snapshots
            .get(&snapshot_id)
            .ok_or_else(|| ReleaseError::NotFound(format!("snapshot {}", snapshot_id)))?;

        let checksum = checksum_fnv1a(&snapshot.payload);
        if checksum != snapshot.checksum {
            return Err(ReleaseError::Parse(format!(
                "snapshot {} checksum mismatch",
                snapshot_id
            )));
        }

        Ok(RollbackRestore {
            snapshot_id: snapshot.id,
            label: snapshot.label.clone(),
            schema_version: snapshot.schema_version,
            payload: snapshot.payload.clone(),
            checksum: snapshot.checksum,
        })
    }

    pub fn prune_keep_latest(&mut self, keep: usize) -> usize {
        if keep == 0 {
            let count = self.snapshots.len();
            self.snapshots.clear();
            return count;
        }

        let ids = self.snapshots.keys().copied().collect::<Vec<_>>();
        if ids.len() <= keep {
            return 0;
        }

        let remove_count = ids.len().saturating_sub(keep);
        let mut removed = 0usize;
        for id in ids.into_iter().take(remove_count) {
            if self.snapshots.remove(&id).is_some() {
                removed = removed.saturating_add(1);
            }
        }
        removed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentationGate {
    pub name: String,
    pub relative_path: String,
    pub required_headings: Vec<String>,
}

impl DocumentationGate {
    pub fn new(
        name: &str,
        relative_path: &str,
        required_headings: Vec<String>,
    ) -> Result<Self, ReleaseError> {
        if name.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "documentation gate name cannot be empty".to_string(),
            ));
        }
        if relative_path.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "documentation gate path cannot be empty".to_string(),
            ));
        }
        let required_headings = required_headings
            .into_iter()
            .filter_map(|heading| {
                let normalized = normalize_heading(&heading);
                (!normalized.is_empty()).then_some(normalized)
            })
            .collect::<Vec<_>>();

        Ok(Self {
            name: name.trim().to_string(),
            relative_path: relative_path.trim().to_string(),
            required_headings,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentationGateResult {
    pub name: String,
    pub relative_path: String,
    pub passed: bool,
    pub file_exists: bool,
    pub missing_headings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentationGateReport {
    pub total_gates: usize,
    pub passed_gates: usize,
    pub failed_gates: usize,
    pub all_passed: bool,
    pub results: Vec<DocumentationGateResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentationGateSuite {
    gates: Vec<DocumentationGate>,
}

impl DocumentationGateSuite {
    pub fn new(gates: Vec<DocumentationGate>) -> Result<Self, ReleaseError> {
        if gates.is_empty() {
            return Err(ReleaseError::Validation(
                "documentation gate suite requires at least one gate".to_string(),
            ));
        }
        Ok(Self { gates })
    }

    pub fn gates(&self) -> &[DocumentationGate] {
        &self.gates
    }

    pub fn evaluate(&self, root: &Path) -> Result<DocumentationGateReport, ReleaseError> {
        let mut results = Vec::with_capacity(self.gates.len());
        let mut passed = 0usize;

        for gate in &self.gates {
            let path = root.join(&gate.relative_path);
            if !path.exists() {
                results.push(DocumentationGateResult {
                    name: gate.name.clone(),
                    relative_path: gate.relative_path.clone(),
                    passed: false,
                    file_exists: false,
                    missing_headings: gate.required_headings.clone(),
                });
                continue;
            }

            let content = std::fs::read_to_string(&path)
                .map_err(|e| ReleaseError::Storage(format!("{}: {e}", gate.relative_path)))?;
            let headings = parse_markdown_headings(&content);
            let missing_headings = gate
                .required_headings
                .iter()
                .filter(|required| !headings.contains(*required))
                .cloned()
                .collect::<Vec<_>>();
            let gate_passed = missing_headings.is_empty();
            if gate_passed {
                passed = passed.saturating_add(1);
            }
            results.push(DocumentationGateResult {
                name: gate.name.clone(),
                relative_path: gate.relative_path.clone(),
                passed: gate_passed,
                file_exists: true,
                missing_headings,
            });
        }

        let total = results.len();
        let failed = total.saturating_sub(passed);
        Ok(DocumentationGateReport {
            total_gates: total,
            passed_gates: passed,
            failed_gates: failed,
            all_passed: failed == 0,
            results,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseChecklistItem {
    pub key: String,
    pub description: String,
    pub required: bool,
}

impl ReleaseChecklistItem {
    pub fn new(key: &str, description: &str, required: bool) -> Result<Self, ReleaseError> {
        if key.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "checklist key cannot be empty".to_string(),
            ));
        }
        if description.trim().is_empty() {
            return Err(ReleaseError::Validation(
                "checklist description cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            key: normalize_token(key),
            description: description.trim().to_string(),
            required,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecklistFailure {
    pub key: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseChecklistReport {
    pub ready: bool,
    pub total_items: usize,
    pub passed_items: usize,
    pub failures: Vec<ChecklistFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseChecklistTemplate {
    items: Vec<ReleaseChecklistItem>,
}

impl ReleaseChecklistTemplate {
    pub fn new(items: Vec<ReleaseChecklistItem>) -> Result<Self, ReleaseError> {
        if items.is_empty() {
            return Err(ReleaseError::Validation(
                "release checklist requires at least one item".to_string(),
            ));
        }
        let mut seen = BTreeSet::new();
        for item in &items {
            if !seen.insert(item.key.clone()) {
                return Err(ReleaseError::Validation(format!(
                    "duplicate checklist key '{}'",
                    item.key
                )));
            }
        }
        Ok(Self { items })
    }

    pub fn default_control_plane() -> Self {
        let items = vec![
            ReleaseChecklistItem::new(
                "compatibility_matrix",
                "Compatibility matrix tests match expected outcomes.",
                true,
            )
            .expect("item"),
            ReleaseChecklistItem::new(
                "migration_path",
                "Supported upgrade path is available for target release schema.",
                true,
            )
            .expect("item"),
            ReleaseChecklistItem::new(
                "rollback_snapshot",
                "Rollback snapshot is present before release apply.",
                true,
            )
            .expect("item"),
            ReleaseChecklistItem::new(
                "documentation_gates",
                "Operator usage documentation is complete and current.",
                true,
            )
            .expect("item"),
            ReleaseChecklistItem::new(
                "usage_notes",
                "Upgrade usage notes reviewed for operator workflows.",
                true,
            )
            .expect("item"),
        ];
        Self::new(items).expect("default checklist")
    }

    pub fn items(&self) -> &[ReleaseChecklistItem] {
        &self.items
    }

    pub fn evaluate(&self, status: &BTreeMap<String, bool>) -> ReleaseChecklistReport {
        let mut passed_items = 0usize;
        let mut failures = Vec::new();

        for item in &self.items {
            let passed = status.get(&item.key).copied().unwrap_or(false);
            if passed {
                passed_items = passed_items.saturating_add(1);
                continue;
            }
            if item.required {
                failures.push(ChecklistFailure {
                    key: item.key.clone(),
                    description: item.description.clone(),
                });
            }
        }

        ReleaseChecklistReport {
            ready: failures.is_empty(),
            total_items: self.items.len(),
            passed_items,
            failures,
        }
    }
}

fn normalize_unique(values: Vec<String>, field_name: &str) -> Result<Vec<String>, ReleaseError> {
    let mut unique = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let normalized = normalize_token(&value);
        if normalized.is_empty() {
            return Err(ReleaseError::Validation(format!(
                "{} values cannot be empty",
                field_name
            )));
        }
        if seen.insert(normalized.clone()) {
            unique.push(normalized);
        }
    }
    if unique.is_empty() {
        return Err(ReleaseError::Validation(format!(
            "at least one {} is required",
            field_name
        )));
    }
    Ok(unique)
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_heading(value: &str) -> String {
    collapse_whitespace(&value.trim().to_ascii_lowercase())
}

fn collapse_whitespace(value: &str) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() {
            if !in_space && !out.is_empty() {
                out.push(' ');
            }
            in_space = true;
        } else {
            in_space = false;
            out.push(ch);
        }
    }
    out.trim().to_string()
}

fn parse_markdown_headings(content: &str) -> BTreeSet<String> {
    let mut headings = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            continue;
        }
        let heading = trimmed.trim_start_matches('#').trim();
        if heading.is_empty() {
            continue;
        }
        headings.insert(normalize_heading(heading));
    }
    headings
}

fn evaluate_compatibility_case(
    policy: &ReleaseCompatibilityPolicy,
    case: &CompatibilityCase,
) -> Vec<String> {
    let mut failures = Vec::new();

    if !policy.supports_runtime(&case.runtime) {
        failures.push(format!(
            "runtime '{}' is unsupported (allowed: {})",
            case.runtime,
            policy.runtimes.join(",")
        ));
    }
    if !policy
        .module_manifest_versions
        .contains(case.module_manifest_version)
    {
        failures.push(format!(
            "manifest version {} outside supported range {}..={}",
            case.module_manifest_version,
            policy.module_manifest_versions.min,
            policy.module_manifest_versions.max
        ));
    }
    if !policy.module_api_versions.contains(case.module_api_version) {
        failures.push(format!(
            "module API version {} outside supported range {}..={}",
            case.module_api_version, policy.module_api_versions.min, policy.module_api_versions.max
        ));
    }
    if !policy
        .control_state_versions
        .contains(case.control_state_version)
    {
        failures.push(format!(
            "control-state version {} outside supported range {}..={}",
            case.control_state_version,
            policy.control_state_versions.min,
            policy.control_state_versions.max
        ));
    }
    if !policy.supports_output_mode(&case.output_mode) {
        failures.push(format!(
            "output mode '{}' is unsupported (allowed: {})",
            case.output_mode,
            policy.output_modes.join(",")
        ));
    }

    failures
}

fn checksum_fnv1a(payload: &str) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = OFFSET;
    for byte in payload.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::Id;

    #[test]
    fn compatibility_matrix_validates_expected_cases() {
        let policy = ReleaseCompatibilityPolicy::default_control_plane();
        let matrix = CompatibilityMatrix::new(vec![
            CompatibilityCase::new("builtin-ok", "builtin", 1, 1, 1, "human", true).expect("case"),
            CompatibilityCase::new("dynlib-ok", "dynlib", 1, 1, 3, "json", true).expect("case"),
            CompatibilityCase::new("manifest-too-old", "builtin", 0, 1, 1, "human", false)
                .expect("case"),
            CompatibilityCase::new("api-too-new", "builtin", 1, 99, 1, "human", false)
                .expect("case"),
        ])
        .expect("matrix");

        let report = matrix.evaluate(&policy);
        assert_eq!(report.total_cases, 4);
        assert!(report.tests_passed);
        assert_eq!(report.failed_cases, 0);
    }

    #[test]
    fn migration_policy_plans_forward_and_rollback_paths() {
        let policy = MigrationPolicy::default_control_plane();

        let forward = policy.plan(1, 3).expect("forward plan");
        assert_eq!(forward.steps.len(), 2);
        assert!(forward.requires_backup);
        assert_eq!(forward.steps[0].direction, MigrationDirection::Forward);

        let rollback = policy.plan(3, 1).expect("rollback plan");
        assert_eq!(rollback.steps.len(), 2);
        assert!(rollback.requires_backup);
        assert_eq!(rollback.steps[0].direction, MigrationDirection::Rollback);
    }

    #[test]
    fn versioned_control_state_applies_plan_in_order() {
        let policy = MigrationPolicy::default_control_plane();
        let plan = policy.plan(1, 3).expect("plan");
        let mut state = VersionedControlState::new(1).expect("state");

        let report = state.apply_migration_plan(&plan, 100).expect("apply");
        assert_eq!(report.applied_steps, 2);
        assert_eq!(state.schema_version, 3);
        assert_eq!(state.migration_history().len(), 2);
    }

    #[test]
    fn rollback_registry_creates_restores_and_prunes_snapshots() {
        let mut registry = RollbackRegistry::default();
        let first = registry
            .create_snapshot("pre-release", 1, "schema_version=1", 10)
            .expect("snapshot-1");
        let second = registry
            .create_snapshot("post-release", 2, "schema_version=2", 20)
            .expect("snapshot-2");

        let listed = registry.list_snapshots();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, second.id);

        let restored = registry.restore(first.id).expect("restore");
        assert_eq!(restored.schema_version, 1);

        let removed = registry.prune_keep_latest(1);
        assert_eq!(removed, 1);
        assert_eq!(registry.list_snapshots().len(), 1);
    }

    #[test]
    fn control_state_can_restore_from_snapshot() {
        let mut state = VersionedControlState::new(3).expect("state");
        let restore = RollbackRestore {
            snapshot_id: 7,
            label: "stable-v1".to_string(),
            schema_version: 1,
            payload: "schema_version=1".to_string(),
            checksum: checksum_fnv1a("schema_version=1"),
        };

        state.apply_rollback_restore(&restore, 123);
        assert_eq!(state.schema_version, 1);
        assert_eq!(state.migration_history().len(), 1);
        assert_eq!(
            state.migration_history()[0].direction,
            MigrationDirection::Rollback
        );
    }

    #[test]
    fn documentation_gate_suite_detects_missing_headings() {
        let root = std::env::temp_dir().join(format!("moonlight-doc-gate-{}", Id::next().0));
        std::fs::create_dir_all(root.join("docs/guide")).expect("mkdir");
        std::fs::write(
            root.join("docs/guide/release.md"),
            "# Release Guide\n\n## Usage\n",
        )
        .expect("write");

        let suite = DocumentationGateSuite::new(vec![DocumentationGate::new(
            "release-guide",
            "docs/guide/release.md",
            vec![
                "release guide".to_string(),
                "migration workflow".to_string(),
            ],
        )
        .expect("gate")])
        .expect("suite");

        let report = suite.evaluate(&root).expect("evaluate");
        assert_eq!(report.total_gates, 1);
        assert!(!report.all_passed);
        assert_eq!(report.results[0].missing_headings.len(), 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn release_checklist_requires_all_required_items() {
        let checklist = ReleaseChecklistTemplate::default_control_plane();
        let mut status = BTreeMap::new();
        status.insert("compatibility_matrix".to_string(), true);
        status.insert("migration_path".to_string(), true);
        status.insert("rollback_snapshot".to_string(), false);
        status.insert("documentation_gates".to_string(), true);
        status.insert("usage_notes".to_string(), true);

        let report = checklist.evaluate(&status);
        assert!(!report.ready);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].key, "rollback_snapshot");
    }
}
