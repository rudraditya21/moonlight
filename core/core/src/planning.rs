use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::collections::{BinaryHeap, VecDeque};
use std::fmt;
use std::sync::Arc;

use crate::campaign::{
    CampaignId, MetadataValue, Objective, ObjectiveId, ObjectiveStatus, Predicate, RiskLevel,
};
use crate::domain::{Artifact, ArtifactKind, ArtifactState, CorrelationId};
use crate::time::now_secs;

pub const PLANNING_CONTRACT_ID: &str = "ml.planning.contract.v1";
pub const PLANNING_SCHEMA_VERSION: u32 = 1;
pub const PLANNING_PERSISTENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanningContractError {
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    InvalidTransition {
        entity: &'static str,
        from: &'static str,
        to: &'static str,
    },
    DuplicateNode {
        node_id: PlanNodeId,
    },
    DuplicateEdge {
        edge_id: PlanEdgeId,
    },
    MissingNode {
        node_id: PlanNodeId,
    },
    InvariantViolation {
        invariant: &'static str,
    },
    DuplicateModuleReference {
        module_reference: String,
    },
    DuplicateObjectiveDefinition {
        objective_id: ObjectiveId,
    },
    DuplicateArtifactRecord {
        artifact_key: String,
    },
    MetadataConflict {
        field: &'static str,
        key: String,
    },
    Storage(String),
}

impl PlanningContractError {
    pub const fn code(&self) -> &'static str {
        match self {
            PlanningContractError::InvalidField { .. } => "ML-PLAN-0001",
            PlanningContractError::InvalidTransition { .. } => "ML-PLAN-0002",
            PlanningContractError::DuplicateNode { .. } => "ML-PLAN-0003",
            PlanningContractError::DuplicateEdge { .. } => "ML-PLAN-0004",
            PlanningContractError::MissingNode { .. } => "ML-PLAN-0005",
            PlanningContractError::InvariantViolation { .. } => "ML-PLAN-0006",
            PlanningContractError::DuplicateModuleReference { .. } => "ML-PLAN-0007",
            PlanningContractError::DuplicateObjectiveDefinition { .. } => "ML-PLAN-0008",
            PlanningContractError::DuplicateArtifactRecord { .. } => "ML-PLAN-0009",
            PlanningContractError::MetadataConflict { .. } => "ML-PLAN-0010",
            PlanningContractError::Storage(_) => "ML-PLAN-0011",
        }
    }
}

impl fmt::Display for PlanningContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanningContractError::InvalidField { field, reason } => {
                write!(f, "invalid field {field}: {reason}")
            }
            PlanningContractError::InvalidTransition { entity, from, to } => {
                write!(f, "invalid {entity} transition: {from} -> {to}")
            }
            PlanningContractError::DuplicateNode { node_id } => {
                write!(f, "duplicate planning graph node id: {}", node_id.as_str())
            }
            PlanningContractError::DuplicateEdge { edge_id } => {
                write!(f, "duplicate planning graph edge id: {}", edge_id.as_str())
            }
            PlanningContractError::MissingNode { node_id } => {
                write!(
                    f,
                    "planning graph references unknown node: {}",
                    node_id.as_str()
                )
            }
            PlanningContractError::InvariantViolation { invariant } => {
                write!(f, "planning invariant violated: {invariant}")
            }
            PlanningContractError::DuplicateModuleReference { module_reference } => {
                write!(
                    f,
                    "duplicate module reference in planner input: {module_reference}"
                )
            }
            PlanningContractError::DuplicateObjectiveDefinition { objective_id } => {
                write!(
                    f,
                    "duplicate objective definition in planner input: {}",
                    objective_id.as_str()
                )
            }
            PlanningContractError::DuplicateArtifactRecord { artifact_key } => {
                write!(
                    f,
                    "duplicate artifact record in planner input: {artifact_key}"
                )
            }
            PlanningContractError::MetadataConflict { field, key } => {
                write!(f, "conflicting metadata key for {field}: {key}")
            }
            PlanningContractError::Storage(msg) => write!(f, "planning storage error: {msg}"),
        }
    }
}

impl std::error::Error for PlanningContractError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanNodeId(String);

impl PlanNodeId {
    pub fn parse(input: &str) -> Result<Self, PlanningContractError> {
        let value = normalize_token(input);
        if value.is_empty() {
            return Err(PlanningContractError::InvalidField {
                field: "plan_node.id",
                reason: "must not be empty",
            });
        }
        if !is_valid_identifier(&value) {
            return Err(PlanningContractError::InvalidField {
                field: "plan_node.id",
                reason: "must contain only [a-z0-9._:/-]",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanEdgeId(String);

impl PlanEdgeId {
    pub fn parse(input: &str) -> Result<Self, PlanningContractError> {
        let value = normalize_token(input);
        if value.is_empty() {
            return Err(PlanningContractError::InvalidField {
                field: "plan_edge.id",
                reason: "must not be empty",
            });
        }
        if !is_valid_identifier(&value) {
            return Err(PlanningContractError::InvalidField {
                field: "plan_edge.id",
                reason: "must contain only [a-z0-9._:/-]",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanNodeType {
    ObjectiveState,
    CapabilityState,
    AssetState,
}

impl PlanNodeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            PlanNodeType::ObjectiveState => "objective_state",
            PlanNodeType::CapabilityState => "capability_state",
            PlanNodeType::AssetState => "asset_state",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanEdgeType {
    ModuleExecution,
    StateTransition,
    PrivilegeEscalation,
    LateralMovement,
}

impl PlanEdgeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            PlanEdgeType::ModuleExecution => "module_execution",
            PlanEdgeType::StateTransition => "state_transition",
            PlanEdgeType::PrivilegeEscalation => "privilege_escalation",
            PlanEdgeType::LateralMovement => "lateral_movement",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanningAlgorithm {
    AStar,
}

impl PlanningAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            PlanningAlgorithm::AStar => "a_star",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanRequestMode {
    Plan,
    Explain,
    Simulate,
}

impl PlanRequestMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            PlanRequestMode::Plan => "plan",
            PlanRequestMode::Explain => "explain",
            PlanRequestMode::Simulate => "simulate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectiveStateNode {
    pub id: PlanNodeId,
    pub objective_id: ObjectiveId,
    pub status: ObjectiveStatus,
    pub label: String,
}

impl ObjectiveStateNode {
    pub fn new(
        id: PlanNodeId,
        objective_id: ObjectiveId,
        status: ObjectiveStatus,
        label: &str,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(label, "objective_state_node.label")?;
        Ok(Self {
            id,
            objective_id,
            status,
            label: label.trim().to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityStateNode {
    pub id: PlanNodeId,
    pub capability: String,
    pub enabled: bool,
}

impl CapabilityStateNode {
    pub fn new(
        id: PlanNodeId,
        capability: &str,
        enabled: bool,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(capability, "capability_state_node.capability")?;
        Ok(Self {
            id,
            capability: normalize_token(capability),
            enabled,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetStateNode {
    pub id: PlanNodeId,
    pub asset_kind: String,
    pub state: String,
}

impl AssetStateNode {
    pub fn new(
        id: PlanNodeId,
        asset_kind: &str,
        state: &str,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(asset_kind, "asset_state_node.asset_kind")?;
        ensure_non_empty(state, "asset_state_node.state")?;
        Ok(Self {
            id,
            asset_kind: normalize_token(asset_kind),
            state: normalize_token(state),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanNode {
    ObjectiveState(ObjectiveStateNode),
    CapabilityState(CapabilityStateNode),
    AssetState(AssetStateNode),
}

impl PlanNode {
    pub fn id(&self) -> &PlanNodeId {
        match self {
            PlanNode::ObjectiveState(node) => &node.id,
            PlanNode::CapabilityState(node) => &node.id,
            PlanNode::AssetState(node) => &node.id,
        }
    }

    pub const fn node_type(&self) -> PlanNodeType {
        match self {
            PlanNode::ObjectiveState(_) => PlanNodeType::ObjectiveState,
            PlanNode::CapabilityState(_) => PlanNodeType::CapabilityState,
            PlanNode::AssetState(_) => PlanNodeType::AssetState,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEdgeAttributes {
    pub required_capabilities: BTreeSet<String>,
    pub estimated_noise_cost: u32,
    pub estimated_risk: RiskLevel,
    pub probability_of_success_bps: u16,
    pub expected_artifacts: BTreeSet<String>,
}

impl PlanEdgeAttributes {
    pub fn new(
        required_capabilities: BTreeSet<String>,
        estimated_noise_cost: u32,
        estimated_risk: RiskLevel,
        probability_of_success_bps: u16,
        expected_artifacts: BTreeSet<String>,
    ) -> Result<Self, PlanningContractError> {
        if probability_of_success_bps > 10_000 {
            return Err(PlanningContractError::InvalidField {
                field: "plan_edge.probability_of_success_bps",
                reason: "must be in 0..=10000",
            });
        }
        Ok(Self {
            required_capabilities: normalize_tokens(required_capabilities),
            estimated_noise_cost,
            estimated_risk,
            probability_of_success_bps,
            expected_artifacts: normalize_tokens(expected_artifacts),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleExecutionEdge {
    pub id: PlanEdgeId,
    pub from: PlanNodeId,
    pub to: PlanNodeId,
    pub module_reference: String,
    pub attrs: PlanEdgeAttributes,
}

impl ModuleExecutionEdge {
    pub fn new(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        module_reference: &str,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        validate_distinct_edge_endpoints(&from, &to)?;
        ensure_non_empty(module_reference, "plan_edge.module_reference")?;
        Ok(Self {
            id,
            from,
            to,
            module_reference: normalize_token(module_reference),
            attrs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransitionEdge {
    pub id: PlanEdgeId,
    pub from: PlanNodeId,
    pub to: PlanNodeId,
    pub attrs: PlanEdgeAttributes,
}

impl StateTransitionEdge {
    pub fn new(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        validate_distinct_edge_endpoints(&from, &to)?;
        Ok(Self {
            id,
            from,
            to,
            attrs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeEscalationEdge {
    pub id: PlanEdgeId,
    pub from: PlanNodeId,
    pub to: PlanNodeId,
    pub attrs: PlanEdgeAttributes,
}

impl PrivilegeEscalationEdge {
    pub fn new(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        validate_distinct_edge_endpoints(&from, &to)?;
        Ok(Self {
            id,
            from,
            to,
            attrs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateralMovementEdge {
    pub id: PlanEdgeId,
    pub from: PlanNodeId,
    pub to: PlanNodeId,
    pub attrs: PlanEdgeAttributes,
}

impl LateralMovementEdge {
    pub fn new(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        validate_distinct_edge_endpoints(&from, &to)?;
        Ok(Self {
            id,
            from,
            to,
            attrs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanEdge {
    ModuleExecution(ModuleExecutionEdge),
    StateTransition(StateTransitionEdge),
    PrivilegeEscalation(PrivilegeEscalationEdge),
    LateralMovement(LateralMovementEdge),
}

impl PlanEdge {
    pub fn module_execution(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        module_reference: &str,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        Ok(Self::ModuleExecution(ModuleExecutionEdge::new(
            id,
            from,
            to,
            module_reference,
            attrs,
        )?))
    }

    pub fn state_transition(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        Ok(Self::StateTransition(StateTransitionEdge::new(
            id, from, to, attrs,
        )?))
    }

    pub fn privilege_escalation(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        Ok(Self::PrivilegeEscalation(PrivilegeEscalationEdge::new(
            id, from, to, attrs,
        )?))
    }

    pub fn lateral_movement(
        id: PlanEdgeId,
        from: PlanNodeId,
        to: PlanNodeId,
        attrs: PlanEdgeAttributes,
    ) -> Result<Self, PlanningContractError> {
        Ok(Self::LateralMovement(LateralMovementEdge::new(
            id, from, to, attrs,
        )?))
    }

    pub fn id(&self) -> &PlanEdgeId {
        match self {
            PlanEdge::ModuleExecution(edge) => &edge.id,
            PlanEdge::StateTransition(edge) => &edge.id,
            PlanEdge::PrivilegeEscalation(edge) => &edge.id,
            PlanEdge::LateralMovement(edge) => &edge.id,
        }
    }

    pub fn from(&self) -> &PlanNodeId {
        match self {
            PlanEdge::ModuleExecution(edge) => &edge.from,
            PlanEdge::StateTransition(edge) => &edge.from,
            PlanEdge::PrivilegeEscalation(edge) => &edge.from,
            PlanEdge::LateralMovement(edge) => &edge.from,
        }
    }

    pub fn to(&self) -> &PlanNodeId {
        match self {
            PlanEdge::ModuleExecution(edge) => &edge.to,
            PlanEdge::StateTransition(edge) => &edge.to,
            PlanEdge::PrivilegeEscalation(edge) => &edge.to,
            PlanEdge::LateralMovement(edge) => &edge.to,
        }
    }

    pub const fn edge_type(&self) -> PlanEdgeType {
        match self {
            PlanEdge::ModuleExecution(_) => PlanEdgeType::ModuleExecution,
            PlanEdge::StateTransition(_) => PlanEdgeType::StateTransition,
            PlanEdge::PrivilegeEscalation(_) => PlanEdgeType::PrivilegeEscalation,
            PlanEdge::LateralMovement(_) => PlanEdgeType::LateralMovement,
        }
    }

    pub fn attrs(&self) -> &PlanEdgeAttributes {
        match self {
            PlanEdge::ModuleExecution(edge) => &edge.attrs,
            PlanEdge::StateTransition(edge) => &edge.attrs,
            PlanEdge::PrivilegeEscalation(edge) => &edge.attrs,
            PlanEdge::LateralMovement(edge) => &edge.attrs,
        }
    }

    pub fn module_reference(&self) -> Option<&str> {
        match self {
            PlanEdge::ModuleExecution(edge) => Some(&edge.module_reference),
            PlanEdge::StateTransition(_)
            | PlanEdge::PrivilegeEscalation(_)
            | PlanEdge::LateralMovement(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGraph {
    nodes: BTreeMap<PlanNodeId, PlanNode>,
    edges: BTreeMap<PlanEdgeId, PlanEdge>,
}

impl CapabilityGraph {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
        }
    }

    pub fn add_node(&mut self, node: PlanNode) -> Result<(), PlanningContractError> {
        let id = node.id().clone();
        if self.nodes.insert(id.clone(), node).is_some() {
            return Err(PlanningContractError::DuplicateNode { node_id: id });
        }
        Ok(())
    }

    pub fn add_edge(&mut self, edge: PlanEdge) -> Result<(), PlanningContractError> {
        if !self.nodes.contains_key(edge.from()) {
            return Err(PlanningContractError::MissingNode {
                node_id: edge.from().clone(),
            });
        }
        if !self.nodes.contains_key(edge.to()) {
            return Err(PlanningContractError::MissingNode {
                node_id: edge.to().clone(),
            });
        }
        let from_type = self
            .nodes
            .get(edge.from())
            .expect("source node existence validated")
            .node_type();
        let to_type = self
            .nodes
            .get(edge.to())
            .expect("target node existence validated")
            .node_type();
        validate_edge_endpoint_types(edge.edge_type(), from_type, to_type)?;

        if self.edges.insert(edge.id().clone(), edge.clone()).is_some() {
            return Err(PlanningContractError::DuplicateEdge {
                edge_id: edge.id().clone(),
            });
        }
        Ok(())
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn nodes(&self) -> &BTreeMap<PlanNodeId, PlanNode> {
        &self.nodes
    }

    pub fn edges(&self) -> &BTreeMap<PlanEdgeId, PlanEdge> {
        &self.edges
    }
}

impl Default for CapabilityGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredModuleInput {
    pub module_reference: String,
    pub required_capabilities: BTreeSet<String>,
    pub estimated_noise_cost: u32,
    pub estimated_risk: RiskLevel,
    pub probability_of_success_bps: u16,
    pub expected_artifacts: BTreeSet<String>,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl RegisteredModuleInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_reference: &str,
        required_capabilities: BTreeSet<String>,
        estimated_noise_cost: u32,
        estimated_risk: RiskLevel,
        probability_of_success_bps: u16,
        expected_artifacts: BTreeSet<String>,
        metadata: BTreeMap<String, MetadataValue>,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(module_reference, "planner_input.module_reference")?;
        if probability_of_success_bps > 10_000 {
            return Err(PlanningContractError::InvalidField {
                field: "planner_input.probability_of_success_bps",
                reason: "must be in 0..=10000",
            });
        }
        Ok(Self {
            module_reference: normalize_token(module_reference),
            required_capabilities: normalize_tokens(required_capabilities),
            estimated_noise_cost,
            estimated_risk,
            probability_of_success_bps,
            expected_artifacts: normalize_tokens(expected_artifacts),
            metadata: normalize_metadata_map(metadata, "planner_input.module.metadata")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectiveDefinitionInput {
    pub objective_id: ObjectiveId,
    pub campaign_id: CampaignId,
    pub status: ObjectiveStatus,
    pub prerequisites: Vec<ObjectiveId>,
    pub success_criteria: Vec<Predicate>,
    pub failure_criteria: Vec<Predicate>,
    pub risk_level: RiskLevel,
    pub noise_budget: Option<u32>,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl ObjectiveDefinitionInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        objective_id: ObjectiveId,
        campaign_id: CampaignId,
        status: ObjectiveStatus,
        prerequisites: Vec<ObjectiveId>,
        success_criteria: Vec<Predicate>,
        failure_criteria: Vec<Predicate>,
        risk_level: RiskLevel,
        noise_budget: Option<u32>,
        metadata: BTreeMap<String, MetadataValue>,
    ) -> Result<Self, PlanningContractError> {
        if success_criteria.is_empty() {
            return Err(PlanningContractError::InvalidField {
                field: "planner_input.objective.success_criteria",
                reason: "must contain at least one predicate",
            });
        }
        if noise_budget == Some(0) {
            return Err(PlanningContractError::InvalidField {
                field: "planner_input.objective.noise_budget",
                reason: "must be greater than zero when provided",
            });
        }
        let mut prereq_set = BTreeSet::new();
        for prerequisite in prerequisites {
            if prerequisite == objective_id {
                return Err(PlanningContractError::InvalidField {
                    field: "planner_input.objective.prerequisites",
                    reason: "cannot include objective id itself",
                });
            }
            prereq_set.insert(prerequisite);
        }
        let success_criteria = canonicalize_predicates(success_criteria);
        let failure_criteria = canonicalize_predicates(failure_criteria);
        Ok(Self {
            objective_id,
            campaign_id,
            status,
            prerequisites: prereq_set.into_iter().collect(),
            success_criteria,
            failure_criteria,
            risk_level,
            noise_budget,
            metadata: normalize_metadata_map(metadata, "planner_input.objective.metadata")?,
        })
    }

    pub fn from_objective(objective: &Objective) -> Result<Self, PlanningContractError> {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "name".to_string(),
            MetadataValue::Text(objective.name.trim().to_string()),
        );
        metadata.insert(
            "description".to_string(),
            MetadataValue::Text(objective.description.trim().to_string()),
        );

        Self::new(
            objective.id.clone(),
            objective.campaign_id.clone(),
            objective.status,
            objective.prerequisites.clone(),
            objective.success_criteria.clone(),
            objective.failure_criteria.clone(),
            objective.risk_level,
            objective.noise_budget,
            metadata,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredArtifactInput {
    pub artifact_key: String,
    pub artifact_type: String,
    pub state: String,
    pub tags: BTreeSet<String>,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl DiscoveredArtifactInput {
    pub fn new(
        artifact_key: &str,
        artifact_type: &str,
        state: &str,
        tags: BTreeSet<String>,
        metadata: BTreeMap<String, MetadataValue>,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(artifact_key, "planner_input.artifact.artifact_key")?;
        ensure_non_empty(artifact_type, "planner_input.artifact.artifact_type")?;
        ensure_non_empty(state, "planner_input.artifact.state")?;
        Ok(Self {
            artifact_key: normalize_token(artifact_key),
            artifact_type: normalize_token(artifact_type),
            state: normalize_token(state),
            tags: normalize_tokens(tags),
            metadata: normalize_metadata_map(metadata, "planner_input.artifact.metadata")?,
        })
    }

    pub fn from_artifact(artifact: &Artifact) -> Result<Self, PlanningContractError> {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "name".to_string(),
            MetadataValue::Text(artifact.name.trim().to_string()),
        );
        metadata.insert(
            "locator".to_string(),
            MetadataValue::Text(artifact.locator.trim().to_string()),
        );
        metadata.insert(
            "run_id".to_string(),
            MetadataValue::Integer(artifact.run_id.0 .0 as i64),
        );
        if let Some(task_id) = artifact.task_id {
            metadata.insert(
                "task_id".to_string(),
                MetadataValue::Integer(task_id.0 .0 as i64),
            );
        }
        if let Some(session_id) = artifact.session_id {
            metadata.insert(
                "session_id".to_string(),
                MetadataValue::Integer(session_id.0 .0 as i64),
            );
        }

        Self::new(
            &format!("artifact:{}", artifact.id.0 .0),
            artifact_kind_token(artifact.kind),
            artifact_state_token(artifact.state),
            BTreeSet::new(),
            metadata,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerNormalizationInput {
    pub modules: Vec<RegisteredModuleInput>,
    pub objectives: Vec<ObjectiveDefinitionInput>,
    pub artifacts: Vec<DiscoveredArtifactInput>,
    pub metadata: BTreeMap<String, MetadataValue>,
}

impl PlannerNormalizationInput {
    pub fn new(
        modules: Vec<RegisteredModuleInput>,
        objectives: Vec<ObjectiveDefinitionInput>,
        artifacts: Vec<DiscoveredArtifactInput>,
        metadata: BTreeMap<String, MetadataValue>,
    ) -> Result<Self, PlanningContractError> {
        Ok(Self {
            modules,
            objectives,
            artifacts,
            metadata: normalize_metadata_map(metadata, "planner_input.metadata")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPlannerSnapshot {
    modules: Vec<RegisteredModuleInput>,
    objectives: Vec<ObjectiveDefinitionInput>,
    artifacts: Vec<DiscoveredArtifactInput>,
    known_artifact_types: Vec<String>,
    metadata: BTreeMap<String, MetadataValue>,
    canonical_signature: String,
}

impl NormalizedPlannerSnapshot {
    pub fn modules(&self) -> &[RegisteredModuleInput] {
        &self.modules
    }

    pub fn objectives(&self) -> &[ObjectiveDefinitionInput] {
        &self.objectives
    }

    pub fn artifacts(&self) -> &[DiscoveredArtifactInput] {
        &self.artifacts
    }

    pub fn known_artifact_types(&self) -> &[String] {
        &self.known_artifact_types
    }

    pub fn metadata(&self) -> &BTreeMap<String, MetadataValue> {
        &self.metadata
    }

    pub fn canonical_signature(&self) -> &str {
        &self.canonical_signature
    }

    pub fn estimated_memory_bytes(&self) -> usize {
        let encoded = encode_normalized_snapshot(
            &self.modules,
            &self.objectives,
            &self.artifacts,
            &self.known_artifact_types,
            &self.metadata,
        );
        encoded.len()
            + self.modules.len() * std::mem::size_of::<RegisteredModuleInput>()
            + self.objectives.len() * std::mem::size_of::<ObjectiveDefinitionInput>()
            + self.artifacts.len() * std::mem::size_of::<DiscoveredArtifactInput>()
            + self.known_artifact_types.len() * std::mem::size_of::<String>()
    }
}

pub fn normalize_planner_input(
    input: PlannerNormalizationInput,
) -> Result<NormalizedPlannerSnapshot, PlanningContractError> {
    let modules = normalize_modules(input.modules)?;
    let objectives = normalize_objectives(input.objectives)?;
    let artifacts = normalize_artifacts(input.artifacts)?;
    let metadata = normalize_metadata_map(input.metadata, "planner_input.metadata")?;

    let mut known_artifact_types = BTreeSet::new();
    for module in &modules {
        known_artifact_types.extend(module.expected_artifacts.iter().cloned());
    }
    for artifact in &artifacts {
        known_artifact_types.insert(artifact.artifact_type.clone());
    }

    let known_artifact_types = known_artifact_types.into_iter().collect::<Vec<_>>();
    let canonical_signature = encode_normalized_snapshot(
        &modules,
        &objectives,
        &artifacts,
        &known_artifact_types,
        &metadata,
    );

    Ok(NormalizedPlannerSnapshot {
        modules,
        objectives,
        artifacts,
        known_artifact_types,
        metadata,
        canonical_signature,
    })
}

fn normalize_modules(
    modules: Vec<RegisteredModuleInput>,
) -> Result<Vec<RegisteredModuleInput>, PlanningContractError> {
    let mut by_module = BTreeMap::<String, RegisteredModuleInput>::new();
    for module in modules {
        let key = normalize_token(&module.module_reference);
        if by_module.contains_key(&key) {
            return Err(PlanningContractError::DuplicateModuleReference {
                module_reference: key,
            });
        }
        by_module.insert(key, module);
    }
    Ok(by_module.into_values().collect())
}

fn normalize_objectives(
    objectives: Vec<ObjectiveDefinitionInput>,
) -> Result<Vec<ObjectiveDefinitionInput>, PlanningContractError> {
    let mut by_objective = BTreeMap::<ObjectiveId, ObjectiveDefinitionInput>::new();
    for objective in objectives {
        let key = objective.objective_id.clone();
        if by_objective.contains_key(&key) {
            return Err(PlanningContractError::DuplicateObjectiveDefinition { objective_id: key });
        }
        by_objective.insert(key, objective);
    }
    Ok(by_objective.into_values().collect())
}

fn normalize_artifacts(
    artifacts: Vec<DiscoveredArtifactInput>,
) -> Result<Vec<DiscoveredArtifactInput>, PlanningContractError> {
    let mut by_artifact = BTreeMap::<String, DiscoveredArtifactInput>::new();
    for artifact in artifacts {
        let key = normalize_token(&artifact.artifact_key);
        if by_artifact.contains_key(&key) {
            return Err(PlanningContractError::DuplicateArtifactRecord { artifact_key: key });
        }
        by_artifact.insert(key, artifact);
    }
    Ok(by_artifact.into_values().collect())
}

fn canonicalize_predicates(mut predicates: Vec<Predicate>) -> Vec<Predicate> {
    predicates.sort_by_key(|predicate| predicate.stable_encoding());
    predicates.dedup_by(|left, right| left.stable_encoding() == right.stable_encoding());
    predicates
}

fn normalize_metadata_map(
    metadata: BTreeMap<String, MetadataValue>,
    field: &'static str,
) -> Result<BTreeMap<String, MetadataValue>, PlanningContractError> {
    let mut out = BTreeMap::new();
    for (key, value) in metadata {
        let normalized_key = normalize_token(&key);
        if normalized_key.is_empty() {
            return Err(PlanningContractError::InvalidField {
                field,
                reason: "metadata keys must not be empty",
            });
        }
        if let Some(existing) = out.get(&normalized_key) {
            if existing != &value {
                return Err(PlanningContractError::MetadataConflict {
                    field,
                    key: normalized_key,
                });
            }
            continue;
        }
        out.insert(normalized_key, value);
    }
    Ok(out)
}

fn encode_normalized_snapshot(
    modules: &[RegisteredModuleInput],
    objectives: &[ObjectiveDefinitionInput],
    artifacts: &[DiscoveredArtifactInput],
    known_artifact_types: &[String],
    metadata: &BTreeMap<String, MetadataValue>,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("schema={PLANNING_SCHEMA_VERSION}"));
    parts.push(
        "modules=".to_string()
            + &modules
                .iter()
                .map(encode_module)
                .collect::<Vec<_>>()
                .join(";"),
    );
    parts.push(
        "objectives=".to_string()
            + &objectives
                .iter()
                .map(encode_objective)
                .collect::<Vec<_>>()
                .join(";"),
    );
    parts.push(
        "artifacts=".to_string()
            + &artifacts
                .iter()
                .map(encode_artifact)
                .collect::<Vec<_>>()
                .join(";"),
    );
    parts.push(format!(
        "known_artifact_types={}",
        known_artifact_types.join(",")
    ));
    parts.push(format!("metadata={}", encode_metadata(metadata)));
    parts.join("|")
}

fn encode_module(module: &RegisteredModuleInput) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        module.module_reference,
        join_set(&module.required_capabilities),
        module.estimated_noise_cost,
        module.estimated_risk.as_str(),
        module.probability_of_success_bps,
        join_set(&module.expected_artifacts),
        encode_metadata(&module.metadata),
    )
}

fn encode_objective(objective: &ObjectiveDefinitionInput) -> String {
    let prerequisites = objective
        .prerequisites
        .iter()
        .map(|id| id.as_str().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let success = objective
        .success_criteria
        .iter()
        .map(|predicate| predicate.stable_encoding())
        .collect::<Vec<_>>()
        .join(",");
    let failure = objective
        .failure_criteria
        .iter()
        .map(|predicate| predicate.stable_encoding())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        objective.objective_id.as_str(),
        objective.campaign_id.as_str(),
        objective.status.as_str(),
        prerequisites,
        success,
        failure,
        objective.risk_level.as_str(),
        objective
            .noise_budget
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        encode_metadata(&objective.metadata),
    )
}

fn encode_artifact(artifact: &DiscoveredArtifactInput) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        artifact.artifact_key,
        artifact.artifact_type,
        artifact.state,
        join_set(&artifact.tags),
        encode_metadata(&artifact.metadata),
    )
}

fn join_set(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(",")
}

fn encode_metadata(metadata: &BTreeMap<String, MetadataValue>) -> String {
    metadata
        .iter()
        .map(|(key, value)| format!("{key}={}", value.stable_encoding()))
        .collect::<Vec<_>>()
        .join(",")
}

fn artifact_kind_token(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Transcript => "transcript",
        ArtifactKind::CommandOutput => "command_output",
        ArtifactKind::StructuredJson => "structured_json",
        ArtifactKind::BinaryBlob => "binary_blob",
        ArtifactKind::FileReference => "file_reference",
    }
}

fn artifact_state_token(state: ArtifactState) -> &'static str {
    match state {
        ArtifactState::Pending => "pending",
        ArtifactState::Available => "available",
        ArtifactState::Expired => "expired",
        ArtifactState::Deleted => "deleted",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphBuildOutput {
    pub graph: CapabilityGraph,
    pub graph_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerBuildIndex {
    pub module_to_objectives: BTreeMap<String, Vec<ObjectiveId>>,
    pub discovered_by_type: BTreeMap<String, Vec<String>>,
    pub signal_tokens: BTreeSet<String>,
    pub capability_set: BTreeSet<String>,
}

impl PlannerBuildIndex {
    pub fn from_snapshot(snapshot: &NormalizedPlannerSnapshot) -> Self {
        let mut module_to_objectives = BTreeMap::<String, Vec<ObjectiveId>>::new();
        for objective in snapshot.objectives() {
            for module_reference in objective_module_references(objective) {
                module_to_objectives
                    .entry(module_reference)
                    .or_default()
                    .push(objective.objective_id.clone());
            }
        }
        for objective_ids in module_to_objectives.values_mut() {
            objective_ids.sort_by_key(|id| id.as_str().to_string());
            objective_ids.dedup();
        }

        let mut capability_set = BTreeSet::<String>::new();
        let mut has_module_without_capability = false;
        for module in snapshot.modules() {
            if module.required_capabilities.is_empty() {
                has_module_without_capability = true;
            }
            capability_set.extend(module.required_capabilities.iter().cloned());
        }
        if has_module_without_capability {
            capability_set.insert("__no_capability__".to_string());
        }

        let mut signal_tokens = BTreeSet::<String>::new();
        signal_tokens.extend(snapshot.known_artifact_types().iter().cloned());
        for artifact in snapshot.artifacts() {
            signal_tokens.insert(artifact.artifact_type.clone());
            signal_tokens.extend(artifact.tags.iter().cloned());
        }

        let mut discovered_by_type = BTreeMap::<String, Vec<String>>::new();
        for artifact in snapshot.artifacts() {
            discovered_by_type
                .entry(artifact.artifact_type.clone())
                .or_default()
                .push(artifact.artifact_key.clone());
        }
        for artifact_keys in discovered_by_type.values_mut() {
            artifact_keys.sort();
            artifact_keys.dedup();
        }

        Self {
            module_to_objectives,
            discovered_by_type,
            signal_tokens,
            capability_set,
        }
    }
}

pub fn build_capability_graph(
    snapshot: &NormalizedPlannerSnapshot,
) -> Result<GraphBuildOutput, PlanningContractError> {
    let index = PlannerBuildIndex::from_snapshot(snapshot);
    build_capability_graph_indexed(snapshot, &index)
}

pub fn build_capability_graph_indexed(
    snapshot: &NormalizedPlannerSnapshot,
    index: &PlannerBuildIndex,
) -> Result<GraphBuildOutput, PlanningContractError> {
    let mut graph = CapabilityGraph::new();
    let mut objective_nodes = BTreeMap::<ObjectiveId, PlanNodeId>::new();
    let mut capability_nodes = BTreeMap::<String, PlanNodeId>::new();
    let mut signal_asset_nodes = BTreeMap::<String, PlanNodeId>::new();
    let mut discovered_asset_nodes = BTreeMap::<String, PlanNodeId>::new();

    for objective in snapshot.objectives() {
        let node_id = plan_node_id(&[
            "objective",
            objective.objective_id.as_str(),
            objective.status.as_str(),
        ])?;
        let label = objective
            .metadata
            .get("name")
            .and_then(metadata_text)
            .unwrap_or_else(|| objective.objective_id.as_str().to_string());
        graph.add_node(PlanNode::ObjectiveState(ObjectiveStateNode::new(
            node_id.clone(),
            objective.objective_id.clone(),
            objective.status,
            &label,
        )?))?;
        objective_nodes.insert(objective.objective_id.clone(), node_id);
    }

    for capability in &index.capability_set {
        let node_id = plan_node_id(&["capability", &capability, "enabled"])?;
        graph.add_node(PlanNode::CapabilityState(CapabilityStateNode::new(
            node_id.clone(),
            &capability,
            true,
        )?))?;
        capability_nodes.insert(capability.clone(), node_id);
    }

    for token in &index.signal_tokens {
        let node_id = plan_node_id(&["asset", "signal", &token, "expected"])?;
        graph.add_node(PlanNode::AssetState(AssetStateNode::new(
            node_id.clone(),
            &token,
            "expected",
        )?))?;
        signal_asset_nodes.insert(token.clone(), node_id);
    }

    for artifact in snapshot.artifacts() {
        let node_id = plan_node_id(&["asset", "record", &artifact.artifact_key])?;
        graph.add_node(PlanNode::AssetState(AssetStateNode::new(
            node_id.clone(),
            &artifact.artifact_type,
            &artifact.state,
        )?))?;
        discovered_asset_nodes.insert(artifact.artifact_key.clone(), node_id);
    }

    for objective in snapshot.objectives() {
        let to_objective = objective_nodes
            .get(&objective.objective_id)
            .expect("objective node exists");

        for prerequisite in &objective.prerequisites {
            if let Some(from_objective) = objective_nodes.get(prerequisite) {
                let edge_id = plan_edge_id(&[
                    "edge",
                    "state-transition",
                    prerequisite.as_str(),
                    objective.objective_id.as_str(),
                ])?;
                graph.add_edge(PlanEdge::state_transition(
                    edge_id,
                    from_objective.clone(),
                    to_objective.clone(),
                    PlanEdgeAttributes::new(
                        BTreeSet::new(),
                        0,
                        RiskLevel::Low,
                        10_000,
                        BTreeSet::new(),
                    )?,
                )?)?;
            }
        }
    }

    for module in snapshot.modules() {
        let sources = if module.required_capabilities.is_empty() {
            vec!["__no_capability__".to_string()]
        } else {
            module
                .required_capabilities
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        };

        for source_capability in &sources {
            let from_node = match capability_nodes.get(source_capability) {
                Some(node) => node.clone(),
                None => continue,
            };

            for expected_artifact in &module.expected_artifacts {
                if let Some(to_signal) = signal_asset_nodes.get(expected_artifact) {
                    let edge_id = plan_edge_id(&[
                        "edge",
                        "module",
                        &module.module_reference,
                        source_capability,
                        expected_artifact,
                    ])?;
                    graph.add_edge(PlanEdge::module_execution(
                        edge_id,
                        from_node.clone(),
                        to_signal.clone(),
                        &module.module_reference,
                        PlanEdgeAttributes::new(
                            module.required_capabilities.clone(),
                            module.estimated_noise_cost,
                            module.estimated_risk,
                            module.probability_of_success_bps,
                            module.expected_artifacts.clone(),
                        )?,
                    )?)?;
                }
            }

            if let Some(objective_ids) = index.module_to_objectives.get(&module.module_reference) {
                for objective_id in objective_ids {
                    let Some(objective_node) = objective_nodes.get(objective_id) else {
                        continue;
                    };
                    let edge_id = plan_edge_id(&[
                        "edge",
                        "module-to-objective",
                        &module.module_reference,
                        source_capability,
                        objective_id.as_str(),
                    ])?;
                    graph.add_edge(PlanEdge::module_execution(
                        edge_id,
                        from_node.clone(),
                        objective_node.clone(),
                        &module.module_reference,
                        PlanEdgeAttributes::new(
                            module.required_capabilities.clone(),
                            module.estimated_noise_cost,
                            module.estimated_risk,
                            module.probability_of_success_bps,
                            module.expected_artifacts.clone(),
                        )?,
                    )?)?;
                }
            }
        }
    }

    for artifact_keys in index.discovered_by_type.values() {
        let nodes = artifact_keys
            .iter()
            .filter_map(|artifact_key| discovered_asset_nodes.get(artifact_key))
            .cloned()
            .collect::<Vec<_>>();
        for pair in nodes.windows(2) {
            let edge_id = plan_edge_id(&["edge", "lateral", pair[0].as_str(), pair[1].as_str()])?;
            graph.add_edge(PlanEdge::lateral_movement(
                edge_id,
                pair[0].clone(),
                pair[1].clone(),
                PlanEdgeAttributes::new(
                    BTreeSet::new(),
                    1,
                    RiskLevel::Medium,
                    7_000,
                    BTreeSet::new(),
                )?,
            )?)?;
        }
    }

    maybe_add_privilege_escalation_edges(&capability_nodes, &mut graph)?;

    let graph_signature = encode_graph_signature(&graph);
    Ok(GraphBuildOutput {
        graph,
        graph_signature,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPlannerSnapshot {
    pub snapshot: NormalizedPlannerSnapshot,
    pub index: PlannerBuildIndex,
    pub graph_output: GraphBuildOutput,
}

impl PreparedPlannerSnapshot {
    pub fn prepare(snapshot: &NormalizedPlannerSnapshot) -> Result<Self, PlanningContractError> {
        let index = PlannerBuildIndex::from_snapshot(snapshot);
        let graph_output = build_capability_graph_indexed(snapshot, &index)?;
        Ok(Self {
            snapshot: snapshot.clone(),
            index,
            graph_output,
        })
    }

    pub fn estimated_footprint_bytes(&self) -> usize {
        self.snapshot.estimated_memory_bytes()
            + estimate_graph_memory_bytes(&self.graph_output.graph)
            + estimate_index_memory_bytes(&self.index)
    }
}

#[derive(Debug, Clone)]
pub struct ConcurrentPlannerEngine {
    prepared: Arc<PreparedPlannerSnapshot>,
}

impl ConcurrentPlannerEngine {
    pub fn new(snapshot: &NormalizedPlannerSnapshot) -> Result<Self, PlanningContractError> {
        let prepared = PreparedPlannerSnapshot::prepare(snapshot)?;
        Ok(Self {
            prepared: Arc::new(prepared),
        })
    }

    pub fn from_prepared(prepared: PreparedPlannerSnapshot) -> Self {
        Self {
            prepared: Arc::new(prepared),
        }
    }

    pub fn prepared(&self) -> Arc<PreparedPlannerSnapshot> {
        self.prepared.clone()
    }

    pub fn execute(
        &self,
        request: &PlanRequest,
        context: &PlannerEngineContext,
    ) -> Result<PlannerEngineOutput, PlanningContractError> {
        execute_planner_pipeline_prepared(&self.prepared.graph_output, request, context)
    }
}

fn estimate_graph_memory_bytes(graph: &CapabilityGraph) -> usize {
    encode_graph_signature(graph).len()
        + graph.node_count() * std::mem::size_of::<PlanNode>()
        + graph.edge_count() * std::mem::size_of::<PlanEdge>()
}

fn estimate_index_memory_bytes(index: &PlannerBuildIndex) -> usize {
    let module_to_objectives = index
        .module_to_objectives
        .iter()
        .map(|(module, objectives)| {
            module.len()
                + objectives.len() * std::mem::size_of::<ObjectiveId>()
                + std::mem::size_of::<Vec<ObjectiveId>>()
        })
        .sum::<usize>();
    let discovered_by_type = index
        .discovered_by_type
        .iter()
        .map(|(artifact_type, keys)| {
            artifact_type.len()
                + keys.iter().map(|key| key.len()).sum::<usize>()
                + std::mem::size_of::<Vec<String>>()
        })
        .sum::<usize>();
    let signal_tokens = index
        .signal_tokens
        .iter()
        .map(|token| token.len())
        .sum::<usize>();
    let capability_set = index
        .capability_set
        .iter()
        .map(|capability| capability.len())
        .sum::<usize>();

    module_to_objectives + discovered_by_type + signal_tokens + capability_set
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GraphRebuildTrigger {
    FullBuild,
    ModulesChanged,
    ObjectivesChanged,
    ArtifactsChanged,
    MetadataChanged,
}

impl GraphRebuildTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            GraphRebuildTrigger::FullBuild => "full_build",
            GraphRebuildTrigger::ModulesChanged => "modules_changed",
            GraphRebuildTrigger::ObjectivesChanged => "objectives_changed",
            GraphRebuildTrigger::ArtifactsChanged => "artifacts_changed",
            GraphRebuildTrigger::MetadataChanged => "metadata_changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphRebuildPlan {
    pub triggers: Vec<GraphRebuildTrigger>,
    pub added_modules: Vec<String>,
    pub removed_modules: Vec<String>,
    pub changed_modules: Vec<String>,
    pub added_objectives: Vec<ObjectiveId>,
    pub removed_objectives: Vec<ObjectiveId>,
    pub changed_objectives: Vec<ObjectiveId>,
    pub added_artifacts: Vec<String>,
    pub removed_artifacts: Vec<String>,
    pub changed_artifacts: Vec<String>,
}

impl GraphRebuildPlan {
    pub fn requires_rebuild(&self) -> bool {
        !self.triggers.is_empty()
    }
}

pub fn plan_graph_rebuild(
    previous: Option<&NormalizedPlannerSnapshot>,
    next: &NormalizedPlannerSnapshot,
) -> GraphRebuildPlan {
    match previous {
        None => GraphRebuildPlan {
            triggers: vec![GraphRebuildTrigger::FullBuild],
            added_modules: next
                .modules()
                .iter()
                .map(|module| module.module_reference.clone())
                .collect(),
            removed_modules: Vec::new(),
            changed_modules: Vec::new(),
            added_objectives: next
                .objectives()
                .iter()
                .map(|objective| objective.objective_id.clone())
                .collect(),
            removed_objectives: Vec::new(),
            changed_objectives: Vec::new(),
            added_artifacts: next
                .artifacts()
                .iter()
                .map(|artifact| artifact.artifact_key.clone())
                .collect(),
            removed_artifacts: Vec::new(),
            changed_artifacts: Vec::new(),
        },
        Some(previous) => {
            let (added_modules, removed_modules, changed_modules) =
                diff_modules(previous.modules(), next.modules());
            let (added_objectives, removed_objectives, changed_objectives) =
                diff_objectives(previous.objectives(), next.objectives());
            let (added_artifacts, removed_artifacts, changed_artifacts) =
                diff_artifacts(previous.artifacts(), next.artifacts());

            let mut triggers = BTreeSet::new();
            if !added_modules.is_empty()
                || !removed_modules.is_empty()
                || !changed_modules.is_empty()
            {
                triggers.insert(GraphRebuildTrigger::ModulesChanged);
            }
            if !added_objectives.is_empty()
                || !removed_objectives.is_empty()
                || !changed_objectives.is_empty()
            {
                triggers.insert(GraphRebuildTrigger::ObjectivesChanged);
            }
            if !added_artifacts.is_empty()
                || !removed_artifacts.is_empty()
                || !changed_artifacts.is_empty()
            {
                triggers.insert(GraphRebuildTrigger::ArtifactsChanged);
            }
            if previous.metadata() != next.metadata() {
                triggers.insert(GraphRebuildTrigger::MetadataChanged);
            }

            GraphRebuildPlan {
                triggers: triggers.into_iter().collect(),
                added_modules,
                removed_modules,
                changed_modules,
                added_objectives,
                removed_objectives,
                changed_objectives,
                added_artifacts,
                removed_artifacts,
                changed_artifacts,
            }
        }
    }
}

fn maybe_add_privilege_escalation_edges(
    capability_nodes: &BTreeMap<String, PlanNodeId>,
    graph: &mut CapabilityGraph,
) -> Result<(), PlanningContractError> {
    let Some(user_node) = capability_nodes.get("user") else {
        return Ok(());
    };
    let Some(elevated_node) = capability_nodes.get("elevated") else {
        return Ok(());
    };
    let Some(root_node) = capability_nodes.get("root") else {
        return Ok(());
    };

    graph.add_edge(PlanEdge::privilege_escalation(
        plan_edge_id(&["edge", "privesc", "user", "elevated"])?,
        user_node.clone(),
        elevated_node.clone(),
        PlanEdgeAttributes::new(BTreeSet::new(), 5, RiskLevel::High, 6_000, BTreeSet::new())?,
    )?)?;
    graph.add_edge(PlanEdge::privilege_escalation(
        plan_edge_id(&["edge", "privesc", "elevated", "root"])?,
        elevated_node.clone(),
        root_node.clone(),
        PlanEdgeAttributes::new(BTreeSet::new(), 8, RiskLevel::High, 5_000, BTreeSet::new())?,
    )?)?;
    Ok(())
}

fn objective_module_references(objective: &ObjectiveDefinitionInput) -> BTreeSet<String> {
    objective
        .success_criteria
        .iter()
        .chain(objective.failure_criteria.iter())
        .filter_map(|predicate| match predicate {
            Predicate::RunSucceeded { module_name } => Some(normalize_token(module_name)),
            _ => None,
        })
        .filter(|value| !value.is_empty())
        .collect()
}

fn diff_modules(
    previous: &[RegisteredModuleInput],
    next: &[RegisteredModuleInput],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let prev = previous
        .iter()
        .map(|module| (module.module_reference.clone(), module))
        .collect::<BTreeMap<_, _>>();
    let cur = next
        .iter()
        .map(|module| (module.module_reference.clone(), module))
        .collect::<BTreeMap<_, _>>();
    diff_by_key(&prev, &cur)
}

fn diff_objectives(
    previous: &[ObjectiveDefinitionInput],
    next: &[ObjectiveDefinitionInput],
) -> (Vec<ObjectiveId>, Vec<ObjectiveId>, Vec<ObjectiveId>) {
    let prev = previous
        .iter()
        .map(|objective| (objective.objective_id.clone(), objective))
        .collect::<BTreeMap<_, _>>();
    let cur = next
        .iter()
        .map(|objective| (objective.objective_id.clone(), objective))
        .collect::<BTreeMap<_, _>>();
    diff_by_key(&prev, &cur)
}

fn diff_artifacts(
    previous: &[DiscoveredArtifactInput],
    next: &[DiscoveredArtifactInput],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let prev = previous
        .iter()
        .map(|artifact| (artifact.artifact_key.clone(), artifact))
        .collect::<BTreeMap<_, _>>();
    let cur = next
        .iter()
        .map(|artifact| (artifact.artifact_key.clone(), artifact))
        .collect::<BTreeMap<_, _>>();
    diff_by_key(&prev, &cur)
}

fn diff_by_key<K, V>(previous: &BTreeMap<K, &V>, next: &BTreeMap<K, &V>) -> (Vec<K>, Vec<K>, Vec<K>)
where
    K: Ord + Clone,
    V: PartialEq + ?Sized,
{
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for key in previous.keys() {
        if !next.contains_key(key) {
            removed.push(key.clone());
        }
    }
    for (key, value) in next {
        match previous.get(key) {
            None => added.push(key.clone()),
            Some(previous_value) if *previous_value != *value => changed.push(key.clone()),
            Some(_) => {}
        }
    }
    (added, removed, changed)
}

fn plan_node_id(parts: &[&str]) -> Result<PlanNodeId, PlanningContractError> {
    PlanNodeId::parse(
        &parts
            .iter()
            .map(|part| identifier_fragment(part))
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn plan_edge_id(parts: &[&str]) -> Result<PlanEdgeId, PlanningContractError> {
    PlanEdgeId::parse(
        &parts
            .iter()
            .map(|part| identifier_fragment(part))
            .collect::<Vec<_>>()
            .join("/"),
    )
}

fn identifier_fragment(input: &str) -> String {
    let mut out = String::new();
    let mut previous_dash = false;
    for ch in normalize_token(input).chars() {
        let valid = ch.is_ascii_lowercase()
            || ch.is_ascii_digit()
            || matches!(ch, '.' | '_' | ':' | '/' | '-');
        let mapped = if valid { ch } else { '-' };
        if mapped == '-' {
            if previous_dash {
                continue;
            }
            previous_dash = true;
        } else {
            previous_dash = false;
        }
        out.push(mapped);
    }
    out.trim_matches('-').to_string()
}

fn metadata_text(value: &MetadataValue) -> Option<String> {
    match value {
        MetadataValue::Text(text) => Some(text.trim().to_string()),
        _ => None,
    }
}

fn encode_graph_signature(graph: &CapabilityGraph) -> String {
    let node_signature = graph
        .nodes()
        .iter()
        .map(|(node_id, node)| format!("{}:{}", node_id.as_str(), node.node_type().as_str()))
        .collect::<Vec<_>>()
        .join(";");
    let edge_signature = graph
        .edges()
        .iter()
        .map(|(edge_id, edge)| {
            format!(
                "{}:{}:{}:{}:{}",
                edge_id.as_str(),
                edge.edge_type().as_str(),
                edge.from().as_str(),
                edge.to().as_str(),
                edge.module_reference().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    format!("nodes={node_signature}|edges={edge_signature}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AStarCostWeights {
    pub noise_weight: u32,
    pub risk_low_weight: u32,
    pub risk_medium_weight: u32,
    pub risk_high_weight: u32,
    pub step_weight: u32,
    pub capability_penalty_weight: u32,
}

impl AStarCostWeights {
    pub fn new(
        noise_weight: u32,
        risk_low_weight: u32,
        risk_medium_weight: u32,
        risk_high_weight: u32,
        step_weight: u32,
        capability_penalty_weight: u32,
    ) -> Result<Self, PlanningContractError> {
        if step_weight == 0 {
            return Err(PlanningContractError::InvalidField {
                field: "astar_cost_weights.step_weight",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            noise_weight,
            risk_low_weight,
            risk_medium_weight,
            risk_high_weight,
            step_weight,
            capability_penalty_weight,
        })
    }

    pub fn default_contract() -> Self {
        Self {
            noise_weight: 10,
            risk_low_weight: 5,
            risk_medium_weight: 25,
            risk_high_weight: 100,
            step_weight: 1,
            capability_penalty_weight: 200,
        }
    }

    fn risk_weight(&self, risk: RiskLevel) -> u64 {
        match risk {
            RiskLevel::Low => self.risk_low_weight as u64,
            RiskLevel::Medium => self.risk_medium_weight as u64,
            RiskLevel::High => self.risk_high_weight as u64,
        }
    }
}

impl Default for AStarCostWeights {
    fn default() -> Self {
        Self::default_contract()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AStarPlanRequest {
    pub objective_id: ObjectiveId,
    pub available_capabilities: BTreeSet<String>,
    pub weights: AStarCostWeights,
}

impl AStarPlanRequest {
    pub fn new(
        objective_id: ObjectiveId,
        available_capabilities: BTreeSet<String>,
        weights: AStarCostWeights,
    ) -> Self {
        Self {
            objective_id,
            available_capabilities: normalize_tokens(available_capabilities),
            weights,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AStarPlanResult {
    pub objective_id: ObjectiveId,
    pub start_node: PlanNodeId,
    pub goal_node: PlanNodeId,
    pub traversed_nodes: Vec<PlanNodeId>,
    pub traversed_edges: Vec<PlanEdgeId>,
    pub total_cost: u64,
    pub total_noise_cost: u64,
    pub required_capabilities: BTreeSet<String>,
    pub blocked_capabilities: BTreeSet<String>,
    pub weighted_success_probability_bps: u16,
}

pub fn astar_plan(
    graph: &CapabilityGraph,
    request: &AStarPlanRequest,
) -> Result<Option<AStarPlanResult>, PlanningContractError> {
    astar_plan_with_forbidden_edges(graph, request, &BTreeSet::new())
}

pub fn astar_plan_with_forbidden_edges(
    graph: &CapabilityGraph,
    request: &AStarPlanRequest,
    forbidden_edges: &BTreeSet<PlanEdgeId>,
) -> Result<Option<AStarPlanResult>, PlanningContractError> {
    let objective_nodes = graph
        .nodes()
        .iter()
        .filter_map(|(node_id, node)| match node {
            PlanNode::ObjectiveState(objective)
                if objective.objective_id == request.objective_id =>
            {
                Some(node_id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if objective_nodes.is_empty() {
        return Ok(None);
    }

    let start_nodes = graph
        .nodes()
        .iter()
        .filter_map(|(node_id, node)| match node {
            PlanNode::CapabilityState(_) => Some(node_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if start_nodes.is_empty() {
        return Ok(None);
    }

    let hop_bounds =
        compute_goal_hop_bounds_with_forbidden_edges(graph, &objective_nodes, forbidden_edges);
    let lower_bound = minimum_edge_lower_bound(graph, &request.weights);
    let adjacency = adjacency_index(graph);

    let mut open = BinaryHeap::<OpenEntry>::new();
    let mut best_g = BTreeMap::<PlanNodeId, u64>::new();
    let mut parent = BTreeMap::<PlanNodeId, ParentStep>::new();
    let mut expansion_seq = 0_u64;

    for start in start_nodes {
        if !hop_bounds.contains_key(&start) {
            continue;
        }
        let g = 0_u64;
        let h = heuristic_cost(&start, &hop_bounds, lower_bound);
        let f = g.saturating_add(h);
        best_g.insert(start.clone(), g);
        open.push(OpenEntry {
            f,
            h,
            g,
            node_id: start,
            seq: expansion_seq,
        });
        expansion_seq = expansion_seq.saturating_add(1);
    }
    if open.is_empty() {
        return Ok(None);
    }

    while let Some(entry) = open.pop() {
        let Some(recorded_g) = best_g.get(&entry.node_id).copied() else {
            continue;
        };
        if recorded_g != entry.g {
            continue;
        }
        if objective_nodes.contains(&entry.node_id) {
            let (nodes, edges) = reconstruct_path(&entry.node_id, &parent);
            let metrics = calculate_path_metrics(graph, &edges, request);
            return Ok(Some(AStarPlanResult {
                objective_id: request.objective_id.clone(),
                start_node: nodes.first().expect("path has at least one node").clone(),
                goal_node: entry.node_id.clone(),
                traversed_nodes: nodes,
                traversed_edges: edges,
                total_cost: entry.g,
                total_noise_cost: metrics.total_noise_cost,
                required_capabilities: metrics.required_capabilities,
                blocked_capabilities: metrics.blocked_capabilities,
                weighted_success_probability_bps: metrics.weighted_success_probability_bps,
            }));
        }

        let Some(neighbors) = adjacency.get(&entry.node_id) else {
            continue;
        };
        for (edge_id, next_node) in neighbors {
            if forbidden_edges.contains(edge_id) {
                continue;
            }
            if !hop_bounds.contains_key(next_node) {
                continue;
            }
            let edge = graph
                .edges()
                .get(edge_id)
                .expect("adjacency edges always resolve in graph");
            let step_cost = edge_weight(edge, &request.available_capabilities, &request.weights);
            let tentative_g = entry.g.saturating_add(step_cost);
            let existing = best_g.get(next_node).copied();
            let should_update = match existing {
                None => true,
                Some(current) if tentative_g < current => true,
                Some(current) if tentative_g == current => {
                    should_prefer_parent(parent.get(next_node), &entry.node_id, edge_id)
                }
                Some(_) => false,
            };
            if !should_update {
                continue;
            }

            best_g.insert(next_node.clone(), tentative_g);
            parent.insert(
                next_node.clone(),
                ParentStep {
                    parent_node: entry.node_id.clone(),
                    edge_id: edge_id.clone(),
                },
            );

            let h = heuristic_cost(next_node, &hop_bounds, lower_bound);
            let f = tentative_g.saturating_add(h);
            open.push(OpenEntry {
                f,
                h,
                g: tentative_g,
                node_id: next_node.clone(),
                seq: expansion_seq,
            });
            expansion_seq = expansion_seq.saturating_add(1);
        }
    }

    Ok(None)
}

fn should_prefer_parent(
    current_parent: Option<&ParentStep>,
    candidate_parent_node: &PlanNodeId,
    candidate_edge_id: &PlanEdgeId,
) -> bool {
    match current_parent {
        None => true,
        Some(current) => {
            let candidate = (candidate_edge_id.as_str(), candidate_parent_node.as_str());
            let existing = (current.edge_id.as_str(), current.parent_node.as_str());
            candidate < existing
        }
    }
}

fn edge_weight(
    edge: &PlanEdge,
    available_capabilities: &BTreeSet<String>,
    weights: &AStarCostWeights,
) -> u64 {
    let attrs = edge.attrs();
    let base_noise =
        (attrs.estimated_noise_cost as u64).saturating_mul(weights.noise_weight as u64);
    let base_risk = weights.risk_weight(attrs.estimated_risk);
    let step = weights.step_weight as u64;
    let missing = attrs
        .required_capabilities
        .iter()
        .filter(|capability| !available_capabilities.contains(*capability))
        .count() as u64;
    let capability_penalty = missing.saturating_mul(weights.capability_penalty_weight as u64);
    base_noise
        .saturating_add(base_risk)
        .saturating_add(step)
        .saturating_add(capability_penalty)
}

fn minimum_edge_lower_bound(graph: &CapabilityGraph, weights: &AStarCostWeights) -> u64 {
    let minimum = graph
        .edges()
        .values()
        .map(|edge| {
            let attrs = edge.attrs();
            (attrs.estimated_noise_cost as u64)
                .saturating_mul(weights.noise_weight as u64)
                .saturating_add(weights.risk_weight(attrs.estimated_risk))
                .saturating_add(weights.step_weight as u64)
        })
        .min()
        .unwrap_or(0);
    minimum
}

fn compute_goal_hop_bounds_with_forbidden_edges(
    graph: &CapabilityGraph,
    goals: &BTreeSet<PlanNodeId>,
    forbidden_edges: &BTreeSet<PlanEdgeId>,
) -> BTreeMap<PlanNodeId, u32> {
    let mut reverse = BTreeMap::<PlanNodeId, Vec<PlanNodeId>>::new();
    for (edge_id, edge) in graph.edges() {
        if forbidden_edges.contains(edge_id) {
            continue;
        }
        reverse
            .entry(edge.to().clone())
            .or_default()
            .push(edge.from().clone());
    }
    for nodes in reverse.values_mut() {
        nodes.sort_by_key(|node| node.as_str().to_string());
    }

    let mut distances = BTreeMap::<PlanNodeId, u32>::new();
    let mut queue = VecDeque::<PlanNodeId>::new();
    for goal in goals {
        distances.insert(goal.clone(), 0);
        queue.push_back(goal.clone());
    }

    while let Some(node) = queue.pop_front() {
        let next_distance = distances.get(&node).copied().unwrap_or(0).saturating_add(1);
        let Some(predecessors) = reverse.get(&node) else {
            continue;
        };
        for predecessor in predecessors {
            let entry = distances.entry(predecessor.clone()).or_insert(u32::MAX);
            if next_distance < *entry {
                *entry = next_distance;
                queue.push_back(predecessor.clone());
            }
        }
    }

    distances
}

fn heuristic_cost(
    node_id: &PlanNodeId,
    hop_bounds: &BTreeMap<PlanNodeId, u32>,
    minimum_edge_cost: u64,
) -> u64 {
    let hops = hop_bounds.get(node_id).copied().unwrap_or(0) as u64;
    hops.saturating_mul(minimum_edge_cost)
}

fn adjacency_index(graph: &CapabilityGraph) -> BTreeMap<PlanNodeId, Vec<(PlanEdgeId, PlanNodeId)>> {
    let mut index = BTreeMap::<PlanNodeId, Vec<(PlanEdgeId, PlanNodeId)>>::new();
    for (edge_id, edge) in graph.edges() {
        index
            .entry(edge.from().clone())
            .or_default()
            .push((edge_id.clone(), edge.to().clone()));
    }
    for neighbors in index.values_mut() {
        neighbors.sort_by(|left, right| match left.1.as_str().cmp(right.1.as_str()) {
            Ordering::Equal => left.0.as_str().cmp(right.0.as_str()),
            order => order,
        });
    }
    index
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParentStep {
    parent_node: PlanNodeId,
    edge_id: PlanEdgeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathMetrics {
    total_noise_cost: u64,
    required_capabilities: BTreeSet<String>,
    blocked_capabilities: BTreeSet<String>,
    weighted_success_probability_bps: u16,
}

fn calculate_path_metrics(
    graph: &CapabilityGraph,
    edges: &[PlanEdgeId],
    request: &AStarPlanRequest,
) -> PathMetrics {
    let mut total_noise_cost = 0_u64;
    let mut required_capabilities = BTreeSet::new();
    let mut blocked_capabilities = BTreeSet::new();
    let mut success_probability_bps = 10_000_u16;

    for edge_id in edges {
        let edge = graph
            .edges()
            .get(edge_id)
            .expect("path edge must exist in graph");
        let attrs = edge.attrs();
        total_noise_cost = total_noise_cost.saturating_add(attrs.estimated_noise_cost as u64);
        required_capabilities.extend(attrs.required_capabilities.iter().cloned());
        for capability in &attrs.required_capabilities {
            if !request.available_capabilities.contains(capability) {
                blocked_capabilities.insert(capability.clone());
            }
        }
        success_probability_bps = ((success_probability_bps as u32)
            .saturating_mul(attrs.probability_of_success_bps as u32)
            / 10_000) as u16;
    }

    PathMetrics {
        total_noise_cost,
        required_capabilities,
        blocked_capabilities,
        weighted_success_probability_bps: success_probability_bps,
    }
}

fn reconstruct_path(
    goal: &PlanNodeId,
    parent: &BTreeMap<PlanNodeId, ParentStep>,
) -> (Vec<PlanNodeId>, Vec<PlanEdgeId>) {
    let mut nodes = vec![goal.clone()];
    let mut edges = Vec::<PlanEdgeId>::new();
    let mut cursor = goal.clone();
    while let Some(step) = parent.get(&cursor) {
        edges.push(step.edge_id.clone());
        nodes.push(step.parent_node.clone());
        cursor = step.parent_node.clone();
    }
    nodes.reverse();
    edges.reverse();
    (nodes, edges)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenEntry {
    f: u64,
    h: u64,
    g: u64,
    node_id: PlanNodeId,
    seq: u64,
}

impl Ord for OpenEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for BinaryHeap max-heap so smallest tuple pops first.
        (other.f, other.h, other.g, other.node_id.as_str(), other.seq).cmp(&(
            self.f,
            self.h,
            self.g,
            self.node_id.as_str(),
            self.seq,
        ))
    }
}

impl PartialOrd for OpenEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanLifecycleStatus {
    Requested,
    GraphReady,
    Proposed,
    Explained,
    Simulated,
    Unreachable,
    Superseded,
    Failed,
}

impl PlanLifecycleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            PlanLifecycleStatus::Requested => "requested",
            PlanLifecycleStatus::GraphReady => "graph_ready",
            PlanLifecycleStatus::Proposed => "proposed",
            PlanLifecycleStatus::Explained => "explained",
            PlanLifecycleStatus::Simulated => "simulated",
            PlanLifecycleStatus::Unreachable => "unreachable",
            PlanLifecycleStatus::Superseded => "superseded",
            PlanLifecycleStatus::Failed => "failed",
        }
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (PlanLifecycleStatus::Requested, PlanLifecycleStatus::GraphReady)
            | (PlanLifecycleStatus::Requested, PlanLifecycleStatus::Failed)
            | (PlanLifecycleStatus::GraphReady, PlanLifecycleStatus::Proposed)
            | (PlanLifecycleStatus::GraphReady, PlanLifecycleStatus::Unreachable)
            | (PlanLifecycleStatus::GraphReady, PlanLifecycleStatus::Failed)
            | (PlanLifecycleStatus::Proposed, PlanLifecycleStatus::Explained)
            | (PlanLifecycleStatus::Proposed, PlanLifecycleStatus::Simulated)
            | (PlanLifecycleStatus::Proposed, PlanLifecycleStatus::Superseded)
            | (PlanLifecycleStatus::Proposed, PlanLifecycleStatus::Failed)
            | (PlanLifecycleStatus::Explained, PlanLifecycleStatus::Simulated)
            | (PlanLifecycleStatus::Explained, PlanLifecycleStatus::Superseded)
            | (PlanLifecycleStatus::Explained, PlanLifecycleStatus::Failed)
            | (PlanLifecycleStatus::Simulated, PlanLifecycleStatus::Superseded)
            | (PlanLifecycleStatus::Simulated, PlanLifecycleStatus::Failed)
            | (PlanLifecycleStatus::Unreachable, PlanLifecycleStatus::Superseded) => true,
            _ => false,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            PlanLifecycleStatus::Superseded | PlanLifecycleStatus::Failed
        )
    }
}

pub const PLAN_LIFECYCLE_ALLOWED_TRANSITIONS: &[(PlanLifecycleStatus, PlanLifecycleStatus)] = &[
    (
        PlanLifecycleStatus::Requested,
        PlanLifecycleStatus::GraphReady,
    ),
    (PlanLifecycleStatus::Requested, PlanLifecycleStatus::Failed),
    (
        PlanLifecycleStatus::GraphReady,
        PlanLifecycleStatus::Proposed,
    ),
    (
        PlanLifecycleStatus::GraphReady,
        PlanLifecycleStatus::Unreachable,
    ),
    (PlanLifecycleStatus::GraphReady, PlanLifecycleStatus::Failed),
    (
        PlanLifecycleStatus::Proposed,
        PlanLifecycleStatus::Explained,
    ),
    (
        PlanLifecycleStatus::Proposed,
        PlanLifecycleStatus::Simulated,
    ),
    (
        PlanLifecycleStatus::Proposed,
        PlanLifecycleStatus::Superseded,
    ),
    (PlanLifecycleStatus::Proposed, PlanLifecycleStatus::Failed),
    (
        PlanLifecycleStatus::Explained,
        PlanLifecycleStatus::Simulated,
    ),
    (
        PlanLifecycleStatus::Explained,
        PlanLifecycleStatus::Superseded,
    ),
    (PlanLifecycleStatus::Explained, PlanLifecycleStatus::Failed),
    (
        PlanLifecycleStatus::Simulated,
        PlanLifecycleStatus::Superseded,
    ),
    (PlanLifecycleStatus::Simulated, PlanLifecycleStatus::Failed),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::Superseded,
    ),
];

pub const PLAN_LIFECYCLE_FORBIDDEN_TRANSITIONS: &[(PlanLifecycleStatus, PlanLifecycleStatus)] = &[
    (
        PlanLifecycleStatus::Requested,
        PlanLifecycleStatus::Requested,
    ),
    (
        PlanLifecycleStatus::Requested,
        PlanLifecycleStatus::Proposed,
    ),
    (
        PlanLifecycleStatus::Requested,
        PlanLifecycleStatus::Explained,
    ),
    (
        PlanLifecycleStatus::Requested,
        PlanLifecycleStatus::Simulated,
    ),
    (
        PlanLifecycleStatus::Requested,
        PlanLifecycleStatus::Unreachable,
    ),
    (
        PlanLifecycleStatus::Requested,
        PlanLifecycleStatus::Superseded,
    ),
    (
        PlanLifecycleStatus::GraphReady,
        PlanLifecycleStatus::Requested,
    ),
    (
        PlanLifecycleStatus::GraphReady,
        PlanLifecycleStatus::GraphReady,
    ),
    (
        PlanLifecycleStatus::GraphReady,
        PlanLifecycleStatus::Explained,
    ),
    (
        PlanLifecycleStatus::GraphReady,
        PlanLifecycleStatus::Simulated,
    ),
    (
        PlanLifecycleStatus::GraphReady,
        PlanLifecycleStatus::Superseded,
    ),
    (
        PlanLifecycleStatus::Proposed,
        PlanLifecycleStatus::Requested,
    ),
    (
        PlanLifecycleStatus::Proposed,
        PlanLifecycleStatus::GraphReady,
    ),
    (PlanLifecycleStatus::Proposed, PlanLifecycleStatus::Proposed),
    (
        PlanLifecycleStatus::Proposed,
        PlanLifecycleStatus::Unreachable,
    ),
    (
        PlanLifecycleStatus::Explained,
        PlanLifecycleStatus::Requested,
    ),
    (
        PlanLifecycleStatus::Explained,
        PlanLifecycleStatus::GraphReady,
    ),
    (
        PlanLifecycleStatus::Explained,
        PlanLifecycleStatus::Proposed,
    ),
    (
        PlanLifecycleStatus::Explained,
        PlanLifecycleStatus::Explained,
    ),
    (
        PlanLifecycleStatus::Explained,
        PlanLifecycleStatus::Unreachable,
    ),
    (
        PlanLifecycleStatus::Simulated,
        PlanLifecycleStatus::Requested,
    ),
    (
        PlanLifecycleStatus::Simulated,
        PlanLifecycleStatus::GraphReady,
    ),
    (
        PlanLifecycleStatus::Simulated,
        PlanLifecycleStatus::Proposed,
    ),
    (
        PlanLifecycleStatus::Simulated,
        PlanLifecycleStatus::Explained,
    ),
    (
        PlanLifecycleStatus::Simulated,
        PlanLifecycleStatus::Simulated,
    ),
    (
        PlanLifecycleStatus::Simulated,
        PlanLifecycleStatus::Unreachable,
    ),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::Requested,
    ),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::GraphReady,
    ),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::Proposed,
    ),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::Explained,
    ),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::Simulated,
    ),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::Unreachable,
    ),
    (
        PlanLifecycleStatus::Unreachable,
        PlanLifecycleStatus::Failed,
    ),
    (
        PlanLifecycleStatus::Superseded,
        PlanLifecycleStatus::Requested,
    ),
    (
        PlanLifecycleStatus::Superseded,
        PlanLifecycleStatus::GraphReady,
    ),
    (
        PlanLifecycleStatus::Superseded,
        PlanLifecycleStatus::Proposed,
    ),
    (
        PlanLifecycleStatus::Superseded,
        PlanLifecycleStatus::Explained,
    ),
    (
        PlanLifecycleStatus::Superseded,
        PlanLifecycleStatus::Simulated,
    ),
    (
        PlanLifecycleStatus::Superseded,
        PlanLifecycleStatus::Unreachable,
    ),
    (
        PlanLifecycleStatus::Superseded,
        PlanLifecycleStatus::Superseded,
    ),
    (PlanLifecycleStatus::Superseded, PlanLifecycleStatus::Failed),
    (PlanLifecycleStatus::Failed, PlanLifecycleStatus::Requested),
    (PlanLifecycleStatus::Failed, PlanLifecycleStatus::GraphReady),
    (PlanLifecycleStatus::Failed, PlanLifecycleStatus::Proposed),
    (PlanLifecycleStatus::Failed, PlanLifecycleStatus::Explained),
    (PlanLifecycleStatus::Failed, PlanLifecycleStatus::Simulated),
    (
        PlanLifecycleStatus::Failed,
        PlanLifecycleStatus::Unreachable,
    ),
    (PlanLifecycleStatus::Failed, PlanLifecycleStatus::Superseded),
    (PlanLifecycleStatus::Failed, PlanLifecycleStatus::Failed),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRequest {
    pub objective_id: ObjectiveId,
    pub mode: PlanRequestMode,
    pub event_key: String,
    pub max_steps: Option<u16>,
    pub include_blocked_paths: bool,
}

impl PlanRequest {
    pub fn new(
        objective_id: ObjectiveId,
        mode: PlanRequestMode,
        event_key: &str,
        max_steps: Option<u16>,
        include_blocked_paths: bool,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(event_key, "plan_request.event_key")?;
        if max_steps.is_some_and(|value| value == 0) {
            return Err(PlanningContractError::InvalidField {
                field: "plan_request.max_steps",
                reason: "must be > 0 when present",
            });
        }
        Ok(Self {
            objective_id,
            mode,
            event_key: normalize_token(event_key),
            max_steps,
            include_blocked_paths,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStepBlockReason {
    CapabilityDisabled { capability: String },
    PolicyDenied { policy_key: String },
    OutOfScope { scope_key: String },
}

impl PlanStepBlockReason {
    pub const fn code(&self) -> &'static str {
        match self {
            PlanStepBlockReason::CapabilityDisabled { .. } => "ML-PLAN-BLOCK-0001",
            PlanStepBlockReason::PolicyDenied { .. } => "ML-PLAN-BLOCK-0002",
            PlanStepBlockReason::OutOfScope { .. } => "ML-PLAN-BLOCK-0003",
        }
    }

    pub fn stable_encoding(&self) -> String {
        match self {
            PlanStepBlockReason::CapabilityDisabled { capability } => {
                format!("capability_disabled:{}", normalize_token(capability))
            }
            PlanStepBlockReason::PolicyDenied { policy_key } => {
                format!("policy_denied:{}", normalize_token(policy_key))
            }
            PlanStepBlockReason::OutOfScope { scope_key } => {
                format!("out_of_scope:{}", normalize_token(scope_key))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub order: u16,
    pub edge_id: PlanEdgeId,
    pub module_reference: Option<String>,
    pub required_capabilities: BTreeSet<String>,
    pub estimated_noise_cost: u32,
    pub estimated_risk: RiskLevel,
    pub probability_of_success_bps: u16,
    pub expected_artifacts: BTreeSet<String>,
    pub blocked_reasons: Vec<PlanStepBlockReason>,
}

impl PlanStep {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        order: u16,
        edge_id: PlanEdgeId,
        module_reference: Option<String>,
        required_capabilities: BTreeSet<String>,
        estimated_noise_cost: u32,
        estimated_risk: RiskLevel,
        probability_of_success_bps: u16,
        expected_artifacts: BTreeSet<String>,
        blocked_reasons: Vec<PlanStepBlockReason>,
    ) -> Result<Self, PlanningContractError> {
        if probability_of_success_bps > 10_000 {
            return Err(PlanningContractError::InvalidField {
                field: "plan_step.probability_of_success_bps",
                reason: "must be in 0..=10000",
            });
        }
        Ok(Self {
            order,
            edge_id,
            module_reference: module_reference
                .map(|value| normalize_token(&value))
                .filter(|value| !value.is_empty()),
            required_capabilities: normalize_tokens(required_capabilities),
            estimated_noise_cost,
            estimated_risk,
            probability_of_success_bps,
            expected_artifacts: normalize_tokens(expected_artifacts),
            blocked_reasons,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanUnreachableReason {
    NoGraphPath,
    PrerequisitesUnsatisfied,
    CapabilityUnavailable,
    PolicyRestricted,
    ScopeRestricted,
    StepLimitExceeded,
}

impl PlanUnreachableReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PlanUnreachableReason::NoGraphPath => "no_graph_path",
            PlanUnreachableReason::PrerequisitesUnsatisfied => "prerequisites_unsatisfied",
            PlanUnreachableReason::CapabilityUnavailable => "capability_unavailable",
            PlanUnreachableReason::PolicyRestricted => "policy_restricted",
            PlanUnreachableReason::ScopeRestricted => "scope_restricted",
            PlanUnreachableReason::StepLimitExceeded => "step_limit_exceeded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanResult {
    pub objective_id: ObjectiveId,
    pub status: PlanLifecycleStatus,
    pub algorithm: PlanningAlgorithm,
    pub generated_at: u64,
    pub step_count: u16,
    pub total_noise_cost: u64,
    pub total_risk_cost: u64,
    pub required_capabilities: BTreeSet<String>,
    pub success_probability_bps: u16,
    pub blocked_capabilities: BTreeSet<String>,
    pub unreachable_reason: Option<PlanUnreachableReason>,
    pub steps: Vec<PlanStep>,
}

impl PlanResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        objective_id: ObjectiveId,
        status: PlanLifecycleStatus,
        algorithm: PlanningAlgorithm,
        generated_at: u64,
        total_noise_cost: u64,
        total_risk_cost: u64,
        required_capabilities: BTreeSet<String>,
        success_probability_bps: u16,
        blocked_capabilities: BTreeSet<String>,
        unreachable_reason: Option<PlanUnreachableReason>,
        steps: Vec<PlanStep>,
    ) -> Result<Self, PlanningContractError> {
        if success_probability_bps > 10_000 {
            return Err(PlanningContractError::InvalidField {
                field: "plan_result.success_probability_bps",
                reason: "must be in 0..=10000",
            });
        }
        if unreachable_reason.is_some() {
            if status != PlanLifecycleStatus::Unreachable {
                return Err(PlanningContractError::InvalidField {
                    field: "plan_result.status",
                    reason: "status must be unreachable when unreachable_reason is present",
                });
            }
            if !steps.is_empty() {
                return Err(PlanningContractError::InvariantViolation {
                    invariant: "unreachable plans must not include executable steps",
                });
            }
        } else if matches!(
            status,
            PlanLifecycleStatus::Proposed
                | PlanLifecycleStatus::Explained
                | PlanLifecycleStatus::Simulated
        ) && steps.is_empty()
        {
            return Err(PlanningContractError::InvalidField {
                field: "plan_result.steps",
                reason: "proposed/explained/simulated plans require at least one step",
            });
        }

        Ok(Self {
            objective_id,
            status,
            algorithm,
            generated_at,
            step_count: steps.len() as u16,
            total_noise_cost,
            total_risk_cost,
            required_capabilities: normalize_tokens(required_capabilities),
            success_probability_bps,
            blocked_capabilities: normalize_tokens(blocked_capabilities),
            unreachable_reason,
            steps,
        })
    }

    pub fn now(
        objective_id: ObjectiveId,
        status: PlanLifecycleStatus,
        total_noise_cost: u64,
        total_risk_cost: u64,
        required_capabilities: BTreeSet<String>,
        success_probability_bps: u16,
        blocked_capabilities: BTreeSet<String>,
        unreachable_reason: Option<PlanUnreachableReason>,
        steps: Vec<PlanStep>,
    ) -> Result<Self, PlanningContractError> {
        Self::new(
            objective_id,
            status,
            PlanningAlgorithm::AStar,
            now_secs(),
            total_noise_cost,
            total_risk_cost,
            required_capabilities,
            success_probability_bps,
            blocked_capabilities,
            unreachable_reason,
            steps,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerEngineContext {
    pub generated_at: u64,
    pub available_capabilities: BTreeSet<String>,
    pub weights: AStarCostWeights,
    pub policy_blocked_modules: BTreeMap<String, String>,
    pub module_scopes: BTreeMap<String, String>,
    pub allowed_scopes: BTreeSet<String>,
}

impl PlannerEngineContext {
    pub fn new(
        generated_at: u64,
        available_capabilities: BTreeSet<String>,
        weights: AStarCostWeights,
    ) -> Self {
        Self {
            generated_at,
            available_capabilities: normalize_tokens(available_capabilities),
            weights,
            policy_blocked_modules: BTreeMap::new(),
            module_scopes: BTreeMap::new(),
            allowed_scopes: BTreeSet::new(),
        }
    }

    pub fn with_policy_blocked_module(mut self, module_reference: &str, policy_key: &str) -> Self {
        let module_reference = normalize_token(module_reference);
        let policy_key = normalize_token(policy_key);
        if !module_reference.is_empty() && !policy_key.is_empty() {
            self.policy_blocked_modules
                .insert(module_reference, policy_key);
        }
        self
    }

    pub fn with_module_scope(mut self, module_reference: &str, scope: &str) -> Self {
        let module_reference = normalize_token(module_reference);
        let scope = normalize_token(scope);
        if !module_reference.is_empty() && !scope.is_empty() {
            self.module_scopes.insert(module_reference, scope);
        }
        self
    }

    pub fn with_allowed_scope(mut self, scope: &str) -> Self {
        let scope = normalize_token(scope);
        if !scope.is_empty() {
            self.allowed_scopes.insert(scope);
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStepExplanation {
    pub order: u16,
    pub edge_id: PlanEdgeId,
    pub module_reference: Option<String>,
    pub weighted_noise_cost: u64,
    pub weighted_risk_cost: u64,
    pub weighted_step_cost: u64,
    pub weighted_capability_penalty_cost: u64,
    pub weighted_total_cost: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanExplanation {
    pub objective_id: ObjectiveId,
    pub total_weighted_cost: u64,
    pub heuristic_model: String,
    pub steps: Vec<PlanStepExplanation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSimulation {
    pub objective_id: ObjectiveId,
    pub predicted_artifact_chain: Vec<String>,
    pub expected_detection_surface: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerEngineOutput {
    pub graph_signature: String,
    pub result: PlanResult,
    pub explanation: Option<PlanExplanation>,
    pub simulation: Option<PlanSimulation>,
    pub event_payloads: Vec<PlanningEventPayload>,
}

pub fn execute_planner_pipeline(
    snapshot: &NormalizedPlannerSnapshot,
    request: &PlanRequest,
    context: &PlannerEngineContext,
) -> Result<PlannerEngineOutput, PlanningContractError> {
    let graph_output = build_capability_graph(snapshot)?;
    execute_planner_pipeline_prepared(&graph_output, request, context)
}

pub fn execute_planner_pipeline_prepared(
    graph_output: &GraphBuildOutput,
    request: &PlanRequest,
    context: &PlannerEngineContext,
) -> Result<PlannerEngineOutput, PlanningContractError> {
    execute_planner_pipeline_with_graph(graph_output, request, context, &BTreeSet::new())
}

fn execute_planner_pipeline_with_graph(
    graph_output: &GraphBuildOutput,
    request: &PlanRequest,
    context: &PlannerEngineContext,
    forbidden_edges: &BTreeSet<PlanEdgeId>,
) -> Result<PlannerEngineOutput, PlanningContractError> {
    let astar_request = AStarPlanRequest::new(
        request.objective_id.clone(),
        context.available_capabilities.clone(),
        context.weights.clone(),
    );
    let mut effective_forbidden_edges = forbidden_edges.clone();
    if !request.include_blocked_paths {
        effective_forbidden_edges.extend(blocked_edges_for_context(&graph_output.graph, context));
    }
    let mut path = astar_plan_with_forbidden_edges(
        &graph_output.graph,
        &astar_request,
        &effective_forbidden_edges,
    )?;
    // Prefer unblocked paths when requested, but keep advisory continuity if none exist.
    if path.is_none()
        && !request.include_blocked_paths
        && effective_forbidden_edges != *forbidden_edges
    {
        path =
            astar_plan_with_forbidden_edges(&graph_output.graph, &astar_request, forbidden_edges)?;
    }
    let Some(path) = path else {
        let result = PlanResult::new(
            request.objective_id.clone(),
            PlanLifecycleStatus::Unreachable,
            PlanningAlgorithm::AStar,
            context.generated_at,
            0,
            0,
            BTreeSet::new(),
            0,
            BTreeSet::new(),
            Some(PlanUnreachableReason::NoGraphPath),
            Vec::new(),
        )?;
        return Ok(PlannerEngineOutput {
            graph_signature: graph_output.graph_signature.clone(),
            result: result.clone(),
            explanation: None,
            simulation: None,
            event_payloads: build_planning_event_payloads(
                request,
                &graph_output.graph,
                &result,
                None,
                None,
            ),
        });
    };

    if request
        .max_steps
        .is_some_and(|max_steps| path.traversed_edges.len() as u16 > max_steps)
    {
        let result = PlanResult::new(
            request.objective_id.clone(),
            PlanLifecycleStatus::Unreachable,
            PlanningAlgorithm::AStar,
            context.generated_at,
            0,
            0,
            BTreeSet::new(),
            0,
            BTreeSet::new(),
            Some(PlanUnreachableReason::StepLimitExceeded),
            Vec::new(),
        )?;
        return Ok(PlannerEngineOutput {
            graph_signature: graph_output.graph_signature.clone(),
            result: result.clone(),
            explanation: None,
            simulation: None,
            event_payloads: build_planning_event_payloads(
                request,
                &graph_output.graph,
                &result,
                None,
                None,
            ),
        });
    }

    let mut steps = Vec::with_capacity(path.traversed_edges.len());
    let mut total_risk_cost = 0_u64;
    for (idx, edge_id) in path.traversed_edges.iter().enumerate() {
        let edge = graph_output
            .graph
            .edges()
            .get(edge_id)
            .expect("A* path edges must exist in graph");
        let attrs = edge.attrs();
        let blocked_reasons = edge_block_reasons(edge, context);
        total_risk_cost =
            total_risk_cost.saturating_add(context.weights.risk_weight(attrs.estimated_risk));
        steps.push(PlanStep::new(
            idx as u16 + 1,
            edge_id.clone(),
            edge.module_reference().map(|value| value.to_string()),
            attrs.required_capabilities.clone(),
            attrs.estimated_noise_cost,
            attrs.estimated_risk,
            attrs.probability_of_success_bps,
            attrs.expected_artifacts.clone(),
            blocked_reasons,
        )?);
    }

    let blocked_capabilities = steps
        .iter()
        .flat_map(|step| step.blocked_reasons.iter())
        .filter_map(|reason| match reason {
            PlanStepBlockReason::CapabilityDisabled { capability } => Some(capability.clone()),
            PlanStepBlockReason::PolicyDenied { .. } | PlanStepBlockReason::OutOfScope { .. } => {
                None
            }
        })
        .collect::<BTreeSet<_>>();

    let status = match request.mode {
        PlanRequestMode::Plan => PlanLifecycleStatus::Proposed,
        PlanRequestMode::Explain => PlanLifecycleStatus::Explained,
        PlanRequestMode::Simulate => PlanLifecycleStatus::Simulated,
    };

    let result = PlanResult::new(
        request.objective_id.clone(),
        status,
        PlanningAlgorithm::AStar,
        context.generated_at,
        path.total_noise_cost,
        total_risk_cost,
        path.required_capabilities.clone(),
        path.weighted_success_probability_bps,
        blocked_capabilities,
        None,
        steps.clone(),
    )?;

    let explanation = if matches!(
        request.mode,
        PlanRequestMode::Explain | PlanRequestMode::Simulate
    ) {
        Some(build_plan_explanation(
            request.objective_id.clone(),
            &steps,
            &context.weights,
        ))
    } else {
        None
    };

    let simulation = if request.mode == PlanRequestMode::Simulate {
        Some(build_plan_simulation(request.objective_id.clone(), &steps))
    } else {
        None
    };

    let event_payloads = build_planning_event_payloads(
        request,
        &graph_output.graph,
        &result,
        explanation.as_ref(),
        simulation.as_ref(),
    );

    Ok(PlannerEngineOutput {
        graph_signature: graph_output.graph_signature.clone(),
        result,
        explanation,
        simulation,
        event_payloads,
    })
}

fn edge_block_reasons(edge: &PlanEdge, context: &PlannerEngineContext) -> Vec<PlanStepBlockReason> {
    let attrs = edge.attrs();
    let mut blocked_reasons = attrs
        .required_capabilities
        .iter()
        .filter(|capability| !context.available_capabilities.contains(*capability))
        .map(|capability| PlanStepBlockReason::CapabilityDisabled {
            capability: capability.clone(),
        })
        .collect::<Vec<_>>();
    if let Some(module_reference) = edge.module_reference() {
        let module_key = normalize_token(module_reference);
        if let Some(policy_key) = context.policy_blocked_modules.get(&module_key) {
            blocked_reasons.push(PlanStepBlockReason::PolicyDenied {
                policy_key: policy_key.clone(),
            });
        }
        if !context.allowed_scopes.is_empty() {
            let scope = context
                .module_scopes
                .get(&module_key)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            if !context.allowed_scopes.contains(&scope) {
                blocked_reasons.push(PlanStepBlockReason::OutOfScope { scope_key: scope });
            }
        }
    }
    blocked_reasons
}

fn blocked_edges_for_context(
    graph: &CapabilityGraph,
    context: &PlannerEngineContext,
) -> BTreeSet<PlanEdgeId> {
    graph
        .edges()
        .iter()
        .filter_map(|(edge_id, edge)| {
            if edge_block_reasons(edge, context).is_empty() {
                None
            } else {
                Some(edge_id.clone())
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplanAlternativeReason {
    DifferentPath,
    LowerNoise,
    LowerRisk,
    FewerCapabilities,
}

impl ReplanAlternativeReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            ReplanAlternativeReason::DifferentPath => "different_path",
            ReplanAlternativeReason::LowerNoise => "lower_noise",
            ReplanAlternativeReason::LowerRisk => "lower_risk",
            ReplanAlternativeReason::FewerCapabilities => "fewer_capabilities",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlternativePlan {
    pub reason: ReplanAlternativeReason,
    pub output: PlannerEngineOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalReplanOutput {
    pub reevaluated: bool,
    pub rebuild: GraphRebuildPlan,
    pub primary: PlannerEngineOutput,
    pub alternatives: Vec<AlternativePlan>,
    pub event_payloads: Vec<PlanningEventPayload>,
}

pub fn conditional_replan(
    previous: Option<&NormalizedPlannerSnapshot>,
    next: &NormalizedPlannerSnapshot,
    request: &PlanRequest,
    context: &PlannerEngineContext,
    max_alternatives: usize,
) -> Result<ConditionalReplanOutput, PlanningContractError> {
    let rebuild = plan_graph_rebuild(previous, next);
    let reevaluated = previous.is_none() || rebuild.requires_rebuild();
    let prepared = PreparedPlannerSnapshot::prepare(next)?;
    let primary = execute_planner_pipeline_prepared(&prepared.graph_output, request, context)?;

    if !reevaluated {
        return Ok(ConditionalReplanOutput {
            reevaluated,
            rebuild,
            primary,
            alternatives: Vec::new(),
            event_payloads: Vec::new(),
        });
    }

    let mut alternatives = Vec::new();
    let mut seen_paths = BTreeSet::<String>::new();
    let primary_signature = step_signature(&primary.result.steps);
    seen_paths.insert(primary_signature);

    let mut forbidden_edges = BTreeSet::<PlanEdgeId>::new();
    let mut candidate_edges = primary
        .result
        .steps
        .iter()
        .map(|step| step.edge_id.clone())
        .collect::<VecDeque<_>>();

    while alternatives.len() < max_alternatives {
        let Some(edge_to_forbid) = candidate_edges.pop_front() else {
            break;
        };
        if !forbidden_edges.insert(edge_to_forbid.clone()) {
            continue;
        }

        let candidate = execute_planner_pipeline_with_graph(
            &prepared.graph_output,
            request,
            context,
            &forbidden_edges,
        )?;
        if !is_reachable_status(candidate.result.status) {
            continue;
        }
        let signature = step_signature(&candidate.result.steps);
        if !seen_paths.insert(signature) {
            continue;
        }

        for step in &candidate.result.steps {
            if !forbidden_edges.contains(&step.edge_id) {
                candidate_edges.push_back(step.edge_id.clone());
            }
        }

        let reason = classify_alternative_reason(&primary.result, &candidate.result);
        alternatives.push(AlternativePlan {
            reason,
            output: candidate,
        });
    }

    let event_payloads = vec![PlanningEventPayload::PlanReplanned {
        objective_id: request.objective_id.clone(),
        reason: rebuild_trigger_reason(&rebuild.triggers),
    }];

    Ok(ConditionalReplanOutput {
        reevaluated,
        rebuild,
        primary,
        alternatives,
        event_payloads,
    })
}

fn is_reachable_status(status: PlanLifecycleStatus) -> bool {
    matches!(
        status,
        PlanLifecycleStatus::Proposed
            | PlanLifecycleStatus::Explained
            | PlanLifecycleStatus::Simulated
    )
}

fn step_signature(steps: &[PlanStep]) -> String {
    steps
        .iter()
        .map(|step| step.edge_id.as_str().to_string())
        .collect::<Vec<_>>()
        .join("|")
}

fn plan_result_hash(result: &PlanResult) -> String {
    format!("{:016x}", fnv1a64(encode_plan_result(result).as_bytes()))
}

fn encode_plan_result(result: &PlanResult) -> String {
    let mut out = Vec::<String>::new();
    out.push(result.objective_id.as_str().to_string());
    out.push(result.status.as_str().to_string());
    out.push(result.algorithm.as_str().to_string());
    out.push(result.generated_at.to_string());
    out.push(result.step_count.to_string());
    out.push(result.total_noise_cost.to_string());
    out.push(result.total_risk_cost.to_string());
    out.push(result.success_probability_bps.to_string());
    out.push(
        result
            .required_capabilities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push(
        result
            .blocked_capabilities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push(
        result
            .unreachable_reason
            .as_ref()
            .map(|value| value.as_str().to_string())
            .unwrap_or_default(),
    );
    for step in &result.steps {
        let required = step
            .required_capabilities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let expected = step
            .expected_artifacts
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let blocked = step
            .blocked_reasons
            .iter()
            .map(|reason| format!("{}:{}", reason.code(), reason.stable_encoding()))
            .collect::<Vec<_>>()
            .join(",");
        out.push(format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            step.order,
            step.edge_id.as_str(),
            step.module_reference.as_deref().unwrap_or(""),
            step.estimated_noise_cost,
            step.estimated_risk.as_str(),
            step.probability_of_success_bps,
            required,
            expected,
            blocked
        ));
    }
    out.join("\n")
}

fn planner_context_signature(context: &PlannerEngineContext) -> String {
    let mut parts = Vec::<String>::new();
    parts.push(context.generated_at.to_string());
    parts.push(
        context
            .available_capabilities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(","),
    );
    parts.push(context.weights.noise_weight.to_string());
    parts.push(context.weights.risk_low_weight.to_string());
    parts.push(context.weights.risk_medium_weight.to_string());
    parts.push(context.weights.risk_high_weight.to_string());
    parts.push(context.weights.step_weight.to_string());
    parts.push(context.weights.capability_penalty_weight.to_string());
    parts.push(
        context
            .policy_blocked_modules
            .iter()
            .map(|(module, policy)| format!("{}={}", module, policy))
            .collect::<Vec<_>>()
            .join(","),
    );
    parts.push(
        context
            .module_scopes
            .iter()
            .map(|(module, scope)| format!("{}={}", module, scope))
            .collect::<Vec<_>>()
            .join(","),
    );
    parts.push(
        context
            .allowed_scopes
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(","),
    );
    format!("{:016x}", fnv1a64(parts.join("|").as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn rebuild_trigger_reason(triggers: &[GraphRebuildTrigger]) -> String {
    if triggers.is_empty() {
        return "none".to_string();
    }
    triggers
        .iter()
        .map(|trigger| trigger.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn classify_alternative_reason(
    primary: &PlanResult,
    candidate: &PlanResult,
) -> ReplanAlternativeReason {
    if candidate.total_noise_cost < primary.total_noise_cost {
        return ReplanAlternativeReason::LowerNoise;
    }
    if candidate.total_risk_cost < primary.total_risk_cost {
        return ReplanAlternativeReason::LowerRisk;
    }
    if candidate.required_capabilities.len() < primary.required_capabilities.len() {
        return ReplanAlternativeReason::FewerCapabilities;
    }
    ReplanAlternativeReason::DifferentPath
}

pub fn plan_pipeline(
    snapshot: &NormalizedPlannerSnapshot,
    objective_id: ObjectiveId,
    event_key: &str,
    generated_at: u64,
    available_capabilities: BTreeSet<String>,
    weights: AStarCostWeights,
) -> Result<PlannerEngineOutput, PlanningContractError> {
    let request = PlanRequest::new(objective_id, PlanRequestMode::Plan, event_key, None, false)?;
    let context = PlannerEngineContext::new(generated_at, available_capabilities, weights);
    execute_planner_pipeline(snapshot, &request, &context)
}

pub fn explain_pipeline(
    snapshot: &NormalizedPlannerSnapshot,
    objective_id: ObjectiveId,
    event_key: &str,
    generated_at: u64,
    available_capabilities: BTreeSet<String>,
    weights: AStarCostWeights,
) -> Result<PlannerEngineOutput, PlanningContractError> {
    let request = PlanRequest::new(
        objective_id,
        PlanRequestMode::Explain,
        event_key,
        None,
        false,
    )?;
    let context = PlannerEngineContext::new(generated_at, available_capabilities, weights);
    execute_planner_pipeline(snapshot, &request, &context)
}

pub fn simulate_pipeline(
    snapshot: &NormalizedPlannerSnapshot,
    objective_id: ObjectiveId,
    event_key: &str,
    generated_at: u64,
    available_capabilities: BTreeSet<String>,
    weights: AStarCostWeights,
) -> Result<PlannerEngineOutput, PlanningContractError> {
    let request = PlanRequest::new(
        objective_id,
        PlanRequestMode::Simulate,
        event_key,
        None,
        true,
    )?;
    let context = PlannerEngineContext::new(generated_at, available_capabilities, weights);
    execute_planner_pipeline(snapshot, &request, &context)
}

fn build_plan_explanation(
    objective_id: ObjectiveId,
    steps: &[PlanStep],
    weights: &AStarCostWeights,
) -> PlanExplanation {
    let mut total_weighted_cost = 0_u64;
    let mut rows = Vec::with_capacity(steps.len());
    for step in steps {
        let weighted_noise_cost =
            (step.estimated_noise_cost as u64).saturating_mul(weights.noise_weight as u64);
        let weighted_risk_cost = weights.risk_weight(step.estimated_risk);
        let weighted_step_cost = weights.step_weight as u64;
        let missing_cap_count = step
            .blocked_reasons
            .iter()
            .filter(|reason| matches!(reason, PlanStepBlockReason::CapabilityDisabled { .. }))
            .count() as u64;
        let weighted_capability_penalty_cost =
            missing_cap_count.saturating_mul(weights.capability_penalty_weight as u64);
        let weighted_total_cost = weighted_noise_cost
            .saturating_add(weighted_risk_cost)
            .saturating_add(weighted_step_cost)
            .saturating_add(weighted_capability_penalty_cost);
        total_weighted_cost = total_weighted_cost.saturating_add(weighted_total_cost);

        rows.push(PlanStepExplanation {
            order: step.order,
            edge_id: step.edge_id.clone(),
            module_reference: step.module_reference.clone(),
            weighted_noise_cost,
            weighted_risk_cost,
            weighted_step_cost,
            weighted_capability_penalty_cost,
            weighted_total_cost,
        });
    }

    PlanExplanation {
        objective_id,
        total_weighted_cost,
        heuristic_model: "astar.lower_bound_hop_cost".to_string(),
        steps: rows,
    }
}

fn build_plan_simulation(objective_id: ObjectiveId, steps: &[PlanStep]) -> PlanSimulation {
    let predicted_artifact_chain = steps
        .iter()
        .flat_map(|step| step.expected_artifacts.iter().cloned())
        .collect::<Vec<_>>();

    let mut expected_detection_surface = BTreeSet::new();
    for step in steps {
        expected_detection_surface.insert(format!("risk:{}", step.estimated_risk.as_str()));
        if let Some(module) = &step.module_reference {
            expected_detection_surface.insert(format!("module:{}", normalize_token(module)));
        }
        for reason in &step.blocked_reasons {
            expected_detection_surface.insert(format!("blocked:{}", reason.stable_encoding()));
        }
    }

    PlanSimulation {
        objective_id,
        predicted_artifact_chain,
        expected_detection_surface,
    }
}

fn build_planning_event_payloads(
    request: &PlanRequest,
    graph: &CapabilityGraph,
    result: &PlanResult,
    explanation: Option<&PlanExplanation>,
    simulation: Option<&PlanSimulation>,
) -> Vec<PlanningEventPayload> {
    let mut payloads = Vec::new();
    payloads.push(PlanningEventPayload::PlanRequested {
        objective_id: request.objective_id.clone(),
        mode: request.mode,
        event_key: request.event_key.clone(),
    });
    payloads.push(PlanningEventPayload::PlanGraphConstructed {
        objective_id: request.objective_id.clone(),
        node_count: graph.nodes().len(),
        edge_count: graph.edges().len(),
    });
    payloads.push(PlanningEventPayload::PlanGenerated {
        objective_id: request.objective_id.clone(),
        status: result.status,
        step_count: result.step_count,
        total_noise_cost: result.total_noise_cost,
        success_probability_bps: result.success_probability_bps,
    });
    if let Some(reason) = result.unreachable_reason.as_ref() {
        payloads.push(PlanningEventPayload::PlanUnreachable {
            objective_id: request.objective_id.clone(),
            reason: reason.clone(),
        });
    }
    if let Some(explanation) = explanation {
        payloads.push(PlanningEventPayload::PlanExplained {
            objective_id: request.objective_id.clone(),
            step_count: explanation.steps.len() as u16,
        });
    }
    if let Some(simulation) = simulation {
        payloads.push(PlanningEventPayload::PlanSimulated {
            objective_id: request.objective_id.clone(),
            predicted_artifacts: simulation
                .predicted_artifact_chain
                .iter()
                .cloned()
                .collect(),
            expected_detection_surface: simulation.expected_detection_surface.clone(),
        });
    }
    payloads
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanningEventPayload {
    PlanRequested {
        objective_id: ObjectiveId,
        mode: PlanRequestMode,
        event_key: String,
    },
    PlanGraphConstructed {
        objective_id: ObjectiveId,
        node_count: usize,
        edge_count: usize,
    },
    PlanGenerated {
        objective_id: ObjectiveId,
        status: PlanLifecycleStatus,
        step_count: u16,
        total_noise_cost: u64,
        success_probability_bps: u16,
    },
    PlanExplained {
        objective_id: ObjectiveId,
        step_count: u16,
    },
    PlanSimulated {
        objective_id: ObjectiveId,
        predicted_artifacts: BTreeSet<String>,
        expected_detection_surface: BTreeSet<String>,
    },
    PlanReplanned {
        objective_id: ObjectiveId,
        reason: String,
    },
    PlanUnreachable {
        objective_id: ObjectiveId,
        reason: PlanUnreachableReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanningEventType {
    PlanRequested,
    PlanGraphConstructed,
    PlanGenerated,
    PlanExplained,
    PlanSimulated,
    PlanReplanned,
    PlanUnreachable,
}

impl PlanningEventType {
    pub const fn as_str(self) -> &'static str {
        match self {
            PlanningEventType::PlanRequested => "plan_requested",
            PlanningEventType::PlanGraphConstructed => "plan_graph_constructed",
            PlanningEventType::PlanGenerated => "plan_generated",
            PlanningEventType::PlanExplained => "plan_explained",
            PlanningEventType::PlanSimulated => "plan_simulated",
            PlanningEventType::PlanReplanned => "plan_replanned",
            PlanningEventType::PlanUnreachable => "plan_unreachable",
        }
    }
}

pub const PLANNING_EVENT_TAXONOMY: &[PlanningEventType] = &[
    PlanningEventType::PlanRequested,
    PlanningEventType::PlanGraphConstructed,
    PlanningEventType::PlanGenerated,
    PlanningEventType::PlanExplained,
    PlanningEventType::PlanSimulated,
    PlanningEventType::PlanReplanned,
    PlanningEventType::PlanUnreachable,
];

impl PlanningEventPayload {
    pub const fn event_type(&self) -> PlanningEventType {
        match self {
            PlanningEventPayload::PlanRequested { .. } => PlanningEventType::PlanRequested,
            PlanningEventPayload::PlanGraphConstructed { .. } => {
                PlanningEventType::PlanGraphConstructed
            }
            PlanningEventPayload::PlanGenerated { .. } => PlanningEventType::PlanGenerated,
            PlanningEventPayload::PlanExplained { .. } => PlanningEventType::PlanExplained,
            PlanningEventPayload::PlanSimulated { .. } => PlanningEventType::PlanSimulated,
            PlanningEventPayload::PlanReplanned { .. } => PlanningEventType::PlanReplanned,
            PlanningEventPayload::PlanUnreachable { .. } => PlanningEventType::PlanUnreachable,
        }
    }

    pub fn objective_id(&self) -> &ObjectiveId {
        match self {
            PlanningEventPayload::PlanRequested { objective_id, .. }
            | PlanningEventPayload::PlanGraphConstructed { objective_id, .. }
            | PlanningEventPayload::PlanGenerated { objective_id, .. }
            | PlanningEventPayload::PlanExplained { objective_id, .. }
            | PlanningEventPayload::PlanSimulated { objective_id, .. }
            | PlanningEventPayload::PlanReplanned { objective_id, .. }
            | PlanningEventPayload::PlanUnreachable { objective_id, .. } => objective_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanningReplayRule {
    AppendOnlyEventLog,
    MonotonicObjectiveSequence,
    IdempotentByEventKey,
    DeterministicSnapshotInputs,
    NoExecutionSideEffects,
}

impl PlanningReplayRule {
    pub const fn as_str(self) -> &'static str {
        match self {
            PlanningReplayRule::AppendOnlyEventLog => "append_only_event_log",
            PlanningReplayRule::MonotonicObjectiveSequence => "monotonic_objective_sequence",
            PlanningReplayRule::IdempotentByEventKey => "idempotent_by_event_key",
            PlanningReplayRule::DeterministicSnapshotInputs => "deterministic_snapshot_inputs",
            PlanningReplayRule::NoExecutionSideEffects => "no_execution_side_effects",
        }
    }
}

pub const PLANNING_REPLAY_RULES: &[PlanningReplayRule] = &[
    PlanningReplayRule::AppendOnlyEventLog,
    PlanningReplayRule::MonotonicObjectiveSequence,
    PlanningReplayRule::IdempotentByEventKey,
    PlanningReplayRule::DeterministicSnapshotInputs,
    PlanningReplayRule::NoExecutionSideEffects,
];

pub const PLANNING_INVARIANTS: &[&str] = &[
    "planner is advisory-only and never executes modules",
    "planning outputs are deterministic for identical snapshots and policy views",
    "all planning actions emit typed immutable events",
    "policy checks annotate blocked steps during planning",
    "policy enforcement remains at execution boundary",
    "planning replay is idempotent by event key",
    "planner must not use wall-clock-dependent heuristics",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningEvent {
    pub sequence: u64,
    pub correlation_id: CorrelationId,
    pub occurred_at: u64,
    pub objective_id: ObjectiveId,
    pub event_key: String,
    pub payload: PlanningEventPayload,
}

impl PlanningEvent {
    pub fn new(
        sequence: u64,
        correlation_id: CorrelationId,
        occurred_at: u64,
        event_key: &str,
        payload: PlanningEventPayload,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(event_key, "planning_event.event_key")?;
        if occurred_at == 0 {
            return Err(PlanningContractError::InvalidField {
                field: "planning_event.occurred_at",
                reason: "must be > 0",
            });
        }
        Ok(Self {
            sequence,
            correlation_id,
            occurred_at,
            objective_id: payload.objective_id().clone(),
            event_key: normalize_token(event_key),
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanningEventLog {
    events: Vec<PlanningEvent>,
    next_sequence: BTreeMap<ObjectiveId, u64>,
    correlations: BTreeMap<ObjectiveId, CorrelationId>,
    applied_event_keys: BTreeSet<String>,
}

impl PlanningEventLog {
    pub fn events(&self) -> &[PlanningEvent] {
        &self.events
    }

    pub fn append_payloads(
        &mut self,
        objective_id: &ObjectiveId,
        payloads: &[PlanningEventPayload],
        correlation_id: Option<CorrelationId>,
        base_event_key: &str,
        occurred_at: u64,
    ) -> Result<CorrelationId, PlanningContractError> {
        ensure_non_empty(base_event_key, "planning_event.event_key")?;
        if occurred_at == 0 {
            return Err(PlanningContractError::InvalidField {
                field: "planning_event.occurred_at",
                reason: "must be > 0",
            });
        }

        let effective_correlation_id =
            match (self.correlations.get(objective_id).copied(), correlation_id) {
                (Some(existing), Some(provided)) if existing != provided => {
                    return Err(PlanningContractError::InvariantViolation {
                        invariant: "objective lineage correlation must remain immutable",
                    });
                }
                (Some(existing), _) => existing,
                (None, Some(provided)) => {
                    self.correlations.insert(objective_id.clone(), provided);
                    provided
                }
                (None, None) => {
                    let generated = CorrelationId::next();
                    self.correlations.insert(objective_id.clone(), generated);
                    generated
                }
            };

        for payload in payloads {
            if payload.objective_id() != objective_id {
                return Err(PlanningContractError::InvariantViolation {
                    invariant: "all planning payloads in one append must target one objective",
                });
            }

            let event_key = format!(
                "{}:{}",
                normalize_token(base_event_key),
                payload.event_type().as_str()
            );
            let dedupe_key = format!("{}:{}", objective_id.as_str(), event_key);
            if self.applied_event_keys.contains(&dedupe_key) {
                continue;
            }

            let sequence = *self.next_sequence.entry(objective_id.clone()).or_insert(1);
            let event = PlanningEvent::new(
                sequence,
                effective_correlation_id,
                occurred_at,
                &event_key,
                payload.clone(),
            )?;
            self.events.push(event);
            self.applied_event_keys.insert(dedupe_key);
            self.next_sequence
                .insert(objective_id.clone(), sequence.saturating_add(1));
        }

        Ok(effective_correlation_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningReplayDiagnostic {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedPlanningDecision {
    pub objective_id: ObjectiveId,
    pub correlation_id: CorrelationId,
    pub sequence_high_watermark: u64,
    pub latest_mode: Option<PlanRequestMode>,
    pub latest_status: Option<PlanLifecycleStatus>,
    pub latest_unreachable_reason: Option<PlanUnreachableReason>,
    pub latest_step_count: u16,
    pub latest_total_noise_cost: u64,
    pub latest_success_probability_bps: u16,
    pub timeline: Vec<PlanningEventPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningReplayReport {
    pub decision: Option<ReconstructedPlanningDecision>,
    pub diagnostics: Vec<PlanningReplayDiagnostic>,
}

pub fn reconstruct_planning_from_events(
    events: &[PlanningEvent],
    objective_id: &ObjectiveId,
) -> PlanningReplayReport {
    let mut diagnostics = Vec::<PlanningReplayDiagnostic>::new();
    let mut reconstructed: Option<ReconstructedPlanningDecision> = None;
    let mut seen_event_keys = BTreeSet::<String>::new();

    for event in events {
        if &event.objective_id != objective_id {
            continue;
        }

        let Some(decision) = reconstructed.as_mut() else {
            reconstructed = Some(ReconstructedPlanningDecision {
                objective_id: objective_id.clone(),
                correlation_id: event.correlation_id,
                sequence_high_watermark: 0,
                latest_mode: None,
                latest_status: None,
                latest_unreachable_reason: None,
                latest_step_count: 0,
                latest_total_noise_cost: 0,
                latest_success_probability_bps: 0,
                timeline: Vec::new(),
            });
            continue;
        };

        if decision.correlation_id != event.correlation_id {
            diagnostics.push(PlanningReplayDiagnostic {
                code: "ML-PLAN-REPLAY-0001",
                message: format!(
                    "objective {} has mixed planning lineage correlations {} and {}",
                    objective_id.as_str(),
                    decision.correlation_id.0 .0,
                    event.correlation_id.0 .0
                ),
            });
        }
    }

    for event in events {
        if &event.objective_id != objective_id {
            continue;
        }
        let Some(decision) = reconstructed.as_mut() else {
            continue;
        };

        let expected_next = decision.sequence_high_watermark.saturating_add(1);
        if event.sequence != expected_next {
            diagnostics.push(PlanningReplayDiagnostic {
                code: "ML-PLAN-REPLAY-0002",
                message: format!(
                    "objective {} planning sequence mismatch: expected {}, found {}",
                    objective_id.as_str(),
                    expected_next,
                    event.sequence
                ),
            });
        }
        decision.sequence_high_watermark = event.sequence;

        if !seen_event_keys.insert(event.event_key.clone()) {
            diagnostics.push(PlanningReplayDiagnostic {
                code: "ML-PLAN-REPLAY-0003",
                message: format!(
                    "objective {} duplicated planning event key '{}'",
                    objective_id.as_str(),
                    event.event_key
                ),
            });
        }

        match &event.payload {
            PlanningEventPayload::PlanRequested { mode, .. } => {
                decision.latest_mode = Some(*mode);
            }
            PlanningEventPayload::PlanGraphConstructed { .. } => {}
            PlanningEventPayload::PlanGenerated {
                status,
                step_count,
                total_noise_cost,
                success_probability_bps,
                ..
            } => {
                decision.latest_status = Some(*status);
                decision.latest_step_count = *step_count;
                decision.latest_total_noise_cost = *total_noise_cost;
                decision.latest_success_probability_bps = *success_probability_bps;
                if *status != PlanLifecycleStatus::Unreachable {
                    decision.latest_unreachable_reason = None;
                }
            }
            PlanningEventPayload::PlanExplained { .. } => {
                decision.latest_status = Some(PlanLifecycleStatus::Explained);
            }
            PlanningEventPayload::PlanSimulated { .. } => {
                decision.latest_status = Some(PlanLifecycleStatus::Simulated);
            }
            PlanningEventPayload::PlanReplanned { .. } => {}
            PlanningEventPayload::PlanUnreachable { reason, .. } => {
                decision.latest_status = Some(PlanLifecycleStatus::Unreachable);
                decision.latest_unreachable_reason = Some(reason.clone());
            }
        }

        decision.timeline.push(event.payload.clone());
    }

    if reconstructed.is_none() {
        diagnostics.push(PlanningReplayDiagnostic {
            code: "ML-PLAN-REPLAY-0004",
            message: format!(
                "objective {} has no planning events in history",
                objective_id.as_str()
            ),
        });
    }

    PlanningReplayReport {
        decision: reconstructed,
        diagnostics,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanningEventLogSnapshot {
    pub schema_version: u32,
    pub events: Vec<PlanningEvent>,
}

impl PlanningEventLog {
    pub fn snapshot(&self) -> PlanningEventLogSnapshot {
        PlanningEventLogSnapshot {
            schema_version: PLANNING_PERSISTENCE_SCHEMA_VERSION,
            events: self.events.clone(),
        }
    }

    pub fn from_snapshot(
        snapshot: &PlanningEventLogSnapshot,
    ) -> Result<Self, PlanningContractError> {
        if snapshot.schema_version != PLANNING_PERSISTENCE_SCHEMA_VERSION {
            return Err(PlanningContractError::InvariantViolation {
                invariant: "planning event log snapshot schema version mismatch",
            });
        }

        let mut log = PlanningEventLog::default();
        for event in &snapshot.events {
            let expected_sequence = *log
                .next_sequence
                .entry(event.objective_id.clone())
                .or_insert(1);
            if event.sequence != expected_sequence {
                return Err(PlanningContractError::InvariantViolation {
                    invariant:
                        "planning event sequence must be monotonic and gapless per objective",
                });
            }

            let effective = match log.correlations.get(&event.objective_id).copied() {
                Some(existing) if existing != event.correlation_id => {
                    return Err(PlanningContractError::InvariantViolation {
                        invariant: "objective lineage correlation must remain immutable",
                    });
                }
                Some(existing) => existing,
                None => {
                    log.correlations
                        .insert(event.objective_id.clone(), event.correlation_id);
                    event.correlation_id
                }
            };
            if effective != event.correlation_id {
                return Err(PlanningContractError::InvariantViolation {
                    invariant: "planning correlation mismatch during restore",
                });
            }

            let dedupe_key = format!("{}:{}", event.objective_id.as_str(), event.event_key);
            if !log.applied_event_keys.insert(dedupe_key) {
                return Err(PlanningContractError::InvariantViolation {
                    invariant: "planning event key must remain unique per objective lineage",
                });
            }

            log.events.push(event.clone());
            log.next_sequence
                .insert(event.objective_id.clone(), event.sequence.saturating_add(1));
        }

        Ok(log)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedPlannerDecision {
    pub objective_id: ObjectiveId,
    pub persisted_at: u64,
    pub snapshot_signature: String,
    pub context_signature: String,
    pub graph_signature: String,
    pub result_hash: String,
    pub snapshot: NormalizedPlannerSnapshot,
    pub request: PlanRequest,
    pub context: PlannerEngineContext,
    pub result: PlanResult,
}

impl PersistedPlannerDecision {
    pub fn from_output(
        snapshot: &NormalizedPlannerSnapshot,
        request: &PlanRequest,
        context: &PlannerEngineContext,
        output: &PlannerEngineOutput,
        persisted_at: u64,
    ) -> Result<Self, PlanningContractError> {
        if persisted_at == 0 {
            return Err(PlanningContractError::InvalidField {
                field: "planner_persisted_decision.persisted_at",
                reason: "must be > 0",
            });
        }
        if request.objective_id != output.result.objective_id {
            return Err(PlanningContractError::InvariantViolation {
                invariant: "persisted planner decision objective ids must match request and result",
            });
        }
        Ok(Self {
            objective_id: request.objective_id.clone(),
            persisted_at,
            snapshot_signature: snapshot.canonical_signature().to_string(),
            context_signature: planner_context_signature(context),
            graph_signature: output.graph_signature.clone(),
            result_hash: plan_result_hash(&output.result),
            snapshot: snapshot.clone(),
            request: request.clone(),
            context: context.clone(),
            result: output.result.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerPersistenceSnapshot {
    pub schema_version: u32,
    pub event_log: PlanningEventLogSnapshot,
    pub decisions: Vec<PersistedPlannerDecision>,
}

impl Default for PlannerPersistenceSnapshot {
    fn default() -> Self {
        Self {
            schema_version: PLANNING_PERSISTENCE_SCHEMA_VERSION,
            event_log: PlanningEventLogSnapshot {
                schema_version: PLANNING_PERSISTENCE_SCHEMA_VERSION,
                events: Vec::new(),
            },
            decisions: Vec::new(),
        }
    }
}

pub trait PlannerStateStore {
    fn load(&mut self) -> Result<Option<PlannerPersistenceSnapshot>, PlanningContractError>;
    fn save(&mut self, snapshot: &PlannerPersistenceSnapshot) -> Result<(), PlanningContractError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryPlannerStateStore {
    snapshot: Option<PlannerPersistenceSnapshot>,
}

impl InMemoryPlannerStateStore {
    pub fn with_snapshot(snapshot: PlannerPersistenceSnapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
        }
    }

    pub fn snapshot(&self) -> Option<PlannerPersistenceSnapshot> {
        self.snapshot.clone()
    }
}

impl PlannerStateStore for InMemoryPlannerStateStore {
    fn load(&mut self) -> Result<Option<PlannerPersistenceSnapshot>, PlanningContractError> {
        Ok(self.snapshot.clone())
    }

    fn save(&mut self, snapshot: &PlannerPersistenceSnapshot) -> Result<(), PlanningContractError> {
        self.snapshot = Some(snapshot.clone());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerReplayEquivalence {
    pub objective_id: ObjectiveId,
    pub persisted_hash: String,
    pub recomputed_hash: String,
    pub equivalent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerRecoveryReport {
    pub schema_version: u32,
    pub replay_reports: Vec<PlanningReplayReport>,
    pub equivalence: Vec<PlannerReplayEquivalence>,
    pub diagnostics: Vec<PlanningReplayDiagnostic>,
    pub consistent: bool,
}

pub struct PlannerStateManager<S: PlannerStateStore> {
    store: S,
    state: PlannerPersistenceSnapshot,
}

impl<S: PlannerStateStore> PlannerStateManager<S> {
    pub fn new(mut store: S) -> Result<Self, PlanningContractError> {
        let state = match store.load()? {
            Some(snapshot) => {
                if snapshot.schema_version != PLANNING_PERSISTENCE_SCHEMA_VERSION {
                    return Err(PlanningContractError::InvariantViolation {
                        invariant: "planner persistence schema version mismatch",
                    });
                }
                let _ = PlanningEventLog::from_snapshot(&snapshot.event_log)?;
                snapshot
            }
            None => PlannerPersistenceSnapshot::default(),
        };
        Ok(Self { store, state })
    }

    pub fn state(&self) -> &PlannerPersistenceSnapshot {
        &self.state
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn record_execution(
        &mut self,
        snapshot: &NormalizedPlannerSnapshot,
        request: &PlanRequest,
        context: &PlannerEngineContext,
        output: &PlannerEngineOutput,
        persisted_at: u64,
    ) -> Result<(), PlanningContractError> {
        let decision = PersistedPlannerDecision::from_output(
            snapshot,
            request,
            context,
            output,
            persisted_at,
        )?;

        let mut event_log = PlanningEventLog::from_snapshot(&self.state.event_log)?;
        let _ = event_log.append_payloads(
            &request.objective_id,
            &output.event_payloads,
            None,
            &request.event_key,
            persisted_at,
        )?;
        self.state.event_log = event_log.snapshot();

        self.state
            .decisions
            .retain(|existing| existing.objective_id != decision.objective_id);
        self.state.decisions.push(decision);
        self.state
            .decisions
            .sort_by_key(|decision| decision.objective_id.as_str().to_string());

        self.store.save(&self.state)
    }

    pub fn cold_recover(&self) -> Result<PlannerRecoveryReport, PlanningContractError> {
        let event_log = PlanningEventLog::from_snapshot(&self.state.event_log)?;
        let mut replay_reports = Vec::<PlanningReplayReport>::new();
        let mut equivalence = Vec::<PlannerReplayEquivalence>::new();
        let mut diagnostics = Vec::<PlanningReplayDiagnostic>::new();

        let event_objectives = event_log
            .events()
            .iter()
            .map(|event| event.objective_id.clone())
            .collect::<BTreeSet<_>>();
        let persisted_objectives = self
            .state
            .decisions
            .iter()
            .map(|decision| decision.objective_id.clone())
            .collect::<BTreeSet<_>>();

        for objective_id in event_objectives.difference(&persisted_objectives) {
            diagnostics.push(PlanningReplayDiagnostic {
                code: "ML-PLAN-RECOVERY-0001",
                message: format!(
                    "objective {} has planning events but no persisted planner snapshot",
                    objective_id.as_str()
                ),
            });
        }

        for decision in &self.state.decisions {
            let replay =
                reconstruct_planning_from_events(event_log.events(), &decision.objective_id);
            diagnostics.extend(replay.diagnostics.iter().cloned());
            replay_reports.push(replay);

            let recomputed =
                execute_planner_pipeline(&decision.snapshot, &decision.request, &decision.context)?;
            let recomputed_hash = plan_result_hash(&recomputed.result);
            let equivalent =
                recomputed_hash == decision.result_hash && recomputed.result == decision.result;
            if !equivalent {
                diagnostics.push(PlanningReplayDiagnostic {
                    code: "ML-PLAN-RECOVERY-0002",
                    message: format!(
                        "objective {} planner replay equivalence mismatch persisted={} recomputed={}",
                        decision.objective_id.as_str(),
                        decision.result_hash,
                        recomputed_hash
                    ),
                });
            }
            equivalence.push(PlannerReplayEquivalence {
                objective_id: decision.objective_id.clone(),
                persisted_hash: decision.result_hash.clone(),
                recomputed_hash,
                equivalent,
            });
        }

        let consistent = diagnostics.is_empty() && equivalence.iter().all(|item| item.equivalent);
        Ok(PlannerRecoveryReport {
            schema_version: self.state.schema_version,
            replay_reports,
            equivalence,
            diagnostics,
            consistent,
        })
    }
}

fn validate_distinct_edge_endpoints(
    from: &PlanNodeId,
    to: &PlanNodeId,
) -> Result<(), PlanningContractError> {
    if from == to {
        return Err(PlanningContractError::InvariantViolation {
            invariant: "planning graph edges must not be self-loops",
        });
    }
    Ok(())
}

fn validate_edge_endpoint_types(
    edge_type: PlanEdgeType,
    from_type: PlanNodeType,
    to_type: PlanNodeType,
) -> Result<(), PlanningContractError> {
    let valid = match edge_type {
        PlanEdgeType::ModuleExecution => true,
        PlanEdgeType::StateTransition => from_type == to_type,
        PlanEdgeType::PrivilegeEscalation => {
            from_type == PlanNodeType::CapabilityState && to_type == PlanNodeType::CapabilityState
        }
        PlanEdgeType::LateralMovement => {
            from_type == PlanNodeType::AssetState && to_type == PlanNodeType::AssetState
        }
    };

    if valid {
        Ok(())
    } else {
        Err(PlanningContractError::InvalidTransition {
            entity: edge_type.as_str(),
            from: from_type.as_str(),
            to: to_type.as_str(),
        })
    }
}

fn ensure_non_empty(value: &str, field: &'static str) -> Result<(), PlanningContractError> {
    if value.trim().is_empty() {
        return Err(PlanningContractError::InvalidField {
            field,
            reason: "must not be empty",
        });
    }
    Ok(())
}

fn is_valid_identifier(value: &str) -> bool {
    value.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | ':' | '/' | '-')
    })
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_tokens(values: BTreeSet<String>) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| normalize_token(&value))
        .filter(|value| !value.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_objective_id(seed: &str) -> ObjectiveId {
        ObjectiveId::parse(seed).expect("objective id")
    }

    fn parse_campaign_id(seed: &str) -> CampaignId {
        CampaignId::parse(seed).expect("campaign id")
    }

    fn parse_node_id(seed: &str) -> PlanNodeId {
        PlanNodeId::parse(seed).expect("node id")
    }

    fn parse_edge_id(seed: &str) -> PlanEdgeId {
        PlanEdgeId::parse(seed).expect("edge id")
    }

    fn edge_attrs() -> PlanEdgeAttributes {
        PlanEdgeAttributes::new(BTreeSet::new(), 10, RiskLevel::Low, 5_000, BTreeSet::new())
            .expect("attrs")
    }

    fn synthetic_scale_snapshot(
        module_count: usize,
    ) -> Result<(NormalizedPlannerSnapshot, ObjectiveId), PlanningContractError> {
        let campaign_id = parse_campaign_id("33333333-3333-3333-3333-333333333333");
        let mut modules = Vec::with_capacity(module_count);
        let mut objectives = Vec::with_capacity(module_count);
        let mut target_objective = None::<ObjectiveId>;

        for idx in 0..module_count {
            let module_reference = format!("auxiliary/scale/module/{}", idx);
            let mut required_capabilities = BTreeSet::new();
            if idx % 3 == 0 {
                required_capabilities.insert("exploit_execution".to_string());
            }
            modules.push(RegisteredModuleInput::new(
                &module_reference,
                required_capabilities,
                (idx % 10) as u32 + 1,
                if idx % 9 == 0 {
                    RiskLevel::High
                } else if idx % 3 == 0 {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                },
                7_000u16.saturating_add((idx % 1_000) as u16),
                BTreeSet::from([format!("signal_type_{}", idx % 64)]),
                BTreeMap::new(),
            )?);

            let objective_id = parse_objective_id(&format!(
                "{:08x}-1234-5678-9abc-{:012x}",
                idx as u64 + 1,
                idx as u64 + 1
            ));
            if idx == module_count.saturating_sub(1) {
                target_objective = Some(objective_id.clone());
            }
            objectives.push(ObjectiveDefinitionInput::new(
                objective_id,
                campaign_id.clone(),
                ObjectiveStatus::Pending,
                vec![],
                vec![Predicate::RunSucceeded {
                    module_name: module_reference,
                }],
                vec![],
                RiskLevel::Low,
                None,
                BTreeMap::new(),
            )?);
        }

        let snapshot = normalize_planner_input(PlannerNormalizationInput::new(
            modules,
            objectives,
            vec![],
            BTreeMap::new(),
        )?)?;

        Ok((
            snapshot,
            target_objective.expect("module_count > 0 should set target objective"),
        ))
    }

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    #[test]
    fn lifecycle_transition_matrix_is_complete_and_unambiguous() {
        let states = [
            PlanLifecycleStatus::Requested,
            PlanLifecycleStatus::GraphReady,
            PlanLifecycleStatus::Proposed,
            PlanLifecycleStatus::Explained,
            PlanLifecycleStatus::Simulated,
            PlanLifecycleStatus::Unreachable,
            PlanLifecycleStatus::Superseded,
            PlanLifecycleStatus::Failed,
        ];

        for from in states {
            for to in states {
                let allowed = PLAN_LIFECYCLE_ALLOWED_TRANSITIONS.contains(&(from, to));
                let forbidden = PLAN_LIFECYCLE_FORBIDDEN_TRANSITIONS.contains(&(from, to));
                assert_ne!(
                    allowed,
                    forbidden,
                    "transition should appear in exactly one matrix: {} -> {}",
                    from.as_str(),
                    to.as_str()
                );
                assert_eq!(
                    from.can_transition_to(to),
                    allowed,
                    "transition function mismatch for {} -> {}",
                    from.as_str(),
                    to.as_str()
                );
            }
        }
    }

    #[test]
    fn module_execution_edges_require_module_reference() {
        let edge = PlanEdge::module_execution(
            parse_edge_id("edge/module"),
            parse_node_id("node/from"),
            parse_node_id("node/to"),
            "   ",
            edge_attrs(),
        )
        .expect_err("must reject missing module reference");

        assert_eq!(edge.code(), "ML-PLAN-0001");
    }

    #[test]
    fn edge_attributes_validate_success_probability() {
        let edge =
            PlanEdgeAttributes::new(BTreeSet::new(), 2, RiskLevel::Low, 10_001, BTreeSet::new())
                .expect_err("must reject out-of-range success probability");

        assert_eq!(edge.code(), "ML-PLAN-0001");
    }

    #[test]
    fn graph_requires_nodes_to_exist_before_edge_insert() {
        let mut graph = CapabilityGraph::new();
        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(parse_node_id("node/cap"), "exploit_execution", true)
                    .expect("node"),
            ))
            .expect("insert node");

        let edge = PlanEdge::state_transition(
            parse_edge_id("edge/one"),
            parse_node_id("node/cap"),
            parse_node_id("node/missing"),
            edge_attrs(),
        )
        .expect("edge");

        let err = graph
            .add_edge(edge)
            .expect_err("must reject missing target node");
        assert_eq!(err.code(), "ML-PLAN-0005");
    }

    #[test]
    fn state_transition_edges_require_same_node_types() {
        let mut graph = CapabilityGraph::new();
        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(parse_node_id("node/cap"), "exploit_execution", true)
                    .expect("node"),
            ))
            .expect("insert capability");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(parse_node_id("node/asset"), "host", "owned").expect("node"),
            ))
            .expect("insert asset");

        let edge = PlanEdge::state_transition(
            parse_edge_id("edge/type-mismatch"),
            parse_node_id("node/cap"),
            parse_node_id("node/asset"),
            edge_attrs(),
        )
        .expect("edge");
        let err = graph
            .add_edge(edge)
            .expect_err("type mismatch should fail deterministically");
        assert_eq!(err.code(), "ML-PLAN-0002");
    }

    #[test]
    fn privilege_escalation_edges_require_capability_nodes() {
        let mut graph = CapabilityGraph::new();
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(parse_node_id("node/asset-from"), "host", "owned")
                    .expect("node"),
            ))
            .expect("insert asset");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(parse_node_id("node/asset-to"), "host", "root").expect("node"),
            ))
            .expect("insert asset");

        let edge = PlanEdge::privilege_escalation(
            parse_edge_id("edge/privesc"),
            parse_node_id("node/asset-from"),
            parse_node_id("node/asset-to"),
            edge_attrs(),
        )
        .expect("edge");
        let err = graph
            .add_edge(edge)
            .expect_err("privilege escalation must connect capability states only");
        assert_eq!(err.code(), "ML-PLAN-0002");
    }

    #[test]
    fn lateral_movement_edges_require_asset_nodes() {
        let mut graph = CapabilityGraph::new();
        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(parse_node_id("node/cap-from"), "exploit_execution", true)
                    .expect("node"),
            ))
            .expect("insert capability");
        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(parse_node_id("node/cap-to"), "payload_execution", true)
                    .expect("node"),
            ))
            .expect("insert capability");

        let edge = PlanEdge::lateral_movement(
            parse_edge_id("edge/lateral"),
            parse_node_id("node/cap-from"),
            parse_node_id("node/cap-to"),
            edge_attrs(),
        )
        .expect("edge");
        let err = graph
            .add_edge(edge)
            .expect_err("lateral movement must connect asset states only");
        assert_eq!(err.code(), "ML-PLAN-0002");
    }

    #[test]
    fn plan_result_requires_unreachable_status_when_reason_is_present() {
        let err = PlanResult::new(
            parse_objective_id("11111111-1111-1111-1111-111111111111"),
            PlanLifecycleStatus::Proposed,
            PlanningAlgorithm::AStar,
            1,
            0,
            0,
            BTreeSet::new(),
            0,
            BTreeSet::new(),
            Some(PlanUnreachableReason::NoGraphPath),
            Vec::new(),
        )
        .expect_err("status mismatch should fail");

        assert_eq!(err.code(), "ML-PLAN-0001");
    }

    #[test]
    fn event_payload_objective_accessor_is_stable() {
        let objective_id = parse_objective_id("11111111-1111-1111-1111-111111111111");
        let payload = PlanningEventPayload::PlanGenerated {
            objective_id: objective_id.clone(),
            status: PlanLifecycleStatus::Proposed,
            step_count: 2,
            total_noise_cost: 14,
            success_probability_bps: 7_500,
        };
        assert_eq!(payload.objective_id(), &objective_id);
        assert_eq!(payload.event_type(), PlanningEventType::PlanGenerated);
    }

    #[test]
    fn planner_pipeline_emits_typed_event_payloads_for_full_lineage() {
        let objective_id = parse_objective_id("88888888-8888-8888-8888-888888888888");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/collect/artifacts",
                    BTreeSet::new(),
                    2,
                    RiskLevel::Low,
                    9_500,
                    BTreeSet::from(["inventory".to_string(), "service_banner".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("14141414-1414-1414-1414-141414141414"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "auxiliary/collect/artifacts".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let output = simulate_pipeline(
            &snapshot,
            objective_id.clone(),
            "event.simulate.lineage",
            12345,
            BTreeSet::new(),
            AStarCostWeights::default(),
        )
        .expect("simulate");

        let event_types = output
            .event_payloads
            .iter()
            .map(|payload| payload.event_type().as_str().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            event_types,
            vec![
                "plan_requested",
                "plan_graph_constructed",
                "plan_generated",
                "plan_explained",
                "plan_simulated"
            ]
        );
        assert!(output
            .event_payloads
            .iter()
            .all(|payload| payload.objective_id() == &objective_id));
    }

    #[test]
    fn planning_event_log_is_idempotent_by_event_key_and_preserves_lineage() {
        let objective_id = parse_objective_id("99999999-9999-9999-9999-999999999999");
        let payloads = vec![
            PlanningEventPayload::PlanRequested {
                objective_id: objective_id.clone(),
                mode: PlanRequestMode::Plan,
                event_key: "test.key".to_string(),
            },
            PlanningEventPayload::PlanGenerated {
                objective_id: objective_id.clone(),
                status: PlanLifecycleStatus::Proposed,
                step_count: 1,
                total_noise_cost: 7,
                success_probability_bps: 9_000,
            },
        ];

        let mut log = PlanningEventLog::default();
        let first = log
            .append_payloads(&objective_id, &payloads, None, "test.key", 100)
            .expect("first append");
        let second = log
            .append_payloads(&objective_id, &payloads, Some(first), "test.key", 100)
            .expect("idempotent append");

        assert_eq!(first, second);
        assert_eq!(log.events().len(), 2);
        assert_eq!(log.events()[0].sequence, 1);
        assert_eq!(log.events()[1].sequence, 2);
        assert!(log
            .events()
            .iter()
            .all(|event| event.correlation_id == first));
    }

    #[test]
    fn planning_replay_reconstructs_decisions_from_event_history() {
        let objective_id = parse_objective_id("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb");
        let correlation_id = CorrelationId::next();
        let events = vec![
            PlanningEvent::new(
                1,
                correlation_id,
                50,
                "trace.plan:plan_requested",
                PlanningEventPayload::PlanRequested {
                    objective_id: objective_id.clone(),
                    mode: PlanRequestMode::Explain,
                    event_key: "trace.plan".to_string(),
                },
            )
            .expect("requested"),
            PlanningEvent::new(
                2,
                correlation_id,
                50,
                "trace.plan:plan_generated",
                PlanningEventPayload::PlanGenerated {
                    objective_id: objective_id.clone(),
                    status: PlanLifecycleStatus::Explained,
                    step_count: 2,
                    total_noise_cost: 14,
                    success_probability_bps: 7_500,
                },
            )
            .expect("generated"),
            PlanningEvent::new(
                3,
                correlation_id,
                50,
                "trace.plan:plan_explained",
                PlanningEventPayload::PlanExplained {
                    objective_id: objective_id.clone(),
                    step_count: 2,
                },
            )
            .expect("explained"),
        ];

        let report = reconstruct_planning_from_events(&events, &objective_id);
        assert!(report.diagnostics.is_empty());
        let decision = report.decision.expect("decision");
        assert_eq!(decision.correlation_id, correlation_id);
        assert_eq!(decision.sequence_high_watermark, 3);
        assert_eq!(decision.latest_mode, Some(PlanRequestMode::Explain));
        assert_eq!(decision.latest_status, Some(PlanLifecycleStatus::Explained));
        assert_eq!(decision.latest_step_count, 2);
        assert_eq!(decision.latest_total_noise_cost, 14);
        assert_eq!(decision.latest_success_probability_bps, 7_500);
        assert_eq!(decision.timeline.len(), 3);
    }

    #[test]
    fn planner_state_manager_cold_recovery_matches_persisted_hash_after_restart() {
        let objective_id = parse_objective_id("abababab-1111-2222-3333-cdcdcdcdcdcd");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/recovery/sample",
                    BTreeSet::new(),
                    3,
                    RiskLevel::Low,
                    8_000,
                    BTreeSet::from(["shell_access".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("cccccccc-1111-2222-3333-dddddddddddd"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "auxiliary/recovery/sample".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let request = PlanRequest::new(
            objective_id.clone(),
            PlanRequestMode::Plan,
            "recover.plan.1",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(999, BTreeSet::new(), AStarCostWeights::default());
        let output = execute_planner_pipeline(&snapshot, &request, &context).expect("output");

        let store = InMemoryPlannerStateStore::default();
        let mut manager = PlannerStateManager::new(store).expect("manager");
        manager
            .record_execution(&snapshot, &request, &context, &output, 999)
            .expect("record");
        let report_a = manager.cold_recover().expect("cold recover first");
        assert!(report_a.consistent);
        assert_eq!(report_a.equivalence.len(), 1);
        assert!(report_a.equivalence[0].equivalent);

        let store = manager.into_store();
        let recovered = PlannerStateManager::new(store).expect("recovered manager");
        let report_b = recovered.cold_recover().expect("cold recover second");
        assert!(report_b.consistent);
        assert_eq!(report_b.equivalence.len(), 1);
        assert!(report_b.equivalence[0].equivalent);
    }

    #[test]
    fn planner_recovery_reports_hash_mismatch_deterministically() {
        let objective_id = parse_objective_id("dededede-1111-2222-3333-efefefefefef");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/recovery/mismatch",
                    BTreeSet::new(),
                    4,
                    RiskLevel::Low,
                    7_000,
                    BTreeSet::from(["shell_access".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("f0f0f0f0-1111-2222-3333-010101010101"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "auxiliary/recovery/mismatch".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let request = PlanRequest::new(
            objective_id.clone(),
            PlanRequestMode::Plan,
            "recover.plan.2",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(1001, BTreeSet::new(), AStarCostWeights::default());
        let output = execute_planner_pipeline(&snapshot, &request, &context).expect("output");

        let store = InMemoryPlannerStateStore::default();
        let mut manager = PlannerStateManager::new(store).expect("manager");
        manager
            .record_execution(&snapshot, &request, &context, &output, 1001)
            .expect("record");
        let mut store = manager.into_store();
        let mut persisted = store.snapshot().expect("persisted snapshot");
        persisted.decisions[0].result_hash = "0000000000000000".to_string();
        store = InMemoryPlannerStateStore::with_snapshot(persisted);

        let recovered = PlannerStateManager::new(store).expect("recovered manager");
        let report = recovered.cold_recover().expect("cold recover");
        assert!(!report.consistent);
        assert!(report
            .diagnostics
            .iter()
            .any(|item| item.code == "ML-PLAN-RECOVERY-0002"));
        assert!(report.equivalence.iter().any(|entry| !entry.equivalent));
    }

    #[test]
    fn replay_rules_and_invariants_are_non_empty_and_stable() {
        assert_eq!(PLANNING_REPLAY_RULES.len(), 5);
        assert_eq!(
            PLANNING_REPLAY_RULES
                .iter()
                .map(|rule| rule.as_str())
                .collect::<Vec<_>>(),
            vec![
                "append_only_event_log",
                "monotonic_objective_sequence",
                "idempotent_by_event_key",
                "deterministic_snapshot_inputs",
                "no_execution_side_effects"
            ]
        );

        assert!(PLANNING_INVARIANTS.len() >= 6);
        assert!(PLANNING_INVARIANTS
            .iter()
            .any(|line| line.contains("advisory-only")));
    }

    #[test]
    fn plan_request_requires_non_empty_event_key() {
        let err = PlanRequest::new(
            parse_objective_id("11111111-1111-1111-1111-111111111111"),
            PlanRequestMode::Plan,
            "   ",
            Some(10),
            false,
        )
        .expect_err("empty event key");
        assert_eq!(err.code(), "ML-PLAN-0001");
    }

    #[test]
    fn normalization_rejects_duplicate_module_references() {
        let module_a = RegisteredModuleInput::new(
            "exploit/linux/example",
            BTreeSet::new(),
            10,
            RiskLevel::Low,
            5_000,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .expect("module a");
        let module_b = RegisteredModuleInput::new(
            " Exploit/Linux/Example ",
            BTreeSet::new(),
            5,
            RiskLevel::Medium,
            6_000,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .expect("module b");

        let input = PlannerNormalizationInput::new(
            vec![module_a, module_b],
            Vec::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .expect("input");
        let err = normalize_planner_input(input).expect_err("duplicate module ref should fail");
        assert_eq!(err.code(), "ML-PLAN-0007");
    }

    #[test]
    fn normalization_is_deterministic_across_input_order() {
        let module_a = RegisteredModuleInput::new(
            "auxiliary/scan/one",
            BTreeSet::from(["cap_scan".to_string()]),
            2,
            RiskLevel::Low,
            8_500,
            BTreeSet::from(["service_banner".to_string()]),
            BTreeMap::new(),
        )
        .expect("module a");
        let module_b = RegisteredModuleInput::new(
            "exploit/linux/two",
            BTreeSet::from(["exploit_execution".to_string()]),
            9,
            RiskLevel::High,
            4_500,
            BTreeSet::from(["shell_access".to_string()]),
            BTreeMap::new(),
        )
        .expect("module b");

        let objective = ObjectiveDefinitionInput::new(
            parse_objective_id("11111111-1111-1111-1111-111111111111"),
            parse_campaign_id("22222222-2222-2222-2222-222222222222"),
            ObjectiveStatus::Pending,
            vec![],
            vec![Predicate::FindingExists {
                finding_type: "shell_access".to_string(),
            }],
            vec![],
            RiskLevel::Medium,
            Some(5),
            BTreeMap::new(),
        )
        .expect("objective");

        let artifact = DiscoveredArtifactInput::new(
            "artifact:1",
            "shell_access",
            "available",
            BTreeSet::from(["interactive".to_string()]),
            BTreeMap::new(),
        )
        .expect("artifact");

        let snapshot_a = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![module_a.clone(), module_b.clone()],
                vec![objective.clone()],
                vec![artifact.clone()],
                BTreeMap::from([(
                    "Operator".to_string(),
                    MetadataValue::Text("red".to_string()),
                )]),
            )
            .expect("input a"),
        )
        .expect("normalize a");

        let snapshot_b = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![module_b, module_a],
                vec![objective],
                vec![artifact],
                BTreeMap::from([(
                    "operator".to_string(),
                    MetadataValue::Text("red".to_string()),
                )]),
            )
            .expect("input b"),
        )
        .expect("normalize b");

        assert_eq!(snapshot_a, snapshot_b);
        assert_eq!(
            snapshot_a.canonical_signature(),
            snapshot_b.canonical_signature()
        );
    }

    #[test]
    fn normalization_adapter_from_domain_entities_is_stable() {
        let objective = Objective::new_at(
            parse_objective_id("33333333-3333-3333-3333-333333333333"),
            parse_campaign_id("44444444-4444-4444-4444-444444444444"),
            "Foothold",
            "Gain shell",
            vec![],
            vec![Predicate::ArtifactTagMatch {
                tag: "shell_access".to_string(),
            }],
            vec![],
            RiskLevel::High,
            Some(20),
            10,
        )
        .expect("objective");
        let objective_input =
            ObjectiveDefinitionInput::from_objective(&objective).expect("objective input");
        assert_eq!(
            objective_input.metadata.get("name"),
            Some(&MetadataValue::Text("Foothold".to_string()))
        );

        let artifact = Artifact::new_at(
            crate::domain::RunId::next(),
            None,
            None,
            ArtifactKind::StructuredJson,
            "result",
            "memory://result",
            11,
        )
        .expect("artifact");
        let artifact_input =
            DiscoveredArtifactInput::from_artifact(&artifact).expect("artifact input");
        assert_eq!(artifact_input.artifact_type, "structured_json");
        assert_eq!(artifact_input.state, "pending");
        assert!(artifact_input.metadata.contains_key("locator"));
    }

    #[test]
    fn graph_builder_is_idempotent_and_deterministic() {
        let modules = vec![
            RegisteredModuleInput::new(
                "exploit/linux/telnet/path-a",
                BTreeSet::from(["exploit_execution".to_string(), "user".to_string()]),
                8,
                RiskLevel::High,
                6_000,
                BTreeSet::from(["shell_access".to_string()]),
                BTreeMap::new(),
            )
            .expect("module a"),
            RegisteredModuleInput::new(
                "auxiliary/scan/path-b",
                BTreeSet::new(),
                2,
                RiskLevel::Low,
                9_000,
                BTreeSet::from(["service_banner".to_string()]),
                BTreeMap::new(),
            )
            .expect("module b"),
        ];
        let objectives = vec![ObjectiveDefinitionInput::new(
            parse_objective_id("55555555-5555-5555-5555-555555555555"),
            parse_campaign_id("66666666-6666-6666-6666-666666666666"),
            ObjectiveStatus::Pending,
            vec![],
            vec![
                Predicate::FindingExists {
                    finding_type: "shell_access".to_string(),
                },
                Predicate::RunSucceeded {
                    module_name: "exploit/linux/telnet/path-a".to_string(),
                },
            ],
            vec![],
            RiskLevel::Medium,
            Some(10),
            BTreeMap::new(),
        )
        .expect("objective")];
        let artifacts = vec![DiscoveredArtifactInput::new(
            "artifact:a",
            "shell_access",
            "available",
            BTreeSet::from(["interactive".to_string()]),
            BTreeMap::new(),
        )
        .expect("artifact")];
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(modules, objectives, artifacts, BTreeMap::new())
                .expect("input"),
        )
        .expect("normalize");

        let build_a = build_capability_graph(&snapshot).expect("build a");
        let build_b = build_capability_graph(&snapshot).expect("build b");
        assert_eq!(build_a.graph, build_b.graph);
        assert_eq!(build_a.graph_signature, build_b.graph_signature);
        assert_eq!(
            build_a
                .graph
                .nodes()
                .keys()
                .map(|id| id.as_str().to_string())
                .collect::<Vec<_>>(),
            build_b
                .graph
                .nodes()
                .keys()
                .map(|id| id.as_str().to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            build_a
                .graph
                .edges()
                .keys()
                .map(|id| id.as_str().to_string())
                .collect::<Vec<_>>(),
            build_b
                .graph
                .edges()
                .keys()
                .map(|id| id.as_str().to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn graph_rebuild_plan_detects_incremental_changes() {
        let previous = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/scan/path-a",
                    BTreeSet::new(),
                    2,
                    RiskLevel::Low,
                    9_000,
                    BTreeSet::from(["service_banner".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    parse_objective_id("77777777-7777-7777-7777-777777777777"),
                    parse_campaign_id("88888888-8888-8888-8888-888888888888"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::FindingExists {
                        finding_type: "service_banner".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![DiscoveredArtifactInput::new(
                    "artifact:one",
                    "service_banner",
                    "available",
                    BTreeSet::new(),
                    BTreeMap::new(),
                )
                .expect("artifact")],
                BTreeMap::from([("operator".to_string(), MetadataValue::Text("a".to_string()))]),
            )
            .expect("input"),
        )
        .expect("normalize");

        let next = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/scan/path-a",
                    BTreeSet::new(),
                    5,
                    RiskLevel::Medium,
                    8_000,
                    BTreeSet::from(["service_banner".to_string(), "host_profile".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    parse_objective_id("77777777-7777-7777-7777-777777777777"),
                    parse_campaign_id("88888888-8888-8888-8888-888888888888"),
                    ObjectiveStatus::InProgress,
                    vec![],
                    vec![Predicate::FindingExists {
                        finding_type: "service_banner".to_string(),
                    }],
                    vec![],
                    RiskLevel::Medium,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![DiscoveredArtifactInput::new(
                    "artifact:one",
                    "service_banner",
                    "expired",
                    BTreeSet::new(),
                    BTreeMap::new(),
                )
                .expect("artifact")],
                BTreeMap::from([("operator".to_string(), MetadataValue::Text("b".to_string()))]),
            )
            .expect("input"),
        )
        .expect("normalize");

        let rebuild = plan_graph_rebuild(Some(&previous), &next);
        assert!(rebuild.requires_rebuild());
        assert_eq!(
            rebuild.triggers,
            vec![
                GraphRebuildTrigger::ModulesChanged,
                GraphRebuildTrigger::ObjectivesChanged,
                GraphRebuildTrigger::ArtifactsChanged,
                GraphRebuildTrigger::MetadataChanged
            ]
        );
        assert_eq!(
            rebuild.changed_modules,
            vec!["auxiliary/scan/path-a".to_string()]
        );
        assert_eq!(
            rebuild.changed_objectives,
            vec![parse_objective_id("77777777-7777-7777-7777-777777777777")]
        );
        assert_eq!(rebuild.changed_artifacts, vec!["artifact:one".to_string()]);
    }

    #[test]
    fn graph_rebuild_plan_reports_full_build_when_no_previous_snapshot() {
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![],
                vec![ObjectiveDefinitionInput::new(
                    parse_objective_id("99999999-9999-9999-9999-999999999999"),
                    parse_campaign_id("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::FindingExists {
                        finding_type: "shell_access".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("normalize");

        let rebuild = plan_graph_rebuild(None, &snapshot);
        assert_eq!(rebuild.triggers, vec![GraphRebuildTrigger::FullBuild]);
        assert!(rebuild.requires_rebuild());
        assert_eq!(
            rebuild.added_objectives,
            vec![parse_objective_id("99999999-9999-9999-9999-999999999999")]
        );
    }

    #[test]
    fn astar_returns_reproducible_optimal_path_under_fixed_weights() {
        let mut graph = CapabilityGraph::new();
        let cap = parse_node_id("node/cap/start");
        let asset = parse_node_id("node/asset/mid");
        let goal = parse_node_id("node/objective/goal");

        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(cap.clone(), "exploit_execution", true).expect("cap"),
            ))
            .expect("cap node");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(asset.clone(), "shell_access", "expected").expect("asset"),
            ))
            .expect("asset node");
        graph
            .add_node(PlanNode::ObjectiveState(
                ObjectiveStateNode::new(
                    goal.clone(),
                    parse_objective_id("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                    ObjectiveStatus::Pending,
                    "goal",
                )
                .expect("goal"),
            ))
            .expect("objective node");

        let direct = PlanEdge::module_execution(
            parse_edge_id("edge/direct"),
            cap.clone(),
            goal.clone(),
            "module/direct",
            PlanEdgeAttributes::new(
                BTreeSet::from(["exploit_execution".to_string()]),
                20,
                RiskLevel::High,
                8_000,
                BTreeSet::new(),
            )
            .expect("attrs"),
        )
        .expect("edge");
        graph.add_edge(direct).expect("insert direct");

        let step_one = PlanEdge::module_execution(
            parse_edge_id("edge/step-one"),
            cap.clone(),
            asset.clone(),
            "module/step-one",
            PlanEdgeAttributes::new(
                BTreeSet::from(["exploit_execution".to_string()]),
                5,
                RiskLevel::Low,
                9_000,
                BTreeSet::new(),
            )
            .expect("attrs"),
        )
        .expect("edge");
        graph.add_edge(step_one).expect("insert step1");
        let step_two = PlanEdge::module_execution(
            parse_edge_id("edge/step-two"),
            asset.clone(),
            goal.clone(),
            "module/step-two",
            PlanEdgeAttributes::new(BTreeSet::new(), 5, RiskLevel::Low, 9_000, BTreeSet::new())
                .expect("attrs"),
        )
        .expect("edge");
        graph.add_edge(step_two).expect("insert step2");

        let request = AStarPlanRequest::new(
            parse_objective_id("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            BTreeSet::from(["exploit_execution".to_string()]),
            AStarCostWeights::default_contract(),
        );
        let first = astar_plan(&graph, &request).expect("plan").expect("path");
        let second = astar_plan(&graph, &request).expect("plan").expect("path");

        assert_eq!(first, second);
        assert_eq!(
            first.traversed_edges,
            vec![
                parse_edge_id("edge/step-one"),
                parse_edge_id("edge/step-two")
            ]
        );
        assert!(
            first.total_cost
                < edge_weight(
                    graph
                        .edges()
                        .get(&parse_edge_id("edge/direct"))
                        .expect("direct edge"),
                    &request.available_capabilities,
                    &request.weights
                )
        );
    }

    #[test]
    fn astar_uses_deterministic_tie_breaking_for_equal_f_scores() {
        let mut graph = CapabilityGraph::new();
        let start = parse_node_id("node/cap/start");
        let branch_a = parse_node_id("node/asset/a");
        let branch_b = parse_node_id("node/asset/b");
        let goal = parse_node_id("node/objective/goal");

        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(start.clone(), "scan", true).expect("cap"),
            ))
            .expect("node");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(branch_a.clone(), "signal", "expected").expect("a"),
            ))
            .expect("node");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(branch_b.clone(), "signal", "expected").expect("b"),
            ))
            .expect("node");
        graph
            .add_node(PlanNode::ObjectiveState(
                ObjectiveStateNode::new(
                    goal.clone(),
                    parse_objective_id("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                    ObjectiveStatus::Pending,
                    "goal",
                )
                .expect("goal"),
            ))
            .expect("node");

        for edge in [
            PlanEdge::module_execution(
                parse_edge_id("edge/start-a"),
                start.clone(),
                branch_a.clone(),
                "module/start-a",
                edge_attrs(),
            ),
            PlanEdge::module_execution(
                parse_edge_id("edge/start-b"),
                start.clone(),
                branch_b.clone(),
                "module/start-b",
                edge_attrs(),
            ),
            PlanEdge::module_execution(
                parse_edge_id("edge/a-goal"),
                branch_a.clone(),
                goal.clone(),
                "module/a-goal",
                edge_attrs(),
            ),
            PlanEdge::module_execution(
                parse_edge_id("edge/b-goal"),
                branch_b.clone(),
                goal.clone(),
                "module/b-goal",
                edge_attrs(),
            ),
        ] {
            graph.add_edge(edge.expect("edge")).expect("insert");
        }

        let request = AStarPlanRequest::new(
            parse_objective_id("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            BTreeSet::new(),
            AStarCostWeights::default_contract(),
        );
        let plan = astar_plan(&graph, &request).expect("plan").expect("path");
        assert_eq!(
            plan.traversed_edges,
            vec![parse_edge_id("edge/start-a"), parse_edge_id("edge/a-goal")]
        );
    }

    #[test]
    fn astar_heuristic_is_consistent_and_admissible() {
        let mut graph = CapabilityGraph::new();
        let start = parse_node_id("node/cap/start");
        let mid = parse_node_id("node/asset/mid");
        let goal = parse_node_id("node/objective/goal");
        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(start.clone(), "scan", true).expect("start"),
            ))
            .expect("insert");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(mid.clone(), "signal", "expected").expect("mid"),
            ))
            .expect("insert");
        graph
            .add_node(PlanNode::ObjectiveState(
                ObjectiveStateNode::new(
                    goal.clone(),
                    parse_objective_id("dddddddd-dddd-dddd-dddd-dddddddddddd"),
                    ObjectiveStatus::Pending,
                    "goal",
                )
                .expect("goal"),
            ))
            .expect("insert");
        graph
            .add_edge(
                PlanEdge::module_execution(
                    parse_edge_id("edge/start-mid"),
                    start.clone(),
                    mid.clone(),
                    "module/start-mid",
                    edge_attrs(),
                )
                .expect("edge"),
            )
            .expect("insert edge");
        graph
            .add_edge(
                PlanEdge::module_execution(
                    parse_edge_id("edge/mid-goal"),
                    mid.clone(),
                    goal.clone(),
                    "module/mid-goal",
                    edge_attrs(),
                )
                .expect("edge"),
            )
            .expect("insert edge");

        let goals = BTreeSet::from([goal.clone()]);
        let weights = AStarCostWeights::default_contract();
        let lower = minimum_edge_lower_bound(&graph, &weights);
        let hops = compute_goal_hop_bounds_with_forbidden_edges(&graph, &goals, &BTreeSet::new());
        let caps = BTreeSet::new();
        for edge in graph.edges().values() {
            let h_from = heuristic_cost(edge.from(), &hops, lower);
            let h_to = heuristic_cost(edge.to(), &hops, lower);
            let c = edge_weight(edge, &caps, &weights);
            assert!(h_from <= c.saturating_add(h_to));
        }

        let request = AStarPlanRequest::new(
            parse_objective_id("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            BTreeSet::new(),
            weights,
        );
        let plan = astar_plan(&graph, &request).expect("plan").expect("path");
        assert_eq!(plan.traversed_edges.len(), 2);
    }

    #[test]
    fn goal_hop_bounds_respect_forbidden_edges() {
        let mut graph = CapabilityGraph::new();
        let start = parse_node_id("node/cap/start");
        let mid = parse_node_id("node/asset/mid");
        let goal = parse_node_id("node/objective/goal");
        let blocked_edge_id = parse_edge_id("edge/mid-goal");

        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(start.clone(), "scan", true).expect("start"),
            ))
            .expect("insert");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(mid.clone(), "signal", "expected").expect("mid"),
            ))
            .expect("insert");
        graph
            .add_node(PlanNode::ObjectiveState(
                ObjectiveStateNode::new(
                    goal.clone(),
                    parse_objective_id("dfdddddd-dddd-dddd-dddd-dddddddddddd"),
                    ObjectiveStatus::Pending,
                    "goal",
                )
                .expect("goal"),
            ))
            .expect("insert");
        graph
            .add_edge(
                PlanEdge::module_execution(
                    parse_edge_id("edge/start-mid"),
                    start.clone(),
                    mid.clone(),
                    "module/start-mid",
                    edge_attrs(),
                )
                .expect("edge"),
            )
            .expect("insert");
        graph
            .add_edge(
                PlanEdge::module_execution(
                    blocked_edge_id.clone(),
                    mid.clone(),
                    goal.clone(),
                    "module/mid-goal",
                    edge_attrs(),
                )
                .expect("edge"),
            )
            .expect("insert");

        let goals = BTreeSet::from([goal.clone()]);
        let all_edges_bounds =
            compute_goal_hop_bounds_with_forbidden_edges(&graph, &goals, &BTreeSet::new());
        assert_eq!(all_edges_bounds.get(&start), Some(&2));
        assert_eq!(all_edges_bounds.get(&mid), Some(&1));
        assert_eq!(all_edges_bounds.get(&goal), Some(&0));

        let forbidden = BTreeSet::from([blocked_edge_id]);
        let constrained_bounds =
            compute_goal_hop_bounds_with_forbidden_edges(&graph, &goals, &forbidden);
        assert_eq!(constrained_bounds.get(&goal), Some(&0));
        assert!(!constrained_bounds.contains_key(&start));
        assert!(!constrained_bounds.contains_key(&mid));
    }

    #[test]
    fn astar_with_forbidden_edges_returns_none_when_goal_paths_are_blocked() {
        let mut graph = CapabilityGraph::new();
        let start = parse_node_id("node/cap/start");
        let mid = parse_node_id("node/asset/mid");
        let goal = parse_node_id("node/objective/goal");
        let blocked_edge_id = parse_edge_id("edge/mid-goal");

        graph
            .add_node(PlanNode::CapabilityState(
                CapabilityStateNode::new(start.clone(), "scan", true).expect("start"),
            ))
            .expect("insert");
        graph
            .add_node(PlanNode::AssetState(
                AssetStateNode::new(mid.clone(), "signal", "expected").expect("mid"),
            ))
            .expect("insert");
        graph
            .add_node(PlanNode::ObjectiveState(
                ObjectiveStateNode::new(
                    goal.clone(),
                    parse_objective_id("eddddddd-dddd-dddd-dddd-dddddddddddd"),
                    ObjectiveStatus::Pending,
                    "goal",
                )
                .expect("goal"),
            ))
            .expect("insert");
        graph
            .add_edge(
                PlanEdge::module_execution(
                    parse_edge_id("edge/start-mid"),
                    start.clone(),
                    mid.clone(),
                    "module/start-mid",
                    edge_attrs(),
                )
                .expect("edge"),
            )
            .expect("insert");
        graph
            .add_edge(
                PlanEdge::module_execution(
                    blocked_edge_id.clone(),
                    mid.clone(),
                    goal.clone(),
                    "module/mid-goal",
                    edge_attrs(),
                )
                .expect("edge"),
            )
            .expect("insert");

        let request = AStarPlanRequest::new(
            parse_objective_id("eddddddd-dddd-dddd-dddd-dddddddddddd"),
            BTreeSet::new(),
            AStarCostWeights::default_contract(),
        );
        let forbidden = BTreeSet::from([blocked_edge_id]);
        let plan =
            astar_plan_with_forbidden_edges(&graph, &request, &forbidden).expect("planner call");
        assert!(plan.is_none());
    }

    #[test]
    fn planner_engine_pipelines_are_deterministic_and_advisory_only() {
        let objective_id = parse_objective_id("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");
        let campaign_id = parse_campaign_id("ffffffff-ffff-ffff-ffff-ffffffffffff");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "exploit/linux/telnet/sample",
                    BTreeSet::from(["exploit_execution".to_string()]),
                    7,
                    RiskLevel::High,
                    7_500,
                    BTreeSet::from(["shell_access".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    campaign_id,
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![
                        Predicate::FindingExists {
                            finding_type: "shell_access".to_string(),
                        },
                        Predicate::RunSucceeded {
                            module_name: "exploit/linux/telnet/sample".to_string(),
                        },
                    ],
                    vec![],
                    RiskLevel::High,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let snapshot_before = snapshot.clone();
        let weights = AStarCostWeights::default_contract();
        let capabilities = BTreeSet::from(["exploit_execution".to_string()]);

        let plan_a = plan_pipeline(
            &snapshot,
            objective_id.clone(),
            "event.plan.1",
            123456,
            capabilities.clone(),
            weights.clone(),
        )
        .expect("plan a");
        let plan_b = plan_pipeline(
            &snapshot,
            objective_id.clone(),
            "event.plan.1",
            123456,
            capabilities.clone(),
            weights.clone(),
        )
        .expect("plan b");

        assert_eq!(snapshot, snapshot_before);
        assert_eq!(plan_a, plan_b);
        assert_eq!(plan_a.result.status, PlanLifecycleStatus::Proposed);
        assert!(plan_a.explanation.is_none());
        assert!(plan_a.simulation.is_none());

        let explain = explain_pipeline(
            &snapshot,
            objective_id.clone(),
            "event.explain.1",
            123456,
            capabilities.clone(),
            weights.clone(),
        )
        .expect("explain");
        assert_eq!(explain.result.status, PlanLifecycleStatus::Explained);
        assert!(explain.explanation.is_some());
        assert!(explain.simulation.is_none());

        let simulate = simulate_pipeline(
            &snapshot,
            objective_id,
            "event.simulate.1",
            123456,
            capabilities,
            weights,
        )
        .expect("simulate");
        assert_eq!(simulate.result.status, PlanLifecycleStatus::Simulated);
        assert!(simulate.explanation.is_some());
        assert!(simulate.simulation.is_some());
    }

    #[test]
    fn indexed_graph_build_scales_to_1000_plus_modules() {
        let (snapshot, _) = synthetic_scale_snapshot(1_200).expect("scale snapshot");
        let prepared = PreparedPlannerSnapshot::prepare(&snapshot).expect("prepared snapshot");
        let memory_bytes = prepared.estimated_footprint_bytes();

        assert_eq!(prepared.snapshot.modules().len(), 1_200);
        assert!(prepared.graph_output.graph.node_count() >= 1_200);
        assert!(prepared.graph_output.graph.edge_count() >= 1_200);
        assert!(
            memory_bytes <= 64 * 1024 * 1024,
            "prepared snapshot memory estimate exceeded budget: {} bytes",
            memory_bytes
        );
    }

    #[test]
    fn prepared_pipeline_matches_unprepared_pipeline_for_identical_inputs() {
        let (snapshot, objective_id) = synthetic_scale_snapshot(1_024).expect("scale snapshot");
        let request = PlanRequest::new(
            objective_id,
            PlanRequestMode::Plan,
            "prepared.equivalence",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(777, BTreeSet::new(), AStarCostWeights::default());

        let baseline = execute_planner_pipeline(&snapshot, &request, &context).expect("baseline");
        let prepared = PreparedPlannerSnapshot::prepare(&snapshot).expect("prepared");
        let accelerated =
            execute_planner_pipeline_prepared(&prepared.graph_output, &request, &context)
                .expect("accelerated");

        assert_eq!(baseline.result, accelerated.result);
        assert_eq!(baseline.graph_signature, accelerated.graph_signature);
        assert_eq!(baseline.event_payloads, accelerated.event_payloads);
    }

    #[test]
    fn concurrent_planning_requests_are_thread_safe_and_stable() {
        let (snapshot, objective_id) = synthetic_scale_snapshot(1_200).expect("scale snapshot");
        let engine = std::sync::Arc::new(ConcurrentPlannerEngine::new(&snapshot).expect("engine"));
        let worker_count = 8usize;
        let requests_per_worker = 80usize;

        let mut handles = Vec::with_capacity(worker_count);
        for worker_id in 0..worker_count {
            let engine = engine.clone();
            let objective_id = objective_id.clone();
            handles.push(std::thread::spawn(move || -> String {
                let context =
                    PlannerEngineContext::new(888, BTreeSet::new(), AStarCostWeights::default());
                let mut expected_hash = None::<String>;
                for idx in 0..requests_per_worker {
                    let request = PlanRequest::new(
                        objective_id.clone(),
                        PlanRequestMode::Plan,
                        &format!("concurrent.plan.{worker_id}.{idx}"),
                        None,
                        false,
                    )
                    .expect("request");
                    let output = engine.execute(&request, &context).expect("execute");
                    let current_hash = plan_result_hash(&output.result);
                    match expected_hash.as_ref() {
                        Some(existing) => assert_eq!(existing, &current_hash),
                        None => expected_hash = Some(current_hash),
                    }
                }
                expected_hash.expect("at least one request")
            }));
        }

        let mut hashes = BTreeSet::new();
        for handle in handles {
            hashes.insert(handle.join().expect("worker join"));
        }

        assert_eq!(
            hashes.len(),
            1,
            "all workers must converge to same plan hash"
        );
    }

    #[test]
    fn randomized_planner_fuzz_is_deterministic_under_replay() {
        for seed in 1_u64..=24_u64 {
            let mut rng = seed;
            let module_count = 96usize;
            let objective_id = parse_objective_id("feedfeed-1111-2222-3333-1234567890ab");
            let campaign_id = parse_campaign_id("deadbeef-1111-2222-3333-1234567890ab");
            let mut modules = Vec::with_capacity(module_count);
            let mut artifacts = Vec::with_capacity(48);
            for idx in 0..module_count {
                let roll = lcg_next(&mut rng);
                let module_reference = format!("auxiliary/fuzz/{seed}/{idx}");
                let mut caps = BTreeSet::new();
                if roll & 1 == 0 {
                    caps.insert("exploit_execution".to_string());
                }
                if roll & 2 == 0 {
                    caps.insert("public_targets".to_string());
                }
                let risk = match roll % 3 {
                    0 => RiskLevel::Low,
                    1 => RiskLevel::Medium,
                    _ => RiskLevel::High,
                };
                let expected = BTreeSet::from([format!("artifact_type_{}", roll % 16)]);
                modules.push(
                    RegisteredModuleInput::new(
                        &module_reference,
                        caps,
                        ((roll % 10) + 1) as u32,
                        risk,
                        4_000 + ((roll % 6_000) as u16),
                        expected,
                        BTreeMap::new(),
                    )
                    .expect("module"),
                );
                if idx % 2 == 0 {
                    artifacts.push(
                        DiscoveredArtifactInput::new(
                            &format!("fuzz-artifact-{seed}-{idx}"),
                            &format!("artifact_type_{}", roll % 16),
                            if roll & 4 == 0 {
                                "available"
                            } else {
                                "expired"
                            },
                            BTreeSet::from([format!("tag_{}", roll % 8)]),
                            BTreeMap::new(),
                        )
                        .expect("artifact"),
                    );
                }
            }
            let selected_module = modules[module_count - 1].module_reference.clone();
            let objective = ObjectiveDefinitionInput::new(
                objective_id.clone(),
                campaign_id,
                ObjectiveStatus::Pending,
                vec![],
                vec![Predicate::RunSucceeded {
                    module_name: selected_module,
                }],
                vec![],
                RiskLevel::Low,
                None,
                BTreeMap::new(),
            )
            .expect("objective");

            let snapshot = normalize_planner_input(
                PlannerNormalizationInput::new(
                    modules,
                    vec![objective],
                    artifacts,
                    BTreeMap::new(),
                )
                .expect("input"),
            )
            .expect("snapshot");
            let request = PlanRequest::new(
                objective_id.clone(),
                PlanRequestMode::Plan,
                &format!("fuzz.plan.{seed}"),
                None,
                false,
            )
            .expect("request");
            let context = PlannerEngineContext::new(
                5_000 + seed,
                BTreeSet::new(),
                AStarCostWeights::default(),
            );

            let output_a = execute_planner_pipeline(&snapshot, &request, &context).expect("first");
            let output_b = execute_planner_pipeline(&snapshot, &request, &context).expect("second");
            assert_eq!(output_a.result, output_b.result, "seed={seed}");
            assert_eq!(
                output_a.graph_signature, output_b.graph_signature,
                "seed={seed}"
            );
        }
    }

    #[test]
    fn planner_engine_marks_capability_constraints_without_blocking_path() {
        let objective_id = parse_objective_id("12121212-3434-5656-7878-909090909090");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "exploit/linux/needs-capability",
                    BTreeSet::from(["exploit_execution".to_string()]),
                    5,
                    RiskLevel::Medium,
                    8_000,
                    BTreeSet::from(["shell_access".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("abababab-abab-abab-abab-abababababab"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "exploit/linux/needs-capability".to_string(),
                    }],
                    vec![],
                    RiskLevel::Medium,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let request = PlanRequest::new(
            objective_id,
            PlanRequestMode::Plan,
            "blocked.path",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(55, BTreeSet::new(), AStarCostWeights::default());
        let output = execute_planner_pipeline(&snapshot, &request, &context).expect("output");
        assert_eq!(output.result.status, PlanLifecycleStatus::Proposed);
        assert!(output.result.unreachable_reason.is_none());
        assert_eq!(output.result.steps.len(), 1);
        assert!(output.result.steps[0].blocked_reasons.iter().any(|reason| {
            matches!(
                reason,
                PlanStepBlockReason::CapabilityDisabled { capability }
                if capability == "exploit_execution"
            ) && reason.code() == "ML-PLAN-BLOCK-0001"
        }));
        assert!(output
            .result
            .blocked_capabilities
            .contains("exploit_execution"));
    }

    #[test]
    fn planner_engine_marks_policy_denied_steps_with_deterministic_code() {
        let objective_id = parse_objective_id("22121212-3434-5656-7878-909090909090");
        let module_ref = "auxiliary/policy/denied";
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    module_ref,
                    BTreeSet::new(),
                    3,
                    RiskLevel::Low,
                    8_000,
                    BTreeSet::from(["shell_access".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("abababab-abab-abab-abab-abababababab"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: module_ref.to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let request = PlanRequest::new(
            objective_id,
            PlanRequestMode::Plan,
            "blocked.policy.path",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(65, BTreeSet::new(), AStarCostWeights::default())
            .with_policy_blocked_module(module_ref, "deny:requires_confirmation");
        let output = execute_planner_pipeline(&snapshot, &request, &context).expect("output");

        assert_eq!(output.result.status, PlanLifecycleStatus::Proposed);
        assert!(output.result.unreachable_reason.is_none());
        assert_eq!(output.result.steps.len(), 1);
        assert!(output.result.steps[0].blocked_reasons.iter().any(|reason| {
            matches!(
                reason,
                PlanStepBlockReason::PolicyDenied { policy_key }
                if policy_key == "deny:requires_confirmation"
            ) && reason.code() == "ML-PLAN-BLOCK-0002"
        }));
    }

    #[test]
    fn planner_engine_marks_scope_blocked_steps_with_deterministic_code() {
        let objective_id = parse_objective_id("23121212-3434-5656-7878-909090909090");
        let module_ref = "auxiliary/scope/public";
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    module_ref,
                    BTreeSet::new(),
                    3,
                    RiskLevel::Low,
                    8_000,
                    BTreeSet::from(["shell_access".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("bcbcbcbc-bcbc-bcbc-bcbc-bcbcbcbcbcbc"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: module_ref.to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let request = PlanRequest::new(
            objective_id,
            PlanRequestMode::Plan,
            "blocked.scope.path",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(75, BTreeSet::new(), AStarCostWeights::default())
            .with_module_scope(module_ref, "public")
            .with_allowed_scope("private");
        let output = execute_planner_pipeline(&snapshot, &request, &context).expect("output");

        assert_eq!(output.result.status, PlanLifecycleStatus::Proposed);
        assert!(output.result.unreachable_reason.is_none());
        assert_eq!(output.result.steps.len(), 1);
        assert!(output.result.steps[0].blocked_reasons.iter().any(|reason| {
            matches!(
                reason,
                PlanStepBlockReason::OutOfScope { scope_key }
                if scope_key == "public"
            ) && reason.code() == "ML-PLAN-BLOCK-0003"
        }));
    }

    #[test]
    fn planner_engine_respects_include_blocked_paths_flag_when_alternative_exists() {
        let objective_id = parse_objective_id("24121212-3434-5656-7878-909090909090");
        let blocked_module_ref = "auxiliary/path/blocked_fast";
        let allowed_module_ref = "auxiliary/path/allowed_slow";
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![
                    RegisteredModuleInput::new(
                        blocked_module_ref,
                        BTreeSet::new(),
                        1,
                        RiskLevel::Low,
                        8_000,
                        BTreeSet::from(["shell_access".to_string()]),
                        BTreeMap::new(),
                    )
                    .expect("blocked module"),
                    RegisteredModuleInput::new(
                        allowed_module_ref,
                        BTreeSet::new(),
                        20,
                        RiskLevel::Low,
                        8_000,
                        BTreeSet::from(["shell_access".to_string()]),
                        BTreeMap::new(),
                    )
                    .expect("allowed module"),
                ],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![
                        Predicate::RunSucceeded {
                            module_name: blocked_module_ref.to_string(),
                        },
                        Predicate::RunSucceeded {
                            module_name: allowed_module_ref.to_string(),
                        },
                    ],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let context = PlannerEngineContext::new(85, BTreeSet::new(), AStarCostWeights::default())
            .with_policy_blocked_module(blocked_module_ref, "deny:policy");

        let request_without_blocked = PlanRequest::new(
            objective_id.clone(),
            PlanRequestMode::Plan,
            "blocked.path.disabled",
            None,
            false,
        )
        .expect("request without blocked");
        let without_blocked =
            execute_planner_pipeline(&snapshot, &request_without_blocked, &context).expect("plan");
        assert_eq!(without_blocked.result.status, PlanLifecycleStatus::Proposed);
        assert_eq!(without_blocked.result.steps.len(), 1);
        assert_eq!(
            without_blocked.result.steps[0].module_reference.as_deref(),
            Some(allowed_module_ref)
        );
        assert!(without_blocked.result.steps[0].blocked_reasons.is_empty());

        let request_with_blocked = PlanRequest::new(
            objective_id,
            PlanRequestMode::Plan,
            "blocked.path.enabled",
            None,
            true,
        )
        .expect("request with blocked");
        let with_blocked =
            execute_planner_pipeline(&snapshot, &request_with_blocked, &context).expect("plan");
        assert_eq!(with_blocked.result.status, PlanLifecycleStatus::Proposed);
        assert_eq!(with_blocked.result.steps.len(), 1);
        assert_eq!(
            with_blocked.result.steps[0].module_reference.as_deref(),
            Some(blocked_module_ref)
        );
        assert!(with_blocked.result.steps[0]
            .blocked_reasons
            .iter()
            .any(|reason| matches!(reason, PlanStepBlockReason::PolicyDenied { policy_key } if policy_key == "deny:policy")));
    }

    #[test]
    fn planner_engine_simulation_outputs_predicted_artifacts_and_detection_surface() {
        let objective_id = parse_objective_id("13131313-1313-1313-1313-131313131313");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/collect/artifacts",
                    BTreeSet::new(),
                    2,
                    RiskLevel::Low,
                    9_500,
                    BTreeSet::from(["inventory".to_string(), "service_banner".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("14141414-1414-1414-1414-141414141414"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "auxiliary/collect/artifacts".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let output = simulate_pipeline(
            &snapshot,
            objective_id,
            "sim.predict",
            99,
            BTreeSet::new(),
            AStarCostWeights::default(),
        )
        .expect("simulate");
        let simulation = output.simulation.expect("simulation payload");
        assert!(!simulation.predicted_artifact_chain.is_empty());
        assert!(simulation
            .expected_detection_surface
            .iter()
            .any(|marker| marker.starts_with("risk:")));
    }

    #[test]
    fn conditional_replan_triggers_on_artifact_change() {
        let objective_id = parse_objective_id("15151515-1515-1515-1515-151515151515");
        let request = PlanRequest::new(
            objective_id.clone(),
            PlanRequestMode::Plan,
            "replan.artifact.change",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(77, BTreeSet::new(), AStarCostWeights::default());

        let previous = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/sample/module",
                    BTreeSet::new(),
                    2,
                    RiskLevel::Low,
                    9_000,
                    BTreeSet::from(["service_banner".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("16161616-1616-1616-1616-161616161616"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "auxiliary/sample/module".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![DiscoveredArtifactInput::new(
                    "artifact:one",
                    "service_banner",
                    "available",
                    BTreeSet::new(),
                    BTreeMap::new(),
                )
                .expect("artifact")],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("normalize");

        let next = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![RegisteredModuleInput::new(
                    "auxiliary/sample/module",
                    BTreeSet::new(),
                    2,
                    RiskLevel::Low,
                    9_000,
                    BTreeSet::from(["service_banner".to_string()]),
                    BTreeMap::new(),
                )
                .expect("module")],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("16161616-1616-1616-1616-161616161616"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "auxiliary/sample/module".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                vec![DiscoveredArtifactInput::new(
                    "artifact:one",
                    "service_banner",
                    "expired",
                    BTreeSet::new(),
                    BTreeMap::new(),
                )
                .expect("artifact")],
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("normalize");

        let output =
            conditional_replan(Some(&previous), &next, &request, &context, 2).expect("replan");
        assert!(output.reevaluated);
        assert!(output
            .rebuild
            .triggers
            .contains(&GraphRebuildTrigger::ArtifactsChanged));
        assert!(output.event_payloads.iter().any(|payload| {
            matches!(payload, PlanningEventPayload::PlanReplanned { objective_id: id, .. } if id == &objective_id)
        }));
    }

    #[test]
    fn conditional_replan_detects_unreachable_objective_with_reason() {
        let objective_id = parse_objective_id("17171717-1717-1717-1717-171717171717");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                Vec::new(),
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("18181818-1818-1818-1818-181818181818"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::FindingExists {
                        finding_type: "shell_access".to_string(),
                    }],
                    vec![],
                    RiskLevel::Low,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                Vec::new(),
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");

        let request = PlanRequest::new(
            objective_id,
            PlanRequestMode::Plan,
            "replan.unreachable",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(88, BTreeSet::new(), AStarCostWeights::default());
        let output = conditional_replan(None, &snapshot, &request, &context, 2).expect("replan");
        assert!(output.reevaluated);
        assert_eq!(
            output.primary.result.status,
            PlanLifecycleStatus::Unreachable
        );
        assert_eq!(
            output.primary.result.unreachable_reason,
            Some(PlanUnreachableReason::NoGraphPath)
        );
        assert!(output.alternatives.is_empty());
    }

    #[test]
    fn conditional_replan_generates_alternative_paths_with_reasons() {
        let objective_id = parse_objective_id("19191919-1919-1919-1919-191919191919");
        let snapshot = normalize_planner_input(
            PlannerNormalizationInput::new(
                vec![
                    RegisteredModuleInput::new(
                        "exploit/path/primary",
                        BTreeSet::new(),
                        8,
                        RiskLevel::High,
                        7_000,
                        BTreeSet::from(["shell_access".to_string()]),
                        BTreeMap::new(),
                    )
                    .expect("module"),
                    RegisteredModuleInput::new(
                        "exploit/path/alternate",
                        BTreeSet::new(),
                        2,
                        RiskLevel::Low,
                        9_000,
                        BTreeSet::from(["shell_access".to_string()]),
                        BTreeMap::new(),
                    )
                    .expect("module"),
                ],
                vec![ObjectiveDefinitionInput::new(
                    objective_id.clone(),
                    parse_campaign_id("20202020-2020-2020-2020-202020202020"),
                    ObjectiveStatus::Pending,
                    vec![],
                    vec![Predicate::RunSucceeded {
                        module_name: "exploit/path/primary".to_string(),
                    }],
                    vec![Predicate::RunSucceeded {
                        module_name: "exploit/path/alternate".to_string(),
                    }],
                    RiskLevel::Medium,
                    None,
                    BTreeMap::new(),
                )
                .expect("objective")],
                Vec::new(),
                BTreeMap::new(),
            )
            .expect("input"),
        )
        .expect("snapshot");
        let request = PlanRequest::new(
            objective_id,
            PlanRequestMode::Plan,
            "replan.alternative",
            None,
            false,
        )
        .expect("request");
        let context = PlannerEngineContext::new(99, BTreeSet::new(), AStarCostWeights::default());

        let output = conditional_replan(None, &snapshot, &request, &context, 3).expect("replan");
        assert!(output.reevaluated);
        assert!(!output.alternatives.is_empty());
        assert!(matches!(
            output.alternatives[0].reason,
            ReplanAlternativeReason::LowerNoise
                | ReplanAlternativeReason::LowerRisk
                | ReplanAlternativeReason::FewerCapabilities
                | ReplanAlternativeReason::DifferentPath
        ));
        assert_ne!(
            step_signature(&output.primary.result.steps),
            step_signature(&output.alternatives[0].output.result.steps)
        );
    }
}
