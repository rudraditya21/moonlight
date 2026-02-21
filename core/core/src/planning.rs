use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::campaign::{
    CampaignId, MetadataValue, Objective, ObjectiveId, ObjectiveStatus, Predicate, RiskLevel,
};
use crate::domain::{Artifact, ArtifactKind, ArtifactState};
use crate::time::now_secs;

pub const PLANNING_CONTRACT_ID: &str = "ml.planning.contract.v1";
pub const PLANNING_SCHEMA_VERSION: u32 = 1;

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

pub fn build_capability_graph(
    snapshot: &NormalizedPlannerSnapshot,
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

    for capability in capability_set {
        let node_id = plan_node_id(&["capability", &capability, "enabled"])?;
        graph.add_node(PlanNode::CapabilityState(CapabilityStateNode::new(
            node_id.clone(),
            &capability,
            true,
        )?))?;
        capability_nodes.insert(capability, node_id);
    }

    let mut signal_tokens = BTreeSet::<String>::new();
    signal_tokens.extend(snapshot.known_artifact_types().iter().cloned());
    for artifact in snapshot.artifacts() {
        signal_tokens.insert(artifact.artifact_type.clone());
        signal_tokens.extend(artifact.tags.iter().cloned());
    }

    for token in signal_tokens {
        let node_id = plan_node_id(&["asset", "signal", &token, "expected"])?;
        graph.add_node(PlanNode::AssetState(AssetStateNode::new(
            node_id.clone(),
            &token,
            "expected",
        )?))?;
        signal_asset_nodes.insert(token, node_id);
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

            for objective in snapshot.objectives() {
                if !objective_uses_module(objective, &module.module_reference) {
                    continue;
                }
                let objective_node = objective_nodes
                    .get(&objective.objective_id)
                    .expect("objective node exists");
                let edge_id = plan_edge_id(&[
                    "edge",
                    "module-to-objective",
                    &module.module_reference,
                    source_capability,
                    objective.objective_id.as_str(),
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

    let mut discovered_by_type = BTreeMap::<String, Vec<PlanNodeId>>::new();
    for artifact in snapshot.artifacts() {
        if let Some(node_id) = discovered_asset_nodes.get(&artifact.artifact_key) {
            discovered_by_type
                .entry(artifact.artifact_type.clone())
                .or_default()
                .push(node_id.clone());
        }
    }
    for nodes in discovered_by_type.values_mut() {
        nodes.sort_by_key(|id| id.as_str().to_string());
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

fn objective_uses_module(objective: &ObjectiveDefinitionInput, module_reference: &str) -> bool {
    let module_reference = normalize_token(module_reference);
    objective
        .success_criteria
        .iter()
        .chain(objective.failure_criteria.iter())
        .any(|predicate| {
            matches!(
                predicate,
                Predicate::RunSucceeded { module_name } if normalize_token(module_name) == module_reference
            )
        })
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
    ScopeRestricted,
}

impl PlanUnreachableReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PlanUnreachableReason::NoGraphPath => "no_graph_path",
            PlanUnreachableReason::PrerequisitesUnsatisfied => "prerequisites_unsatisfied",
            PlanUnreachableReason::CapabilityUnavailable => "capability_unavailable",
            PlanUnreachableReason::ScopeRestricted => "scope_restricted",
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
            required_capabilities,
            success_probability_bps,
            blocked_capabilities,
            unreachable_reason,
            steps,
        )
    }
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
    pub objective_id: ObjectiveId,
    pub event_key: String,
    pub payload: PlanningEventPayload,
}

impl PlanningEvent {
    pub fn new(
        sequence: u64,
        event_key: &str,
        payload: PlanningEventPayload,
    ) -> Result<Self, PlanningContractError> {
        ensure_non_empty(event_key, "planning_event.event_key")?;
        Ok(Self {
            sequence,
            objective_id: payload.objective_id().clone(),
            event_key: normalize_token(event_key),
            payload,
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
}
