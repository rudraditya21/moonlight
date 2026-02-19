# Core Domain Model (Phase 1)

## Scope
This document defines the canonical control-plane entities and lifecycle rules for Moonlight Phase 1.

The objective is:
- unambiguous entity schemas
- deterministic state transitions
- explicit mapping from operator/system actions to entity changes

Reference implementation: `core/core/src/domain.rs`.

## Canonical Entities

### Workspace
Schema:
- `id: WorkspaceId`
- `name: String`
- `description: String`
- `state: WorkspaceState`
- `created_at: u64`
- `updated_at: u64`

States:
- `active`
- `archived`

### Target
Schema:
- `id: TargetId`
- `workspace_id: WorkspaceId`
- `address: String`
- `tags: Vec<String>`
- `state: TargetState`
- `created_at: u64`
- `updated_at: u64`

States:
- `active`
- `paused`
- `retired`

### ModuleVersion
Schema:
- `id: ModuleVersionId`
- `module_name: String`
- `semantic_version: String`
- `api_version: u16`
- `entrypoint: String`
- `digest_sha256: String`
- `state: ModuleVersionState`
- `created_at: u64`
- `updated_at: u64`

States:
- `registered`
- `deprecated`
- `disabled`

### Run
Schema:
- `id: RunId`
- `workspace_id: WorkspaceId`
- `module_version_id: ModuleVersionId`
- `target_id: Option<TargetId>`
- `requested_by: String`
- `state: RunState`
- `created_at: u64`
- `queued_at: u64`
- `started_at: Option<u64>`
- `finished_at: Option<u64>`
- `updated_at: u64`
- `error: Option<String>`

States:
- `queued`
- `running`
- `succeeded`
- `failed`
- `canceled`

### Task
Schema:
- `id: TaskId`
- `run_id: RunId`
- `name: String`
- `state: TaskState`
- `attempt_count: u32`
- `max_attempts: u32`
- `created_at: u64`
- `queued_at: u64`
- `started_at: Option<u64>`
- `finished_at: Option<u64>`
- `updated_at: u64`
- `error: Option<String>`

States:
- `queued`
- `running`
- `retrying`
- `succeeded`
- `failed`
- `canceled`

### Session
Schema:
- `id: SessionId`
- `run_id: RunId`
- `task_id: Option<TaskId>`
- `kind: String`
- `target: String`
- `state: SessionState`
- `created_at: u64`
- `opened_at: Option<u64>`
- `closed_at: Option<u64>`
- `last_activity_at: u64`
- `updated_at: u64`

States:
- `opening`
- `open`
- `backgrounded`
- `lost`
- `closed`

### Artifact
Schema:
- `id: ArtifactId`
- `run_id: RunId`
- `task_id: Option<TaskId>`
- `session_id: Option<SessionId>`
- `kind: ArtifactKind`
- `name: String`
- `locator: String`
- `state: ArtifactState`
- `created_at: u64`
- `updated_at: u64`

States:
- `pending`
- `available`
- `expired`
- `deleted`

### Finding
Schema:
- `id: FindingId`
- `run_id: RunId`
- `task_id: Option<TaskId>`
- `session_id: Option<SessionId>`
- `title: String`
- `details: String`
- `severity: FindingSeverity`
- `state: FindingState`
- `created_at: u64`
- `updated_at: u64`
- `resolved_at: Option<u64>`

States:
- `open`
- `confirmed`
- `resolved`
- `false_positive`

### Event
Schema:
- `id: EventId`
- `correlation_id: CorrelationId`
- `entity: EntityKind`
- `action: ControlAction`
- `message: String`
- `state: EventState`
- `created_at: u64`
- `updated_at: u64`
- `persisted_at: Option<u64>`
- `delivered_at: Option<u64>`

States:
- `emitted`
- `persisted`
- `delivered`
- `failed`

## Transition Matrix

### Workspace
- `active -> archived`
- `archived -> active`

### Target
- `active -> paused`
- `active -> retired`
- `paused -> active`
- `paused -> retired`

### ModuleVersion
- `registered -> deprecated`
- `registered -> disabled`
- `deprecated -> disabled`

### Run
- `queued -> running`
- `queued -> failed`
- `queued -> canceled`
- `running -> succeeded`
- `running -> failed`
- `running -> canceled`

### Task
- `queued -> running`
- `queued -> canceled`
- `running -> succeeded`
- `running -> failed`
- `running -> retrying`
- `running -> canceled`
- `retrying -> queued`
- `retrying -> canceled`

### Session
- `opening -> open`
- `opening -> lost`
- `opening -> closed`
- `open -> backgrounded`
- `open -> lost`
- `open -> closed`
- `backgrounded -> open`
- `backgrounded -> lost`
- `backgrounded -> closed`
- `lost -> open`
- `lost -> closed`

### Artifact
- `pending -> available`
- `pending -> deleted`
- `available -> expired`
- `available -> deleted`
- `expired -> deleted`

### Finding
- `open -> confirmed`
- `open -> resolved`
- `open -> false_positive`
- `confirmed -> resolved`
- `confirmed -> false_positive`

### Event
- `emitted -> persisted`
- `emitted -> failed`
- `persisted -> delivered`
- `persisted -> failed`

Any transition not listed above is invalid by contract.

## Action to Entity Mapping
All control-plane actions are mapped in `action_entity_changes(ControlAction)`.

Mapping groups:
- workspace actions change `workspace` and `event`
- target actions change `target` and `event`
- module actions change `module_version` and `event`
- run actions change `run` and `event`
- task actions change `task` and `event`
- session actions change `session` and `event`
- artifact actions change `artifact` and `event`
- finding actions change `finding` and `event`
- event actions change `event`

This guarantees Phase 1’s requirement that every action maps to at least one entity change.

## Contract Rules
- entity creation validates mandatory fields and rejects empty required values
- transitions are only legal through explicit `transition_state(...)` methods
- terminal states cannot transition further
- lifecycle timestamps are updated on transition boundaries (`started_at`, `finished_at`, `closed_at`, `resolved_at`)

## Validation
Phase 1 tests exist in `core/core/src/domain.rs` and cover:
- invalid transition rejection
- retry/attempt bound enforcement
- session lost/open recovery flow
- action-to-entity mapping completeness
- event lifecycle terminal behavior
