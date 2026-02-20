# Release Operations Guide

This guide documents the release-control commands available in the Moonlight REPL and the core functions that power them.

## Release Command Usage
Use `release` to inspect or enforce release discipline from the operator console.

### Summary

```text
moonlight> release
moonlight> help release
```

What it does:
- Shows current control-state schema version.
- Shows the latest supported schema version.
- Shows rollback snapshot count.
- Prints release command usage.

### Readiness Check

```text
moonlight> release check
```

What it does:
- Runs the compatibility matrix tests.
- Evaluates documentation completeness gates.
- Validates migration path from current schema to latest schema.
- Verifies rollback snapshot availability.
- Verifies rollback snapshot payload compatibility with schema semantics.
- Evaluates checklist requirements and reports blockers.

### Compatibility Matrix

```text
moonlight> release matrix
```

What it does:
- Runs deterministic compatibility test cases against the active compatibility policy.
- Verifies expected pass/fail outcomes for each case.
- Reports total, passed, failed, and detailed mismatch reasons.

## Migration Workflow

### Plan a migration

```text
moonlight> release migrate plan <from-version> <to-version>
moonlight> release migrate plan <to-version>
```

What it does:
- Calculates a valid path across migration steps.
- Supports forward migration and reversible rollback paths.
- Reports direction, impact, and whether backup is required for each step.

### Apply a migration

```text
moonlight> release migrate apply <to-version>
```

What it does:
- Creates a rollback snapshot before applying the migration plan.
- Applies each migration step in order.
- Updates the control-state schema version.
- Reports applied step count and generated rollback snapshot id.

## Rollback Workflow

### Create snapshot

```text
moonlight> release rollback snapshot <label>
```

What it does:
- Captures a rollback snapshot of current control-state payload.
- Stores schema version, timestamp, and checksum.

### List snapshots

```text
moonlight> release rollback list
```

What it does:
- Lists snapshots with id, schema version, capture time, checksum, and label.

### Restore snapshot

```text
moonlight> release rollback apply <snapshot-id>
```

What it does:
- Validates snapshot checksum.
- Validates snapshot payload compatibility with target schema.
- Restores control-state schema version from snapshot.
- Records restore in migration history.

Schema note:
- For schema `v5+`, rollback snapshots include campaign/objective envelope fields.
- Incompatible payloads are rejected deterministically before restore.

### Prune snapshots

```text
moonlight> release rollback prune <keep-latest>
```

What it does:
- Removes old rollback snapshots while keeping the newest `N` entries.

## Documentation Completeness Gates
Documentation gates verify that required usage docs exist and include required headings.

Current gates:
- `docs/guide/modules.md`
- `docs/guide/release_operations.md`

Related operator guide:
- `docs/guide/campaign_objective_operations.md`

Gate behavior:
- Fails when required files are missing.
- Fails when required headings are missing.
- Passes only when all required files and headings are present.

## Core Function Reference
The release control implementation is in `core/core/src/release.rs`.

### Compatibility
- `ReleaseCompatibilityPolicy::new`: defines supported version windows, runtimes, and output modes.
- `CompatibilityCase::new`: defines one compatibility test case with expected outcome.
- `CompatibilityMatrix::evaluate`: runs all compatibility cases and returns deterministic pass/fail results.

### Migration
- `MigrationPolicy::new`: defines supported schema range and migration graph.
- `MigrationPolicy::plan`: builds a migration path (forward/rollback) between versions.
- `VersionedControlState::apply_migration_plan`: applies a plan to control state with ordered history records.

### Rollback
- `RollbackRegistry::create_snapshot`: captures a labeled snapshot with checksum.
- `RollbackRegistry::restore`: validates and prepares restore payload from snapshot id.
- `VersionedControlState::apply_rollback_restore`: applies a validated rollback restore.

### Release Gates
- `DocumentationGateSuite::evaluate`: checks required docs and headings.
- `ReleaseChecklistTemplate::evaluate`: computes release readiness from required checklist statuses.
