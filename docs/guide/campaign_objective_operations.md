# Campaign and Objective Operations Guide

This guide explains how to operate campaigns and objectives from the Moonlight REPL without reading source code.

## Command Usage

### Campaign Commands

```text
moonlight> campaign create <name> [description] [--yes]
moonlight> campaign list
moonlight> campaign show <campaign-id>
moonlight> campaign status
moonlight> campaign status <campaign-id>
moonlight> campaign status <campaign-id> <active|paused|completed|failed> [--yes]
```

### Objective Commands

```text
moonlight> objective create <campaign-id> <name> --success <predicate[,predicate...]> [--failure <predicate[,predicate...]>] [--risk <low|medium|high>] [--noise-budget <n>] [--description <text>] [--yes]
moonlight> objective link-prereq <objective-id> <prerequisite-id> [--yes]
moonlight> objective list [campaign-id]
moonlight> objective status
moonlight> objective status <objective-id>
moonlight> objective status <objective-id> <start|evaluate> [--yes]
```

### Output Mode

Use machine-friendly output for scripts:

```text
moonlight> output json
```

In JSON mode, command responses include stable CLI codes (for example `ML-CLI-0000` for success, `ML-CLI-0004` for policy denial).

## Quick Operator Flow

```text
moonlight> campaign create operation-alpha "Internal operation" --yes
moonlight> campaign list
moonlight> objective create <campaign-id> foothold --success finding_exists:shell_access --risk high --yes
moonlight> objective create <campaign-id> post-exploit --success finding_exists:post_access --risk medium
moonlight> objective link-prereq <post-objective-id> <foothold-objective-id>
moonlight> objective status <foothold-objective-id> start --yes
moonlight> objective status <foothold-objective-id> evaluate
moonlight> objective status
moonlight> campaign status <campaign-id> paused
moonlight> campaign status <campaign-id> completed --yes
```

## Transition Behavior

### Campaign State Machine

- `active -> paused`
- `active -> completed`
- `active -> failed`
- `paused -> active`
- `paused -> completed`
- `paused -> failed`

Notes:

- `completed` and `failed` are terminal.
- Terminal transitions require explicit intent (confirmation or `--yes`) via policy guardrails.

### Objective State Machine

- `pending -> eligible`
- `eligible -> in_progress`
- `in_progress -> achieved`
- `in_progress -> failed`

Rules:

- `eligible` requires all prerequisites to be achieved.
- `achieved` requires success criteria to be satisfied.
- `failed` requires failure criteria to be satisfied.
- No silent transitions are allowed.

## Predicate Examples

Supported predicate formats:

- `finding_exists:<finding-type>`
- `session_privilege:<user|elevated|root>`
- `artifact_tag_match:<tag>`
- `run_succeeded:<module-path>`
- `custom_metadata_match:<key>=<value>`

Examples:

```text
--success finding_exists:shell_access
--success session_privilege:root
--success artifact_tag_match:loot
--success run_succeeded:exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass
--success custom_metadata_match:owner=red
--failure custom_metadata_match:fail=true
```

Multiple predicates:

```text
--success finding_exists:shell_access,session_privilege:root
--failure custom_metadata_match:fail=true,finding_exists:tripwire
```

## Recovery and Replay Semantics

- Objective evaluations are deterministic and event-driven.
- Ingestion dispatch is idempotent by event key (duplicate source event keys do not re-apply state changes).
- Campaign/objective state can be reconstructed from audit history using replay projection.
- Replay consistency compares reconstructed state against persisted control-state snapshots.
- On restart, control state and orchestrator snapshots are reloaded and resumed with deterministic behavior.

Operational meaning:

- Re-running evaluation on the same snapshot yields the same result.
- Restarting does not require manual state repair for campaigns/objectives.

## Troubleshooting

### `ML-CLI-0001` Usage errors

Cause:

- Missing required arguments or invalid command form.

Fix:

- Run `help campaign` or `help objective`.
- Use the exact command signatures shown above.

### `ML-CLI-0003` Validation errors

Common causes:

- Invalid UUID format for campaign/objective IDs.
- Invalid predicate syntax.
- Invalid state transition (for example terminal-to-active).
- Prerequisite cycle or cross-campaign prerequisite linkage.

Fix:

- Verify IDs are canonical UUIDs.
- Validate predicate format.
- Confirm transition is legal in the state matrix.

### `ML-CLI-0004` Policy denied

Common causes:

- High-risk objective create/start without required capability.
- Terminal campaign status change without explicit intent.

Fix:

- Enable required capability:

```text
moonlight> policy enable exploit_execution
```

- Re-run with explicit confirmation or `--yes`.

### Replay/rollback compatibility failures

Symptoms:

- Release rollback apply fails with payload compatibility error.

Fix:

- Create a fresh rollback snapshot from current version:

```text
moonlight> release rollback snapshot pre-change
```

- Re-run `release check` and ensure rollback payload compatibility is reported as true.
