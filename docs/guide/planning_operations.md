# Planning Operations Guide

This guide covers operator usage of the planner (`plan`, `plan explain`, `plan simulate`).

## Quick Start

1. Select a module context and configure objectives as usual.
2. Generate a plan for an objective:

```text
moonlight> plan <objective-id>
```

3. Get weighted cost breakdown:

```text
moonlight> plan explain <objective-id>
```

4. Run advisory simulation (predicted artifacts + detection surface):

```text
moonlight> plan simulate <objective-id>
```

Planner behavior is advisory-only. It never executes modules.

## Output Modes

Human output (default):

```text
moonlight> output human
moonlight> plan <objective-id>
```

JSON output for automation:

```text
moonlight> output json
moonlight> plan <objective-id>
moonlight> plan explain <objective-id>
moonlight> plan simulate <objective-id>
```

`json` mode includes stable fields for:
- `status`, `step_count`, `graph_signature`
- `blocked_reasons`
- `required_capabilities`, `blocked_capabilities`
- `unreachable_reason`

## Blocked Step Reasons

Each blocked step reason includes a stable code:

- `ML-PLAN-BLOCK-0001`: capability disabled
- `ML-PLAN-BLOCK-0002`: policy denied
- `ML-PLAN-BLOCK-0003`: out of scope

These are annotations for planning output. Enforcement remains at execution time.

## Policy and Scope Awareness

Planning automatically annotates constraints based on current capability/policy/scope view.

Useful commands:

```text
moonlight> policy
moonlight> policy enable exploit_execution
moonlight> policy enable public_targets
moonlight> policy enable wide_target_scope
```

Then re-run:

```text
moonlight> plan <objective-id>
```

## Troubleshooting

If a plan is empty or unreachable:

1. Confirm objective exists:
```text
moonlight> objective list
moonlight> objective status <objective-id>
```

2. Inspect blocked reasons / capabilities:
```text
moonlight> plan <objective-id>
moonlight> policy
```

3. Compare plan modes:
```text
moonlight> plan <objective-id>
moonlight> plan explain <objective-id>
moonlight> plan simulate <objective-id>
```

4. Switch to JSON for script debugging:
```text
moonlight> output json
```
