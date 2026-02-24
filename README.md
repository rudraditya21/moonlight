# Moonlight

Moonlight is a Rust-based modular security framework with a deterministic control plane for running modules, managing sessions, tracking campaigns/objectives, and generating advisory plans.

## Legal and Responsible Use Notice

Moonlight is provided for authorized security research, testing, and defensive purposes only. You are solely responsible for ensuring that your use complies with all applicable laws, regulations, contracts, and organizational policies. Do not use Moonlight against any system, network, or service without explicit prior permission from the owner.

The authors, maintainers, and contributors of this project are not responsible for any misuse, damage, service disruption, data loss, legal consequences, or other harm resulting from use of this software. By using Moonlight, you accept full responsibility and liability for your actions.

## What Is Implemented

- Deterministic execution model: `Run -> Task -> Session -> Artifact -> Finding -> Event`
- Module-agnostic catalog and manifest validation pipeline
- Session control plane with attach/detach/background/close flows
- Typed immutable event stream and audit lineage
- Persistence, replay, and restart recovery behavior
- Policy/capability guardrails (safe-by-default)
- Campaign and objective lifecycle model with strict state transitions
- Advisory A* graph planner (`plan`, `plan explain`, `plan simulate`) with no auto-execution side effects
- Human and JSON output contracts for CLI automation

## Workspace Layout

- `core/core`: orchestration, domain model, policy, events, planning, persistence logic
- `core/repl`: operator command surface and interactive workflow
- `modules/modules`: builtin modules, registry integration, module runtime contracts
- `network/proto`: protocol implementations used by modules/sessions
- `docs/guide`: usage-focused operator guides

## Prerequisites

- Stable Rust toolchain
- `make` (optional but recommended for common workflows)

## Quick Start

```bash
git clone https://github.com/rudraditya21/moonlight
cd moonlight
make build
make run
```

## Minimal REPL Flow

```text
moonlight> setg output_mode json
moonlight> search auxiliary/crypto/hash_
moonlight> use auxiliary/crypto/hash_sha2_256
moonlight(auxiliary/crypto/hash_sha2_256)> set INPUT moonlight
moonlight(auxiliary/crypto/hash_sha2_256)> run
```

## Advanced Campaign + Planner Flow

Use this end-to-end sequence to verify plan generation, execution progress, and objective completion.

```text
moonlight> output json

# 1) Create campaign and capture campaign_id from JSON output
moonlight> campaign create operation-alpha "Internal validation operation" --yes
moonlight> campaign list

# 2) Create chained objectives and capture objective IDs from JSON output
moonlight> objective create <campaign-id> foothold --success run_succeeded:auxiliary/crypto/hash_sha2_256 --risk low --yes
moonlight> objective create <campaign-id> post-check --success run_succeeded:auxiliary/crypto/hash_sha3_256 --risk low --yes
moonlight> objective link-prereq <post-check-objective-id> <foothold-objective-id> --yes
moonlight> objective list <campaign-id>

# 3) Start the first objective and inspect advisory plan
moonlight> objective status <foothold-objective-id> start --yes
moonlight> plan <foothold-objective-id>
moonlight> plan explain <foothold-objective-id>

# 4) Execute the planned module
moonlight> use auxiliary/crypto/hash_sha2_256
moonlight(auxiliary/crypto/hash_sha2_256)> set INPUT moonlight
moonlight(auxiliary/crypto/hash_sha2_256)> run --yes
moonlight(auxiliary/crypto/hash_sha2_256)> back

# 5) Evaluate objective and confirm completion display state
moonlight> objective status <foothold-objective-id> evaluate --yes
moonlight> objective status <foothold-objective-id>

# 6) Re-run plan to confirm completed step status is shown as done
moonlight> plan <foothold-objective-id>

# 7) Continue with dependent objective
moonlight> objective status <post-check-objective-id> start --yes
moonlight> plan simulate <post-check-objective-id>
```

## Common Commands

- Build: `make build`
- Run: `make run`
- Test: `make test`
- Format: `make fmt`
- Lint: `make clippy`
- Catalog perf checks: `make perf`

## Documentation

- Operator guide (modules): `docs/guide/modules.md`
- Operator guide (campaign/objective): `docs/guide/campaign_objective_operations.md`
- Operator guide (planning): `docs/guide/planning_operations.md`
- Operator guide (release): `docs/guide/release_operations.md`
- Protocol reference: `docs/proto/`
- Module usage docs: `docs/modules/`

## License

GPLv3. See `LICENSE`.
