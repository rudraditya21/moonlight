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

Campaign + planner flow:

```text
moonlight> campaign create operation-alpha --yes
moonlight> objective create <campaign-id> foothold --success run_succeeded:auxiliary/crypto/hash_sha2_256 --risk low --yes
moonlight> plan <objective-id>
moonlight> plan explain <objective-id>
moonlight> plan simulate <objective-id>
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
