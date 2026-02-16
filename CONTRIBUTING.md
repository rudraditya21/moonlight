# Contributing

Thanks for your interest in contributing to Moonlight.

## Principles
- Prefer correctness over cleverness.
- Keep dependencies minimal and justified.
- Every change should include tests where applicable.
- Performance and memory behavior matter.

## Workflow
1. Create a focused branch.
2. Keep commits small and scoped.
3. Format and test before submitting.

### Formatting
```
make fmt
```

### Tests
```
make test
```

### Linting
```
make clippy
```

## Modules
- Place manifests under `registry/<category>/<path>/module.json`.
- Use real protocol stacks; avoid protocol stubs.
- Add unit tests and at least one end‑to‑end test per module.

## Protocols
- Follow the protocol SDK layers (transport, framing, codec, state, client/server APIs).
- Add negative and fuzz tests where appropriate.

## License
By contributing, you agree that your contributions are licensed under GPLv3.
