# Git Hooks

This repository includes shared hooks under `.githooks/`.

To enable them locally, run:

```
git config core.hooksPath .githooks
```

Current hooks:
- `pre-commit` runs `make fmt` to enforce formatting before commits.
