# Module Authoring Guide

This guide explains how to build Moonlight modules and integrate them into the registry and runtime.

## Module Types
Moonlight supports two module integration paths:

1. Built‑in Rust modules compiled into the `modules` crate.
2. Dynamic modules loaded at runtime via the dynlib API.

Use built‑in modules for core utilities or when you want tight integration with the Rust codebase. Use dynlib modules for independently versioned modules that live alongside `registry/` manifests.

## Registry Layout
Each module has a manifest in the registry tree:

```
registry/<category>/<path>/module.json
```

Example:

```
registry/nops/riscv32le/simple/module.json
```

The manifest is used for indexing, search, and loading.

## Manifest Format
`module.json` is parsed by `ModuleManifest::parse_str` and supports:

- `manifest_version` (integer, required) — current value: `1`
- `module_api_version` (integer, required) — current value: `1`
- `runtime` (string, required) — `builtin` or `dynlib`
- `name` (string, required) — full module path, e.g. `nops/riscv32le/simple`
- `description` (string, required)
- `category` (string, required) — `auxiliary`, `payload`, `exploit`, `post`, `evasion`, `nop`, etc.
- `rank` (string, required) — `manual`, `low`, `average`, `normal`, `good`, `great`, `excellent`
- `author` (string, required)
- `platforms` (array of strings, required)
- `tags` (array of strings, required)
- `entrypoint` (string, required) — filename or dynlib name to load
- `references` (array of objects, optional) — `{ "kind": "cve", "value": "2024-0001" }`

Strict behavior:
- Unknown top-level fields are rejected.
- Category must match the module path prefix.
- `dynlib` modules must be compatible with the supported module API policy.

## Built‑in Modules (Rust)
Built‑in modules implement the `Module` trait and are registered in `modules/modules/src/builtins.rs`.

Key traits and types:

- `Module` — runtime interface (`metadata`, `options`, `run`)
- `ModuleFactory` — creates module instances
- `ModuleBase` — helper with metadata + options
- `ModuleOptions` / `ModuleOption` — typed options + validation

Steps:

1. Implement a module in `modules/modules/src/<area>/...`.
2. Provide metadata using `ModuleMetadata` (name, description, category, tags, platforms).
3. Define options with `ModuleOptions` and validate in `run`.
4. Add a `ModuleFactory` and register it in `register_builtin_modules`.
5. Add unit tests under the module file and end‑to‑end tests if applicable.

Example patterns are in:
- `modules/modules/src/crypto/hash_md5.rs`
- `modules/modules/src/nops/*`

## Dynamic Modules (dynlib)
Dynamic modules are loaded from the registry when a manifest has an `entrypoint` and no built‑in module matches the name.

The dynlib interface uses `moonlight_module_v1` which returns a `ModuleApiV1` vtable. The test module in `modules/dynlib_test` demonstrates a minimal implementation.

Required exports:

- `moonlight_module_v1() -> *const ModuleApiV1`
- `get_metadata_json() -> *const c_char`
- `get_options_json() -> *const c_char`
- `create() -> *mut c_void`
- `destroy(handle)`
- `set_option(handle, key, value)`
- `run(handle, ctx_json)`
- `free_string(ptr)`

The metadata JSON must match the manifest schema (same fields).

## Options and Validation
Options are strongly typed:

- `string`, `bool`, `integer`, `address`, `port`

The runtime validates required options before `run` executes.

## Tests
For every module:

- Unit tests for core logic.
- Integration tests for end‑to‑end execution (at least one `run` path).
- Negative tests for invalid input or missing requirements.

See `modules/modules/tests/nops_end_to_end.rs` for patterns.

## REPL Usage
Typical flow:

```
moonlight> use <module>
moonlight> show options
moonlight> set OPTION value
moonlight> run
```

Global operator settings:

```
moonlight> setg output_mode json
moonlight> setg session_max_pending_bytes 65536
moonlight> setg session_drain_bytes 4096
moonlight> getg output_mode
```

Release-discipline commands:

```
moonlight> release check
moonlight> release matrix
moonlight> release migrate plan <from-version> <to-version>
moonlight> release rollback snapshot <label>
```

The prompt reflects the active module when one is selected:

```
moonlight(nops/riscv32le/simple)>
```

## Performance
Keep modules efficient and avoid expensive initialization in `run`. If a module performs heavy work, consider lazy initialization and reuse internal state.
