# Module Documentation

This directory contains operator-focused documentation for Moonlight modules.

## Policy and Global Settings
Moonlight runs with safety guardrails enabled by default.

- Exploit modules require `policy enable exploit_execution` before `run`.
- Payload modules require `policy enable payload_execution` before `run`.
- Evasion modules require `policy enable evasion_execution` before `run`.
- Public targets can require `policy enable public_targets`.
- Wide-scope targets can require `policy enable wide_target_scope`.
- Use `run --yes` to skip interactive confirmation prompts for a single run.
- Use `policy` to inspect currently enabled capabilities.

Useful operator settings:

```text
setg output_mode human
setg output_mode json
setg session_max_pending_bytes 65536
setg session_drain_bytes 4096
getg output_mode
```

Console help utilities:

```text
help
help <command>
clear
```

## Exploit Modules
- `exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass`  
  See `docs/modules/exploit/linux/telnet/gnu_inetutils_telnetd_auth_bypass.md`.

## Auxiliary Modules
- `auxiliary/crypto/hash_blake2b_256`  
  See `docs/modules/auxiliary/crypto/hash_blake2b_256.md`.
- `auxiliary/crypto/hash_blake2b_512`  
  See `docs/modules/auxiliary/crypto/hash_blake2b_512.md`.
- `auxiliary/crypto/hash_blake2s_256`  
  See `docs/modules/auxiliary/crypto/hash_blake2s_256.md`.
- `auxiliary/crypto/hash_crc32`  
  See `docs/modules/auxiliary/crypto/hash_crc32.md`.
- `auxiliary/crypto/hash_crc32c`  
  See `docs/modules/auxiliary/crypto/hash_crc32c.md`.
- `auxiliary/crypto/hash_crc64_jones`  
  See `docs/modules/auxiliary/crypto/hash_crc64_jones.md`.
- `auxiliary/crypto/hash_half_md5`  
  See `docs/modules/auxiliary/crypto/hash_half_md5.md`.
- `auxiliary/crypto/hash_keccak_224`  
  See `docs/modules/auxiliary/crypto/hash_keccak_224.md`.
- `auxiliary/crypto/hash_keccak_256`  
  See `docs/modules/auxiliary/crypto/hash_keccak_256.md`.
- `auxiliary/crypto/hash_keccak_384`  
  See `docs/modules/auxiliary/crypto/hash_keccak_384.md`.
- `auxiliary/crypto/hash_keccak_512`  
  See `docs/modules/auxiliary/crypto/hash_keccak_512.md`.
- `auxiliary/crypto/hash_md4`  
  See `docs/modules/auxiliary/crypto/hash_md4.md`.
- `auxiliary/crypto/hash_md5`  
  See `docs/modules/auxiliary/crypto/hash_md5.md`.
- `auxiliary/crypto/hash_md6_256`  
  See `docs/modules/auxiliary/crypto/hash_md6_256.md`.
- `auxiliary/crypto/hash_recipe`  
  See `docs/modules/auxiliary/crypto/hash_recipe.md`.
- `auxiliary/crypto/hash_ripemd160`  
  See `docs/modules/auxiliary/crypto/hash_ripemd160.md`.
- `auxiliary/crypto/hash_ripemd320`  
  See `docs/modules/auxiliary/crypto/hash_ripemd320.md`.
- `auxiliary/crypto/hash_sha1`  
  See `docs/modules/auxiliary/crypto/hash_sha1.md`.
- `auxiliary/crypto/hash_sha2_224`  
  See `docs/modules/auxiliary/crypto/hash_sha2_224.md`.
- `auxiliary/crypto/hash_sha2_256`  
  See `docs/modules/auxiliary/crypto/hash_sha2_256.md`.
- `auxiliary/crypto/hash_sha2_384`  
  See `docs/modules/auxiliary/crypto/hash_sha2_384.md`.
- `auxiliary/crypto/hash_sha2_512`  
  See `docs/modules/auxiliary/crypto/hash_sha2_512.md`.
- `auxiliary/crypto/hash_sha3_224`  
  See `docs/modules/auxiliary/crypto/hash_sha3_224.md`.
- `auxiliary/crypto/hash_sha3_256`  
  See `docs/modules/auxiliary/crypto/hash_sha3_256.md`.
- `auxiliary/crypto/hash_sha3_384`  
  See `docs/modules/auxiliary/crypto/hash_sha3_384.md`.
- `auxiliary/crypto/hash_sha3_512`  
  See `docs/modules/auxiliary/crypto/hash_sha3_512.md`.
- `auxiliary/crypto/hash_siphash`  
  See `docs/modules/auxiliary/crypto/hash_siphash.md`.
