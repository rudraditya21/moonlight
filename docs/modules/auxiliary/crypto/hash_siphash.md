# `auxiliary/crypto/hash_siphash`

## Purpose
Compute or verify SipHash-2-4 digests.

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `KEY` | `string` | yes | - | 128-bit key as 32 hex chars (`0x` prefix allowed) |
| `HASH` | `string` | no | - | Expected digest for verify mode |

## Usage
```text
moonlight> use auxiliary/crypto/hash_siphash
moonlight(auxiliary/crypto/hash_siphash)> set INPUT hello
moonlight(auxiliary/crypto/hash_siphash)> set KEY 000102030405060708090a0b0c0d0e0f
moonlight(auxiliary/crypto/hash_siphash)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_siphash)> set HASH 726fdb47dd0e0e31
moonlight(auxiliary/crypto/hash_siphash)> run
```
