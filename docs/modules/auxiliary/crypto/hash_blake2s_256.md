# `auxiliary/crypto/hash_blake2s_256`

## Purpose
Compute or verify BLAKE2s-256 hashes

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected hash for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_blake2s_256
moonlight(auxiliary/crypto/hash_blake2s_256)> show options
moonlight(auxiliary/crypto/hash_blake2s_256)> set INPUT abc
moonlight(auxiliary/crypto/hash_blake2s_256)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_blake2s_256)> set HASH <expected-hex>
moonlight(auxiliary/crypto/hash_blake2s_256)> run
```

## Notes
- Output is lowercase hexadecimal.
- This module computes `BLAKE2S-256` and optionally verifies against `HASH`.
