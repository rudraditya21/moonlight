# `auxiliary/crypto/hash_md4`

## Purpose
Compute or verify MD4 hashes

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected hash for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_md4
moonlight(auxiliary/crypto/hash_md4)> show options
moonlight(auxiliary/crypto/hash_md4)> set INPUT abc
moonlight(auxiliary/crypto/hash_md4)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_md4)> set HASH <expected-hex>
moonlight(auxiliary/crypto/hash_md4)> run
```

## Notes
- Output is lowercase hexadecimal.
- This module computes `MD4` and optionally verifies against `HASH`.
