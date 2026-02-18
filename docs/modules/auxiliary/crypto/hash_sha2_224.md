# `auxiliary/crypto/hash_sha2_224`

## Purpose
Compute or verify SHA2-224 hashes

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected hash for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_sha2_224
moonlight(auxiliary/crypto/hash_sha2_224)> show options
moonlight(auxiliary/crypto/hash_sha2_224)> set INPUT abc
moonlight(auxiliary/crypto/hash_sha2_224)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_sha2_224)> set HASH <expected-hex>
moonlight(auxiliary/crypto/hash_sha2_224)> run
```

## Notes
- Output is lowercase hexadecimal.
- This module computes `SHA2-224` and optionally verifies against `HASH`.
