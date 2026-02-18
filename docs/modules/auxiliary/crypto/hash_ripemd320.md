# `auxiliary/crypto/hash_ripemd320`

## Purpose
Compute or verify RIPEMD-320 hashes

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected hash for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_ripemd320
moonlight(auxiliary/crypto/hash_ripemd320)> show options
moonlight(auxiliary/crypto/hash_ripemd320)> set INPUT abc
moonlight(auxiliary/crypto/hash_ripemd320)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_ripemd320)> set HASH <expected-hex>
moonlight(auxiliary/crypto/hash_ripemd320)> run
```

## Notes
- Output is lowercase hexadecimal.
- This module computes `RIPEMD320` and optionally verifies against `HASH`.
