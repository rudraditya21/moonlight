# `auxiliary/crypto/hash_ripemd160`

## Purpose
Compute or verify RIPEMD-160 hashes

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected hash for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_ripemd160
moonlight(auxiliary/crypto/hash_ripemd160)> show options
moonlight(auxiliary/crypto/hash_ripemd160)> set INPUT abc
moonlight(auxiliary/crypto/hash_ripemd160)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_ripemd160)> set HASH <expected-hex>
moonlight(auxiliary/crypto/hash_ripemd160)> run
```

## Notes
- Output is lowercase hexadecimal.
- This module computes `RIPEMD160` and optionally verifies against `HASH`.
