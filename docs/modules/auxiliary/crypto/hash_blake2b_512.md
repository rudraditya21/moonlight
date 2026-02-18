# `auxiliary/crypto/hash_blake2b_512`

## Purpose
Compute or verify BLAKE2b-512 hashes

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected hash for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_blake2b_512
moonlight(auxiliary/crypto/hash_blake2b_512)> show options
moonlight(auxiliary/crypto/hash_blake2b_512)> set INPUT abc
moonlight(auxiliary/crypto/hash_blake2b_512)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_blake2b_512)> set HASH <expected-hex>
moonlight(auxiliary/crypto/hash_blake2b_512)> run
```

## Notes
- Output is lowercase hexadecimal.
- This module computes `BLAKE2B-512` and optionally verifies against `HASH`.
