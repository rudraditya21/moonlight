# `auxiliary/crypto/hash_md6_256`

## Purpose
Compute or verify MD6-256 hashes

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected hash for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_md6_256
moonlight(auxiliary/crypto/hash_md6_256)> show options
moonlight(auxiliary/crypto/hash_md6_256)> set INPUT abc
moonlight(auxiliary/crypto/hash_md6_256)> run
```

## Verify Example
```text
moonlight(auxiliary/crypto/hash_md6_256)> set HASH <expected-hex>
moonlight(auxiliary/crypto/hash_md6_256)> run
```

## Notes
- Output is lowercase hexadecimal.
- This module computes `MD6-256` and optionally verifies against `HASH`.
