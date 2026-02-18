# `auxiliary/crypto/hash_crc32c`

## Purpose
Compute or verify CRC32C checksums.

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected checksum for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_crc32c
moonlight(auxiliary/crypto/hash_crc32c)> set INPUT 123456789
moonlight(auxiliary/crypto/hash_crc32c)> run
```
