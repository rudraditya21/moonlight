# `auxiliary/crypto/hash_crc64_jones`

## Purpose
Compute or verify CRC64-Jones checksums.

## Options
| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `INPUT` | `string` | yes | - | Input string to hash |
| `HASH` | `string` | no | - | Expected checksum for verify mode |
| `OUTPUT_HEX` | `bool` | no | `true` | Return hex output |

## Usage
```text
moonlight> use auxiliary/crypto/hash_crc64_jones
moonlight(auxiliary/crypto/hash_crc64_jones)> set INPUT 123456789
moonlight(auxiliary/crypto/hash_crc64_jones)> run
```
