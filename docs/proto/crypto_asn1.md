# CRYPTO_ASN1 Protocol

## Location
`network/proto/src/crypto_asn1/`

## Overview
This module provides a full CRYPTO_ASN1 protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Enums
- `Asn1Value`

## Key Entry Points
### Methods
- `Asn1Value`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(data: &[u8]) -> CoreResult<(Self, usize)>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/crypto_asn1/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

