# MDNS Protocol

## Location
`network/proto/src/mdns/`

## Overview
This module provides a full MDNS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `MdnsService`

### Type Aliases
- `MdnsAsyncClient`
- `MdnsAsyncServer`
- `MdnsSyncClient`
- `MdnsSyncServer`

### Constants
- `MDNS_IPV4`
- `MDNS_IPV6`
- `MDNS_PORT`

## Key Entry Points
### Servers
- `MdnsService`

### Free Functions
- `pub fn build_query(service_type: &str) -> DnsMessage {`
- `pub fn build_response(service: &MdnsService) -> DnsMessage {`
- `pub fn decode_message(bytes: &[u8]) -> CoreResult<DnsMessage> {`

### Methods
- `MdnsService`
  - `pub fn instance_name(&self) -> String`
  - `pub fn service_name(&self) -> String`
  - `pub fn host_name(&self) -> String`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/mdns/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

