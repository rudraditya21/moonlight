# NATPMP Protocol

## Location
`network/proto/src/natpmp/`

## Overview
This module provides a full NATPMP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncNatPmpServer`
- `NatPmpClient`
- `NatPmpClientConfig`
- `NatPmpServer`
- `NatPmpServerConfig`

### Enums
- `NatPmpOpcode`
- `NatPmpRequest`
- `NatPmpResponse`
- `NatPmpResultCode`

### Constants
- `NATPMP_DEFAULT_PORT`

## Key Entry Points
### Clients
- `NatPmpClient`
- `NatPmpClientConfig`

### Servers
- `AsyncNatPmpServer`
- `NatPmpServer`
- `NatPmpServerConfig`

### Free Functions
- `pub fn map_tcp( &self, internal_port: u16, requested_external: u16, lifetime: u32, ) -> CoreResult<NatPmpResponse> {`

### Methods
- `AsyncNatPmpServer`
  - `pub async fn bind(addr: SocketAddr, config: NatPmpServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `NatPmpClient`
  - `pub fn new(gateway: SocketAddr, config: NatPmpClientConfig) -> CoreResult<Self>`
  - `pub fn public_address(&self) -> CoreResult<Ipv4Addr>`
  - `pub fn map_udp( &self, internal_port: u16, requested_external: u16, lifetime: u32, ) -> CoreResult<NatPmpResponse>`
- `NatPmpRequest`
  - `pub fn public_address() -> Self`
  - `pub fn map_udp(internal_port: u16, requested_external_port: u16, lifetime: u32) -> Self`
  - `pub fn map_tcp(internal_port: u16, requested_external_port: u16, lifetime: u32) -> Self`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `NatPmpResponse`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `NatPmpServer`
  - `pub fn bind(addr: SocketAddr, config: NatPmpServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/natpmp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

