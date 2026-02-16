# SASL Protocol

## Location
`network/proto/src/sasl/`

## Overview
This module provides a full SASL protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncSaslClient`
- `AsyncSaslServer`
- `SaslClient`
- `SaslClientConfig`
- `SaslFrame`
- `SaslServer`
- `SaslServerConfig`

### Enums
- `SaslMessageType`

## Key Entry Points
### Clients
- `AsyncSaslClient`
- `SaslClient`
- `SaslClientConfig`

### Servers
- `AsyncSaslServer`
- `SaslServer`
- `SaslServerConfig`

### Methods
- `AsyncSaslClient`
  - `pub async fn connect(addr: &net::NetAddr, config: SaslClientConfig) -> CoreResult<Self>`
- `AsyncSaslServer`
  - `pub async fn bind(addr: SocketAddr, config: SaslServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `SaslClient`
  - `pub fn connect(addr: &net::NetAddr, config: SaslClientConfig) -> CoreResult<Self>`
- `SaslFrame`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `SaslServer`
  - `pub fn bind(addr: SocketAddr, config: SaslServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/sasl/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

