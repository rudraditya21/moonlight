# GSS Protocol

## Location
`network/proto/src/gss/`

## Overview
This module provides a full GSS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncGssClient`
- `AsyncGssServer`
- `GssClient`
- `GssClientConfig`
- `GssMessage`
- `GssServer`
- `GssServerConfig`

### Enums
- `GssMessageType`

## Key Entry Points
### Clients
- `AsyncGssClient`
- `GssClient`
- `GssClientConfig`

### Servers
- `AsyncGssServer`
- `GssServer`
- `GssServerConfig`

### Methods
- `AsyncGssClient`
  - `pub async fn connect(addr: &NetAddr, config: GssClientConfig) -> CoreResult<Self>`
  - `pub async fn wrap(&mut self, data: &[u8]) -> CoreResult<Vec<u8>>`
- `AsyncGssServer`
  - `pub async fn bind(addr: SocketAddr, config: GssServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `GssClient`
  - `pub fn connect(addr: &NetAddr, config: GssClientConfig) -> CoreResult<Self>`
  - `pub fn wrap(&mut self, data: &[u8]) -> CoreResult<Vec<u8>>`
- `GssMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `GssServer`
  - `pub fn bind(addr: SocketAddr, config: GssServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/gss/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

