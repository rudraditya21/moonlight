# DRDA Protocol

## Location
`network/proto/src/drda/`

## Overview
This module provides a full DRDA protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncDrdaClient`
- `AsyncDrdaServer`
- `DrdaClient`
- `DrdaClientConfig`
- `DrdaMessage`
- `DrdaServer`
- `DrdaServerConfig`

### Enums
- `DrdaMessageType`

## Key Entry Points
### Clients
- `AsyncDrdaClient`
- `DrdaClient`
- `DrdaClientConfig`

### Servers
- `AsyncDrdaServer`
- `DrdaServer`
- `DrdaServerConfig`

### Methods
- `AsyncDrdaClient`
  - `pub async fn connect(addr: &net::NetAddr, config: DrdaClientConfig) -> CoreResult<Self>`
  - `pub async fn query(&mut self, sql: &str) -> CoreResult<String>`
- `AsyncDrdaServer`
  - `pub async fn bind(addr: SocketAddr, config: DrdaServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `DrdaClient`
  - `pub fn connect(addr: &net::NetAddr, config: DrdaClientConfig) -> CoreResult<Self>`
  - `pub fn query(&mut self, sql: &str) -> CoreResult<String>`
- `DrdaMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `DrdaServer`
  - `pub fn bind(addr: SocketAddr, config: DrdaServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/drda/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

