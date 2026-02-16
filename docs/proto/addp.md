# ADDP Protocol

## Location
`network/proto/src/addp/`

## Overview
This module provides a full ADDP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AddpClient`
- `AddpClientConfig`
- `AddpMessage`
- `AddpServer`
- `AddpServerConfig`
- `AsyncAddpClient`
- `AsyncAddpServer`

### Enums
- `AddpMessageType`

## Key Entry Points
### Clients
- `AddpClient`
- `AddpClientConfig`
- `AsyncAddpClient`

### Servers
- `AddpServer`
- `AddpServerConfig`
- `AsyncAddpServer`

### Methods
- `AddpClient`
  - `pub fn connect(config: AddpClientConfig) -> CoreResult<Self>`
  - `pub fn discover(&self, addr: SocketAddr, query: &str) -> CoreResult<AddpMessage>`
- `AddpMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `AddpServer`
  - `pub fn bind(addr: SocketAddr, config: AddpServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`
- `AsyncAddpClient`
  - `pub async fn connect() -> CoreResult<Self>`
  - `pub async fn discover(&self, addr: SocketAddr, query: &str) -> CoreResult<AddpMessage>`
- `AsyncAddpServer`
  - `pub async fn bind(addr: SocketAddr, config: AddpServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/addp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

