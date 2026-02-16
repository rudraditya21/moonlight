# PJL Protocol

## Location
`network/proto/src/pjl/`

## Overview
This module provides a full PJL protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncPjlClient`
- `AsyncPjlServer`
- `PjlClient`
- `PjlClientConfig`
- `PjlCommand`
- `PjlResponse`
- `PjlServer`
- `PjlServerConfig`

## Key Entry Points
### Clients
- `AsyncPjlClient`
- `PjlClient`
- `PjlClientConfig`

### Servers
- `AsyncPjlServer`
- `PjlServer`
- `PjlServerConfig`

### Methods
- `AsyncPjlClient`
  - `pub async fn connect(addr: &net::NetAddr, config: PjlClientConfig) -> CoreResult<Self>`
  - `pub async fn send_command(&mut self, command: &str) -> CoreResult<PjlResponse>`
  - `pub async fn info_id(&mut self) -> CoreResult<String>`
- `AsyncPjlServer`
  - `pub async fn bind(addr: SocketAddr, config: PjlServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `PjlClient`
  - `pub fn connect(addr: &net::NetAddr, config: PjlClientConfig) -> CoreResult<Self>`
  - `pub fn send_command(&mut self, command: &str) -> CoreResult<PjlResponse>`
  - `pub fn info_id(&mut self) -> CoreResult<String>`
- `PjlCommand`
  - `pub fn parse(line: &str) -> Option<Self>`
- `PjlResponse`
  - `pub fn ok() -> Self`
  - `pub fn error(message: &str) -> Self`
  - `pub fn to_bytes(&self) -> Vec<u8>`
- `PjlServer`
  - `pub fn bind(addr: SocketAddr, config: PjlServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/pjl/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

