# NUUO Protocol

## Location
`network/proto/src/nuuo/`

## Overview
This module provides a full NUUO protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncNuuoClient`
- `AsyncNuuoServer`
- `NuuoCamera`
- `NuuoClient`
- `NuuoClientConfig`
- `NuuoFrame`
- `NuuoServer`
- `NuuoServerConfig`

### Enums
- `NuuoMessageType`

## Key Entry Points
### Clients
- `AsyncNuuoClient`
- `NuuoClient`
- `NuuoClientConfig`

### Servers
- `AsyncNuuoServer`
- `NuuoServer`
- `NuuoServerConfig`

### Methods
- `AsyncNuuoClient`
  - `pub async fn connect(addr: &net::NetAddr, config: NuuoClientConfig) -> CoreResult<Self>`
  - `pub async fn ping(&mut self) -> CoreResult<()>`
  - `pub async fn get_info(&mut self) -> CoreResult<HashMap<String, String>>`
  - `pub async fn list_cameras(&mut self) -> CoreResult<Vec<NuuoCamera>>`
- `AsyncNuuoServer`
  - `pub async fn bind(addr: SocketAddr, config: NuuoServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `NuuoClient`
  - `pub fn connect(addr: &net::NetAddr, config: NuuoClientConfig) -> CoreResult<Self>`
  - `pub fn ping(&mut self) -> CoreResult<()>`
  - `pub fn get_info(&mut self) -> CoreResult<HashMap<String, String>>`
  - `pub fn list_cameras(&mut self) -> CoreResult<Vec<NuuoCamera>>`
- `NuuoFrame`
  - `pub fn new(msg_type: NuuoMessageType, payload: Vec<u8>) -> Self`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `NuuoServer`
  - `pub fn bind(addr: SocketAddr, config: NuuoServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/nuuo/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

