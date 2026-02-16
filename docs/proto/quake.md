# QUAKE Protocol

## Location
`network/proto/src/quake/`

## Overview
This module provides a full QUAKE protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncQuakeClient`
- `AsyncQuakeServer`
- `QuakeClient`
- `QuakeClientConfig`
- `QuakeInfo`
- `QuakePlayer`
- `QuakeServer`
- `QuakeServerConfig`
- `QuakeStatus`

### Enums
- `QuakeQuery`

### Constants
- `QUAKE_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncQuakeClient`
- `QuakeClient`
- `QuakeClientConfig`

### Servers
- `AsyncQuakeServer`
- `QuakeServer`
- `QuakeServerConfig`

### Methods
- `AsyncQuakeClient`
  - `pub async fn new(server: SocketAddr) -> CoreResult<Self>`
  - `pub async fn get_info(&self) -> CoreResult<QuakeInfo>`
  - `pub async fn get_status(&self) -> CoreResult<QuakeStatus>`
- `AsyncQuakeServer`
  - `pub async fn bind(addr: SocketAddr, config: QuakeServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `QuakeClient`
  - `pub fn new(server: SocketAddr, config: QuakeClientConfig) -> CoreResult<Self>`
  - `pub fn get_info(&self) -> CoreResult<QuakeInfo>`
  - `pub fn get_status(&self) -> CoreResult<QuakeStatus>`
- `QuakeServer`
  - `pub fn bind(addr: SocketAddr, config: QuakeServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/quake/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

