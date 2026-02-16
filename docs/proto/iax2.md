# IAX2 Protocol

## Location
`network/proto/src/iax2/`

## Overview
This module provides a full IAX2 protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncIaxClient`
- `AsyncIaxServer`
- `IaxClient`
- `IaxClientConfig`
- `IaxFrame`
- `IaxServer`
- `IaxServerConfig`

### Enums
- `AuthMethod`
- `IaxFrameType`
- `IaxIe`
- `IaxSubclass`

### Constants
- `IAX2_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncIaxClient`
- `IaxClient`
- `IaxClientConfig`

### Servers
- `AsyncIaxServer`
- `IaxServer`
- `IaxServerConfig`

### Methods
- `AsyncIaxClient`
  - `pub async fn connect(config: IaxClientConfig) -> CoreResult<Self>`
  - `pub async fn start_call(&mut self, addr: SocketAddr, called_number: &str) -> CoreResult<()>`
  - `pub async fn ping(&self, addr: SocketAddr) -> CoreResult<()>`
- `AsyncIaxServer`
  - `pub async fn bind(addr: SocketAddr, config: IaxServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `IaxClient`
  - `pub fn connect(config: IaxClientConfig) -> CoreResult<Self>`
  - `pub fn start_call(&mut self, addr: SocketAddr, called_number: &str) -> CoreResult<()>`
  - `pub fn ping(&self, addr: SocketAddr) -> CoreResult<()>`
- `IaxFrame`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `IaxServer`
  - `pub fn bind(addr: SocketAddr, config: IaxServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/iax2/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

