# MS_TDS Protocol

## Location
`network/proto/src/ms_tds/`

## Overview
This module provides a full MS_TDS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncTdsClient`
- `AsyncTdsServer`
- `Login7`
- `PreloginInfo`
- `TdsClient`
- `TdsClientConfig`
- `TdsHeader`
- `TdsPacket`
- `TdsResponse`
- `TdsServer`
- `TdsServerConfig`

### Enums
- `TdsMessageType`
- `TdsToken`

### Constants
- `MSTDS_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncTdsClient`
- `TdsClient`
- `TdsClientConfig`

### Servers
- `AsyncTdsServer`
- `TdsServer`
- `TdsServerConfig`

### Methods
- `AsyncTdsClient`
  - `pub async fn connect(addr: &net::NetAddr, config: TdsClientConfig) -> CoreResult<Self>`
  - `pub async fn query(&mut self, sql: &str) -> CoreResult<TdsResponse>`
- `AsyncTdsServer`
  - `pub async fn bind(addr: SocketAddr, config: TdsServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `Login7`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `PreloginInfo`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `TdsClient`
  - `pub fn connect(addr: &net::NetAddr, config: TdsClientConfig) -> CoreResult<Self>`
  - `pub fn query(&mut self, sql: &str) -> CoreResult<TdsResponse>`
- `TdsHeader`
  - `pub fn encode(&self) -> [u8; 8]`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `TdsPacket`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `TdsResponse`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `TdsServer`
  - `pub fn bind(addr: SocketAddr, config: TdsServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`
- `TdsToken`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8], idx: &mut usize) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ms_tds/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

