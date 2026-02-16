# DCERPC Protocol

## Location
`network/proto/src/dcerpc/`

## Overview
This module provides a full DCERPC protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncDceRpcClient`
- `AsyncDceRpcServer`
- `BindContext`
- `DceRpcClient`
- `DceRpcClientConfig`
- `DceRpcHeader`
- `DceRpcPdu`
- `DceRpcServer`
- `DceRpcServerConfig`
- `EchoDceRpcHandler`
- `Uuid`

### Enums
- `PduType`

### Traits
- `DceRpcHandler`

## Key Entry Points
### Clients
- `AsyncDceRpcClient`
- `DceRpcClient`
- `DceRpcClientConfig`

### Servers
- `AsyncDceRpcServer`
- `DceRpcServer`
- `DceRpcServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncDceRpcClient`
  - `pub async fn connect(addr: &net::NetAddr, config: DceRpcClientConfig) -> CoreResult<Self>`
  - `pub async fn request(&mut self, opnum: u16, stub: &[u8]) -> CoreResult<Vec<u8>>`
- `AsyncDceRpcServer`
  - `pub async fn bind( addr: SocketAddr, config: DceRpcServerConfig, handler: Arc<dyn DceRpcHandler>, ) -> CoreResult<Self>`
- `DceRpcClient`
  - `pub fn connect(addr: &net::NetAddr, config: DceRpcClientConfig) -> CoreResult<Self>`
  - `pub fn request(&mut self, opnum: u16, stub: &[u8]) -> CoreResult<Vec<u8>>`
- `DceRpcHeader`
  - `pub fn encode(&self) -> [u8; 16]`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `DceRpcPdu`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `DceRpcServer`
  - `pub fn bind( addr: SocketAddr, config: DceRpcServerConfig, handler: Arc<dyn DceRpcHandler>, ) -> CoreResult<Self>`
- `Uuid`
  - `pub fn encode_le(&self) -> [u8; 16]`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/dcerpc/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

