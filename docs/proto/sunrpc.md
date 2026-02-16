# SUNRPC Protocol

## Location
`network/proto/src/sunrpc/`

## Overview
This module provides a full SUNRPC protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncRpcClient`
- `AsyncRpcServer`
- `AsyncRpcUdpServer`
- `PortmapRegistry`
- `PortmapService`
- `RpcAuth`
- `RpcCall`
- `RpcClient`
- `RpcClientConfig`
- `RpcReply`
- `RpcServer`
- `RpcServerConfig`
- `RpcUdpServer`

### Enums
- `RpcServiceResult`

### Traits
- `RpcService`

## Key Entry Points
### Clients
- `AsyncRpcClient`
- `RpcClient`
- `RpcClientConfig`

### Servers
- `AsyncRpcServer`
- `AsyncRpcUdpServer`
- `PortmapService`
- `RpcServer`
- `RpcServerConfig`
- `RpcUdpServer`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncRpcClient`
  - `pub async fn connect(addr: &NetAddr, config: RpcClientConfig) -> CoreResult<Self>`
  - `pub async fn call( &mut self, program: u32, version: u32, procedure: u32, payload: &[u8], ) -> CoreResult<Vec<u8>>`
- `AsyncRpcServer`
  - `pub async fn bind( addr: SocketAddr, config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>, ) -> CoreResult<Self>`
- `AsyncRpcUdpServer`
  - `pub async fn bind( addr: SocketAddr, _config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>, ) -> CoreResult<Self>`
- `PortmapRegistry`
  - `pub fn set(&mut self, program: u32, version: u32, protocol: u32, port: u32)`
  - `pub fn get(&self, program: u32, version: u32, protocol: u32) -> u32`
- `PortmapService`
  - `pub fn new(registry: Arc<std::sync::Mutex<PortmapRegistry>>) -> Self`
- `RpcAuth`
  - `pub fn null() -> Self`
- `RpcClient`
  - `pub fn connect(addr: &NetAddr, config: RpcClientConfig) -> CoreResult<Self>`
  - `pub fn call( &mut self, program: u32, version: u32, procedure: u32, payload: &[u8], ) -> CoreResult<Vec<u8>>`
- `RpcServer`
  - `pub fn bind( addr: SocketAddr, config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>, ) -> CoreResult<Self>`
- `RpcUdpServer`
  - `pub fn bind( addr: SocketAddr, config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/sunrpc/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

