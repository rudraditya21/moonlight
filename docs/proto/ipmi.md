# IPMI Protocol

## Location
`network/proto/src/ipmi/`

## Overview
This module provides a full IPMI protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncIpmiClient`
- `AsyncIpmiServer`
- `DefaultIpmiHandler`
- `IpmiClient`
- `IpmiClientConfig`
- `IpmiRequest`
- `IpmiResponse`
- `IpmiServer`
- `IpmiServerConfig`

### Traits
- `IpmiHandler`

### Constants
- `IPMI_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncIpmiClient`
- `IpmiClient`
- `IpmiClientConfig`

### Servers
- `AsyncIpmiServer`
- `IpmiServer`
- `IpmiServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub fn get_device_id(&self, addr: SocketAddr) -> CoreResult<IpmiResponse> {`
- `pub fn get_channel_auth_capabilities( &self, addr: SocketAddr, channel: u8, ) -> CoreResult<IpmiResponse> {`

### Methods
- `AsyncIpmiClient`
  - `pub async fn connect() -> CoreResult<Self>`
  - `pub async fn request( &self, addr: SocketAddr, netfn: u8, cmd: u8, data: &[u8], ) -> CoreResult<IpmiResponse>`
- `AsyncIpmiServer`
  - `pub async fn bind(addr: SocketAddr, handler: Arc<dyn IpmiHandler>) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `DefaultIpmiHandler`
  - `pub fn new(config: IpmiServerConfig) -> Self`
- `IpmiClient`
  - `pub fn connect(config: IpmiClientConfig) -> CoreResult<Self>`
  - `pub fn request( &self, addr: SocketAddr, netfn: u8, cmd: u8, data: &[u8], ) -> CoreResult<IpmiResponse>`
- `IpmiServer`
  - `pub fn bind( addr: SocketAddr, handler: Arc<dyn IpmiHandler>, config: IpmiServerConfig, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ipmi/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

