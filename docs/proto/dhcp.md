# DHCP Protocol

## Location
`network/proto/src/dhcp/`

## Overview
This module provides a full DHCP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncDhcpClient`
- `AsyncDhcpServer`
- `DhcpClient`
- `DhcpClientConfig`
- `DhcpLease`
- `DhcpLeaseEntry`
- `DhcpPacket`
- `DhcpServer`
- `DhcpServerConfig`

### Enums
- `DhcpMessageType`
- `DhcpOption`

## Key Entry Points
### Clients
- `AsyncDhcpClient`
- `DhcpClient`
- `DhcpClientConfig`

### Servers
- `AsyncDhcpServer`
- `DhcpServer`
- `DhcpServerConfig`

### Free Functions
- `pub async fn obtain_lease(&mut self, server: SocketAddr) -> CoreResult<DhcpLease> {`

### Methods
- `AsyncDhcpClient`
  - `pub async fn bind(config: DhcpClientConfig, mac: [u8; 6]) -> CoreResult<Self>`
  - `pub async fn discover(&mut self, server: SocketAddr) -> CoreResult<DhcpPacket>`
  - `pub async fn request( &mut self, server: SocketAddr, offer: &DhcpPacket, ) -> CoreResult<DhcpLease>`
- `AsyncDhcpServer`
  - `pub async fn bind(addr: SocketAddr, config: DhcpServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `DhcpClient`
  - `pub fn bind(config: DhcpClientConfig, mac: [u8; 6]) -> CoreResult<Self>`
  - `pub fn discover(&mut self, server: SocketAddr) -> CoreResult<DhcpPacket>`
  - `pub fn request(&mut self, server: SocketAddr, offer: &DhcpPacket) -> CoreResult<DhcpLease>`
  - `pub fn obtain_lease(&mut self, server: SocketAddr) -> CoreResult<DhcpLease>`
- `DhcpPacket`
  - `pub fn new() -> Self`
  - `pub fn client_mac(&self) -> [u8; 6]`
  - `pub fn get_option(&self, code: u8) -> Option<&DhcpOption>`
  - `pub fn message_type(&self) -> Option<DhcpMessageType>`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `DhcpServer`
  - `pub fn bind(addr: SocketAddr, config: DhcpServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/dhcp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

