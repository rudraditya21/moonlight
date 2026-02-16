# RFB Protocol

## Location
`network/proto/src/rfb/`

## Overview
This module provides a full RFB protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncRfbClient`
- `AsyncRfbServer`
- `RfbClient`
- `RfbClientConfig`
- `RfbClientState`
- `RfbPixelFormat`
- `RfbRectangle`
- `RfbServer`
- `RfbServerConfig`
- `RfbServerInit`

### Enums
- `RfbClientMessage`
- `RfbSecurityType`
- `RfbServerMessage`

### Constants
- `RFB_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncRfbClient`
- `RfbClient`
- `RfbClientConfig`
- `RfbClientState`

### Servers
- `AsyncRfbServer`
- `RfbServer`
- `RfbServerConfig`
- `RfbServerInit`

### Free Functions
- `pub fn read_message(&mut self) -> CoreResult<RfbServerMessage> {`
- `pub async fn read_message(&mut self) -> CoreResult<RfbServerMessage> {`

### Methods
- `AsyncRfbClient`
  - `pub async fn connect(addr: &net::NetAddr, config: RfbClientConfig) -> CoreResult<Self>`
  - `pub async fn framebuffer_update_request( &mut self, incremental: bool, x: u16, y: u16, width: u16, height: u16, ) -> CoreResult<()>`
- `AsyncRfbServer`
  - `pub async fn bind(addr: SocketAddr, config: RfbServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `RfbClient`
  - `pub fn connect(addr: &net::NetAddr, config: RfbClientConfig) -> CoreResult<Self>`
  - `pub fn framebuffer_update_request( &mut self, incremental: bool, x: u16, y: u16, width: u16, height: u16, ) -> CoreResult<()>`
- `RfbPixelFormat`
  - `pub fn encode(&self) -> [u8; 16]`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `RfbServer`
  - `pub fn bind(addr: SocketAddr, config: RfbServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/rfb/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

