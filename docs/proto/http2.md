# HTTP2 Protocol

## Location
`network/proto/src/http2/`

## Overview
This module provides a full HTTP2 protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `Http2Client`
- `Http2Request`
- `Http2Response`
- `Http2Server`
- `Http2TlsServer`

## Key Entry Points
### Clients
- `Http2Client`

### Servers
- `Http2Server`
- `Http2TlsServer`

### Free Functions
- `pub fn max_body(mut self, max_body: usize) -> Self {`
- `pub async fn send(&mut self, request: &Http2Request) -> CoreResult<Http2Response> {`

### Methods
- `Http2Client`
  - `pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub async fn connect_tls( addr: &NetAddr, server_name: &str, config: &TlsClientConfig, timeouts: Timeouts, ) -> CoreResult<Self>`
- `Http2Request`
  - `pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self`
  - `pub fn set_header(&mut self, name: &str, value: &str)`
- `Http2Response`
  - `pub fn new(status: u16) -> Self`
  - `pub fn set_header(&mut self, name: &str, value: &str)`
- `Http2Server`
  - `pub async fn bind(addr: SocketAddr) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(Http2Request) -> Http2Response + Send + Sync + 'static,`
- `Http2TlsServer`
  - `pub async fn bind(addr: SocketAddr, config: &TlsServerConfig) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(Http2Request) -> Http2Response + Send + Sync + 'static,`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/http2/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

