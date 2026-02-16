# HTTP3 Protocol

## Location
`network/proto/src/http3/`

## Overview
This module provides a full HTTP3 protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `Http3Client`
- `Http3Request`
- `Http3Response`
- `Http3Server`

## Key Entry Points
### Clients
- `Http3Client`

### Servers
- `Http3Server`

### Methods
- `Http3Client`
  - `pub async fn connect(addr: &NetAddr, server_name: &str) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub async fn request(&mut self, request: &Http3Request) -> CoreResult<Http3Response>`
- `Http3Request`
  - `pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self`
  - `pub fn set_header(&mut self, name: &str, value: &str)`
- `Http3Response`
  - `pub fn new(status: u16) -> Self`
  - `pub fn set_header(&mut self, name: &str, value: &str)`
- `Http3Server`
  - `pub async fn bind(addr: SocketAddr, cert_path: &str, key_path: &str) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn local_addr(&self) -> SocketAddr`
  - `pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(Http3Request) -> Http3Response + Send + Sync + 'static,`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/http3/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

