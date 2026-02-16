# APACHE_J_P Protocol

## Location
`network/proto/src/apache_j_p/`

## Overview
This module provides a full APACHE_J_P protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AjpClient`
- `AjpClientConfig`
- `AjpRequest`
- `AjpResponse`
- `AjpServer`
- `AjpServerConfig`
- `AsyncAjpClient`
- `AsyncAjpServer`
- `StaticAjpHandler`

### Enums
- `AjpMethod`

### Traits
- `AjpHandler`

## Key Entry Points
### Clients
- `AjpClient`
- `AjpClientConfig`
- `AsyncAjpClient`

### Servers
- `AjpServer`
- `AjpServerConfig`
- `AsyncAjpServer`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AjpClient`
  - `pub fn connect(addr: &NetAddr, config: AjpClientConfig) -> CoreResult<Self>`
  - `pub fn request( &mut self, request: &AjpRequest, body: Option<&[u8]>, ) -> CoreResult<AjpResponse>`
- `AjpRequest`
  - `pub fn new(method: AjpMethod, uri: &str) -> Self`
  - `pub fn header(&self, name: &str) -> Option<&str>`
- `AjpResponse`
  - `pub fn new(status: u16, reason: &str, body: Vec<u8>) -> Self`
- `AjpServer`
  - `pub fn bind( addr: SocketAddr, config: AjpServerConfig, handler: Arc<dyn AjpHandler>, ) -> CoreResult<Self>`
- `AsyncAjpClient`
  - `pub async fn connect(addr: &NetAddr, config: AjpClientConfig) -> CoreResult<Self>`
  - `pub async fn request( &mut self, request: &AjpRequest, body: Option<&[u8]>, ) -> CoreResult<AjpResponse>`
- `AsyncAjpServer`
  - `pub async fn bind( addr: SocketAddr, config: AjpServerConfig, handler: Arc<dyn AjpHandler>, ) -> CoreResult<Self>`
- `StaticAjpHandler`
  - `pub fn new(response: AjpResponse) -> Self`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/apache_j_p/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

