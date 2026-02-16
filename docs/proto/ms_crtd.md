# MS_CRTD Protocol

## Location
`network/proto/src/ms_crtd/`

## Overview
This module provides a full MS_CRTD protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncCrtdClient`
- `AsyncCrtdServer`
- `CertificateRequest`
- `CertificateResponse`
- `CertificateTemplate`
- `CrtdClient`
- `CrtdClientConfig`
- `CrtdMessage`
- `CrtdServer`
- `CrtdServerConfig`

### Enums
- `CrtdMessageType`

## Key Entry Points
### Clients
- `AsyncCrtdClient`
- `CrtdClient`
- `CrtdClientConfig`

### Servers
- `AsyncCrtdServer`
- `CrtdServer`
- `CrtdServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncCrtdClient`
  - `pub async fn connect(addr: &net::NetAddr, config: CrtdClientConfig) -> CoreResult<Self>`
  - `pub async fn enroll(&mut self, request: CertificateRequest) -> CoreResult<CertificateResponse>`
- `AsyncCrtdServer`
  - `pub async fn bind( addr: SocketAddr, templates: Vec<CertificateTemplate>, config: CrtdServerConfig, ) -> CoreResult<Self>`
- `CrtdClient`
  - `pub fn connect(addr: &net::NetAddr, config: CrtdClientConfig) -> CoreResult<Self>`
  - `pub fn list_templates(&mut self) -> CoreResult<Vec<CertificateTemplate>>`
  - `pub fn get_template(&mut self, name: &str) -> CoreResult<CertificateTemplate>`
  - `pub fn enroll(&mut self, request: CertificateRequest) -> CoreResult<CertificateResponse>`
- `CrtdMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `CrtdServer`
  - `pub fn bind( addr: SocketAddr, templates: Vec<CertificateTemplate>, config: CrtdServerConfig, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ms_crtd/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

