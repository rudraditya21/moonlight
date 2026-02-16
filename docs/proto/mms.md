# MMS Protocol

## Location
`network/proto/src/mms/`

## Overview
This module provides a full MMS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncMmsClient`
- `AsyncMmsServer`
- `InMemoryMmsHandler`
- `MmsClient`
- `MmsClientConfig`
- `MmsDescription`
- `MmsFrame`
- `MmsServer`
- `MmsServerConfig`

### Enums
- `MmsCommand`

### Traits
- `MmsHandler`

## Key Entry Points
### Clients
- `AsyncMmsClient`
- `MmsClient`
- `MmsClientConfig`

### Servers
- `AsyncMmsServer`
- `MmsServer`
- `MmsServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub async fn serve(&self) -> CoreResult<()> {`
- `pub fn describe(&mut self) -> CoreResult<MmsDescription> {`
- `pub fn play(&mut self) -> CoreResult<Vec<u8>> {`
- `pub async fn describe(&mut self) -> CoreResult<MmsDescription> {`
- `pub async fn play(&mut self) -> CoreResult<Vec<u8>> {`

### Methods
- `AsyncMmsClient`
  - `pub async fn connect( addr: &net::NetAddr, path: impl Into<String>, config: MmsClientConfig, ) -> CoreResult<Self>`
- `AsyncMmsServer`
  - `pub async fn bind( addr: SocketAddr, handler: Arc<dyn MmsHandler>, config: MmsServerConfig, ) -> CoreResult<Self>`
- `InMemoryMmsHandler`
  - `pub fn new(content_type: impl Into<String>, files: HashMap<String, Vec<u8>>) -> Self`
- `MmsClient`
  - `pub fn connect( addr: &net::NetAddr, path: impl Into<String>, config: MmsClientConfig, ) -> CoreResult<Self>`
- `MmsDescription`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `MmsFrame`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `MmsServer`
  - `pub fn bind( addr: SocketAddr, handler: Arc<dyn MmsHandler>, config: MmsServerConfig, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/mms/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

