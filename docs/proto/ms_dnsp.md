# MS_DNSP Protocol

## Location
`network/proto/src/ms_dnsp/`

## Overview
This module provides a full MS_DNSP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncMsDnspClient`
- `AsyncMsDnspServer`
- `MsDnspClient`
- `MsDnspClientConfig`
- `MsDnspEntry`
- `MsDnspMessage`
- `MsDnspRecord`
- `MsDnspServer`
- `MsDnspServerConfig`

### Enums
- `MsDnspOpcode`
- `MsDnspRData`
- `MsDnspRecordType`

### Constants
- `MSDNSP_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncMsDnspClient`
- `MsDnspClient`
- `MsDnspClientConfig`

### Servers
- `AsyncMsDnspServer`
- `MsDnspServer`
- `MsDnspServerConfig`

### Free Functions
- `pub fn update(&self, addr: SocketAddr, name: &str, record: MsDnspRecord) -> CoreResult<()> {`

### Methods
- `AsyncMsDnspClient`
  - `pub async fn connect() -> CoreResult<Self>`
  - `pub async fn query( &self, addr: SocketAddr, name: &str, rtype: MsDnspRecordType, ) -> CoreResult<Vec<MsDnspRecord>>`
- `AsyncMsDnspServer`
  - `pub async fn bind(addr: SocketAddr, config: MsDnspServerConfig) -> CoreResult<Self>`
  - `pub fn insert_record(&self, name: &str, record: MsDnspRecord)`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `MsDnspClient`
  - `pub fn connect(config: MsDnspClientConfig) -> CoreResult<Self>`
  - `pub fn query( &self, addr: SocketAddr, name: &str, rtype: MsDnspRecordType, ) -> CoreResult<Vec<MsDnspRecord>>`
- `MsDnspMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `MsDnspRecord`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<(Self, usize)>`
- `MsDnspServer`
  - `pub fn bind(addr: SocketAddr, config: MsDnspServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn insert_record(&self, name: &str, record: MsDnspRecord)`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ms_dnsp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

