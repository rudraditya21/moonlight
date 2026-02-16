# MS_DTYP Protocol

## Location
`network/proto/src/ms_dtyp/`

## Overview
This module provides a full MS_DTYP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncDtypClient`
- `AsyncDtypServer`
- `DtypClient`
- `DtypMessage`
- `DtypServer`
- `DtypServerConfig`
- `FileTime`
- `Guid`
- `Sid`
- `UnicodeString`

### Enums
- `DtypValue`

## Key Entry Points
### Clients
- `AsyncDtypClient`
- `DtypClient`

### Servers
- `AsyncDtypServer`
- `DtypServer`
- `DtypServerConfig`

### Methods
- `AsyncDtypClient`
  - `pub async fn connect(addr: &net::NetAddr, config: DtypServerConfig) -> CoreResult<Self>`
  - `pub async fn send(&mut self, message: &DtypMessage) -> CoreResult<DtypMessage>`
- `AsyncDtypServer`
  - `pub async fn bind(addr: SocketAddr, config: DtypServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `DtypClient`
  - `pub fn connect(addr: &net::NetAddr, config: DtypServerConfig) -> CoreResult<Self>`
  - `pub fn send(&mut self, message: &DtypMessage) -> CoreResult<DtypMessage>`
- `DtypMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `DtypServer`
  - `pub fn bind(addr: SocketAddr, config: DtypServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`
- `FileTime`
  - `pub fn now() -> Self`
  - `pub fn to_unix_seconds(&self) -> u64`
- `Guid`
  - `pub fn encode(&self) -> [u8; 16]`
  - `pub fn decode(bytes: &[u8]) -> CoreResult<Self>`
  - `pub fn to_string(&self) -> String`
- `Sid`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
  - `pub fn to_string(&self) -> String`
- `UnicodeString`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ms_dtyp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

