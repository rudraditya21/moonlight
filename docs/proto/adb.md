# ADB Protocol

## Location
`network/proto/src/adb/`

## Overview
This module provides a full ADB protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AdbClient`
- `AdbClientConfig`
- `AdbPacket`
- `AdbServer`
- `AdbServerConfig`
- `AsyncAdbClient`
- `AsyncAdbServer`
- `EchoAdbService`

### Enums
- `AdbCommand`

### Traits
- `AdbServiceHandler`

## Key Entry Points
### Clients
- `AdbClient`
- `AdbClientConfig`
- `AsyncAdbClient`

### Servers
- `AdbServer`
- `AdbServerConfig`
- `AsyncAdbServer`
- `EchoAdbService`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AdbClient`
  - `pub fn connect(addr: &NetAddr, config: AdbClientConfig) -> CoreResult<Self>`
  - `pub fn open(&mut self, service: &str) -> CoreResult<()>`
  - `pub fn write(&mut self, data: &[u8]) -> CoreResult<Vec<u8>>`
- `AdbPacket`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `AdbServer`
  - `pub fn bind( addr: SocketAddr, config: AdbServerConfig, handler: Arc<dyn AdbServiceHandler>, ) -> CoreResult<Self>`
- `AsyncAdbClient`
  - `pub async fn connect(addr: &NetAddr, config: AdbClientConfig) -> CoreResult<Self>`
  - `pub async fn open(&mut self, service: &str) -> CoreResult<()>`
  - `pub async fn write(&mut self, data: &[u8]) -> CoreResult<Vec<u8>>`
- `AsyncAdbServer`
  - `pub async fn bind( addr: SocketAddr, config: AdbServerConfig, handler: Arc<dyn AdbServiceHandler>, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/adb/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

