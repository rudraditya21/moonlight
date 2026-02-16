# TFTP Protocol

## Location
`network/proto/src/tftp/`

## Overview
This module provides a full TFTP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncTftpClient`
- `AsyncTftpServer`
- `InMemoryTftpBackend`
- `TftpClient`
- `TftpClientConfig`
- `TftpOptions`
- `TftpServer`
- `TftpServerConfig`

### Enums
- `TftpErrorCode`
- `TftpMode`
- `TftpPacket`

### Traits
- `TftpBackend`

### Constants
- `TFTP_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncTftpClient`
- `TftpClient`
- `TftpClientConfig`

### Servers
- `AsyncTftpServer`
- `TftpServer`
- `TftpServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncTftpClient`
  - `pub fn new(config: TftpClientConfig) -> Self`
  - `pub async fn read(&self, addr: SocketAddr, filename: &str) -> CoreResult<Vec<u8>>`
  - `pub async fn write(&self, addr: SocketAddr, filename: &str, data: &[u8]) -> CoreResult<()>`
- `AsyncTftpServer`
  - `pub async fn bind( addr: SocketAddr, config: TftpServerConfig, backend: Arc<dyn TftpBackend>, ) -> CoreResult<Self>`
- `InMemoryTftpBackend`
  - `pub fn with_file(self, filename: &str, data: Vec<u8>) -> Self`
- `TftpClient`
  - `pub fn new(config: TftpClientConfig) -> Self`
  - `pub fn read(&self, addr: SocketAddr, filename: &str) -> CoreResult<Vec<u8>>`
  - `pub fn write(&self, addr: SocketAddr, filename: &str, data: &[u8]) -> CoreResult<()>`
- `TftpMode`
  - `pub fn parse(value: &str) -> CoreResult<Self>`
  - `pub fn as_str(&self) -> &'static str`
- `TftpOptions`
  - `pub fn is_empty(&self) -> bool`
- `TftpPacket`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `TftpServer`
  - `pub fn bind( addr: SocketAddr, config: TftpServerConfig, backend: Arc<dyn TftpBackend>, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/tftp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

