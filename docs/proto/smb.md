# SMB Protocol

## Location
`network/proto/src/smb/`

## Overview
This module provides a full SMB protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncSmbClient`
- `AsyncSmbServer`
- `Smb2Header`
- `Smb2Packet`
- `SmbClient`
- `SmbClientConfig`
- `SmbServer`
- `SmbServerConfig`
- `SmbShare`

## Key Entry Points
### Clients
- `AsyncSmbClient`
- `SmbClient`
- `SmbClientConfig`

### Servers
- `AsyncSmbServer`
- `SmbServer`
- `SmbServerConfig`

### Methods
- `AsyncSmbClient`
  - `pub async fn connect(addr: &NetAddr, config: SmbClientConfig) -> CoreResult<Self>`
  - `pub async fn negotiate(&mut self) -> CoreResult<()>`
  - `pub async fn session_setup_ntlm(&mut self, config: NtlmClientConfig) -> CoreResult<()>`
  - `pub async fn tree_connect(&mut self, share: &str) -> CoreResult<()>`
  - `pub async fn create(&mut self, path: &str) -> CoreResult<[u8; 16]>`
  - `pub async fn read( &mut self, file_id: [u8; 16],`
  - `pub async fn write(&mut self, file_id: [u8; 16], offset: u64, data: &[u8]) -> CoreResult<u32>`
  - `pub async fn close(&mut self, file_id: [u8; 16]) -> CoreResult<()>`
  - `pub async fn logoff(&mut self) -> CoreResult<()>`
- `AsyncSmbServer`
  - `pub async fn bind(addr: SocketAddr, config: SmbServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `Smb2Header`
  - `pub fn new(command: u16, message_id: u64) -> Self`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `Smb2Packet`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `SmbClient`
  - `pub fn connect(addr: &NetAddr, config: SmbClientConfig) -> CoreResult<Self>`
  - `pub fn negotiate(&mut self) -> CoreResult<()>`
  - `pub fn session_setup_ntlm(&mut self, config: NtlmClientConfig) -> CoreResult<()>`
  - `pub fn tree_connect(&mut self, share: &str) -> CoreResult<()>`
  - `pub fn create(&mut self, path: &str) -> CoreResult<[u8; 16]>`
  - `pub fn read(&mut self, file_id: [u8; 16], offset: u64, length: u32) -> CoreResult<Vec<u8>>`
  - `pub fn write(&mut self, file_id: [u8; 16], offset: u64, data: &[u8]) -> CoreResult<u32>`
  - `pub fn close(&mut self, file_id: [u8; 16]) -> CoreResult<()>`
  - `pub fn logoff(&mut self) -> CoreResult<()>`
- `SmbServer`
  - `pub fn bind(addr: SocketAddr, config: SmbServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`
- `SmbShare`
  - `pub fn new(name: &str) -> Self`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/smb/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

