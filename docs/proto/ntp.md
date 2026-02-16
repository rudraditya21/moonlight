# NTP Protocol

## Location
`network/proto/src/ntp/`

## Overview
This module provides a full NTP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncNtpClient`
- `AsyncNtpServer`
- `NtpClient`
- `NtpClientConfig`
- `NtpPacket`
- `NtpServer`
- `NtpServerConfig`
- `NtpTimestamp`

### Constants
- `NTP_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncNtpClient`
- `NtpClient`
- `NtpClientConfig`

### Servers
- `AsyncNtpServer`
- `NtpServer`
- `NtpServerConfig`

### Methods
- `AsyncNtpClient`
  - `pub async fn new(server: SocketAddr) -> CoreResult<Self>`
  - `pub async fn request_time(&self) -> CoreResult<SystemTime>`
- `AsyncNtpServer`
  - `pub async fn bind(addr: SocketAddr, config: NtpServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `NtpClient`
  - `pub fn new(server: SocketAddr, config: NtpClientConfig) -> CoreResult<Self>`
  - `pub fn request_time(&self) -> CoreResult<SystemTime>`
- `NtpPacket`
  - `pub fn client_request() -> Self`
  - `pub fn server_response(request: &NtpPacket, stratum: u8, reference_id: u32) -> Self`
  - `pub fn encode(&self) -> [u8; 48]`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
  - `pub fn mode(&self) -> u8`
- `NtpServer`
  - `pub fn bind(addr: SocketAddr, config: NtpServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`
- `NtpTimestamp`
  - `pub fn from_system_time(time: SystemTime) -> Self`
  - `pub fn to_system_time(&self) -> SystemTime`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ntp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

