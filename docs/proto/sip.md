# SIP Protocol

## Location
`network/proto/src/sip/`

## Overview
This module provides a full SIP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncSipTcpClient`
- `AsyncSipTcpServer`
- `AsyncSipUdpClient`
- `AsyncSipUdpServer`
- `SipClientConfig`
- `SipHeaders`
- `SipRequest`
- `SipResponse`
- `SipServerConfig`
- `SipTcpClient`
- `SipTcpServer`
- `SipUdpClient`
- `SipUdpServer`

### Enums
- `SipMessage`
- `SipMethod`

### Constants
- `SIP_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncSipTcpClient`
- `AsyncSipUdpClient`
- `SipClientConfig`
- `SipTcpClient`
- `SipUdpClient`

### Servers
- `AsyncSipTcpServer`
- `AsyncSipUdpServer`
- `SipServerConfig`
- `SipTcpServer`
- `SipUdpServer`

### Methods
- `AsyncSipTcpClient`
  - `pub async fn connect(addr: &net::NetAddr, config: SipClientConfig) -> CoreResult<Self>`
  - `pub async fn options(&mut self, uri: &str) -> CoreResult<SipResponse>`
- `AsyncSipTcpServer`
  - `pub async fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `AsyncSipUdpClient`
  - `pub async fn new(server: SocketAddr, config: SipClientConfig) -> CoreResult<Self>`
  - `pub async fn options(&self, uri: &str) -> CoreResult<SipResponse>`
- `AsyncSipUdpServer`
  - `pub async fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `SipHeaders`
  - `pub fn new() -> Self`
  - `pub fn get(&self, name: &str) -> Option<&str>`
  - `pub fn set(&mut self, name: &str, value: String)`
  - `pub fn push(&mut self, name: &str, value: String)`
  - `pub fn iter(&self) -> impl Iterator<Item = &(String, String)>`
- `SipMethod`
  - `pub fn as_str(&self) -> &'static str`
  - `pub fn parse(value: &str) -> Option<Self>`
- `SipRequest`
  - `pub fn new(method: SipMethod, uri: &str) -> Self`
  - `pub fn to_bytes(&self) -> CoreResult<Vec<u8>>`
- `SipResponse`
  - `pub fn new(code: u16, reason: &str) -> Self`
  - `pub fn to_bytes(&self) -> CoreResult<Vec<u8>>`
- `SipTcpClient`
  - `pub fn connect(addr: &net::NetAddr, config: SipClientConfig) -> CoreResult<Self>`
  - `pub fn options(&mut self, uri: &str) -> CoreResult<SipResponse>`
- `SipTcpServer`
  - `pub fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`
- `SipUdpClient`
  - `pub fn new(server: SocketAddr, config: SipClientConfig) -> CoreResult<Self>`
  - `pub fn options(&self, uri: &str) -> CoreResult<SipResponse>`
  - `pub fn register(&self, uri: &str) -> CoreResult<SipResponse>`
- `SipUdpServer`
  - `pub fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/sip/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

