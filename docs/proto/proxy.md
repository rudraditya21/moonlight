# PROXY Protocol

## Location
`network/proto/src/proxy/`

## Overview
This module provides a full PROXY protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncSocks5Client`
- `AsyncSocks5Server`
- `Socks5Client`
- `Socks5ClientConfig`
- `Socks5Server`
- `Socks5ServerConfig`

### Enums
- `Socks5Address`
- `Socks5AuthMethod`
- `Socks5Command`

### Constants
- `SOCKS5_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncSocks5Client`
- `Socks5Client`
- `Socks5ClientConfig`

### Servers
- `AsyncSocks5Server`
- `Socks5Server`
- `Socks5ServerConfig`

### Free Functions
- `pub fn into_stream(self) -> TcpStream {`
- `pub fn into_stream(self) -> tokio::net::TcpStream {`

### Methods
- `AsyncSocks5Client`
  - `pub async fn connect( proxy: &net::NetAddr, target: Socks5Address, port: u16, config: Socks5ClientConfig, ) -> CoreResult<Self>`
- `AsyncSocks5Server`
  - `pub async fn bind(addr: SocketAddr, config: Socks5ServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `Socks5Client`
  - `pub fn connect( proxy: &net::NetAddr, target: Socks5Address, port: u16, config: Socks5ClientConfig, ) -> CoreResult<Self>`
- `Socks5Server`
  - `pub fn bind(addr: SocketAddr, config: Socks5ServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/proxy/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

