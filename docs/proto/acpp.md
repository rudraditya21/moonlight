# ACPP Protocol

## Location
`network/proto/src/acpp/`

## Overview
This module provides a full ACPP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncClient`
- `AsyncServer`
- `Client`
- `Message`
- `Server`

### Constants
- `DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncClient`
- `Client`

### Servers
- `AsyncServer`
- `Server`

### Methods
- `AsyncClient`
  - `pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub async fn authenticate(&mut self, password: &str) -> CoreResult<Message>`
  - `pub async fn send(&mut self, message: &Message) -> CoreResult<()>`
  - `pub async fn recv(&mut self, validate_checksums: bool) -> CoreResult<Message>`
- `AsyncServer`
  - `pub async fn bind(addr: SocketAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(Message) -> Message + Send + Sync + 'static,`
- `Client`
  - `pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn authenticate(&mut self, password: &str) -> CoreResult<Message>`
  - `pub fn send(&mut self, message: &Message) -> CoreResult<()>`
  - `pub fn recv(&mut self, validate_checksums: bool) -> CoreResult<Message>`
- `Message`
  - `pub fn new() -> Self`
  - `pub fn login(password: &str) -> Self`
  - `pub fn successful(&self) -> bool`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(data: &[u8], validate_checksums: bool) -> CoreResult<Self>`
- `Server`
  - `pub fn bind(addr: SocketAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(Message) -> Message + Send + Sync + 'static,`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/acpp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

