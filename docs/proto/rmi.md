# RMI Protocol

## Location
`network/proto/src/rmi/`

## Overview
This module provides a full RMI protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncRmiClient`
- `AsyncRmiServer`
- `EchoRmiHandler`
- `RmiClient`
- `RmiClientConfig`
- `RmiFrame`
- `RmiServer`
- `RmiServerConfig`

### Enums
- `RmiOp`

### Traits
- `RmiHandler`

## Key Entry Points
### Clients
- `AsyncRmiClient`
- `RmiClient`
- `RmiClientConfig`

### Servers
- `AsyncRmiServer`
- `RmiServer`
- `RmiServerConfig`

### Methods
- `AsyncRmiClient`
  - `pub async fn connect(addr: &net::NetAddr, config: RmiClientConfig) -> CoreResult<Self>`
  - `pub async fn call(&mut self, method: &str, args: &[String]) -> CoreResult<String>`
  - `pub async fn ping(&mut self) -> CoreResult<()>`
- `AsyncRmiServer`
  - `pub async fn bind(addr: SocketAddr, config: RmiServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `RmiClient`
  - `pub fn connect(addr: &net::NetAddr, config: RmiClientConfig) -> CoreResult<Self>`
  - `pub fn call(&mut self, method: &str, args: &[String]) -> CoreResult<String>`
  - `pub fn ping(&mut self) -> CoreResult<()>`
- `RmiFrame`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `RmiServer`
  - `pub fn bind(addr: SocketAddr, config: RmiServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/rmi/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

