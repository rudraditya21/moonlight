# THRIFT Protocol

## Location
`network/proto/src/thrift/`

## Overview
This module provides a full THRIFT protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncThriftClient`
- `AsyncThriftServer`
- `ThriftApplicationException`
- `ThriftClient`
- `ThriftClientConfig`
- `ThriftField`
- `ThriftMessage`
- `ThriftServer`
- `ThriftServerConfig`

### Enums
- `ThriftMessageType`
- `ThriftResponse`
- `ThriftType`
- `ThriftValue`

### Traits
- `ThriftService`

### Type Aliases
- `ThriftStruct`

## Key Entry Points
### Clients
- `AsyncThriftClient`
- `ThriftClient`
- `ThriftClientConfig`

### Servers
- `AsyncThriftServer`
- `ThriftServer`
- `ThriftServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncThriftClient`
  - `pub async fn connect(addr: &NetAddr, config: ThriftClientConfig) -> CoreResult<Self>`
  - `pub async fn call(&mut self, method: &str, args: ThriftStruct) -> CoreResult<ThriftStruct>`
  - `pub async fn oneway(&mut self, method: &str, args: ThriftStruct) -> CoreResult<()>`
- `AsyncThriftServer`
  - `pub async fn bind( addr: SocketAddr, config: ThriftServerConfig, service: Arc<dyn ThriftService>, ) -> CoreResult<Self>`
- `ThriftApplicationException`
  - `pub fn encode(&self) -> Vec<u8>`
- `ThriftClient`
  - `pub fn connect(addr: &NetAddr, config: ThriftClientConfig) -> CoreResult<Self>`
  - `pub fn call(&mut self, method: &str, args: ThriftStruct) -> CoreResult<ThriftStruct>`
  - `pub fn oneway(&mut self, method: &str, args: ThriftStruct) -> CoreResult<()>`
- `ThriftServer`
  - `pub fn bind( addr: SocketAddr, config: ThriftServerConfig, service: Arc<dyn ThriftService>, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/thrift/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

