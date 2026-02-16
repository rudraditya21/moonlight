# SECAUTHZ Protocol

## Location
`network/proto/src/secauthz/`

## Overview
This module provides a full SECAUTHZ protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncSecAuthzClient`
- `AsyncSecAuthzServer`
- `PolicyHandler`
- `SecAuthzClient`
- `SecAuthzClientConfig`
- `SecAuthzFrame`
- `SecAuthzPolicy`
- `SecAuthzServer`
- `SecAuthzServerConfig`

### Enums
- `SecAuthzDecision`
- `SecAuthzMessageType`

### Traits
- `SecAuthzHandler`

## Key Entry Points
### Clients
- `AsyncSecAuthzClient`
- `SecAuthzClient`
- `SecAuthzClientConfig`

### Servers
- `AsyncSecAuthzServer`
- `SecAuthzServer`
- `SecAuthzServerConfig`

### Methods
- `AsyncSecAuthzClient`
  - `pub async fn connect(addr: &net::NetAddr, config: SecAuthzClientConfig) -> CoreResult<Self>`
  - `pub async fn authorize( &mut self, subject: &str, action: &str, resource: &str, token: Option<&str>, ) -> CoreResult<SecAuthzDecision>`
- `AsyncSecAuthzServer`
  - `pub async fn bind(addr: SocketAddr, config: SecAuthzServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `PolicyHandler`
  - `pub fn new(policies: Vec<SecAuthzPolicy>) -> Self`
- `SecAuthzClient`
  - `pub fn connect(addr: &net::NetAddr, config: SecAuthzClientConfig) -> CoreResult<Self>`
  - `pub fn authorize( &mut self, subject: &str, action: &str, resource: &str, token: Option<&str>, ) -> CoreResult<SecAuthzDecision>`
- `SecAuthzFrame`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `SecAuthzServer`
  - `pub fn bind(addr: SocketAddr, config: SecAuthzServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/secauthz/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

