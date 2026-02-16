# STEAM Protocol

## Location
`network/proto/src/steam/`

## Overview
This module provides a full STEAM protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncSteamClient`
- `AsyncSteamServer`
- `SteamClient`
- `SteamClientConfig`
- `SteamPlayer`
- `SteamServer`
- `SteamServerConfig`
- `SteamServerInfo`

## Key Entry Points
### Clients
- `AsyncSteamClient`
- `SteamClient`
- `SteamClientConfig`

### Servers
- `AsyncSteamServer`
- `SteamServer`
- `SteamServerConfig`
- `SteamServerInfo`

### Methods
- `AsyncSteamClient`
  - `pub async fn new(_config: SteamClientConfig) -> CoreResult<Self>`
  - `pub async fn info(&self, addr: SocketAddr) -> CoreResult<SteamServerInfo>`
  - `pub async fn players(&self, addr: SocketAddr) -> CoreResult<Vec<SteamPlayer>>`
  - `pub async fn rules(&self, addr: SocketAddr) -> CoreResult<HashMap<String, String>>`
- `AsyncSteamServer`
  - `pub async fn bind(addr: SocketAddr, config: SteamServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `SteamClient`
  - `pub fn new(config: SteamClientConfig) -> CoreResult<Self>`
  - `pub fn info(&self, addr: SocketAddr) -> CoreResult<SteamServerInfo>`
  - `pub fn players(&self, addr: SocketAddr) -> CoreResult<Vec<SteamPlayer>>`
  - `pub fn rules(&self, addr: SocketAddr) -> CoreResult<HashMap<String, String>>`
- `SteamServer`
  - `pub fn bind(addr: SocketAddr, config: SteamServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/steam/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

