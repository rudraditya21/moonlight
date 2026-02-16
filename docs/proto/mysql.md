# MYSQL Protocol

## Location
`network/proto/src/mysql/`

## Overview
This module provides a full MYSQL protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncMysqlClient`
- `AsyncMysqlServer`
- `MysqlClient`
- `MysqlClientConfig`
- `MysqlQueryResult`
- `MysqlServer`
- `MysqlServerConfig`

## Key Entry Points
### Clients
- `AsyncMysqlClient`
- `MysqlClient`
- `MysqlClientConfig`

### Servers
- `AsyncMysqlServer`
- `MysqlServer`
- `MysqlServerConfig`

### Methods
- `AsyncMysqlClient`
  - `pub async fn connect(addr: &net::NetAddr, config: MysqlClientConfig) -> CoreResult<Self>`
  - `pub async fn query(&mut self, sql: &str) -> CoreResult<MysqlQueryResult>`
  - `pub fn server_version(&self) -> &str`
  - `pub fn connection_id(&self) -> u32`
  - `pub fn capability_flags(&self) -> u32`
  - `pub fn status_flags(&self) -> u16`
  - `pub async fn ping(&mut self) -> CoreResult<()>`
- `AsyncMysqlServer`
  - `pub async fn bind(addr: SocketAddr, config: MysqlServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `MysqlClient`
  - `pub fn connect(addr: &net::NetAddr, config: MysqlClientConfig) -> CoreResult<Self>`
  - `pub fn server_version(&self) -> &str`
  - `pub fn connection_id(&self) -> u32`
  - `pub fn capability_flags(&self) -> u32`
  - `pub fn status_flags(&self) -> u16`
  - `pub fn query(&mut self, sql: &str) -> CoreResult<MysqlQueryResult>`
  - `pub fn ping(&mut self) -> CoreResult<()>`
- `MysqlServer`
  - `pub fn bind(addr: SocketAddr, config: MysqlServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/mysql/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

