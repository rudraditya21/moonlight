# MSSQL Protocol

## Location
`network/proto/src/mssql/`

## Overview
This module provides a full MSSQL protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncMssqlClient`
- `AsyncMssqlServer`
- `MssqlClient`
- `MssqlClientConfig`
- `MssqlQueryResult`
- `MssqlServer`
- `MssqlServerConfig`

### Constants
- `MSSQL_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncMssqlClient`
- `MssqlClient`
- `MssqlClientConfig`

### Servers
- `AsyncMssqlServer`
- `MssqlServer`
- `MssqlServerConfig`

### Methods
- `AsyncMssqlClient`
  - `pub async fn connect(addr: &net::NetAddr, config: MssqlClientConfig) -> CoreResult<Self>`
  - `pub async fn query(&mut self, sql: &str) -> CoreResult<MssqlQueryResult>`
  - `pub async fn query_raw(&mut self, sql: &str) -> CoreResult<TdsResponse>`
- `AsyncMssqlServer`
  - `pub async fn bind(addr: SocketAddr, config: MssqlServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `MssqlClient`
  - `pub fn connect(addr: &net::NetAddr, config: MssqlClientConfig) -> CoreResult<Self>`
  - `pub fn query(&mut self, sql: &str) -> CoreResult<MssqlQueryResult>`
  - `pub fn query_raw(&mut self, sql: &str) -> CoreResult<TdsResponse>`
- `MssqlQueryResult`
  - `pub fn from_response(resp: &TdsResponse) -> Self`
  - `pub fn into_result(self) -> CoreResult<Self>`
- `MssqlServer`
  - `pub fn bind(addr: SocketAddr, config: MssqlServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/mssql/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

