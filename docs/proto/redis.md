# REDIS Protocol

## Location
`network/proto/src/redis/`

## Overview
This module provides a full REDIS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncRedisClient`
- `AsyncRedisConnection`
- `AsyncRedisServer`
- `AsyncUpstreamRedisClient`
- `DefaultRedisHandler`
- `RedisClient`
- `RedisCommand`
- `RedisConnection`
- `RedisContext`
- `RedisServer`
- `RedisServerConfig`
- `RedisStore`
- `UpstreamRedisClient`

### Enums
- `RespFrame`
- `RespVersion`

### Traits
- `RedisHandler`

## Key Entry Points
### Clients
- `AsyncRedisClient`
- `AsyncUpstreamRedisClient`
- `RedisClient`
- `UpstreamRedisClient`

### Servers
- `AsyncRedisServer`
- `RedisServer`
- `RedisServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncRedisClient`
  - `pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub async fn call(&mut self, cmd: RedisCommand) -> CoreResult<RespFrame>`
  - `pub async fn auth(&mut self, password: &str) -> CoreResult<RespFrame>`
  - `pub async fn hello(&mut self, version: RespVersion) -> CoreResult<RespFrame>`
- `AsyncRedisConnection`
  - `pub fn new(transport: T) -> Self`
  - `pub async fn read_frame(&mut self) -> CoreResult<RespFrame>`
  - `pub async fn write_frame(&mut self, frame: &RespFrame, version: RespVersion) -> CoreResult<()>`
  - `pub fn into_inner(self) -> T`
- `AsyncRedisServer`
  - `pub async fn bind( addr: SocketAddr, config: RedisServerConfig, handler: Arc<dyn RedisHandler>, ) -> CoreResult<Self>`
- `AsyncUpstreamRedisClient`
  - `pub async fn connect(addr: &NetAddr, _timeouts: Timeouts) -> CoreResult<Self>`
  - `pub async fn call(&mut self, cmd: RedisCommand) -> CoreResult<RespFrame>`
  - `pub async fn auth(&mut self, password: &str) -> CoreResult<RespFrame>`
  - `pub async fn hello(&mut self, version: RespVersion) -> CoreResult<RespFrame>`
- `RedisClient`
  - `pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn call(&mut self, cmd: RedisCommand) -> CoreResult<RespFrame>`
  - `pub fn auth(&mut self, password: &str) -> CoreResult<RespFrame>`
  - `pub fn hello(&mut self, version: RespVersion) -> CoreResult<RespFrame>`
- `RedisCommand`
  - `pub fn new(name: &str, args: Vec<Vec<u8>>) -> Self`
  - `pub fn to_frame(&self) -> RespFrame`
  - `pub fn from_frame(frame: &RespFrame) -> CoreResult<Self>`
- `RedisConnection`
  - `pub fn new(transport: T) -> Self`
  - `pub fn read_frame(&mut self) -> CoreResult<RespFrame>`
  - `pub fn write_frame(&mut self, frame: &RespFrame, version: RespVersion) -> CoreResult<()>`
  - `pub fn into_inner(self) -> T`
- `RedisServer`
  - `pub fn bind( addr: SocketAddr, config: RedisServerConfig, handler: Arc<dyn RedisHandler>, ) -> CoreResult<Self>`
- `RedisStore`
  - `pub fn new(databases: usize) -> Self`
- `UpstreamRedisClient`
  - `pub fn connect(addr: &NetAddr, _timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn call(&mut self, cmd: RedisCommand) -> CoreResult<RespFrame>`
  - `pub fn auth(&mut self, password: &str) -> CoreResult<RespFrame>`
  - `pub fn hello(&mut self, version: RespVersion) -> CoreResult<RespFrame>`
- `RespFrame`
  - `pub fn encode(&self, version: RespVersion) -> Vec<u8>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/redis/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.
