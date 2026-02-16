# SSH Protocol

## Location
`network/proto/src/ssh/`

## Overview
This module provides a full SSH protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AllowAllAuth`
- `AsyncChannel`
- `AsyncSshClient`
- `AsyncSshServer`
- `AuthConfig`
- `Channel`
- `HostKey`
- `KexInit`
- `SshClient`
- `SshConfig`
- `SshServer`

### Traits
- `AuthHandler`

## Key Entry Points
### Clients
- `AsyncSshClient`
- `SshClient`

### Servers
- `AsyncSshServer`
- `SshServer`

### Free Functions
- `pub async fn recv_channel_data(&mut self, channel: &mut AsyncChannel) -> CoreResult<Vec<u8>> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve<F>(&self, handler: F) -> CoreResult<()> where F: AuthHandler + 'static, {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: AuthHandler + 'static, {`

### Methods
- `AsyncSshClient`
  - `pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub async fn userauth_password(&mut self, username: &str, password: &str) -> CoreResult<()>`
  - `pub async fn open_session(&mut self) -> CoreResult<AsyncChannel>`
  - `pub async fn send_channel_data( &mut self, channel: &mut AsyncChannel, data: &[u8], ) -> CoreResult<()>`
- `AsyncSshServer`
  - `pub async fn bind( addr: SocketAddr, host_key: HostKey, config: SshConfig, timeouts: Timeouts, ) -> CoreResult<Self>`
- `HostKey`
  - `pub fn from_seed(seed: &[u8; 32]) -> CoreResult<Self>`
  - `pub fn public_key_blob(&self) -> Vec<u8>`
  - `pub fn sign(&self, data: &[u8]) -> Vec<u8>`
- `SshClient`
  - `pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn userauth_password(&mut self, username: &str, password: &str) -> CoreResult<()>`
  - `pub fn open_session(&mut self) -> CoreResult<Channel>`
  - `pub fn send_channel_data(&mut self, channel: &mut Channel, data: &[u8]) -> CoreResult<()>`
  - `pub fn recv_channel_data(&mut self, channel: &mut Channel) -> CoreResult<Vec<u8>>`
- `SshServer`
  - `pub fn bind( addr: SocketAddr, host_key: HostKey, config: SshConfig, timeouts: Timeouts, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ssh/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

