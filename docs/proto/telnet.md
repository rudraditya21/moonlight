# TELNET Protocol

## Location
`network/proto/src/telnet/`

## Overview
This module provides a full TELNET protocol implementation intended for use by Moonlight modules. It includes:
- sync and async client/server stacks
- incremental TELNET stream parsing (`IAC`, option negotiation, subnegotiation)
- NEW-ENVIRON helpers (RFC 1572 style option exchange)
- output filtering helpers for ANSI stripping and echoed-command suppression

## Public Types
### Structs
- `AnsiStripper`
- `AsyncTelnetClient`
- `AsyncTelnetServer`
- `EchoSuppressor`
- `TelnetClient`
- `TelnetClientConfig`
- `TelnetOutputFilter`
- `TelnetParser`
- `TelnetServer`
- `TelnetServerConfig`

### Enums
- `TelnetEvent`
- `TelnetNegotiationCommand`

## Key Entry Points
### Clients
- `AsyncTelnetClient`
- `TelnetClient`
- `TelnetClientConfig`

### Servers
- `AsyncTelnetServer`
- `TelnetServer`
- `TelnetServerConfig`

### Free Functions
- `pub fn build_new_environ_is(vars: &[(&str, &str)]) -> Vec<u8>`
- `pub fn build_new_environ_send(vars: &[&str]) -> Vec<u8>`
- `pub fn build_new_environ_user_is(user_value: &str) -> Vec<u8>`
- `pub fn default_client_negotiation_reply(command: TelnetNegotiationCommand, option: u8) -> Option<[u8; 3]>`
- `pub fn default_server_negotiation_reply(command: TelnetNegotiationCommand, option: u8) -> Option<[u8; 3]>`

### Methods
- `AsyncTelnetClient`
  - `pub async fn connect(addr: &net::NetAddr, config: TelnetClientConfig) -> CoreResult<Self>`
  - `pub async fn send_raw(&mut self, bytes: &[u8]) -> CoreResult<()>`
  - `pub async fn recv_events(&mut self) -> CoreResult<Vec<TelnetEvent>>`
- `AsyncTelnetServer`
  - `pub async fn bind(addr: SocketAddr, config: TelnetServerConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `TelnetClient`
  - `pub fn connect(addr: &net::NetAddr, config: TelnetClientConfig) -> CoreResult<Self>`
  - `pub fn send_raw(&mut self, bytes: &[u8]) -> CoreResult<()>`
  - `pub fn recv_events(&mut self) -> CoreResult<Vec<TelnetEvent>>`
- `TelnetServer`
  - `pub fn bind(addr: SocketAddr, config: TelnetServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Use `TelnetParser` to split raw byte streams into typed TELNET events.
- Use `default_client_negotiation_reply` and `default_server_negotiation_reply` for baseline option negotiation handling.
- Use `build_new_environ_*` helpers for NEW-ENVIRON exchanges and `TelnetOutputFilter` for terminal-safe output processing.

## Constants
The module exports TELNET constants directly (e.g. `IAC`, `DO`, `WILL`, `SB`, `SE`, `NEW_ENVIRON`, `TELNET_DEFAULT_PORT`).

## Tests and Examples
- Unit and interoperability tests live in `network/proto/src/telnet/mod.rs`.
- Protocol-level fuzz/negative suites remain in `network/proto/tests/` for cross-protocol validation.
