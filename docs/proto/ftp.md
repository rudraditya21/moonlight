# FTP Protocol

## Location
`network/proto/src/ftp/`

## Overview
This module provides a full FTP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncFtpClient`
- `AsyncFtpClientConfig`
- `AsyncFtpServer`
- `FtpClient`
- `FtpClientConfig`
- `FtpCommand`
- `FtpResponse`
- `FtpServer`
- `FtpServerConfig`
- `FtpSession`
- `InMemoryFtpBackend`

### Traits
- `FtpBackend`

## Key Entry Points
### Clients
- `AsyncFtpClient`
- `AsyncFtpClientConfig`
- `FtpClient`
- `FtpClientConfig`

### Servers
- `AsyncFtpServer`
- `FtpServer`
- `FtpServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncFtpClient`
  - `pub async fn connect(addr: &NetAddr, config: AsyncFtpClientConfig) -> CoreResult<Self>`
  - `pub async fn read_response(&mut self) -> CoreResult<FtpResponse>`
  - `pub async fn send_command(&mut self, cmd: &FtpCommand) -> CoreResult<()>`
  - `pub async fn command(&mut self, name: &str, argument: Option<&str>) -> CoreResult<FtpResponse>`
  - `pub async fn login(&mut self, user: &str, pass: &str) -> CoreResult<()>`
  - `pub async fn list(&mut self, path: Option<&str>) -> CoreResult<Vec<String>>`
  - `pub async fn retr(&mut self, path: &str) -> CoreResult<Vec<u8>>`
  - `pub async fn stor(&mut self, path: &str, data: &[u8]) -> CoreResult<()>`
  - `pub async fn enter_pasv(&mut self) -> CoreResult<AsyncTcpTransport>`
- `AsyncFtpServer`
  - `pub async fn bind( addr: SocketAddr, config: FtpServerConfig, backend: Arc<dyn FtpBackend>, ) -> CoreResult<Self>`
- `FtpClient`
  - `pub fn connect(addr: &NetAddr, config: FtpClientConfig) -> CoreResult<Self>`
  - `pub fn read_response(&mut self) -> CoreResult<FtpResponse>`
  - `pub fn send_command(&mut self, cmd: &FtpCommand) -> CoreResult<()>`
  - `pub fn command(&mut self, name: &str, argument: Option<&str>) -> CoreResult<FtpResponse>`
  - `pub fn login(&mut self, user: &str, pass: &str) -> CoreResult<()>`
  - `pub fn list(&mut self, path: Option<&str>) -> CoreResult<Vec<String>>`
  - `pub fn retr(&mut self, path: &str) -> CoreResult<Vec<u8>>`
  - `pub fn stor(&mut self, path: &str, data: &[u8]) -> CoreResult<()>`
  - `pub fn enter_pasv(&mut self) -> CoreResult<TcpTransport>`
- `FtpCommand`
  - `pub fn parse(line: &str) -> CoreResult<Self>`
  - `pub fn format(&self) -> String`
- `FtpResponse`
  - `pub fn new(code: u16, message: impl Into<String>) -> Self`
  - `pub fn to_line(&self) -> String`
- `FtpServer`
  - `pub fn bind( addr: SocketAddr, config: FtpServerConfig, backend: Arc<dyn FtpBackend>, ) -> CoreResult<Self>`
- `InMemoryFtpBackend`
  - `pub fn with_user(mut self, user: &str, pass: &str) -> Self`
  - `pub fn with_file(self, path: &str, data: Vec<u8>) -> Self`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ftp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

