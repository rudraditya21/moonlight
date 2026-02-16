# HTTP Protocol

## Location
`network/proto/src/http/`

## Overview
This module provides a full HTTP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncHttpClient`
- `AsyncHttpServer`
- `AsyncProxyConnect`
- `AsyncProxyServer`
- `DigestChallenge`
- `DigestResponse`
- `HttpClient`
- `HttpRequest`
- `HttpResponse`
- `HttpServer`
- `ProxyConnect`
- `ProxyServer`

### Enums
- `HttpMethod`
- `HttpTarget`
- `HttpVersion`

## Key Entry Points
### Clients
- `AsyncHttpClient`
- `HttpClient`

### Servers
- `AsyncHttpServer`
- `AsyncProxyServer`
- `HttpServer`
- `ProxyServer`

### Free Functions
- `pub fn basic_auth(username: &str, password: &str) -> String {`
- `pub fn bearer_auth(token: &str) -> String {`
- `pub fn parse_digest_challenge(header: &str) -> CoreResult<DigestChallenge> {`
- `pub fn digest_authorization( challenge: &DigestChallenge, username: &str, password: &str, method: &str, uri: &str, ) -> CoreResult<String> {`
- `pub fn digest_authorization_with_body( challenge: &DigestChallenge, username: &str, password: &str, method: &str, uri: &str, body: &[u8], ) -> CoreResult<String> {`
- `pub fn serve_forward(&self) -> CoreResult<()> {`
- `pub fn proxy_forward(request: &HttpRequest, timeouts: Timeouts) -> CoreResult<HttpResponse> {`
- `pub async fn proxy_forward_async( request: &HttpRequest, timeouts: Timeouts, ) -> CoreResult<HttpResponse> {`

### Methods
- `AsyncHttpClient`
  - `pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub async fn connect_tls( addr: &NetAddr, server_name: &str, config: &crate::transport::TlsClientConfig, timeouts: Timeouts, ) -> CoreResult<Self>`
  - `pub fn new(transport: T) -> Self`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub async fn send(&mut self, request: &HttpRequest) -> CoreResult<HttpResponse>`
- `AsyncHttpServer`
  - `pub async fn bind(addr: SocketAddr) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,`
- `AsyncProxyServer`
  - `pub async fn bind(addr: SocketAddr) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub async fn serve<F, C>(&self, handler: F, connect_handler: C) -> CoreResult<()> where F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static, C: Fn(AsyncProxyConnect) -> CoreResult<()> + Send + Sync + 'static,`
- `HttpClient`
  - `pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn connect_tls( addr: &NetAddr, server_name: &str, config: &crate::transport::TlsClientConfig, timeouts: Timeouts, ) -> CoreResult<Self>`
  - `pub fn new(transport: T) -> Self`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn send(&mut self, request: &HttpRequest) -> CoreResult<HttpResponse>`
- `HttpRequest`
  - `pub fn new(method: HttpMethod, path: impl Into<String>) -> Self`
  - `pub fn set_header(&mut self, name: &str, value: &str)`
  - `pub fn target(&self) -> CoreResult<HttpTarget>`
  - `pub fn set_absolute_uri(&mut self, scheme: &str, host: &str, port: u16, path: &str)`
  - `pub fn to_bytes(&self) -> CoreResult<Vec<u8>>`
- `HttpResponse`
  - `pub fn new(status_code: u16) -> Self`
  - `pub fn set_header(&mut self, name: &str, value: &str)`
  - `pub fn to_bytes(&self) -> CoreResult<Vec<u8>>`
- `HttpServer`
  - `pub fn bind(addr: SocketAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,`
- `ProxyServer`
  - `pub fn bind(addr: SocketAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn max_body(mut self, max_body: usize) -> Self`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve<F, C>(&self, handler: F, connect_handler: C) -> CoreResult<()> where F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static, C: Fn(ProxyConnect) -> CoreResult<()> + Send + Sync + 'static,`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/http/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

