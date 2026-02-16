# KERBEROS Protocol

## Location
`network/proto/src/kerberos/`

## Overview
This module provides a full KERBEROS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncKerbClient`
- `AsyncKerbKdcServer`
- `AsyncKerbServiceServer`
- `CryptoBlob`
- `KerbApRep`
- `KerbApReq`
- `KerbAsRep`
- `KerbAsReq`
- `KerbAuthenticator`
- `KerbClient`
- `KerbClientConfig`
- `KerbClientState`
- `KerbEncryptedTicket`
- `KerbError`
- `KerbFrame`
- `KerbKdcConfig`
- `KerbKdcServer`
- `KerbPrincipal`
- `KerbServiceConfig`
- `KerbServiceServer`
- `KerbTgsRep`
- `KerbTgsReq`
- `KerbTicket`

### Enums
- `KerbMsgType`

## Key Entry Points
### Clients
- `AsyncKerbClient`
- `KerbClient`
- `KerbClientConfig`
- `KerbClientState`

### Servers
- `AsyncKerbKdcServer`
- `AsyncKerbServiceServer`
- `KerbKdcServer`
- `KerbServiceConfig`
- `KerbServiceServer`

### Free Functions
- `pub fn build_ap_req( &self, service_ticket: KerbEncryptedTicket, service_session: [u8; 32],`
- `pub fn build_ap_req( &self, service_ticket: KerbEncryptedTicket, service_session: [u8; 32],`

### Methods
- `AsyncKerbClient`
  - `pub async fn connect(addr: &net::NetAddr, config: KerbClientConfig) -> CoreResult<Self>`
  - `pub async fn request_service_ticket( &mut self, service: &str, ) -> CoreResult<(KerbEncryptedTicket, [u8; 32])>`
- `AsyncKerbKdcServer`
  - `pub async fn bind(addr: SocketAddr, config: KerbKdcConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `AsyncKerbServiceServer`
  - `pub async fn bind(addr: SocketAddr, config: KerbServiceConfig) -> CoreResult<Self>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `KerbApRep`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `KerbApReq`
  - `pub fn encode(&self) -> Vec<u8>`
- `KerbClient`
  - `pub fn connect(addr: &net::NetAddr, config: KerbClientConfig) -> CoreResult<Self>`
  - `pub fn request_service_ticket( &mut self, service: &str, ) -> CoreResult<(KerbEncryptedTicket, [u8; 32])>`
- `KerbFrame`
  - `pub fn new(msg_type: KerbMsgType, payload: Vec<u8>) -> Self`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `KerbKdcServer`
  - `pub fn bind(addr: SocketAddr, config: KerbKdcConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn add_user(&self, username: &str, password: &str)`
  - `pub fn add_service(&self, service: &str, password: &str)`
  - `pub fn serve(&self) -> CoreResult<()>`
- `KerbPrincipal`
  - `pub fn new(name: &str, realm: &str) -> Self`
  - `pub fn as_string(&self) -> String`
- `KerbServiceConfig`
  - `pub fn new(service: &str, realm: &str, password: &str) -> Self`
- `KerbServiceServer`
  - `pub fn bind(addr: SocketAddr, config: KerbServiceConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/kerberos/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

