# BCRYPT_PUBLIC_KEY Protocol

## Location
`network/proto/src/bcrypt_public_key/`

## Overview
This module provides a full BCRYPT_PUBLIC_KEY protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncBcryptPublicKeyClient`
- `AsyncBcryptPublicKeyServer`
- `BcryptPublicKey`
- `BcryptPublicKeyClient`
- `BcryptPublicKeyClientConfig`
- `BcryptPublicKeyServer`
- `BcryptPublicKeyServerConfig`
- `InMemoryBcryptKeyStore`

### Traits
- `BcryptPublicKeyHandler`

### Constants
- `BCRYPT_PUBLIC_KEY_MAGIC`

## Key Entry Points
### Clients
- `AsyncBcryptPublicKeyClient`
- `BcryptPublicKeyClient`
- `BcryptPublicKeyClientConfig`

### Servers
- `AsyncBcryptPublicKeyServer`
- `BcryptPublicKeyServer`
- `BcryptPublicKeyServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncBcryptPublicKeyClient`
  - `pub async fn connect(addr: &NetAddr, config: BcryptPublicKeyClientConfig) -> CoreResult<Self>`
  - `pub async fn send_key(&mut self, key: &BcryptPublicKey) -> CoreResult<()>`
- `AsyncBcryptPublicKeyServer`
  - `pub async fn bind( addr: SocketAddr, _config: BcryptPublicKeyServerConfig, handler: Arc<dyn BcryptPublicKeyHandler>, ) -> CoreResult<Self>`
- `BcryptPublicKey`
  - `pub fn new(exponent: Vec<u8>, modulus: Vec<u8>) -> Self`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `BcryptPublicKeyClient`
  - `pub fn connect(addr: &NetAddr, config: BcryptPublicKeyClientConfig) -> CoreResult<Self>`
  - `pub fn send_key(&mut self, key: &BcryptPublicKey) -> CoreResult<()>`
- `BcryptPublicKeyServer`
  - `pub fn bind( addr: SocketAddr, config: BcryptPublicKeyServerConfig, handler: Arc<dyn BcryptPublicKeyHandler>, ) -> CoreResult<Self>`
- `InMemoryBcryptKeyStore`
  - `pub fn latest(&self) -> Option<BcryptPublicKey>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/bcrypt_public_key/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

