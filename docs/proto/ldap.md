# LDAP Protocol

## Location
`network/proto/src/ldap/`

## Overview
This module provides a full LDAP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AddRequest`
- `AsyncLdapClient`
- `AsyncUpstreamLdapClient`
- `AsyncLdapServer`
- `Attribute`
- `AttributeValueAssertion`
- `BindRequest`
- `BindResponse`
- `Change`
- `CompareRequest`
- `Control`
- `ExtendedRequest`
- `ExtendedResponse`
- `ExtensibleMatch`
- `InMemoryBackend`
- `LdapClient`
- `LdapMessage`
- `LdapResult`
- `LdapServer`
- `UpstreamLdapClient`
- `ModifyDnRequest`
- `ModifyRequest`
- `SearchRequest`
- `SearchResultEntry`

### Enums
- `BindAuth`
- `DerefAliases`
- `Filter`
- `ModifyOp`
- `ProtocolOp`
- `ResultCode`
- `SearchScope`
- `Substring`

### Traits
- `LdapBackend`

## Key Entry Points
### Clients
- `AsyncLdapClient`
- `AsyncUpstreamLdapClient`
- `LdapClient`
- `UpstreamLdapClient`

### Servers
- `AsyncLdapServer`
- `LdapServer`

### Free Functions
- `pub fn ldap_success() -> LdapResult {`
- `pub fn add(&mut self, request: AddRequest) -> CoreResult<LdapResult> {`
- `pub fn modify(&mut self, request: ModifyRequest) -> CoreResult<LdapResult> {`
- `pub fn delete(&mut self, dn: &str) -> CoreResult<LdapResult> {`
- `pub fn compare(&mut self, request: CompareRequest) -> CoreResult<LdapResult> {`
- `pub fn unbind(&mut self) -> CoreResult<()> {`
- `pub async fn unbind(&mut self) -> CoreResult<()> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncLdapClient`
  - `pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub async fn send(&mut self, op: ProtocolOp) -> CoreResult<i32>`
  - `pub async fn recv(&mut self) -> CoreResult<LdapMessage>`
  - `pub async fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult>`
  - `pub async fn search( &mut self, request: SearchRequest, ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)>`
- `AsyncLdapServer`
  - `pub async fn bind( addr: SocketAddr, timeouts: Timeouts, backend: Arc<dyn LdapBackend>, ) -> CoreResult<Self>`
- `AsyncUpstreamLdapClient`
  - `pub async fn connect(addr: &NetAddr) -> CoreResult<Self>`
  - `pub async fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult>`
  - `pub async fn search( &mut self, request: SearchRequest, ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)>`
  - `pub async fn unbind(&mut self) -> CoreResult<()>`
- `InMemoryBackend`
  - `pub fn new() -> Self`
  - `pub fn with_entry(self, entry: SearchResultEntry) -> Self`
  - `pub fn allow_anonymous(mut self, allow: bool) -> Self`
- `LdapClient`
  - `pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn send(&mut self, op: ProtocolOp) -> CoreResult<i32>`
  - `pub fn recv(&mut self) -> CoreResult<LdapMessage>`
  - `pub fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult>`
  - `pub fn search( &mut self, request: SearchRequest, ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)>`
- `LdapMessage`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `LdapServer`
  - `pub fn bind( addr: SocketAddr, timeouts: Timeouts, backend: Arc<dyn LdapBackend>, ) -> CoreResult<Self>`
- `UpstreamLdapClient`
  - `pub fn connect(addr: &NetAddr, _timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn bind_simple(&mut self, dn: &str, password: &str) -> CoreResult<LdapResult>`
  - `pub fn search( &mut self, request: SearchRequest, ) -> CoreResult<(Vec<SearchResultEntry>, LdapResult)>`
  - `pub fn unbind(&mut self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ldap/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.
