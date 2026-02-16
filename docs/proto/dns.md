# DNS Protocol

## Location
`network/proto/src/dns/`

## Overview
This module provides a full DNS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncDnsClient`
- `AsyncDnsServer`
- `AsyncDoh2Client`
- `AsyncDoh3Client`
- `AsyncDohClient`
- `AsyncMdnsClient`
- `AsyncMdnsServer`
- `DnsClient`
- `DnsClientSubnet`
- `DnsDnskey`
- `DnsDs`
- `DnsFlags`
- `DnsHeader`
- `DnsMessage`
- `DnsNsec`
- `DnsNsec3`
- `DnsOption`
- `DnsQuestion`
- `DnsRecord`
- `DnsRrsig`
- `DnsServer`
- `DohClient`
- `DohServer`
- `MdnsClient`
- `MdnsServer`

### Enums
- `DnsOptionValue`
- `DnsRecordData`

## Key Entry Points
### Clients
- `AsyncDnsClient`
- `AsyncDoh2Client`
- `AsyncDoh3Client`
- `AsyncDohClient`
- `AsyncMdnsClient`
- `DnsClient`
- `DnsClientSubnet`
- `DohClient`
- `MdnsClient`

### Servers
- `AsyncDnsServer`
- `AsyncMdnsServer`
- `DnsServer`
- `DohServer`
- `MdnsServer`

### Free Functions
- `pub fn dnskey_tag(key: &DnsDnskey) -> u16 {`
- `pub fn compute_ds(owner: &str, key: &DnsDnskey, digest_type: u8) -> CoreResult<Vec<u8>> {`
- `pub fn verify_ds(owner: &str, ds: &DnsDs, key: &DnsDnskey) -> CoreResult<bool> {`
- `pub fn verify_rrsig_at( owner: &str, rrset: &[DnsRecord], rrsig: &DnsRrsig, dnskey: &DnsDnskey, now: u32, ) -> CoreResult<()> {`
- `pub fn verify_rrsig( owner: &str, rrset: &[DnsRecord], rrsig: &DnsRrsig, dnskey: &DnsDnskey, ) -> CoreResult<()> {`
- `pub fn nsec_type_bitmap_contains(type_bitmaps: &[u8], rr_type: u16) -> CoreResult<bool> {`
- `pub fn nsec_type_bitmap_list(type_bitmaps: &[u8]) -> CoreResult<Vec<u16>> {`
- `pub fn nsec_type_bitmap_build(types: &[u16]) -> Vec<u8> {`
- `pub fn nsec_covers(name: &str, owner: &str, next: &str) -> bool {`
- `pub fn nsec3_hash(name: &str, iterations: u16, salt: &[u8]) -> Vec<u8> {`
- `pub fn nsec3_hash_base32(name: &str, iterations: u16, salt: &[u8]) -> String {`
- `pub fn nsec3_covers(name_hash: &[u8], owner_hash: &[u8], next_hash: &[u8]) -> bool {`
- `pub async fn serve_http2<F>(&self, addr: SocketAddr, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static, {`
- `pub async fn serve_http2_tls<F>( &self, addr: SocketAddr, tls: &TlsServerConfig, handler: F, ) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static, {`
- `pub async fn serve_http3<F>( &self, addr: SocketAddr, cert_path: &str, key_path: &str, handler: F, ) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static, {`
- `pub fn serve_tcp<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static, {`
- `pub fn serve_tls<F>(&self, config: &TlsServerConfig, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static, {`
- `pub async fn serve_tcp<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static, {`
- `pub async fn serve_tls<F>(&self, config: &TlsServerConfig, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static, {`

### Methods
- `AsyncDnsClient`
  - `pub fn new(server: SocketAddr, timeouts: Timeouts) -> Self`
  - `pub async fn query_udp(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
  - `pub async fn query_tcp(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
  - `pub async fn query_tls( &self, message: &DnsMessage, server_name: &str, tls: &TlsClientConfig, ) -> CoreResult<DnsMessage>`
- `AsyncDnsServer`
  - `pub fn new(udp_addr: SocketAddr, tcp_addr: SocketAddr) -> Self`
  - `pub async fn serve_udp<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,`
- `AsyncDoh2Client`
  - `pub fn new(url: &str, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn max_packet(mut self, max_packet: usize) -> Self`
  - `pub async fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
- `AsyncDoh3Client`
  - `pub fn new(url: &str) -> CoreResult<Self>`
  - `pub fn max_packet(mut self, max_packet: usize) -> Self`
  - `pub async fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
- `AsyncDohClient`
  - `pub fn new(url: &str, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn max_packet(mut self, max_packet: usize) -> Self`
  - `pub async fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
- `AsyncMdnsClient`
  - `pub async fn bind_v4() -> CoreResult<Self>`
  - `pub async fn bind_v6() -> CoreResult<Self>`
  - `pub async fn send_query(&self, message: &DnsMessage) -> CoreResult<()>`
  - `pub async fn send_query_v6(&self, message: &DnsMessage) -> CoreResult<()>`
  - `pub async fn recv(&self, max_bytes: usize) -> CoreResult<(DnsMessage, SocketAddr)>`
- `AsyncMdnsServer`
  - `pub async fn bind_v4() -> CoreResult<Self>`
  - `pub async fn bind_v6() -> CoreResult<Self>`
  - `pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,`
- `DnsClient`
  - `pub fn new(server: SocketAddr, timeouts: Timeouts) -> Self`
  - `pub fn max_packet(mut self, max_packet: usize) -> Self`
  - `pub fn query_udp(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
  - `pub fn query_tcp(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
  - `pub fn query_tls( &self, message: &DnsMessage, server_name: &str, tls: &TlsClientConfig, ) -> CoreResult<DnsMessage>`
- `DnsFlags`
  - `pub fn to_bits(self) -> u16`
  - `pub fn from_bits(bits: u16) -> Self`
- `DnsMessage`
  - `pub fn new_query(id: u16, name: impl Into<String>, qtype: u16) -> Self`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(bytes: &[u8]) -> CoreResult<Self>`
- `DnsOption`
  - `pub fn ecs(family: u16, source_prefix: u8, scope_prefix: u8, address: Vec<u8>) -> Self`
  - `pub fn cookie(client: &[u8], server: Option<&[u8]>) -> Self`
  - `pub fn padding(len: usize) -> Self`
  - `pub fn tcp_keepalive(timeout: Option<u16>) -> Self`
  - `pub fn nsid() -> Self`
  - `pub fn dau(algs: &[u8]) -> Self`
  - `pub fn dhu(algs: &[u8]) -> Self`
  - `pub fn n3u(algs: &[u8]) -> Self`
  - `pub fn expire(seconds: u32) -> Self`
  - `pub fn chain(data: Vec<u8>) -> Self`
  - `pub fn key_tag(tags: &[u16]) -> Self`
  - `pub fn ede(code: u16, text: Option<&str>) -> Self`
  - `pub fn parse_ecs(&self) -> Option<DnsClientSubnet>`
  - `pub fn parse(&self) -> CoreResult<DnsOptionValue>`
- `DnsRecord`
  - `pub fn mdns_cache_flush(&self) -> bool`
  - `pub fn mdns_class(&self) -> u16`
  - `pub fn set_mdns_cache_flush(&mut self, enabled: bool)`
- `DnsServer`
  - `pub fn new(udp_addr: SocketAddr, tcp_addr: SocketAddr) -> Self`
  - `pub fn serve_udp<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,`
- `DohClient`
  - `pub fn new(url: &str, timeouts: Timeouts) -> CoreResult<Self>`
  - `pub fn max_packet(mut self, max_packet: usize) -> Self`
  - `pub fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage>`
- `DohServer`
  - `pub fn new() -> Self`
  - `pub fn path(mut self, path: impl Into<String>) -> Self`
  - `pub fn max_packet(mut self, max_packet: usize) -> Self`
  - `pub fn serve_http<F>(&self, addr: SocketAddr, timeouts: Timeouts, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,`
- `MdnsClient`
  - `pub fn bind_v4() -> CoreResult<Self>`
  - `pub fn bind_v6() -> CoreResult<Self>`
  - `pub fn send_query(&self, message: &DnsMessage) -> CoreResult<()>`
  - `pub fn send_query_v6(&self, message: &DnsMessage) -> CoreResult<()>`
  - `pub fn recv(&self, max_bytes: usize) -> CoreResult<(DnsMessage, SocketAddr)>`
- `MdnsServer`
  - `pub fn bind_v4() -> CoreResult<Self>`
  - `pub fn bind_v6() -> CoreResult<Self>`
  - `pub fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/dns/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

