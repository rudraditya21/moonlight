# KADEMLIA Protocol

## Location
`network/proto/src/kademlia/`

## Overview
This module provides a full KADEMLIA protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncKademliaClient`
- `AsyncKademliaServer`
- `InMemoryStore`
- `KademliaClient`
- `KademliaConfig`
- `KademliaServer`
- `NodeId`
- `NodeInfo`

### Enums
- `Bencode`
- `KrpcMessage`

### Traits
- `KademliaStore`

### Constants
- `KADEMLIA_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncKademliaClient`
- `KademliaClient`

### Servers
- `AsyncKademliaServer`
- `KademliaServer`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AsyncKademliaClient`
  - `pub async fn connect(config: KademliaConfig) -> CoreResult<Self>`
  - `pub async fn ping(&self, addr: SocketAddr) -> CoreResult<NodeId>`
- `AsyncKademliaServer`
  - `pub async fn bind( addr: SocketAddr, config: KademliaConfig, store: Arc<dyn KademliaStore>, ) -> CoreResult<Self>`
- `InMemoryStore`
  - `pub fn new() -> Self`
- `KademliaClient`
  - `pub fn connect(config: KademliaConfig) -> CoreResult<Self>`
  - `pub fn ping(&self, addr: SocketAddr) -> CoreResult<NodeId>`
  - `pub fn find_node(&self, addr: SocketAddr, target: NodeId) -> CoreResult<Vec<NodeInfo>>`
  - `pub fn find_value(&self, addr: SocketAddr, key: &[u8]) -> CoreResult<Option<Vec<u8>>>`
  - `pub fn store( &self, addr: SocketAddr, key: &[u8], value: &[u8], token: Option<Vec<u8>>, ) -> CoreResult<()>`
- `KademliaServer`
  - `pub fn bind( addr: SocketAddr, config: KademliaConfig, store: Arc<dyn KademliaStore>, ) -> CoreResult<Self>`
- `NodeId`
  - `pub fn from_seed(seed: u64) -> Self`
  - `pub fn xor_distance(&self, other: &NodeId) -> [u8; NODE_ID_LEN]`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/kademlia/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

