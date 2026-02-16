# AMQP Protocol

## Location
`network/proto/src/amqp/`

## Overview
This module provides a full AMQP protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AmqpClient`
- `AmqpClientConfig`
- `AmqpContentHeader`
- `AmqpDeliveredMessage`
- `AmqpFrame`
- `AmqpMethod`
- `AmqpServer`
- `AmqpServerConfig`
- `AsyncAmqpClient`
- `AsyncAmqpServer`
- `InMemoryAmqpBroker`

### Traits
- `AmqpBroker`

## Key Entry Points
### Clients
- `AmqpClient`
- `AmqpClientConfig`
- `AsyncAmqpClient`

### Servers
- `AmqpServer`
- `AmqpServerConfig`
- `AsyncAmqpServer`

### Free Functions
- `pub fn basic_consume( &mut self, channel: u16, queue: &str, consumer_tag: &str, ) -> CoreResult<()> {`
- `pub fn consume_next(&mut self) -> CoreResult<AmqpDeliveredMessage> {`
- `pub async fn basic_consume( &mut self, channel: u16, queue: &str, consumer_tag: &str, ) -> CoreResult<()> {`
- `pub async fn consume_next(&mut self) -> CoreResult<AmqpDeliveredMessage> {`
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn serve(&self) -> CoreResult<()> {`

### Methods
- `AmqpClient`
  - `pub fn connect(addr: &NetAddr, config: AmqpClientConfig) -> CoreResult<Self>`
  - `pub fn handshake(&mut self) -> CoreResult<()>`
  - `pub fn channel_open(&mut self, channel: u16) -> CoreResult<()>`
  - `pub fn queue_declare(&mut self, channel: u16, queue: &str) -> CoreResult<()>`
  - `pub fn basic_publish( &mut self, channel: u16, exchange: &str, routing_key: &str, body: &[u8], ) -> CoreResult<()>`
- `AmqpContentHeader`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(payload: &[u8]) -> CoreResult<Self>`
- `AmqpFrame`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `AmqpMethod`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(payload: &[u8]) -> CoreResult<Self>`
- `AmqpServer`
  - `pub fn bind( addr: SocketAddr, config: AmqpServerConfig, broker: Arc<dyn AmqpBroker>, ) -> CoreResult<Self>`
- `AsyncAmqpClient`
  - `pub async fn connect(addr: &NetAddr, config: AmqpClientConfig) -> CoreResult<Self>`
  - `pub async fn handshake(&mut self) -> CoreResult<()>`
  - `pub async fn channel_open(&mut self, channel: u16) -> CoreResult<()>`
  - `pub async fn queue_declare(&mut self, channel: u16, queue: &str) -> CoreResult<()>`
  - `pub async fn basic_publish( &mut self, channel: u16, exchange: &str, routing_key: &str, body: &[u8], ) -> CoreResult<()>`
- `AsyncAmqpServer`
  - `pub async fn bind( addr: SocketAddr, config: AmqpServerConfig, broker: Arc<dyn AmqpBroker>, ) -> CoreResult<Self>`
- `InMemoryAmqpBroker`
  - `pub fn with_queue(self, name: &str) -> Self`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/amqp/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

