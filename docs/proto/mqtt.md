# MQTT Protocol

## Location
`network/proto/src/mqtt/`

## Overview
This module provides a full MQTT protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncMqttClient`
- `AsyncMqttServer`
- `MqttClient`
- `MqttClientConfig`
- `MqttServer`
- `MqttServerConfig`

### Enums
- `MqttPacket`
- `MqttPacketType`

## Key Entry Points
### Clients
- `AsyncMqttClient`
- `MqttClient`
- `MqttClientConfig`

### Servers
- `AsyncMqttServer`
- `MqttServer`
- `MqttServerConfig`

### Methods
- `AsyncMqttClient`
  - `pub async fn connect(addr: &NetAddr, config: MqttClientConfig) -> CoreResult<Self>`
  - `pub async fn publish(&mut self, topic: &str, payload: Vec<u8>, qos: u8) -> CoreResult<()>`
  - `pub async fn subscribe(&mut self, topics: Vec<(String, u8)>) -> CoreResult<()>`
  - `pub async fn recv(&mut self) -> CoreResult<MqttPacket>`
- `AsyncMqttServer`
  - `pub async fn bind(addr: SocketAddr, config: MqttServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub async fn serve(&self) -> CoreResult<()>`
- `MqttClient`
  - `pub fn connect(addr: &NetAddr, config: MqttClientConfig) -> CoreResult<Self>`
  - `pub fn publish(&mut self, topic: &str, payload: Vec<u8>, qos: u8) -> CoreResult<()>`
  - `pub fn subscribe(&mut self, topics: Vec<(String, u8)>) -> CoreResult<()>`
  - `pub fn ping(&mut self) -> CoreResult<()>`
  - `pub fn recv(&mut self) -> CoreResult<MqttPacket>`
- `MqttPacket`
  - `pub fn encode(&self) -> CoreResult<Vec<u8>>`
  - `pub fn decode(mut data: &[u8]) -> CoreResult<Self>`
- `MqttServer`
  - `pub fn bind(addr: SocketAddr, config: MqttServerConfig) -> CoreResult<Self>`
  - `pub fn local_addr(&self) -> CoreResult<SocketAddr>`
  - `pub fn serve(&self) -> CoreResult<()>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/mqtt/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

