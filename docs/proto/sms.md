# SMS Protocol

## Location
`network/proto/src/sms/`

## Overview
This module provides a full SMS protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AsyncSmsClient`
- `AsyncSmsServer`
- `InMemorySmsHandler`
- `SmsBind`
- `SmsClient`
- `SmsClientConfig`
- `SmsDeliver`
- `SmsError`
- `SmsFrame`
- `SmsServer`
- `SmsServerConfig`
- `SmsStatus`
- `SmsSubmit`

### Enums
- `SmsCommand`
- `SmsDeliveryStatus`
- `SmsMessage`

### Traits
- `SmsHandler`

### Constants
- `SMS_DEFAULT_PORT`

## Key Entry Points
### Clients
- `AsyncSmsClient`
- `SmsClient`
- `SmsClientConfig`

### Servers
- `AsyncSmsServer`
- `SmsServer`
- `SmsServerConfig`

### Free Functions
- `pub fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub fn serve(&self) -> CoreResult<()> {`
- `pub async fn local_addr(&self) -> CoreResult<SocketAddr> {`
- `pub async fn serve(&self) -> CoreResult<()> {`
- `pub async fn unbind(&mut self) -> CoreResult<()> {`

### Methods
- `AsyncSmsClient`
  - `pub async fn connect(addr: &NetAddr, config: SmsClientConfig) -> CoreResult<Self>`
  - `pub async fn bind(&mut self, system_id: &str, password: &str) -> CoreResult<()>`
  - `pub async fn submit(&mut self, submit: SmsSubmit) -> CoreResult<SmsStatus>`
  - `pub async fn status(&mut self, message_id: &str) -> CoreResult<SmsStatus>`
  - `pub async fn next_delivery(&mut self) -> CoreResult<SmsDeliver>`
  - `pub async fn ack_delivery( &mut self, message_id: &str, status: SmsDeliveryStatus, ) -> CoreResult<()>`
- `AsyncSmsServer`
  - `pub async fn bind( addr: SocketAddr, handler: Arc<dyn SmsHandler>, config: SmsServerConfig, ) -> CoreResult<Self>`
- `InMemorySmsHandler`
  - `pub fn new(users: HashMap<String, String>) -> Self`
  - `pub fn add_user(&mut self, system_id: impl Into<String>, password: impl Into<String>)`
  - `pub fn enqueue_delivery(&self, system_id: &str, mut deliver: SmsDeliver)`
- `SmsClient`
  - `pub fn connect(addr: &NetAddr, config: SmsClientConfig) -> CoreResult<Self>`
  - `pub fn bind(&mut self, system_id: &str, password: &str) -> CoreResult<()>`
  - `pub fn submit(&mut self, submit: SmsSubmit) -> CoreResult<SmsStatus>`
  - `pub fn status(&mut self, message_id: &str) -> CoreResult<SmsStatus>`
  - `pub fn next_delivery(&mut self) -> CoreResult<SmsDeliver>`
  - `pub fn ack_delivery(&mut self, message_id: &str, status: SmsDeliveryStatus) -> CoreResult<()>`
  - `pub fn unbind(&mut self) -> CoreResult<()>`
- `SmsFrame`
  - `pub fn encode(&self) -> Vec<u8>`
- `SmsServer`
  - `pub fn bind( addr: SocketAddr, handler: Arc<dyn SmsHandler>, config: SmsServerConfig, ) -> CoreResult<Self>`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/sms/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

