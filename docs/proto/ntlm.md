# NTLM Protocol

## Location
`network/proto/src/ntlm/`

## Overview
This module provides a full NTLM protocol implementation intended for use by Moonlight modules. Use the public types and functions below as the stable entry points.

## Public Types
### Structs
- `AuthenticateMessage`
- `ChallengeMessage`
- `NegotiateMessage`
- `NtlmClient`
- `NtlmClientConfig`
- `NtlmSealer`
- `NtlmServer`
- `NtlmServerConfig`
- `NtlmSession`
- `NtlmSigner`
- `Version`

### Enums
- `AvPair`
- `NtlmMessage`
- `NtlmSecret`

### Constants
- `NEGOTIATE_128`
- `NEGOTIATE_56`
- `NEGOTIATE_ALWAYS_SIGN`
- `NEGOTIATE_DATAGRAM`
- `NEGOTIATE_EXTENDED_SESSIONSECURITY`
- `NEGOTIATE_KEY_EXCH`
- `NEGOTIATE_LM_KEY`
- `NEGOTIATE_NTLM`
- `NEGOTIATE_OEM`
- `NEGOTIATE_OEM_DOMAIN_SUPPLIED`
- `NEGOTIATE_OEM_WORKSTATION_SUPPLIED`
- `NEGOTIATE_SEAL`
- `NEGOTIATE_SIGN`
- `NEGOTIATE_TARGET_INFO`
- `NEGOTIATE_UNICODE`
- `NEGOTIATE_VERSION`
- `REQUEST_TARGET`
- `TARGET_TYPE_DOMAIN`
- `TARGET_TYPE_SERVER`

## Key Entry Points
### Clients
- `NtlmClient`
- `NtlmClientConfig`

### Servers
- `NtlmServer`
- `NtlmServerConfig`

### Free Functions
- `pub fn default_flags() -> u32 {`
- `pub fn encode_http_token(message: &NtlmMessage) -> String {`
- `pub fn decode_http_token(header_value: &str) -> CoreResult<NtlmMessage> {`
- `pub fn encode(data: impl AsRef<[u8]>) -> String {`

### Methods
- `AuthenticateMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `ChallengeMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `NegotiateMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `NtlmClient`
  - `pub fn new(config: NtlmClientConfig) -> Self`
  - `pub fn negotiate(&self) -> NegotiateMessage`
  - `pub fn respond( &self, challenge: &ChallengeMessage, ) -> CoreResult<(AuthenticateMessage, NtlmSession)>`
- `NtlmMessage`
  - `pub fn encode(&self) -> Vec<u8>`
  - `pub fn decode(data: &[u8]) -> CoreResult<Self>`
- `NtlmSealer`
  - `pub fn new(sealing_key: [u8; 16], signing_key: [u8; 16]) -> Self`
  - `pub fn seal(&mut self, message: &[u8]) -> (Vec<u8>, [u8; 16])`
- `NtlmServer`
  - `pub fn new(config: NtlmServerConfig) -> Self`
  - `pub fn challenge(&self, negotiate: &NegotiateMessage) -> ChallengeMessage`
  - `pub fn authenticate( &self, challenge: &ChallengeMessage, authenticate: &AuthenticateMessage, ) -> CoreResult<NtlmSession>`
- `NtlmSigner`
  - `pub fn new(key: [u8; 16]) -> Self`
  - `pub fn sign(&mut self, message: &[u8]) -> [u8; 16]`
- `Version`
  - `pub fn windows_10() -> Self`

## Usage Notes
- Start with the client or server structs listed above, then follow their constructors and connect/bind/listen methods if present.
- Encode and decode helpers are exposed as public functions or methods in this module; use them to build protocol frames.
- When in doubt, search for the types above in the code to find concrete examples and tests in the same module directory.

## Tests and Examples
- Unit tests live alongside the implementation in `network/proto/src/ntlm/`.
- Protocol‑level fuzz/negative tests are located in `network/proto/tests/negative_fuzz.rs` where applicable.

