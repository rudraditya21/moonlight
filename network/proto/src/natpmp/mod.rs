use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

pub const NATPMP_DEFAULT_PORT: u16 = 5351;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatPmpOpcode {
    PublicAddress = 0,
    MapUdp = 1,
    MapTcp = 2,
}

impl NatPmpOpcode {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            0 => Ok(NatPmpOpcode::PublicAddress),
            1 => Ok(NatPmpOpcode::MapUdp),
            2 => Ok(NatPmpOpcode::MapTcp),
            _ => Err(CoreError::Parse("natpmp invalid opcode".to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatPmpResultCode {
    Success = 0,
    UnsupportedVersion = 1,
    NotAuthorized = 2,
    NetworkFailure = 3,
    OutOfResources = 4,
    UnsupportedOpcode = 5,
}

impl NatPmpResultCode {
    fn from_u16(value: u16) -> Self {
        match value {
            0 => NatPmpResultCode::Success,
            1 => NatPmpResultCode::UnsupportedVersion,
            2 => NatPmpResultCode::NotAuthorized,
            3 => NatPmpResultCode::NetworkFailure,
            4 => NatPmpResultCode::OutOfResources,
            5 => NatPmpResultCode::UnsupportedOpcode,
            _ => NatPmpResultCode::NetworkFailure,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatPmpRequest {
    PublicAddress,
    Map {
        opcode: NatPmpOpcode,
        internal_port: u16,
        requested_external_port: u16,
        lifetime: u32,
    },
}

impl NatPmpRequest {
    pub fn public_address() -> Self {
        NatPmpRequest::PublicAddress
    }

    pub fn map_udp(internal_port: u16, requested_external_port: u16, lifetime: u32) -> Self {
        NatPmpRequest::Map {
            opcode: NatPmpOpcode::MapUdp,
            internal_port,
            requested_external_port,
            lifetime,
        }
    }

    pub fn map_tcp(internal_port: u16, requested_external_port: u16, lifetime: u32) -> Self {
        NatPmpRequest::Map {
            opcode: NatPmpOpcode::MapTcp,
            internal_port,
            requested_external_port,
            lifetime,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.push(0u8);
        match self {
            NatPmpRequest::PublicAddress => {
                out.push(NatPmpOpcode::PublicAddress as u8);
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&[0u8; 8]);
            }
            NatPmpRequest::Map {
                opcode,
                internal_port,
                requested_external_port,
                lifetime,
            } => {
                out.push(*opcode as u8);
                out.extend_from_slice(&[0u8; 2]);
                out.extend_from_slice(&internal_port.to_be_bytes());
                out.extend_from_slice(&requested_external_port.to_be_bytes());
                out.extend_from_slice(&lifetime.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 2 {
            return Err(CoreError::Parse("natpmp request too short".to_string()));
        }
        let version = data[0];
        if version != 0 {
            return Err(CoreError::Parse("natpmp unsupported version".to_string()));
        }
        let opcode = NatPmpOpcode::from_u8(data[1])?;
        match opcode {
            NatPmpOpcode::PublicAddress => Ok(NatPmpRequest::PublicAddress),
            NatPmpOpcode::MapUdp | NatPmpOpcode::MapTcp => {
                if data.len() < 12 {
                    return Err(CoreError::Parse("natpmp map request".to_string()));
                }
                let internal_port = u16::from_be_bytes([data[4], data[5]]);
                let requested_external_port = u16::from_be_bytes([data[6], data[7]]);
                let lifetime = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                Ok(NatPmpRequest::Map {
                    opcode,
                    internal_port,
                    requested_external_port,
                    lifetime,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatPmpResponse {
    PublicAddress {
        result: NatPmpResultCode,
        epoch: u32,
        address: Ipv4Addr,
    },
    Map {
        opcode: NatPmpOpcode,
        result: NatPmpResultCode,
        epoch: u32,
        internal_port: u16,
        external_port: u16,
        lifetime: u32,
    },
}

impl NatPmpResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.push(0u8);
        match self {
            NatPmpResponse::PublicAddress {
                result,
                epoch,
                address,
            } => {
                out.push((NatPmpOpcode::PublicAddress as u8) | 0x80);
                out.extend_from_slice(&(*result as u16).to_be_bytes());
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&address.octets());
            }
            NatPmpResponse::Map {
                opcode,
                result,
                epoch,
                internal_port,
                external_port,
                lifetime,
            } => {
                out.push((*opcode as u8) | 0x80);
                out.extend_from_slice(&(*result as u16).to_be_bytes());
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&internal_port.to_be_bytes());
                out.extend_from_slice(&external_port.to_be_bytes());
                out.extend_from_slice(&lifetime.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 8 {
            return Err(CoreError::Parse("natpmp response too short".to_string()));
        }
        if data[0] != 0 {
            return Err(CoreError::Parse("natpmp response version".to_string()));
        }
        let opcode = data[1] & 0x7f;
        let opcode = NatPmpOpcode::from_u8(opcode)?;
        let result = NatPmpResultCode::from_u16(u16::from_be_bytes([data[2], data[3]]));
        let epoch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        match opcode {
            NatPmpOpcode::PublicAddress => {
                if data.len() < 12 {
                    return Err(CoreError::Parse("natpmp response addr".to_string()));
                }
                let address = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
                Ok(NatPmpResponse::PublicAddress {
                    result,
                    epoch,
                    address,
                })
            }
            NatPmpOpcode::MapUdp | NatPmpOpcode::MapTcp => {
                if data.len() < 16 {
                    return Err(CoreError::Parse("natpmp response map".to_string()));
                }
                let internal_port = u16::from_be_bytes([data[8], data[9]]);
                let external_port = u16::from_be_bytes([data[10], data[11]]);
                let lifetime = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
                Ok(NatPmpResponse::Map {
                    opcode,
                    result,
                    epoch,
                    internal_port,
                    external_port,
                    lifetime,
                })
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NatPmpClientConfig {
    pub timeouts: Timeouts,
}

impl Default for NatPmpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct NatPmpClient {
    transport: UdpTransport,
    gateway: SocketAddr,
}

impl NatPmpClient {
    pub fn new(gateway: SocketAddr, config: NatPmpClientConfig) -> CoreResult<Self> {
        let transport = UdpTransport::bind_any()?;
        transport.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { transport, gateway })
    }

    pub fn public_address(&self) -> CoreResult<Ipv4Addr> {
        let request = NatPmpRequest::public_address();
        let response = self.send_request(&request)?;
        match response {
            NatPmpResponse::PublicAddress { result, address, .. } => match result {
                NatPmpResultCode::Success => Ok(address),
                _ => Err(CoreError::Message("natpmp failed".to_string())),
            },
            _ => Err(CoreError::Parse("natpmp unexpected response".to_string())),
        }
    }

    pub fn map_udp(&self, internal_port: u16, requested_external: u16, lifetime: u32) -> CoreResult<NatPmpResponse> {
        let request = NatPmpRequest::map_udp(internal_port, requested_external, lifetime);
        self.send_request(&request)
    }

    pub fn map_tcp(&self, internal_port: u16, requested_external: u16, lifetime: u32) -> CoreResult<NatPmpResponse> {
        let request = NatPmpRequest::map_tcp(internal_port, requested_external, lifetime);
        self.send_request(&request)
    }

    fn send_request(&self, request: &NatPmpRequest) -> CoreResult<NatPmpResponse> {
        let payload = request.encode();
        self.transport.send_to(&payload, self.gateway)?;
        let (data, _) = self.transport.recv_from(1024)?;
        NatPmpResponse::decode(&data)
    }
}

#[derive(Debug, Clone)]
pub struct NatPmpServerConfig {
    pub timeouts: Timeouts,
    pub public_address: Ipv4Addr,
    pub port_range: RangeInclusive<u16>,
}

impl Default for NatPmpServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            public_address: Ipv4Addr::new(203, 0, 113, 1),
            port_range: 40000..=50000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MappingKey {
    opcode: NatPmpOpcode,
    internal_addr: Ipv4Addr,
    internal_port: u16,
}

#[derive(Debug, Clone)]
struct NatPmpLease {
    external_port: u16,
    expires_at: Instant,
}

struct NatPmpState {
    mappings: HashMap<MappingKey, NatPmpLease>,
    external_map: HashMap<u16, MappingKey>,
}

impl NatPmpState {
    fn new() -> Self {
        Self {
            mappings: HashMap::new(),
            external_map: HashMap::new(),
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .mappings
            .iter()
            .filter_map(|(key, lease)| if lease.expires_at <= now { Some((*key, lease.external_port)) } else { None })
            .collect();
        for (key, port) in expired {
            self.mappings.remove(&key);
            self.external_map.remove(&port);
        }
    }

    fn is_port_free(&self, port: u16) -> bool {
        !self.external_map.contains_key(&port)
    }

    fn allocate_port(&self, requested: u16, range: &RangeInclusive<u16>) -> Option<u16> {
        if requested != 0 && self.is_port_free(requested) {
            return Some(requested);
        }
        for port in range.clone() {
            if self.is_port_free(port) {
                return Some(port);
            }
        }
        None
    }
}

pub struct NatPmpServer {
    socket: UdpTransport,
    config: NatPmpServerConfig,
    state: Arc<Mutex<NatPmpState>>,
    start: Instant,
}

impl NatPmpServer {
    pub fn bind(addr: SocketAddr, config: NatPmpServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            config,
            state: Arc::new(Mutex::new(NatPmpState::new())),
            start: Instant::now(),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = match self.socket.recv_from(1500) {
                Ok(value) => value,
                Err(CoreError::Io(err))
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            };
            let response = self.handle_request(peer, &data);
            if let Ok(resp) = response {
                let _ = self.socket.send_to(&resp.encode(), peer);
            }
        }
    }

    fn handle_request(&self, peer: SocketAddr, data: &[u8]) -> CoreResult<NatPmpResponse> {
        let epoch = self.start.elapsed().as_secs() as u32;
        let request = match NatPmpRequest::decode(data) {
            Ok(req) => req,
            Err(_) => {
                return Ok(NatPmpResponse::PublicAddress {
                    result: NatPmpResultCode::UnsupportedVersion,
                    epoch,
                    address: self.config.public_address,
                });
            }
        };
        let internal_addr = match peer {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => return Ok(NatPmpResponse::PublicAddress {
                result: NatPmpResultCode::UnsupportedOpcode,
                epoch,
                address: self.config.public_address,
            }),
        };
        let mut state = self.state.lock().unwrap();
        state.cleanup();
        match request {
            NatPmpRequest::PublicAddress => Ok(NatPmpResponse::PublicAddress {
                result: NatPmpResultCode::Success,
                epoch,
                address: self.config.public_address,
            }),
            NatPmpRequest::Map {
                opcode,
                internal_port,
                requested_external_port,
                lifetime,
            } => {
                let key = MappingKey {
                    opcode,
                    internal_addr,
                    internal_port,
                };
                if lifetime == 0 {
                    let external_port = if let Some(lease) = state.mappings.remove(&key) {
                        state.external_map.remove(&lease.external_port);
                        lease.external_port
                    } else {
                        0
                    };
                    return Ok(NatPmpResponse::Map {
                        opcode,
                        result: NatPmpResultCode::Success,
                        epoch,
                        internal_port,
                        external_port,
                        lifetime: 0,
                    });
                }
                let existing_port = state.mappings.get(&key).map(|lease| lease.external_port);
                let external_port = match existing_port {
                    Some(port) => {
                        if requested_external_port != 0 && requested_external_port != port {
                            if state.is_port_free(requested_external_port) {
                                state.external_map.remove(&port);
                                requested_external_port
                            } else {
                                port
                            }
                        } else {
                            port
                        }
                    }
                    None => match state.allocate_port(requested_external_port, &self.config.port_range) {
                        Some(port) => port,
                        None => {
                            return Ok(NatPmpResponse::Map {
                                opcode,
                                result: NatPmpResultCode::OutOfResources,
                                epoch,
                                internal_port,
                                external_port: 0,
                                lifetime: 0,
                            })
                        }
                    },
                };
                let expires_at = Instant::now() + Duration::from_secs(lifetime as u64);
                state.mappings.insert(
                    key,
                    NatPmpLease {
                        external_port,
                        expires_at,
                    },
                );
                state.external_map.insert(external_port, key);
                Ok(NatPmpResponse::Map {
                    opcode,
                    result: NatPmpResultCode::Success,
                    epoch,
                    internal_port,
                    external_port,
                    lifetime,
                })
            }
        }
    }
}

pub struct AsyncNatPmpServer {
    socket: AsyncUdpTransport,
    config: NatPmpServerConfig,
    state: Arc<Mutex<NatPmpState>>,
    start: Instant,
}

impl AsyncNatPmpServer {
    pub async fn bind(addr: SocketAddr, config: NatPmpServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            config,
            state: Arc::new(Mutex::new(NatPmpState::new())),
            start: Instant::now(),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(1500).await?;
            let response = self.handle_request(peer, &data);
            if let Ok(resp) = response {
                let _ = self.socket.send_to(&resp.encode(), peer).await;
            }
        }
    }

    fn handle_request(&self, peer: SocketAddr, data: &[u8]) -> CoreResult<NatPmpResponse> {
        let epoch = self.start.elapsed().as_secs() as u32;
        let request = match NatPmpRequest::decode(data) {
            Ok(req) => req,
            Err(_) => {
                return Ok(NatPmpResponse::PublicAddress {
                    result: NatPmpResultCode::UnsupportedVersion,
                    epoch,
                    address: self.config.public_address,
                });
            }
        };
        let internal_addr = match peer {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => return Ok(NatPmpResponse::PublicAddress {
                result: NatPmpResultCode::UnsupportedOpcode,
                epoch,
                address: self.config.public_address,
            }),
        };
        let mut state = self.state.lock().unwrap();
        state.cleanup();
        match request {
            NatPmpRequest::PublicAddress => Ok(NatPmpResponse::PublicAddress {
                result: NatPmpResultCode::Success,
                epoch,
                address: self.config.public_address,
            }),
            NatPmpRequest::Map {
                opcode,
                internal_port,
                requested_external_port,
                lifetime,
            } => {
                let key = MappingKey {
                    opcode,
                    internal_addr,
                    internal_port,
                };
                if lifetime == 0 {
                    let external_port = if let Some(lease) = state.mappings.remove(&key) {
                        state.external_map.remove(&lease.external_port);
                        lease.external_port
                    } else {
                        0
                    };
                    return Ok(NatPmpResponse::Map {
                        opcode,
                        result: NatPmpResultCode::Success,
                        epoch,
                        internal_port,
                        external_port,
                        lifetime: 0,
                    });
                }
                let existing_port = state.mappings.get(&key).map(|lease| lease.external_port);
                let external_port = match existing_port {
                    Some(port) => {
                        if requested_external_port != 0 && requested_external_port != port {
                            if state.is_port_free(requested_external_port) {
                                state.external_map.remove(&port);
                                requested_external_port
                            } else {
                                port
                            }
                        } else {
                            port
                        }
                    }
                    None => match state.allocate_port(requested_external_port, &self.config.port_range) {
                        Some(port) => port,
                        None => {
                            return Ok(NatPmpResponse::Map {
                                opcode,
                                result: NatPmpResultCode::OutOfResources,
                                epoch,
                                internal_port,
                                external_port: 0,
                                lifetime: 0,
                            })
                        }
                    },
                };
                let expires_at = Instant::now() + Duration::from_secs(lifetime as u64);
                state.mappings.insert(
                    key,
                    NatPmpLease {
                        external_port,
                        expires_at,
                    },
                );
                state.external_map.insert(external_port, key);
                Ok(NatPmpResponse::Map {
                    opcode,
                    result: NatPmpResultCode::Success,
                    epoch,
                    internal_port,
                    external_port,
                    lifetime,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn natpmp_public_address() {
        let server = crate::skip_if_perm!(NatPmpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            NatPmpServerConfig {
                public_address: Ipv4Addr::new(10, 0, 0, 1),
                ..NatPmpServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let client = NatPmpClient::new(addr, NatPmpClientConfig::default()).unwrap();
        let address = client.public_address().unwrap();
        assert_eq!(address, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn natpmp_map_udp() {
        let server = crate::skip_if_perm!(NatPmpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            NatPmpServerConfig {
                public_address: Ipv4Addr::new(198, 51, 100, 10),
                port_range: 45000..=45010,
                ..NatPmpServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let client = NatPmpClient::new(addr, NatPmpClientConfig::default()).unwrap();
        let response = client.map_udp(8080, 45001, 3600).unwrap();
        match response {
            NatPmpResponse::Map {
                result,
                external_port,
                lifetime,
                ..
            } => {
                assert_eq!(result, NatPmpResultCode::Success);
                assert_eq!(external_port, 45001);
                assert_eq!(lifetime, 3600);
            }
            _ => panic!("unexpected response"),
        }
    }
}
