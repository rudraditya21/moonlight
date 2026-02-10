use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

pub const MSNRTP_DEFAULT_PORT: u16 = 5355;

const MAGIC: [u8; 4] = *b"NRTP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrtpMessageType {
    Register = 1,
    Resolve = 2,
    Unregister = 3,
    Response = 4,
}

#[derive(Debug, Clone)]
pub struct NrtpMessage {
    pub msg_type: NrtpMessageType,
    pub id: u16,
    pub name: String,
    pub addresses: Vec<SocketAddr>,
    pub status: u8,
}

impl NrtpMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.push(self.status);
        out.extend_from_slice(&(self.name.len() as u16).to_be_bytes());
        out.extend_from_slice(self.name.as_bytes());
        out.push(self.addresses.len() as u8);
        for addr in &self.addresses {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    out.push(4);
                    out.extend_from_slice(&addr.port().to_be_bytes());
                    out.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.push(6);
                    out.extend_from_slice(&addr.port().to_be_bytes());
                    out.extend_from_slice(&ip.octets());
                }
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 9 {
            return Err(CoreError::Parse("nrtp packet too short".to_string()));
        }
        if &data[..4] != MAGIC {
            return Err(CoreError::Parse("nrtp bad magic".to_string()));
        }
        let msg_type = match data[4] {
            1 => NrtpMessageType::Register,
            2 => NrtpMessageType::Resolve,
            3 => NrtpMessageType::Unregister,
            4 => NrtpMessageType::Response,
            _ => return Err(CoreError::Parse("nrtp invalid type".to_string())),
        };
        let id = u16::from_be_bytes([data[5], data[6]]);
        let status = data[7];
        let name_len = u16::from_be_bytes([data[8], data[9]]) as usize;
        let mut idx = 10;
        if idx + name_len > data.len() {
            return Err(CoreError::Parse("nrtp name bounds".to_string()));
        }
        let name = String::from_utf8_lossy(&data[idx..idx + name_len]).to_string();
        idx += name_len;
        if idx >= data.len() {
            return Err(CoreError::Parse("nrtp addr count".to_string()));
        }
        let count = data[idx] as usize;
        idx += 1;
        let mut addresses = Vec::new();
        for _ in 0..count {
            if idx + 3 > data.len() {
                return Err(CoreError::Parse("nrtp addr header".to_string()));
            }
            let kind = data[idx];
            let port = u16::from_be_bytes([data[idx + 1], data[idx + 2]]);
            idx += 3;
            match kind {
                4 => {
                    if idx + 4 > data.len() {
                        return Err(CoreError::Parse("nrtp addr v4".to_string()));
                    }
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(data[idx], data[idx + 1], data[idx + 2], data[idx + 3]));
                    idx += 4;
                    addresses.push(SocketAddr::new(ip, port));
                }
                6 => {
                    if idx + 16 > data.len() {
                        return Err(CoreError::Parse("nrtp addr v6".to_string()));
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[idx..idx + 16]);
                    idx += 16;
                    addresses.push(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port));
                }
                _ => return Err(CoreError::Parse("nrtp addr type".to_string())),
            }
        }
        Ok(Self {
            msg_type,
            id,
            name,
            addresses,
            status,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NrtpServerConfig {
    pub timeouts: Timeouts,
}

impl Default for NrtpServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

#[derive(Debug, Default)]
struct NameTable {
    entries: HashMap<String, Vec<SocketAddr>>,
}

impl NameTable {
    fn register(&mut self, name: String, addresses: Vec<SocketAddr>) {
        self.entries.insert(name, addresses);
    }

    fn resolve(&self, name: &str) -> Vec<SocketAddr> {
        self.entries.get(name).cloned().unwrap_or_default()
    }

    fn unregister(&mut self, name: &str) {
        self.entries.remove(name);
    }
}

pub struct NrtpServer {
    socket: UdpTransport,
    table: Arc<Mutex<NameTable>>,
}

impl NrtpServer {
    pub fn bind(addr: SocketAddr, config: NrtpServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            table: Arc::new(Mutex::new(NameTable::default())),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(2048)?;
            let socket = self.socket.clone();
            let table = Arc::clone(&self.table);
            thread::spawn(move || {
                let _ = handle_nrtp_request(socket, table, &data, peer);
            });
        }
    }
}

pub struct AsyncNrtpServer {
    socket: AsyncUdpTransport,
    table: Arc<Mutex<NameTable>>,
}

impl AsyncNrtpServer {
    pub async fn bind(addr: SocketAddr, _config: NrtpServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            table: Arc::new(Mutex::new(NameTable::default())),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(2048).await?;
            let table = Arc::clone(&self.table);
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_nrtp_request_async(socket, table, &data, peer).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct NrtpClientConfig {
    pub timeouts: Timeouts,
}

impl Default for NrtpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct NrtpClient {
    socket: UdpTransport,
}

impl NrtpClient {
    pub fn connect(config: NrtpClientConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket })
    }

    pub fn register(&self, addr: SocketAddr, name: &str, addresses: Vec<SocketAddr>) -> CoreResult<()> {
        let msg = NrtpMessage {
            msg_type: NrtpMessageType::Register,
            id: rand_id(),
            name: name.to_string(),
            addresses,
            status: 0,
        };
        self.socket.send_to(&msg.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let msg = NrtpMessage::decode(&resp)?;
        if msg.status == 0 {
            Ok(())
        } else {
            Err(CoreError::Message("nrtp register failed".to_string()))
        }
    }

    pub fn resolve(&self, addr: SocketAddr, name: &str) -> CoreResult<Vec<SocketAddr>> {
        let msg = NrtpMessage {
            msg_type: NrtpMessageType::Resolve,
            id: rand_id(),
            name: name.to_string(),
            addresses: Vec::new(),
            status: 0,
        };
        self.socket.send_to(&msg.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let msg = NrtpMessage::decode(&resp)?;
        Ok(msg.addresses)
    }

    pub fn unregister(&self, addr: SocketAddr, name: &str) -> CoreResult<()> {
        let msg = NrtpMessage {
            msg_type: NrtpMessageType::Unregister,
            id: rand_id(),
            name: name.to_string(),
            addresses: Vec::new(),
            status: 0,
        };
        self.socket.send_to(&msg.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let msg = NrtpMessage::decode(&resp)?;
        if msg.status == 0 {
            Ok(())
        } else {
            Err(CoreError::Message("nrtp unregister failed".to_string()))
        }
    }
}

pub struct AsyncNrtpClient {
    socket: AsyncUdpTransport,
}

impl AsyncNrtpClient {
    pub async fn connect() -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self { socket })
    }

    pub async fn resolve(&self, addr: SocketAddr, name: &str) -> CoreResult<Vec<SocketAddr>> {
        let msg = NrtpMessage {
            msg_type: NrtpMessageType::Resolve,
            id: rand_id(),
            name: name.to_string(),
            addresses: Vec::new(),
            status: 0,
        };
        self.socket.send_to(&msg.encode(), addr).await?;
        let (resp, _) = self.socket.recv_from(2048).await?;
        let msg = NrtpMessage::decode(&resp)?;
        Ok(msg.addresses)
    }
}

fn handle_nrtp_request(
    socket: UdpTransport,
    table: Arc<Mutex<NameTable>>,
    data: &[u8],
    peer: SocketAddr,
) -> CoreResult<()> {
    let msg = NrtpMessage::decode(data)?;
    let resp = handle_nrtp_message(table, msg);
    socket.send_to(&resp.encode(), peer)?;
    Ok(())
}

async fn handle_nrtp_request_async(
    socket: AsyncUdpTransport,
    table: Arc<Mutex<NameTable>>,
    data: &[u8],
    peer: SocketAddr,
) -> CoreResult<()> {
    let msg = NrtpMessage::decode(data)?;
    let resp = handle_nrtp_message(table, msg);
    socket.send_to(&resp.encode(), peer).await?;
    Ok(())
}

fn handle_nrtp_message(table: Arc<Mutex<NameTable>>, msg: NrtpMessage) -> NrtpMessage {
    match msg.msg_type {
        NrtpMessageType::Register => {
            if let Ok(mut table) = table.lock() {
                table.register(msg.name.clone(), msg.addresses.clone());
            }
            NrtpMessage { status: 0, msg_type: NrtpMessageType::Response, ..msg }
        }
        NrtpMessageType::Resolve => {
            let addresses = table.lock().map(|t| t.resolve(&msg.name)).unwrap_or_default();
            NrtpMessage {
                msg_type: NrtpMessageType::Response,
                status: 0,
                addresses,
                ..msg
            }
        }
        NrtpMessageType::Unregister => {
            if let Ok(mut table) = table.lock() {
                table.unregister(&msg.name);
            }
            NrtpMessage { status: 0, msg_type: NrtpMessageType::Response, ..msg }
        }
        NrtpMessageType::Response => msg,
    }
}

fn rand_id() -> u16 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_nanos() & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nrtp_register_resolve() {
        let server = NrtpServer::bind("127.0.0.1:0".parse().unwrap(), NrtpServerConfig::default()).unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let client = NrtpClient::connect(NrtpClientConfig::default()).unwrap();
        let endpoint: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        client.register(addr, "node", vec![endpoint]).unwrap();
        let result = client.resolve(addr, "node").unwrap();
        assert_eq!(result, vec![endpoint]);

        drop(handle);
    }
}
