use std::net::{SocketAddr, UdpSocket};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::AsyncUdpTransport;
use crate::util::Timeouts;

const MAGIC: [u8; 4] = *b"ADDP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddpMessageType {
    Discover = 1,
    Announce = 2,
    Query = 3,
    Response = 4,
}

#[derive(Debug, Clone)]
pub struct AddpMessage {
    pub msg_type: AddpMessageType,
    pub version: u8,
    pub flags: u16,
    pub payload: Vec<u8>,
}

impl AddpMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 10 {
            return Err(CoreError::Parse("addp packet too short".to_string()));
        }
        if &data[0..4] != MAGIC {
            return Err(CoreError::Parse("addp magic mismatch".to_string()));
        }
        let version = data[4];
        let msg_type = match data[5] {
            1 => AddpMessageType::Discover,
            2 => AddpMessageType::Announce,
            3 => AddpMessageType::Query,
            4 => AddpMessageType::Response,
            _ => return Err(CoreError::Parse("addp unknown type".to_string())),
        };
        let flags = u16::from_be_bytes([data[6], data[7]]);
        let len = u16::from_be_bytes([data[8], data[9]]) as usize;
        if data.len() < 10 + len {
            return Err(CoreError::Parse("addp payload length".to_string()));
        }
        Ok(Self {
            msg_type,
            version,
            flags,
            payload: data[10..10 + len].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AddpServerConfig {
    pub timeouts: Timeouts,
    pub device_name: String,
    pub services: Vec<String>,
}

impl Default for AddpServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            device_name: "moonlight".to_string(),
            services: vec!["adb".to_string(), "ssh".to_string()],
        }
    }
}

pub struct AddpServer {
    socket: UdpSocket,
    config: AddpServerConfig,
}

impl AddpServer {
    pub fn bind(addr: SocketAddr, config: AddpServerConfig) -> CoreResult<Self> {
        let socket = UdpSocket::bind(addr).map_err(CoreError::Io)?;
        socket.set_read_timeout(Some(config.timeouts.read)).map_err(CoreError::Io)?;
        Ok(Self { socket, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let mut buf = [0u8; 2048];
            let (len, peer) = self.socket.recv_from(&mut buf).map_err(CoreError::Io)?;
            let data = buf[..len].to_vec();
            let socket = self.socket.try_clone().map_err(CoreError::Io)?;
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_addp_request(socket, config, &data, peer);
            });
        }
    }
}

pub struct AsyncAddpServer {
    socket: AsyncUdpTransport,
    config: AddpServerConfig,
}

impl AsyncAddpServer {
    pub async fn bind(addr: SocketAddr, config: AddpServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self { socket, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(2048).await?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_addp_request_async(socket, config, &data, peer).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct AddpClientConfig {
    pub timeouts: Timeouts,
}

impl Default for AddpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct AddpClient {
    socket: UdpSocket,
}

impl AddpClient {
    pub fn connect(config: AddpClientConfig) -> CoreResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(CoreError::Io)?;
        socket.set_read_timeout(Some(config.timeouts.read)).map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub fn discover(&self, addr: SocketAddr, query: &str) -> CoreResult<AddpMessage> {
        let msg = AddpMessage {
            msg_type: AddpMessageType::Discover,
            version: 1,
            flags: 0,
            payload: query.as_bytes().to_vec(),
        };
        self.socket.send_to(&msg.encode(), addr).map_err(CoreError::Io)?;
        let mut buf = [0u8; 2048];
        let (len, _) = self.socket.recv_from(&mut buf).map_err(CoreError::Io)?;
        AddpMessage::decode(&buf[..len])
    }
}

pub struct AsyncAddpClient {
    socket: AsyncUdpTransport,
}

impl AsyncAddpClient {
    pub async fn connect() -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self { socket })
    }

    pub async fn discover(&self, addr: SocketAddr, query: &str) -> CoreResult<AddpMessage> {
        let msg = AddpMessage {
            msg_type: AddpMessageType::Discover,
            version: 1,
            flags: 0,
            payload: query.as_bytes().to_vec(),
        };
        self.socket.send_to(&msg.encode(), addr).await?;
        let (data, _) = self.socket.recv_from(2048).await?;
        AddpMessage::decode(&data)
    }
}

fn handle_addp_request(socket: UdpSocket, config: AddpServerConfig, data: &[u8], peer: SocketAddr) -> CoreResult<()> {
    let msg = AddpMessage::decode(data)?;
    match msg.msg_type {
        AddpMessageType::Discover | AddpMessageType::Query => {
            let payload = format!("{}|{}", config.device_name, config.services.join(","));
            let resp = AddpMessage {
                msg_type: AddpMessageType::Response,
                version: msg.version,
                flags: 0,
                payload: payload.into_bytes(),
            };
            socket.send_to(&resp.encode(), peer).map_err(CoreError::Io)?;
        }
        _ => {}
    }
    Ok(())
}

async fn handle_addp_request_async(
    socket: AsyncUdpTransport,
    config: AddpServerConfig,
    data: &[u8],
    peer: SocketAddr,
) -> CoreResult<()> {
    let msg = AddpMessage::decode(data)?;
    match msg.msg_type {
        AddpMessageType::Discover | AddpMessageType::Query => {
            let payload = format!("{}|{}", config.device_name, config.services.join(","));
            let resp = AddpMessage {
                msg_type: AddpMessageType::Response,
                version: msg.version,
                flags: 0,
                payload: payload.into_bytes(),
            };
            socket.send_to(&resp.encode(), peer).await?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addp_discover() {
        let server = crate::skip_if_perm!(AddpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            AddpServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let client = AddpClient::connect(AddpClientConfig::default()).unwrap();
        let resp = client.discover(addr, "moonlight").unwrap();
        assert_eq!(resp.msg_type, AddpMessageType::Response);

        drop(handle);
    }
}
