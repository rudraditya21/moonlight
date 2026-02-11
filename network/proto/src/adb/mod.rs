use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdbCommand {
    Cnxn,
    Auth,
    Open,
    Okay,
    Clse,
    Wrte,
}

impl AdbCommand {
    fn to_u32(self) -> u32 {
        match self {
            AdbCommand::Cnxn => u32::from_le_bytes(*b"CNXN"),
            AdbCommand::Auth => u32::from_le_bytes(*b"AUTH"),
            AdbCommand::Open => u32::from_le_bytes(*b"OPEN"),
            AdbCommand::Okay => u32::from_le_bytes(*b"OKAY"),
            AdbCommand::Clse => u32::from_le_bytes(*b"CLSE"),
            AdbCommand::Wrte => u32::from_le_bytes(*b"WRTE"),
        }
    }

    fn from_u32(value: u32) -> CoreResult<Self> {
        match value {
            v if v == u32::from_le_bytes(*b"CNXN") => Ok(AdbCommand::Cnxn),
            v if v == u32::from_le_bytes(*b"AUTH") => Ok(AdbCommand::Auth),
            v if v == u32::from_le_bytes(*b"OPEN") => Ok(AdbCommand::Open),
            v if v == u32::from_le_bytes(*b"OKAY") => Ok(AdbCommand::Okay),
            v if v == u32::from_le_bytes(*b"CLSE") => Ok(AdbCommand::Clse),
            v if v == u32::from_le_bytes(*b"WRTE") => Ok(AdbCommand::Wrte),
            _ => Err(CoreError::Parse("adb unknown command".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdbPacket {
    pub command: AdbCommand,
    pub arg0: u32,
    pub arg1: u32,
    pub payload: Vec<u8>,
}

impl AdbPacket {
    pub fn encode(&self) -> Vec<u8> {
        let command = self.command.to_u32();
        let checksum = adb_checksum(&self.payload);
        let magic = command ^ 0xFFFF_FFFF;
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&command.to_le_bytes());
        out.extend_from_slice(&self.arg0.to_le_bytes());
        out.extend_from_slice(&self.arg1.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&magic.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < HEADER_LEN {
            return Err(CoreError::Parse("adb header too short".to_string()));
        }
        let command = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let arg0 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let arg1 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let checksum = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let magic = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        if command ^ 0xFFFF_FFFF != magic {
            return Err(CoreError::Parse("adb magic mismatch".to_string()));
        }
        if data.len() < HEADER_LEN + len {
            return Err(CoreError::Parse("adb payload length".to_string()));
        }
        let payload = data[HEADER_LEN..HEADER_LEN + len].to_vec();
        if adb_checksum(&payload) != checksum {
            return Err(CoreError::Parse("adb checksum mismatch".to_string()));
        }
        Ok(Self {
            command: AdbCommand::from_u32(command)?,
            arg0,
            arg1,
            payload,
        })
    }
}

fn adb_checksum(payload: &[u8]) -> u32 {
    payload
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
}

#[derive(Debug, Clone)]
pub struct AdbClientConfig {
    pub timeouts: Timeouts,
    pub max_payload: u32,
}

impl Default for AdbClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            max_payload: 4096,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AdbServerConfig {
    pub timeouts: Timeouts,
    pub banner: String,
}

impl Default for AdbServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            banner: "device::moonlight".to_string(),
        }
    }
}

pub trait AdbServiceHandler: Send + Sync {
    fn on_open(&self, service: &str) -> CoreResult<Vec<u8>>;
    fn on_write(&self, service: &str, data: &[u8]) -> CoreResult<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct EchoAdbService;

impl AdbServiceHandler for EchoAdbService {
    fn on_open(&self, _service: &str) -> CoreResult<Vec<u8>> {
        Ok(Vec::new())
    }

    fn on_write(&self, _service: &str, data: &[u8]) -> CoreResult<Vec<u8>> {
        Ok(data.to_vec())
    }
}

pub struct AdbClient {
    transport: TcpTransport,
    max_payload: u32,
    local_id: u32,
    remote_id: u32,
}

impl AdbClient {
    pub fn connect(addr: &NetAddr, config: AdbClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let cnxn = AdbPacket {
            command: AdbCommand::Cnxn,
            arg0: 0x01000000,
            arg1: config.max_payload,
            payload: b"host::moonlight\0".to_vec(),
        };
        write_packet(&mut transport, &cnxn)?;
        let resp = read_packet(&mut transport)?;
        if resp.command != AdbCommand::Cnxn {
            return Err(CoreError::Parse("adb expected cnxn".to_string()));
        }
        Ok(Self {
            transport,
            max_payload: config.max_payload,
            local_id: 1,
            remote_id: 0,
        })
    }

    pub fn open(&mut self, service: &str) -> CoreResult<()> {
        let payload = format!("{}\0", service).into_bytes();
        let open = AdbPacket {
            command: AdbCommand::Open,
            arg0: self.local_id,
            arg1: 0,
            payload,
        };
        write_packet(&mut self.transport, &open)?;
        let resp = read_packet(&mut self.transport)?;
        if resp.command != AdbCommand::Okay {
            return Err(CoreError::Parse("adb expected okay".to_string()));
        }
        self.remote_id = resp.arg0;
        Ok(())
    }

    pub fn write(&mut self, data: &[u8]) -> CoreResult<Vec<u8>> {
        let packet = AdbPacket {
            command: AdbCommand::Wrte,
            arg0: self.local_id,
            arg1: self.remote_id,
            payload: data.to_vec(),
        };
        write_packet(&mut self.transport, &packet)?;
        let _ = read_packet(&mut self.transport)?; // OKAY
        let resp = read_packet(&mut self.transport)?;
        if resp.command == AdbCommand::Wrte {
            let ack = AdbPacket {
                command: AdbCommand::Okay,
                arg0: self.local_id,
                arg1: self.remote_id,
                payload: Vec::new(),
            };
            write_packet(&mut self.transport, &ack)?;
            Ok(resp.payload)
        } else {
            Err(CoreError::Parse("adb unexpected response".to_string()))
        }
    }
}

pub struct AsyncAdbClient {
    transport: AsyncTcpTransport,
    max_payload: u32,
    local_id: u32,
    remote_id: u32,
}

impl AsyncAdbClient {
    pub async fn connect(addr: &NetAddr, config: AdbClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let cnxn = AdbPacket {
            command: AdbCommand::Cnxn,
            arg0: 0x01000000,
            arg1: config.max_payload,
            payload: b"host::moonlight\0".to_vec(),
        };
        write_packet_async(&mut transport, &cnxn).await?;
        let resp = read_packet_async(&mut transport).await?;
        if resp.command != AdbCommand::Cnxn {
            return Err(CoreError::Parse("adb expected cnxn".to_string()));
        }
        Ok(Self {
            transport,
            max_payload: config.max_payload,
            local_id: 1,
            remote_id: 0,
        })
    }

    pub async fn open(&mut self, service: &str) -> CoreResult<()> {
        let payload = format!("{}\0", service).into_bytes();
        let open = AdbPacket {
            command: AdbCommand::Open,
            arg0: self.local_id,
            arg1: 0,
            payload,
        };
        write_packet_async(&mut self.transport, &open).await?;
        let resp = read_packet_async(&mut self.transport).await?;
        if resp.command != AdbCommand::Okay {
            return Err(CoreError::Parse("adb expected okay".to_string()));
        }
        self.remote_id = resp.arg0;
        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> CoreResult<Vec<u8>> {
        let packet = AdbPacket {
            command: AdbCommand::Wrte,
            arg0: self.local_id,
            arg1: self.remote_id,
            payload: data.to_vec(),
        };
        write_packet_async(&mut self.transport, &packet).await?;
        let _ = read_packet_async(&mut self.transport).await?;
        let resp = read_packet_async(&mut self.transport).await?;
        if resp.command == AdbCommand::Wrte {
            let ack = AdbPacket {
                command: AdbCommand::Okay,
                arg0: self.local_id,
                arg1: self.remote_id,
                payload: Vec::new(),
            };
            write_packet_async(&mut self.transport, &ack).await?;
            Ok(resp.payload)
        } else {
            Err(CoreError::Parse("adb unexpected response".to_string()))
        }
    }
}

pub struct AdbServer {
    listener: TcpListener,
    config: AdbServerConfig,
    handler: Arc<dyn AdbServiceHandler>,
}

impl AdbServer {
    pub fn bind(
        addr: SocketAddr,
        config: AdbServerConfig,
        handler: Arc<dyn AdbServiceHandler>,
    ) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            handler,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let config = self.config.clone();
            let handler = Arc::clone(&self.handler);
            thread::spawn(move || {
                let _ = handle_adb_stream(stream, config, handler);
            });
        }
        Ok(())
    }
}

pub struct AsyncAdbServer {
    listener: tokio::net::TcpListener,
    config: AdbServerConfig,
    handler: Arc<dyn AdbServiceHandler>,
}

impl AsyncAdbServer {
    pub async fn bind(
        addr: SocketAddr,
        config: AdbServerConfig,
        handler: Arc<dyn AdbServiceHandler>,
    ) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            handler,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                let _ = handle_adb_stream_async(stream, config, handler).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
struct ChannelState {
    service: String,
    local_id: u32,
    remote_id: u32,
}

fn handle_adb_stream(
    stream: TcpStream,
    config: AdbServerConfig,
    handler: Arc<dyn AdbServiceHandler>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let cnxn = read_packet(&mut transport)?;
    if cnxn.command != AdbCommand::Cnxn {
        return Err(CoreError::Parse("adb expected cnxn".to_string()));
    }
    let resp = AdbPacket {
        command: AdbCommand::Cnxn,
        arg0: 0x01000000,
        arg1: 4096,
        payload: format!("{}\0", config.banner).into_bytes(),
    };
    write_packet(&mut transport, &resp)?;
    let mut channels = HashMap::<u32, ChannelState>::new();
    loop {
        let packet = read_packet(&mut transport)?;
        match packet.command {
            AdbCommand::Open => {
                let service = String::from_utf8_lossy(&packet.payload)
                    .trim_end_matches('\0')
                    .to_string();
                let remote_id = 1 + channels.len() as u32;
                channels.insert(
                    packet.arg0,
                    ChannelState {
                        service: service.clone(),
                        local_id: packet.arg0,
                        remote_id,
                    },
                );
                let okay = AdbPacket {
                    command: AdbCommand::Okay,
                    arg0: remote_id,
                    arg1: packet.arg0,
                    payload: Vec::new(),
                };
                write_packet(&mut transport, &okay)?;
                let greeting = handler.on_open(&service)?;
                if !greeting.is_empty() {
                    let wrte = AdbPacket {
                        command: AdbCommand::Wrte,
                        arg0: remote_id,
                        arg1: packet.arg0,
                        payload: greeting,
                    };
                    write_packet(&mut transport, &wrte)?;
                }
            }
            AdbCommand::Wrte => {
                if let Some(channel) = channels.get(&packet.arg1) {
                    let resp = handler.on_write(&channel.service, &packet.payload)?;
                    let okay = AdbPacket {
                        command: AdbCommand::Okay,
                        arg0: channel.remote_id,
                        arg1: channel.local_id,
                        payload: Vec::new(),
                    };
                    write_packet(&mut transport, &okay)?;
                    if !resp.is_empty() {
                        let wrte = AdbPacket {
                            command: AdbCommand::Wrte,
                            arg0: channel.remote_id,
                            arg1: channel.local_id,
                            payload: resp,
                        };
                        write_packet(&mut transport, &wrte)?;
                    }
                }
            }
            AdbCommand::Clse => {
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn handle_adb_stream_async(
    stream: tokio::net::TcpStream,
    config: AdbServerConfig,
    handler: Arc<dyn AdbServiceHandler>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let cnxn = read_packet_async(&mut transport).await?;
    if cnxn.command != AdbCommand::Cnxn {
        return Err(CoreError::Parse("adb expected cnxn".to_string()));
    }
    let resp = AdbPacket {
        command: AdbCommand::Cnxn,
        arg0: 0x01000000,
        arg1: 4096,
        payload: format!("{}\0", config.banner).into_bytes(),
    };
    write_packet_async(&mut transport, &resp).await?;
    let mut channels = HashMap::<u32, ChannelState>::new();
    loop {
        let packet = read_packet_async(&mut transport).await?;
        match packet.command {
            AdbCommand::Open => {
                let service = String::from_utf8_lossy(&packet.payload)
                    .trim_end_matches('\0')
                    .to_string();
                let remote_id = 1 + channels.len() as u32;
                channels.insert(
                    packet.arg0,
                    ChannelState {
                        service: service.clone(),
                        local_id: packet.arg0,
                        remote_id,
                    },
                );
                let okay = AdbPacket {
                    command: AdbCommand::Okay,
                    arg0: remote_id,
                    arg1: packet.arg0,
                    payload: Vec::new(),
                };
                write_packet_async(&mut transport, &okay).await?;
                let greeting = handler.on_open(&service)?;
                if !greeting.is_empty() {
                    let wrte = AdbPacket {
                        command: AdbCommand::Wrte,
                        arg0: remote_id,
                        arg1: packet.arg0,
                        payload: greeting,
                    };
                    write_packet_async(&mut transport, &wrte).await?;
                }
            }
            AdbCommand::Wrte => {
                if let Some(channel) = channels.get(&packet.arg1) {
                    let resp = handler.on_write(&channel.service, &packet.payload)?;
                    let okay = AdbPacket {
                        command: AdbCommand::Okay,
                        arg0: channel.remote_id,
                        arg1: channel.local_id,
                        payload: Vec::new(),
                    };
                    write_packet_async(&mut transport, &okay).await?;
                    if !resp.is_empty() {
                        let wrte = AdbPacket {
                            command: AdbCommand::Wrte,
                            arg0: channel.remote_id,
                            arg1: channel.local_id,
                            payload: resp,
                        };
                        write_packet_async(&mut transport, &wrte).await?;
                    }
                }
            }
            AdbCommand::Clse => break,
            _ => {}
        }
    }
    Ok(())
}

fn read_packet<T: StreamTransport>(transport: &mut T) -> CoreResult<AdbPacket> {
    let mut header = [0u8; HEADER_LEN];
    transport.read_exact(&mut header)?;
    let len = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    AdbPacket::decode(&data)
}

async fn read_packet_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<AdbPacket> {
    let mut header = [0u8; HEADER_LEN];
    transport.read_exact(&mut header).await?;
    let len = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    AdbPacket::decode(&data)
}

fn write_packet<T: StreamTransport>(transport: &mut T, packet: &AdbPacket) -> CoreResult<()> {
    transport.write_all(&packet.encode())
}

async fn write_packet_async<T: AsyncStreamTransport>(
    transport: &mut T,
    packet: &AdbPacket,
) -> CoreResult<()> {
    transport.write_all(&packet.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adb_open_write_echo() {
        let server = crate::skip_if_perm!(AdbServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            AdbServerConfig::default(),
            Arc::new(EchoAdbService),
        ));
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client =
            AdbClient::connect(&NetAddr::from_socket(addr), AdbClientConfig::default()).unwrap();
        client.open("shell:echo").unwrap();
        let response = client.write(b"ping").unwrap();
        assert_eq!(response, b"ping".to_vec());

        drop(handle);
    }
}
