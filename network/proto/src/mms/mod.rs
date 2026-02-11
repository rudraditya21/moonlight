use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const MAGIC: [u8; 4] = *b"MMS1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmsCommand {
    Hello = 0x01,
    Auth = 0x02,
    Describe = 0x03,
    Play = 0x04,
    Data = 0x05,
    Bye = 0x06,
    Error = 0x07,
    Ok = 0x08,
}

#[derive(Debug, Clone)]
pub struct MmsFrame {
    pub command: MmsCommand,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl MmsFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.command as u8);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 13 {
            return Err(CoreError::Parse("mms frame too short".to_string()));
        }
        if &data[0..4] != MAGIC {
            return Err(CoreError::Parse("mms bad magic".to_string()));
        }
        let command = match data[4] {
            0x01 => MmsCommand::Hello,
            0x02 => MmsCommand::Auth,
            0x03 => MmsCommand::Describe,
            0x04 => MmsCommand::Play,
            0x05 => MmsCommand::Data,
            0x06 => MmsCommand::Bye,
            0x07 => MmsCommand::Error,
            0x08 => MmsCommand::Ok,
            value => return Err(CoreError::Parse(format!("mms unknown command {value}"))),
        };
        let stream_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
        let len = u32::from_be_bytes([data[9], data[10], data[11], data[12]]) as usize;
        if data.len() < 13 + len {
            return Err(CoreError::Parse("mms payload length invalid".to_string()));
        }
        let payload = data[13..13 + len].to_vec();
        Ok(Self {
            command,
            stream_id,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MmsDescription {
    pub content_type: String,
    pub length: usize,
}

impl MmsDescription {
    pub fn encode(&self) -> Vec<u8> {
        format!("{}\n{}\n", self.content_type, self.length).into_bytes()
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        let text = String::from_utf8_lossy(data);
        let mut parts = text.lines();
        let content_type = parts
            .next()
            .ok_or_else(|| CoreError::Parse("mms description missing type".to_string()))?
            .to_string();
        let length = parts
            .next()
            .ok_or_else(|| CoreError::Parse("mms description missing length".to_string()))?
            .parse::<usize>()
            .map_err(|_| CoreError::Parse("mms description length invalid".to_string()))?;
        Ok(Self { content_type, length })
    }
}

pub trait MmsHandler: Send + Sync {
    fn describe(&self, path: &str) -> CoreResult<MmsDescription>;
    fn open(&self, path: &str) -> CoreResult<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct InMemoryMmsHandler {
    content_type: String,
    files: Arc<HashMap<String, Vec<u8>>>,
}

impl InMemoryMmsHandler {
    pub fn new(content_type: impl Into<String>, files: HashMap<String, Vec<u8>>) -> Self {
        Self {
            content_type: content_type.into(),
            files: Arc::new(files),
        }
    }
}

impl MmsHandler for InMemoryMmsHandler {
    fn describe(&self, path: &str) -> CoreResult<MmsDescription> {
        let data = self
            .files
            .get(path)
            .ok_or_else(|| CoreError::Message("mms file not found".to_string()))?;
        Ok(MmsDescription {
            content_type: self.content_type.clone(),
            length: data.len(),
        })
    }

    fn open(&self, path: &str) -> CoreResult<Vec<u8>> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| CoreError::Message("mms file not found".to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct MmsServerConfig {
    pub timeouts: Timeouts,
    pub chunk_size: usize,
    pub require_auth: bool,
    pub auth_token: Option<String>,
}

impl Default for MmsServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            chunk_size: 1024,
            require_auth: false,
            auth_token: None,
        }
    }
}

pub struct MmsServer {
    listener: TcpListener,
    handler: Arc<dyn MmsHandler>,
    config: MmsServerConfig,
}

impl MmsServer {
    pub fn bind(addr: SocketAddr, handler: Arc<dyn MmsHandler>, config: MmsServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            handler,
            config,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_mms_stream(stream, handler, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncMmsServer {
    listener: tokio::net::TcpListener,
    handler: Arc<dyn MmsHandler>,
    config: MmsServerConfig,
}

impl AsyncMmsServer {
    pub async fn bind(addr: SocketAddr, handler: Arc<dyn MmsHandler>, config: MmsServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            handler,
            config,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_mms_stream_async(stream, handler, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct MmsClientConfig {
    pub timeouts: Timeouts,
    pub auth_token: Option<String>,
}

impl Default for MmsClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            auth_token: None,
        }
    }
}

pub struct MmsClient {
    transport: TcpTransport,
    stream_id: u32,
    path: String,
    auth_token: Option<String>,
}

impl MmsClient {
    pub fn connect(addr: &net::NetAddr, path: impl Into<String>, config: MmsClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        let mut client = Self {
            transport,
            stream_id: 1,
            path: path.into(),
            auth_token: config.auth_token,
        };
        client.send_hello()?;
        if let Some(token) = client.auth_token.clone() {
            client.send_auth(&token)?;
        }
        Ok(client)
    }

    pub fn describe(&mut self) -> CoreResult<MmsDescription> {
        let frame = MmsFrame {
            command: MmsCommand::Describe,
            stream_id: self.stream_id,
            payload: self.path.clone().into_bytes(),
        };
        write_frame(&mut self.transport, &frame)?;
        let response = read_frame(&mut self.transport)?;
        if response.command == MmsCommand::Ok {
            MmsDescription::decode(&response.payload)
        } else {
            Err(CoreError::Message("mms describe failed".to_string()))
        }
    }

    pub fn play(&mut self) -> CoreResult<Vec<u8>> {
        let frame = MmsFrame {
            command: MmsCommand::Play,
            stream_id: self.stream_id,
            payload: self.path.clone().into_bytes(),
        };
        write_frame(&mut self.transport, &frame)?;
        let mut out = Vec::new();
        loop {
            let frame = read_frame(&mut self.transport)?;
            match frame.command {
                MmsCommand::Data => out.extend_from_slice(&frame.payload),
                MmsCommand::Bye => break,
                MmsCommand::Error => return Err(CoreError::Message("mms play failed".to_string())),
                _ => {}
            }
        }
        Ok(out)
    }

    fn send_hello(&mut self) -> CoreResult<()> {
        let frame = MmsFrame {
            command: MmsCommand::Hello,
            stream_id: self.stream_id,
            payload: self.path.clone().into_bytes(),
        };
        write_frame(&mut self.transport, &frame)?;
        let response = read_frame(&mut self.transport)?;
        if response.command == MmsCommand::Ok {
            Ok(())
        } else {
            Err(CoreError::Message("mms hello failed".to_string()))
        }
    }

    fn send_auth(&mut self, token: &str) -> CoreResult<()> {
        let frame = MmsFrame {
            command: MmsCommand::Auth,
            stream_id: self.stream_id,
            payload: token.as_bytes().to_vec(),
        };
        write_frame(&mut self.transport, &frame)?;
        let response = read_frame(&mut self.transport)?;
        if response.command == MmsCommand::Ok {
            Ok(())
        } else {
            Err(CoreError::Message("mms auth failed".to_string()))
        }
    }
}

pub struct AsyncMmsClient {
    transport: AsyncTcpTransport,
    stream_id: u32,
    path: String,
    auth_token: Option<String>,
}

impl AsyncMmsClient {
    pub async fn connect(addr: &net::NetAddr, path: impl Into<String>, config: MmsClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let mut client = Self {
            transport,
            stream_id: 1,
            path: path.into(),
            auth_token: config.auth_token,
        };
        client.send_hello().await?;
        if let Some(token) = client.auth_token.clone() {
            client.send_auth(&token).await?;
        }
        Ok(client)
    }

    pub async fn describe(&mut self) -> CoreResult<MmsDescription> {
        let frame = MmsFrame {
            command: MmsCommand::Describe,
            stream_id: self.stream_id,
            payload: self.path.clone().into_bytes(),
        };
        write_frame_async(&mut self.transport, &frame).await?;
        let response = read_frame_async(&mut self.transport).await?;
        if response.command == MmsCommand::Ok {
            MmsDescription::decode(&response.payload)
        } else {
            Err(CoreError::Message("mms describe failed".to_string()))
        }
    }

    pub async fn play(&mut self) -> CoreResult<Vec<u8>> {
        let frame = MmsFrame {
            command: MmsCommand::Play,
            stream_id: self.stream_id,
            payload: self.path.clone().into_bytes(),
        };
        write_frame_async(&mut self.transport, &frame).await?;
        let mut out = Vec::new();
        loop {
            let frame = read_frame_async(&mut self.transport).await?;
            match frame.command {
                MmsCommand::Data => out.extend_from_slice(&frame.payload),
                MmsCommand::Bye => break,
                MmsCommand::Error => return Err(CoreError::Message("mms play failed".to_string())),
                _ => {}
            }
        }
        Ok(out)
    }

    async fn send_hello(&mut self) -> CoreResult<()> {
        let frame = MmsFrame {
            command: MmsCommand::Hello,
            stream_id: self.stream_id,
            payload: self.path.clone().into_bytes(),
        };
        write_frame_async(&mut self.transport, &frame).await?;
        let response = read_frame_async(&mut self.transport).await?;
        if response.command == MmsCommand::Ok {
            Ok(())
        } else {
            Err(CoreError::Message("mms hello failed".to_string()))
        }
    }

    async fn send_auth(&mut self, token: &str) -> CoreResult<()> {
        let frame = MmsFrame {
            command: MmsCommand::Auth,
            stream_id: self.stream_id,
            payload: token.as_bytes().to_vec(),
        };
        write_frame_async(&mut self.transport, &frame).await?;
        let response = read_frame_async(&mut self.transport).await?;
        if response.command == MmsCommand::Ok {
            Ok(())
        } else {
            Err(CoreError::Message("mms auth failed".to_string()))
        }
    }
}

fn handle_mms_stream(stream: TcpStream, handler: Arc<dyn MmsHandler>, config: MmsServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let hello = read_frame(&mut transport)?;
    if hello.command != MmsCommand::Hello {
        return Err(CoreError::Parse("mms expected hello".to_string()));
    }
    let path = String::from_utf8_lossy(&hello.payload).to_string();
    send_ok(&mut transport, hello.stream_id, &[])?;
    if config.require_auth {
        let auth = read_frame(&mut transport)?;
        if auth.command != MmsCommand::Auth {
            send_error(&mut transport, hello.stream_id, "auth required")?;
            return Ok(());
        }
        let token = String::from_utf8_lossy(&auth.payload).to_string();
        if config.auth_token.as_deref() != Some(token.trim()) {
            send_error(&mut transport, hello.stream_id, "auth failed")?;
            return Ok(());
        }
    }
    loop {
        let frame = read_frame(&mut transport)?;
        match frame.command {
            MmsCommand::Describe => {
                let desc = handler.describe(&path)?;
                send_ok(&mut transport, frame.stream_id, &desc.encode())?;
            }
            MmsCommand::Play => {
                let data = handler.open(&path)?;
                for chunk in data.chunks(config.chunk_size) {
                    let data_frame = MmsFrame {
                        command: MmsCommand::Data,
                        stream_id: frame.stream_id,
                        payload: chunk.to_vec(),
                    };
                    write_frame(&mut transport, &data_frame)?;
                }
                let bye = MmsFrame {
                    command: MmsCommand::Bye,
                    stream_id: frame.stream_id,
                    payload: Vec::new(),
                };
                write_frame(&mut transport, &bye)?;
            }
            MmsCommand::Bye => return Ok(()),
            _ => {}
        }
    }
}

async fn handle_mms_stream_async(
    stream: tokio::net::TcpStream,
    handler: Arc<dyn MmsHandler>,
    config: MmsServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let hello = read_frame_async(&mut transport).await?;
    if hello.command != MmsCommand::Hello {
        return Err(CoreError::Parse("mms expected hello".to_string()));
    }
    let path = String::from_utf8_lossy(&hello.payload).to_string();
    send_ok_async(&mut transport, hello.stream_id, &[]).await?;
    if config.require_auth {
        let auth = read_frame_async(&mut transport).await?;
        if auth.command != MmsCommand::Auth {
            send_error_async(&mut transport, hello.stream_id, "auth required").await?;
            return Ok(());
        }
        let token = String::from_utf8_lossy(&auth.payload).to_string();
        if config.auth_token.as_deref() != Some(token.trim()) {
            send_error_async(&mut transport, hello.stream_id, "auth failed").await?;
            return Ok(());
        }
    }
    loop {
        let frame = read_frame_async(&mut transport).await?;
        match frame.command {
            MmsCommand::Describe => {
                let desc = handler.describe(&path)?;
                send_ok_async(&mut transport, frame.stream_id, &desc.encode()).await?;
            }
            MmsCommand::Play => {
                let data = handler.open(&path)?;
                for chunk in data.chunks(config.chunk_size) {
                    let data_frame = MmsFrame {
                        command: MmsCommand::Data,
                        stream_id: frame.stream_id,
                        payload: chunk.to_vec(),
                    };
                    write_frame_async(&mut transport, &data_frame).await?;
                }
                let bye = MmsFrame {
                    command: MmsCommand::Bye,
                    stream_id: frame.stream_id,
                    payload: Vec::new(),
                };
                write_frame_async(&mut transport, &bye).await?;
            }
            MmsCommand::Bye => return Ok(()),
            _ => {}
        }
    }
}

fn send_ok(transport: &mut TcpTransport, stream_id: u32, payload: &[u8]) -> CoreResult<()> {
    let frame = MmsFrame {
        command: MmsCommand::Ok,
        stream_id,
        payload: payload.to_vec(),
    };
    write_frame(transport, &frame)
}

fn send_error(transport: &mut TcpTransport, stream_id: u32, message: &str) -> CoreResult<()> {
    let frame = MmsFrame {
        command: MmsCommand::Error,
        stream_id,
        payload: message.as_bytes().to_vec(),
    };
    write_frame(transport, &frame)
}

async fn send_ok_async(transport: &mut AsyncTcpTransport, stream_id: u32, payload: &[u8]) -> CoreResult<()> {
    let frame = MmsFrame {
        command: MmsCommand::Ok,
        stream_id,
        payload: payload.to_vec(),
    };
    write_frame_async(transport, &frame).await
}

async fn send_error_async(transport: &mut AsyncTcpTransport, stream_id: u32, message: &str) -> CoreResult<()> {
    let frame = MmsFrame {
        command: MmsCommand::Error,
        stream_id,
        payload: message.as_bytes().to_vec(),
    };
    write_frame_async(transport, &frame).await
}

fn read_frame<T: StreamTransport>(transport: &mut T) -> CoreResult<MmsFrame> {
    let mut header = [0u8; 13];
    transport.read_exact(&mut header)?;
    let payload_len = u32::from_be_bytes([header[9], header[10], header[11], header[12]]) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    MmsFrame::decode(&data)
}

fn write_frame<T: StreamTransport>(transport: &mut T, frame: &MmsFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode())
}

async fn read_frame_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<MmsFrame> {
    let mut header = [0u8; 13];
    transport.read_exact(&mut header).await?;
    let payload_len = u32::from_be_bytes([header[9], header[10], header[11], header[12]]) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    MmsFrame::decode(&data)
}

async fn write_frame_async<T: AsyncStreamTransport>(transport: &mut T, frame: &MmsFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mms_stream_roundtrip() {
        let mut files = HashMap::new();
        files.insert("/stream".to_string(), b"hello world".to_vec());
        let handler = Arc::new(InMemoryMmsHandler::new("application/octet-stream", files));
        let server = crate::skip_if_perm!(MmsServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            MmsServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let client_addr = net::NetAddr::from_socket(addr);
        let mut client = MmsClient::connect(&client_addr, "/stream", MmsClientConfig::default()).unwrap();
        let data = client.play().unwrap();
        assert_eq!(data, b"hello world".to_vec());

        drop(handle);
    }
}
