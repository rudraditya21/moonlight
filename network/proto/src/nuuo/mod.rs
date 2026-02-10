use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const MAGIC: &[u8; 4] = b"NUUO";
const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NuuoMessageType {
    Hello = 0x01,
    Auth = 0x02,
    AuthOk = 0x03,
    AuthFail = 0x04,
    Ping = 0x05,
    Pong = 0x06,
    GetInfo = 0x10,
    Info = 0x11,
    ListCameras = 0x12,
    CameraList = 0x13,
    Error = 0x7f,
}

impl NuuoMessageType {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            0x01 => Ok(NuuoMessageType::Hello),
            0x02 => Ok(NuuoMessageType::Auth),
            0x03 => Ok(NuuoMessageType::AuthOk),
            0x04 => Ok(NuuoMessageType::AuthFail),
            0x05 => Ok(NuuoMessageType::Ping),
            0x06 => Ok(NuuoMessageType::Pong),
            0x10 => Ok(NuuoMessageType::GetInfo),
            0x11 => Ok(NuuoMessageType::Info),
            0x12 => Ok(NuuoMessageType::ListCameras),
            0x13 => Ok(NuuoMessageType::CameraList),
            0x7f => Ok(NuuoMessageType::Error),
            _ => Err(CoreError::Parse("nuuo invalid message type".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NuuoFrame {
    pub version: u8,
    pub msg_type: NuuoMessageType,
    pub payload: Vec<u8>,
}

impl NuuoFrame {
    pub fn new(msg_type: NuuoMessageType, payload: Vec<u8>) -> Self {
        Self {
            version: 1,
            msg_type,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.push(self.version);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 10 {
            return Err(CoreError::Parse("nuuo frame too short".to_string()));
        }
        if &data[0..4] != MAGIC {
            return Err(CoreError::Parse("nuuo bad magic".to_string()));
        }
        let version = data[4];
        let msg_type = NuuoMessageType::from_u8(data[5])?;
        let len = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;
        if len > MAX_PAYLOAD || data.len() < 10 + len {
            return Err(CoreError::Parse("nuuo payload length".to_string()));
        }
        let payload = data[10..10 + len].to_vec();
        Ok(Self {
            version,
            msg_type,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NuuoCamera {
    pub id: u32,
    pub name: String,
    pub ip: Option<Ipv4Addr>,
}

#[derive(Debug, Clone)]
pub struct NuuoServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
    pub product_name: String,
    pub version: String,
    pub cameras: Vec<NuuoCamera>,
}

impl Default for NuuoServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: HashMap::new(),
            product_name: "Moonlight NUUO".to_string(),
            version: "1.0".to_string(),
            cameras: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NuuoClientConfig {
    pub timeouts: Timeouts,
    pub username: String,
    pub password: String,
}

impl Default for NuuoClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: "admin".to_string(),
            password: "moonlight".to_string(),
        }
    }
}

pub struct NuuoServer {
    listener: TcpListener,
    config: NuuoServerConfig,
}

impl NuuoServer {
    pub fn bind(addr: SocketAddr, config: NuuoServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_session(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncNuuoServer {
    listener: tokio::net::TcpListener,
    config: NuuoServerConfig,
}

impl AsyncNuuoServer {
    pub async fn bind(addr: SocketAddr, config: NuuoServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_session_async(stream, config).await;
            });
        }
    }
}

pub struct NuuoClient {
    transport: TcpTransport,
}

impl NuuoClient {
    pub fn connect(addr: &net::NetAddr, config: NuuoClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let hello = build_hello("moonlight", "1.0");
        write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::Hello, hello))?;
        let _ = read_frame(&mut transport)?;
        let auth = build_auth(&config.username, &config.password);
        write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::Auth, auth))?;
        let response = read_frame(&mut transport)?;
        if response.msg_type != NuuoMessageType::AuthOk {
            return Err(CoreError::Message("nuuo auth failed".to_string()));
        }
        Ok(Self { transport })
    }

    pub fn ping(&mut self) -> CoreResult<()> {
        write_frame(&mut self.transport, &NuuoFrame::new(NuuoMessageType::Ping, Vec::new()))?;
        let response = read_frame(&mut self.transport)?;
        if response.msg_type != NuuoMessageType::Pong {
            return Err(CoreError::Parse("nuuo expected pong".to_string()));
        }
        Ok(())
    }

    pub fn get_info(&mut self) -> CoreResult<HashMap<String, String>> {
        write_frame(&mut self.transport, &NuuoFrame::new(NuuoMessageType::GetInfo, Vec::new()))?;
        let response = read_frame(&mut self.transport)?;
        if response.msg_type != NuuoMessageType::Info {
            return Err(CoreError::Parse("nuuo expected info".to_string()));
        }
        Ok(parse_kv_payload(&response.payload))
    }

    pub fn list_cameras(&mut self) -> CoreResult<Vec<NuuoCamera>> {
        write_frame(&mut self.transport, &NuuoFrame::new(NuuoMessageType::ListCameras, Vec::new()))?;
        let response = read_frame(&mut self.transport)?;
        if response.msg_type != NuuoMessageType::CameraList {
            return Err(CoreError::Parse("nuuo expected camera list".to_string()));
        }
        Ok(parse_camera_list(&response.payload))
    }
}

pub struct AsyncNuuoClient {
    transport: AsyncTcpTransport,
}

impl AsyncNuuoClient {
    pub async fn connect(addr: &net::NetAddr, config: NuuoClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let hello = build_hello("moonlight", "1.0");
        write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::Hello, hello)).await?;
        let _ = read_frame_async(&mut transport).await?;
        let auth = build_auth(&config.username, &config.password);
        write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::Auth, auth)).await?;
        let response = read_frame_async(&mut transport).await?;
        if response.msg_type != NuuoMessageType::AuthOk {
            return Err(CoreError::Message("nuuo auth failed".to_string()));
        }
        Ok(Self { transport })
    }

    pub async fn ping(&mut self) -> CoreResult<()> {
        write_frame_async(&mut self.transport, &NuuoFrame::new(NuuoMessageType::Ping, Vec::new())).await?;
        let response = read_frame_async(&mut self.transport).await?;
        if response.msg_type != NuuoMessageType::Pong {
            return Err(CoreError::Parse("nuuo expected pong".to_string()));
        }
        Ok(())
    }

    pub async fn get_info(&mut self) -> CoreResult<HashMap<String, String>> {
        write_frame_async(&mut self.transport, &NuuoFrame::new(NuuoMessageType::GetInfo, Vec::new())).await?;
        let response = read_frame_async(&mut self.transport).await?;
        if response.msg_type != NuuoMessageType::Info {
            return Err(CoreError::Parse("nuuo expected info".to_string()));
        }
        Ok(parse_kv_payload(&response.payload))
    }

    pub async fn list_cameras(&mut self) -> CoreResult<Vec<NuuoCamera>> {
        write_frame_async(&mut self.transport, &NuuoFrame::new(NuuoMessageType::ListCameras, Vec::new())).await?;
        let response = read_frame_async(&mut self.transport).await?;
        if response.msg_type != NuuoMessageType::CameraList {
            return Err(CoreError::Parse("nuuo expected camera list".to_string()));
        }
        Ok(parse_camera_list(&response.payload))
    }
}

fn handle_session(stream: TcpStream, config: NuuoServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let hello = read_frame(&mut transport)?;
    if hello.msg_type != NuuoMessageType::Hello {
        return Err(CoreError::Parse("nuuo expected hello".to_string()));
    }
    let server_hello = build_hello(&config.product_name, &config.version);
    write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::Hello, server_hello))?;

    let auth = read_frame(&mut transport)?;
    if auth.msg_type != NuuoMessageType::Auth {
        return Err(CoreError::Parse("nuuo expected auth".to_string()));
    }
    let auth_ok = validate_auth(&config.users, &auth.payload);
    if !auth_ok {
        write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::AuthFail, Vec::new()))?;
        return Ok(());
    }
    write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::AuthOk, Vec::new()))?;

    loop {
        let frame = match read_frame(&mut transport) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame.msg_type {
            NuuoMessageType::Ping => {
                write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::Pong, Vec::new()))?;
            }
            NuuoMessageType::GetInfo => {
                let payload = build_info(&config);
                write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::Info, payload))?;
            }
            NuuoMessageType::ListCameras => {
                let payload = build_camera_list(&config.cameras);
                write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::CameraList, payload))?;
            }
            _ => {
                write_frame(&mut transport, &NuuoFrame::new(NuuoMessageType::Error, b"unsupported".to_vec()))?;
            }
        }
    }
    Ok(())
}

async fn handle_session_async(stream: tokio::net::TcpStream, config: NuuoServerConfig) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let hello = read_frame_async(&mut transport).await?;
    if hello.msg_type != NuuoMessageType::Hello {
        return Err(CoreError::Parse("nuuo expected hello".to_string()));
    }
    let server_hello = build_hello(&config.product_name, &config.version);
    write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::Hello, server_hello)).await?;

    let auth = read_frame_async(&mut transport).await?;
    if auth.msg_type != NuuoMessageType::Auth {
        return Err(CoreError::Parse("nuuo expected auth".to_string()));
    }
    let auth_ok = validate_auth(&config.users, &auth.payload);
    if !auth_ok {
        write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::AuthFail, Vec::new())).await?;
        return Ok(());
    }
    write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::AuthOk, Vec::new())).await?;

    loop {
        let frame = match read_frame_async(&mut transport).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame.msg_type {
            NuuoMessageType::Ping => {
                write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::Pong, Vec::new())).await?;
            }
            NuuoMessageType::GetInfo => {
                let payload = build_info(&config);
                write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::Info, payload)).await?;
            }
            NuuoMessageType::ListCameras => {
                let payload = build_camera_list(&config.cameras);
                write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::CameraList, payload)).await?;
            }
            _ => {
                write_frame_async(&mut transport, &NuuoFrame::new(NuuoMessageType::Error, b"unsupported".to_vec())).await?;
            }
        }
    }
    Ok(())
}

fn build_hello(client: &str, version: &str) -> Vec<u8> {
    let mut map = HashMap::new();
    map.insert("name".to_string(), client.to_string());
    map.insert("version".to_string(), version.to_string());
    encode_kv_payload(&map)
}

fn build_auth(username: &str, password: &str) -> Vec<u8> {
    let mut map = HashMap::new();
    map.insert("username".to_string(), username.to_string());
    map.insert("password".to_string(), password.to_string());
    encode_kv_payload(&map)
}

fn build_info(config: &NuuoServerConfig) -> Vec<u8> {
    let mut map = HashMap::new();
    map.insert("product".to_string(), config.product_name.clone());
    map.insert("version".to_string(), config.version.clone());
    map.insert("cameras".to_string(), config.cameras.len().to_string());
    encode_kv_payload(&map)
}

fn build_camera_list(cameras: &[NuuoCamera]) -> Vec<u8> {
    let mut lines = Vec::new();
    for cam in cameras {
        let ip = cam.ip.map(|ip| ip.to_string()).unwrap_or_else(|| "".to_string());
        lines.push(format!("id={},name={},ip={}", cam.id, cam.name, ip));
    }
    lines.join("\n").into_bytes()
}

fn parse_camera_list(data: &[u8]) -> Vec<NuuoCamera> {
    let text = String::from_utf8_lossy(data);
    let mut cams = Vec::new();
    for line in text.lines() {
        let mut id = 0;
        let mut name = String::new();
        let mut ip = None;
        for part in line.split(',') {
            let mut iter = part.splitn(2, '=');
            let key = iter.next().unwrap_or("");
            let value = iter.next().unwrap_or("");
            match key {
                "id" => id = value.parse().unwrap_or(0),
                "name" => name = value.to_string(),
                "ip" => {
                    ip = value.parse::<Ipv4Addr>().ok();
                }
                _ => {}
            }
        }
        if !name.is_empty() {
            cams.push(NuuoCamera { id, name, ip });
        }
    }
    cams
}

fn validate_auth(users: &HashMap<String, String>, payload: &[u8]) -> bool {
    if users.is_empty() {
        return true;
    }
    let map = parse_kv_payload(payload);
    let username = map.get("username").cloned().unwrap_or_default();
    let password = map.get("password").cloned().unwrap_or_default();
    users.get(&username).map(|p| p == &password).unwrap_or(false)
}

fn encode_kv_payload(map: &HashMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in map {
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out
}

fn parse_kv_payload(payload: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(payload);
    let mut map = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

fn read_frame<T: StreamTransport>(transport: &mut T) -> CoreResult<NuuoFrame> {
    let mut header = [0u8; 10];
    transport.read_exact(&mut header)?;
    if &header[0..4] != MAGIC {
        return Err(CoreError::Parse("nuuo bad magic".to_string()));
    }
    let version = header[4];
    let msg_type = NuuoMessageType::from_u8(header[5])?;
    let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(CoreError::Parse("nuuo payload too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    Ok(NuuoFrame {
        version,
        msg_type,
        payload,
    })
}

async fn read_frame_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<NuuoFrame> {
    let mut header = [0u8; 10];
    transport.read_exact(&mut header).await?;
    if &header[0..4] != MAGIC {
        return Err(CoreError::Parse("nuuo bad magic".to_string()));
    }
    let version = header[4];
    let msg_type = NuuoMessageType::from_u8(header[5])?;
    let len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(CoreError::Parse("nuuo payload too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    Ok(NuuoFrame {
        version,
        msg_type,
        payload,
    })
}

fn write_frame<T: StreamTransport>(transport: &mut T, frame: &NuuoFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode())
}

async fn write_frame_async<T: AsyncStreamTransport>(
    transport: &mut T,
    frame: &NuuoFrame,
) -> CoreResult<()> {
    transport.write_all(&frame.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuuo_roundtrip() {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "moonlight".to_string());
        let server = NuuoServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            NuuoServerConfig {
                users,
                cameras: vec![NuuoCamera {
                    id: 1,
                    name: "Front".to_string(),
                    ip: Some(Ipv4Addr::new(192, 168, 1, 10)),
                }],
                ..NuuoServerConfig::default()
            },
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = NuuoClient::connect(
            &net::NetAddr::from_socket(addr),
            NuuoClientConfig::default(),
        )
        .unwrap();
        client.ping().unwrap();
        let info = client.get_info().unwrap();
        assert_eq!(info.get("product").unwrap(), "Moonlight NUUO");
        let cameras = client.list_cameras().unwrap();
        assert_eq!(cameras.len(), 1);
    }
}
