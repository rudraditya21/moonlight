use std::collections::HashMap;
use std::net::SocketAddr;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

pub const QUAKE_DEFAULT_PORT: u16 = 27960;
const PREFIX: &[u8] = b"\xff\xff\xff\xff";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuakeQuery {
    GetInfo,
    GetStatus,
}

#[derive(Debug, Clone)]
pub struct QuakeInfo {
    pub values: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct QuakePlayer {
    pub score: i32,
    pub ping: i32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct QuakeStatus {
    pub values: HashMap<String, String>,
    pub players: Vec<QuakePlayer>,
}

#[derive(Debug, Clone)]
pub struct QuakeServerConfig {
    pub timeouts: Timeouts,
    pub info: HashMap<String, String>,
    pub players: Vec<QuakePlayer>,
}

impl Default for QuakeServerConfig {
    fn default() -> Self {
        let mut info = HashMap::new();
        info.insert("sv_hostname".to_string(), "Moonlight Quake".to_string());
        info.insert("mapname".to_string(), "q3dm1".to_string());
        info.insert("sv_maxclients".to_string(), "8".to_string());
        Self {
            timeouts: Timeouts::default(),
            info,
            players: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QuakeClientConfig {
    pub timeouts: Timeouts,
}

impl Default for QuakeClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct QuakeClient {
    transport: UdpTransport,
    server: SocketAddr,
}

impl QuakeClient {
    pub fn new(server: SocketAddr, config: QuakeClientConfig) -> CoreResult<Self> {
        let transport = UdpTransport::bind_any()?;
        transport.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { transport, server })
    }

    pub fn get_info(&self) -> CoreResult<QuakeInfo> {
        let payload = build_query(QuakeQuery::GetInfo);
        self.transport.send_to(&payload, self.server)?;
        let (data, _) = self.transport.recv_from(4096)?;
        parse_info_response(&data)
    }

    pub fn get_status(&self) -> CoreResult<QuakeStatus> {
        let payload = build_query(QuakeQuery::GetStatus);
        self.transport.send_to(&payload, self.server)?;
        let (data, _) = self.transport.recv_from(8192)?;
        parse_status_response(&data)
    }
}

pub struct AsyncQuakeClient {
    transport: AsyncUdpTransport,
    server: SocketAddr,
}

impl AsyncQuakeClient {
    pub async fn new(server: SocketAddr) -> CoreResult<Self> {
        let transport = AsyncUdpTransport::bind_any().await?;
        Ok(Self { transport, server })
    }

    pub async fn get_info(&self) -> CoreResult<QuakeInfo> {
        let payload = build_query(QuakeQuery::GetInfo);
        self.transport.send_to(&payload, self.server).await?;
        let (data, _) = self.transport.recv_from(4096).await?;
        parse_info_response(&data)
    }

    pub async fn get_status(&self) -> CoreResult<QuakeStatus> {
        let payload = build_query(QuakeQuery::GetStatus);
        self.transport.send_to(&payload, self.server).await?;
        let (data, _) = self.transport.recv_from(8192).await?;
        parse_status_response(&data)
    }
}

pub struct QuakeServer {
    socket: UdpTransport,
    config: QuakeServerConfig,
}

impl QuakeServer {
    pub fn bind(addr: SocketAddr, config: QuakeServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(4096)?;
            if let Some(query) = parse_query(&data) {
                let response = match query {
                    QuakeQuery::GetInfo => build_info_response(&self.config),
                    QuakeQuery::GetStatus => build_status_response(&self.config),
                };
                let _ = self.socket.send_to(&response, peer);
            }
        }
    }
}

pub struct AsyncQuakeServer {
    socket: AsyncUdpTransport,
    config: QuakeServerConfig,
}

impl AsyncQuakeServer {
    pub async fn bind(addr: SocketAddr, config: QuakeServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self { socket, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(4096).await?;
            if let Some(query) = parse_query(&data) {
                let response = match query {
                    QuakeQuery::GetInfo => build_info_response(&self.config),
                    QuakeQuery::GetStatus => build_status_response(&self.config),
                };
                let _ = self.socket.send_to(&response, peer).await;
            }
        }
    }
}

fn build_query(query: QuakeQuery) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PREFIX);
    match query {
        QuakeQuery::GetInfo => out.extend_from_slice(b"getinfo"),
        QuakeQuery::GetStatus => out.extend_from_slice(b"getstatus"),
    }
    out
}

fn parse_query(data: &[u8]) -> Option<QuakeQuery> {
    if data.len() < PREFIX.len() + 4 {
        return None;
    }
    if &data[..4] != PREFIX {
        return None;
    }
    let payload = String::from_utf8_lossy(&data[4..]);
    if payload.starts_with("getinfo") {
        Some(QuakeQuery::GetInfo)
    } else if payload.starts_with("getstatus") {
        Some(QuakeQuery::GetStatus)
    } else {
        None
    }
}

fn build_info_response(config: &QuakeServerConfig) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(b"infoResponse\n");
    out.extend_from_slice(encode_kv_pairs(&config.info).as_bytes());
    out
}

fn build_status_response(config: &QuakeServerConfig) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(b"statusResponse\n");
    out.extend_from_slice(encode_kv_pairs(&config.info).as_bytes());
    out.extend_from_slice(b"\n");
    for player in &config.players {
        out.extend_from_slice(format!("{} {} \"{}\"\n", player.score, player.ping, player.name).as_bytes());
    }
    out
}

fn parse_info_response(data: &[u8]) -> CoreResult<QuakeInfo> {
    let text = validate_prefix(data, "infoResponse")?;
    let values = parse_kv_pairs(text.trim());
    Ok(QuakeInfo { values })
}

fn parse_status_response(data: &[u8]) -> CoreResult<QuakeStatus> {
    let text = validate_prefix(data, "statusResponse")?;
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    let values = parse_kv_pairs(first.trim());
    let mut players = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((score, rest)) = line.split_once(' ') {
            if let Some((ping, name)) = rest.trim().split_once(' ') {
                let score = score.parse().unwrap_or(0);
                let ping = ping.parse().unwrap_or(0);
                let name = name.trim_matches('"').to_string();
                players.push(QuakePlayer { score, ping, name });
            }
        }
    }
    Ok(QuakeStatus { values, players })
}

fn validate_prefix(data: &[u8], label: &str) -> CoreResult<String> {
    if data.len() < PREFIX.len() + label.len() {
        return Err(CoreError::Parse("quake response short".to_string()));
    }
    if &data[..4] != PREFIX {
        return Err(CoreError::Parse("quake prefix".to_string()));
    }
    let text = String::from_utf8_lossy(&data[4..]).to_string();
    if !text.starts_with(label) {
        return Err(CoreError::Parse("quake response label".to_string()));
    }
    Ok(text[label.len()..].trim_start_matches('\n').to_string())
}

fn encode_kv_pairs(values: &HashMap<String, String>) -> String {
    let mut out = String::new();
    for (key, value) in values {
        out.push('\\');
        out.push_str(key);
        out.push('\\');
        out.push_str(value);
    }
    out
}

fn parse_kv_pairs(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut iter = text.split('\\').filter(|s| !s.is_empty());
    while let Some(key) = iter.next() {
        if let Some(value) = iter.next() {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn quake_info_status() {
        let mut info = HashMap::new();
        info.insert("sv_hostname".to_string(), "Moonlight".to_string());
        info.insert("mapname".to_string(), "q3dm17".to_string());
        let server = QuakeServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            QuakeServerConfig {
                info,
                players: vec![QuakePlayer { score: 1, ping: 33, name: "bot".to_string() }],
                ..QuakeServerConfig::default()
            },
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let client = QuakeClient::new(addr, QuakeClientConfig::default()).unwrap();
        let info = client.get_info().unwrap();
        assert_eq!(info.values.get("mapname").unwrap(), "q3dm17");
        let status = client.get_status().unwrap();
        assert_eq!(status.players.len(), 1);
    }
}
