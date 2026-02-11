use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

pub const MSTDS_DEFAULT_PORT: u16 = 1433;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdsMessageType {
    SqlBatch = 0x01,
    Prelogin = 0x12,
    Login7 = 0x10,
    Response = 0x04,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdsHeader {
    pub msg_type: TdsMessageType,
    pub status: u8,
    pub length: u16,
    pub spid: u16,
    pub packet_id: u8,
    pub window: u8,
}

impl TdsHeader {
    pub fn encode(&self) -> [u8; 8] {
        [
            self.msg_type as u8,
            self.status,
            (self.length >> 8) as u8,
            (self.length & 0xFF) as u8,
            (self.spid >> 8) as u8,
            (self.spid & 0xFF) as u8,
            self.packet_id,
            self.window,
        ]
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 8 {
            return Err(CoreError::Parse("tds header too short".to_string()));
        }
        let msg_type = match data[0] {
            0x01 => TdsMessageType::SqlBatch,
            0x12 => TdsMessageType::Prelogin,
            0x10 => TdsMessageType::Login7,
            0x04 => TdsMessageType::Response,
            _ => return Err(CoreError::Parse("tds unknown message type".to_string())),
        };
        let length = u16::from_be_bytes([data[2], data[3]]);
        Ok(Self {
            msg_type,
            status: data[1],
            length,
            spid: u16::from_be_bytes([data[4], data[5]]),
            packet_id: data[6],
            window: data[7],
        })
    }
}

#[derive(Debug, Clone)]
pub struct TdsPacket {
    pub header: TdsHeader,
    pub payload: Vec<u8>,
}

impl TdsPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        let header = TdsHeader::decode(data)?;
        let len = header.length as usize;
        if data.len() < len {
            return Err(CoreError::Parse("tds packet length".to_string()));
        }
        Ok(Self {
            header,
            payload: data[8..len].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PreloginInfo {
    pub version: u32,
    pub encryption: u8,
}

impl PreloginInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.encryption);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 5 {
            return Err(CoreError::Parse("tds prelogin len".to_string()));
        }
        Ok(Self {
            version: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            encryption: data[4],
        })
    }
}

#[derive(Debug, Clone)]
pub struct Login7 {
    pub username: String,
    pub password: String,
    pub database: String,
}

impl Login7 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_string(&mut out, &self.username);
        encode_string(&mut out, &self.password);
        encode_string(&mut out, &self.database);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        let mut idx = 0;
        let username = decode_string(data, &mut idx)?;
        let password = decode_string(data, &mut idx)?;
        let database = decode_string(data, &mut idx)?;
        Ok(Self {
            username,
            password,
            database,
        })
    }
}

#[derive(Debug, Clone)]
pub enum TdsToken {
    ColumnMetadata(Vec<String>),
    Row(Vec<Option<Vec<u8>>>),
    Done { row_count: u64 },
    Error(String),
}

impl TdsToken {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            TdsToken::ColumnMetadata(columns) => {
                out.push(0x81);
                out.extend_from_slice(&(columns.len() as u16).to_be_bytes());
                for col in columns {
                    out.push(col.len() as u8);
                    out.extend_from_slice(col.as_bytes());
                }
            }
            TdsToken::Row(values) => {
                out.push(0xD1);
                out.extend_from_slice(&(values.len() as u16).to_be_bytes());
                for value in values {
                    match value {
                        Some(bytes) => {
                            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                            out.extend_from_slice(bytes);
                        }
                        None => out.extend_from_slice(&0xFFFFu16.to_be_bytes()),
                    }
                }
            }
            TdsToken::Done { row_count } => {
                out.push(0xFD);
                out.extend_from_slice(&row_count.to_be_bytes());
            }
            TdsToken::Error(message) => {
                out.push(0xAA);
                out.extend_from_slice(&(message.len() as u16).to_be_bytes());
                out.extend_from_slice(message.as_bytes());
            }
        }
        out
    }

    pub fn decode(data: &[u8], idx: &mut usize) -> CoreResult<Self> {
        if *idx >= data.len() {
            return Err(CoreError::Parse("tds token eof".to_string()));
        }
        let kind = data[*idx];
        *idx += 1;
        match kind {
            0x81 => {
                if *idx + 2 > data.len() {
                    return Err(CoreError::Parse("tds columns len".to_string()));
                }
                let count = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
                *idx += 2;
                let mut cols = Vec::new();
                for _ in 0..count {
                    if *idx >= data.len() {
                        return Err(CoreError::Parse("tds column name".to_string()));
                    }
                    let len = data[*idx] as usize;
                    *idx += 1;
                    if *idx + len > data.len() {
                        return Err(CoreError::Parse("tds column name bounds".to_string()));
                    }
                    cols.push(String::from_utf8_lossy(&data[*idx..*idx + len]).to_string());
                    *idx += len;
                }
                Ok(TdsToken::ColumnMetadata(cols))
            }
            0xD1 => {
                if *idx + 2 > data.len() {
                    return Err(CoreError::Parse("tds row count".to_string()));
                }
                let count = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
                *idx += 2;
                let mut values = Vec::new();
                for _ in 0..count {
                    if *idx + 2 > data.len() {
                        return Err(CoreError::Parse("tds row value len".to_string()));
                    }
                    let len = u16::from_be_bytes([data[*idx], data[*idx + 1]]);
                    *idx += 2;
                    if len == 0xFFFF {
                        values.push(None);
                        continue;
                    }
                    let len = len as usize;
                    if *idx + len > data.len() {
                        return Err(CoreError::Parse("tds row value".to_string()));
                    }
                    values.push(Some(data[*idx..*idx + len].to_vec()));
                    *idx += len;
                }
                Ok(TdsToken::Row(values))
            }
            0xFD => {
                if *idx + 8 > data.len() {
                    return Err(CoreError::Parse("tds done".to_string()));
                }
                let row_count = u64::from_be_bytes(data[*idx..*idx + 8].try_into().unwrap());
                *idx += 8;
                Ok(TdsToken::Done { row_count })
            }
            0xAA => {
                if *idx + 2 > data.len() {
                    return Err(CoreError::Parse("tds error len".to_string()));
                }
                let len = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
                *idx += 2;
                if *idx + len > data.len() {
                    return Err(CoreError::Parse("tds error".to_string()));
                }
                let message = String::from_utf8_lossy(&data[*idx..*idx + len]).to_string();
                *idx += len;
                Ok(TdsToken::Error(message))
            }
            _ => Err(CoreError::Parse("tds token unknown".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TdsResponse {
    pub tokens: Vec<TdsToken>,
}

impl TdsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for token in &self.tokens {
            out.extend_from_slice(&token.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        let mut idx = 0;
        let mut tokens = Vec::new();
        while idx < data.len() {
            tokens.push(TdsToken::decode(data, &mut idx)?);
        }
        Ok(Self { tokens })
    }
}

#[derive(Debug, Clone)]
pub struct TdsServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
    pub default_database: String,
}

impl Default for TdsServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: HashMap::new(),
            default_database: "master".to_string(),
        }
    }
}

#[derive(Debug)]
struct TdsState {
    authenticated: bool,
    database: String,
}

pub struct TdsServer {
    listener: TcpListener,
    config: TdsServerConfig,
}

impl TdsServer {
    pub fn bind(addr: SocketAddr, config: TdsServerConfig) -> CoreResult<Self> {
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
                let _ = handle_tds_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncTdsServer {
    listener: tokio::net::TcpListener,
    config: TdsServerConfig,
}

impl AsyncTdsServer {
    pub async fn bind(addr: SocketAddr, config: TdsServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_tds_stream_async(stream, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct TdsClientConfig {
    pub timeouts: Timeouts,
    pub username: String,
    pub password: String,
    pub database: String,
}

impl Default for TdsClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: "sa".to_string(),
            password: "moonlight".to_string(),
            database: "master".to_string(),
        }
    }
}

pub struct TdsClient {
    transport: TcpTransport,
    packet_id: u8,
}

impl TdsClient {
    pub fn connect(addr: &net::NetAddr, config: TdsClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let prelogin = PreloginInfo { version: 1, encryption: 0 };
        write_packet(&mut transport, TdsMessageType::Prelogin, prelogin.encode(), 1)?;
        let _ = read_packet(&mut transport)?;

        let login = Login7 {
            username: config.username,
            password: config.password,
            database: config.database,
        };
        write_packet(&mut transport, TdsMessageType::Login7, login.encode(), 1)?;
        let resp = read_packet(&mut transport)?;
        let response = TdsResponse::decode(&resp.payload)?;
        if response.tokens.iter().any(|t| matches!(t, TdsToken::Error(_))) {
            return Err(CoreError::Message("tds login failed".to_string()));
        }
        Ok(Self { transport, packet_id: 1 })
    }

    pub fn query(&mut self, sql: &str) -> CoreResult<TdsResponse> {
        let payload = sql.as_bytes().to_vec();
        write_packet(&mut self.transport, TdsMessageType::SqlBatch, payload, self.packet_id)?;
        self.packet_id = self.packet_id.wrapping_add(1).max(1);
        let resp = read_packet(&mut self.transport)?;
        TdsResponse::decode(&resp.payload)
    }
}

pub struct AsyncTdsClient {
    transport: AsyncTcpTransport,
    packet_id: u8,
}

impl AsyncTdsClient {
    pub async fn connect(addr: &net::NetAddr, config: TdsClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let prelogin = PreloginInfo { version: 1, encryption: 0 };
        write_packet_async(&mut transport, TdsMessageType::Prelogin, prelogin.encode(), 1).await?;
        let _ = read_packet_async(&mut transport).await?;

        let login = Login7 {
            username: config.username,
            password: config.password,
            database: config.database,
        };
        write_packet_async(&mut transport, TdsMessageType::Login7, login.encode(), 1).await?;
        let resp = read_packet_async(&mut transport).await?;
        let response = TdsResponse::decode(&resp.payload)?;
        if response.tokens.iter().any(|t| matches!(t, TdsToken::Error(_))) {
            return Err(CoreError::Message("tds login failed".to_string()));
        }
        Ok(Self { transport, packet_id: 1 })
    }

    pub async fn query(&mut self, sql: &str) -> CoreResult<TdsResponse> {
        let payload = sql.as_bytes().to_vec();
        write_packet_async(&mut self.transport, TdsMessageType::SqlBatch, payload, self.packet_id).await?;
        self.packet_id = self.packet_id.wrapping_add(1).max(1);
        let resp = read_packet_async(&mut self.transport).await?;
        TdsResponse::decode(&resp.payload)
    }
}

fn handle_tds_stream(stream: TcpStream, config: TdsServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let mut state = TdsState {
        authenticated: false,
        database: config.default_database.clone(),
    };
    loop {
        let packet = read_packet(&mut transport)?;
        match packet.header.msg_type {
            TdsMessageType::Prelogin => {
                let prelogin = PreloginInfo::decode(&packet.payload)?;
                let resp = PreloginInfo {
                    version: prelogin.version,
                    encryption: 0,
                };
                write_packet(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id)?;
            }
            TdsMessageType::Login7 => {
                let login = Login7::decode(&packet.payload)?;
                if !config.users.is_empty() {
                    let ok = config.users.get(&login.username).map(|p| p == &login.password).unwrap_or(false);
                    if !ok {
                        let resp = TdsResponse {
                            tokens: vec![TdsToken::Error("login failed".to_string())],
                        };
                        write_packet(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id)?;
                        return Ok(());
                    }
                }
                state.authenticated = true;
                state.database = login.database;
                let resp = TdsResponse {
                    tokens: vec![TdsToken::Done { row_count: 0 }],
                };
                write_packet(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id)?;
            }
            TdsMessageType::SqlBatch => {
                if !state.authenticated {
                    let resp = TdsResponse {
                        tokens: vec![TdsToken::Error("not authenticated".to_string())],
                    };
                    write_packet(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id)?;
                    continue;
                }
                let sql = String::from_utf8_lossy(&packet.payload).trim().to_string();
                let response = execute_query(&sql, &state);
                write_packet(&mut transport, TdsMessageType::Response, response.encode(), packet.header.packet_id)?;
            }
            _ => {}
        }
    }
}

async fn handle_tds_stream_async(stream: tokio::net::TcpStream, config: TdsServerConfig) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut state = TdsState {
        authenticated: false,
        database: config.default_database.clone(),
    };
    loop {
        let packet = read_packet_async(&mut transport).await?;
        match packet.header.msg_type {
            TdsMessageType::Prelogin => {
                let prelogin = PreloginInfo::decode(&packet.payload)?;
                let resp = PreloginInfo {
                    version: prelogin.version,
                    encryption: 0,
                };
                write_packet_async(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id).await?;
            }
            TdsMessageType::Login7 => {
                let login = Login7::decode(&packet.payload)?;
                if !config.users.is_empty() {
                    let ok = config.users.get(&login.username).map(|p| p == &login.password).unwrap_or(false);
                    if !ok {
                        let resp = TdsResponse {
                            tokens: vec![TdsToken::Error("login failed".to_string())],
                        };
                        write_packet_async(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id).await?;
                        return Ok(());
                    }
                }
                state.authenticated = true;
                state.database = login.database;
                let resp = TdsResponse {
                    tokens: vec![TdsToken::Done { row_count: 0 }],
                };
                write_packet_async(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id).await?;
            }
            TdsMessageType::SqlBatch => {
                if !state.authenticated {
                    let resp = TdsResponse {
                        tokens: vec![TdsToken::Error("not authenticated".to_string())],
                    };
                    write_packet_async(&mut transport, TdsMessageType::Response, resp.encode(), packet.header.packet_id).await?;
                    continue;
                }
                let sql = String::from_utf8_lossy(&packet.payload).trim().to_string();
                let response = execute_query(&sql, &state);
                write_packet_async(&mut transport, TdsMessageType::Response, response.encode(), packet.header.packet_id).await?;
            }
            _ => {}
        }
    }
}

fn execute_query(sql: &str, state: &TdsState) -> TdsResponse {
    let lower = sql.to_lowercase();
    if lower.starts_with("select") {
        if lower.contains("@@version") {
            return simple_row(vec!["version".to_string()], vec!["Moonlight TDS 0.1".as_bytes().to_vec()]);
        }
        if lower.contains("1") {
            return simple_row(vec!["1".to_string()], vec![b"1".to_vec()]);
        }
        if let Some(start) = sql.find('\'') {
            if let Some(end) = sql[start + 1..].find('\'') {
                let value = &sql[start + 1..start + 1 + end];
                return simple_row(vec!["value".to_string()], vec![value.as_bytes().to_vec()]);
            }
        }
        return simple_row(vec!["database".to_string()], vec![state.database.as_bytes().to_vec()]);
    }
    if lower.starts_with("use ") {
        let db = sql[4..].trim();
        return TdsResponse {
            tokens: vec![TdsToken::Done { row_count: 0 }, TdsToken::Row(vec![Some(db.as_bytes().to_vec())])],
        };
    }
    TdsResponse {
        tokens: vec![TdsToken::Error("unsupported query".to_string())],
    }
}

fn simple_row(columns: Vec<String>, values: Vec<Vec<u8>>) -> TdsResponse {
    TdsResponse {
        tokens: vec![
            TdsToken::ColumnMetadata(columns),
            TdsToken::Row(values.into_iter().map(Some).collect()),
            TdsToken::Done { row_count: 1 },
        ],
    }
}

fn read_packet<T: StreamTransport>(transport: &mut T) -> CoreResult<TdsPacket> {
    let mut header = [0u8; 8];
    transport.read_exact(&mut header)?;
    let hdr = TdsHeader::decode(&header)?;
    let length = hdr.length as usize;
    if length < 8 {
        return Err(CoreError::Parse("tds invalid length".to_string()));
    }
    let mut payload = vec![0u8; length - 8];
    if !payload.is_empty() {
        transport.read_exact(&mut payload)?;
    }
    Ok(TdsPacket {
        header: hdr,
        payload,
    })
}

async fn read_packet_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<TdsPacket> {
    let mut header = [0u8; 8];
    transport.read_exact(&mut header).await?;
    let hdr = TdsHeader::decode(&header)?;
    let length = hdr.length as usize;
    if length < 8 {
        return Err(CoreError::Parse("tds invalid length".to_string()));
    }
    let mut payload = vec![0u8; length - 8];
    if !payload.is_empty() {
        transport.read_exact(&mut payload).await?;
    }
    Ok(TdsPacket {
        header: hdr,
        payload,
    })
}

fn write_packet<T: StreamTransport>(transport: &mut T, msg_type: TdsMessageType, payload: Vec<u8>, packet_id: u8) -> CoreResult<()> {
    let length = (payload.len() + 8) as u16;
    let header = TdsHeader {
        msg_type,
        status: 0x01,
        length,
        spid: 0,
        packet_id,
        window: 0,
    };
    let packet = TdsPacket { header, payload };
    transport.write_all(&packet.encode())
}

async fn write_packet_async<T: AsyncStreamTransport>(
    transport: &mut T,
    msg_type: TdsMessageType,
    payload: Vec<u8>,
    packet_id: u8,
) -> CoreResult<()> {
    let length = (payload.len() + 8) as u16;
    let header = TdsHeader {
        msg_type,
        status: 0x01,
        length,
        spid: 0,
        packet_id,
        window: 0,
    };
    let packet = TdsPacket { header, payload };
    transport.write_all(&packet.encode()).await
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn decode_string(data: &[u8], idx: &mut usize) -> CoreResult<String> {
    if *idx + 2 > data.len() {
        return Err(CoreError::Parse("tds string len".to_string()));
    }
    let len = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
    *idx += 2;
    if *idx + len > data.len() {
        return Err(CoreError::Parse("tds string bounds".to_string()));
    }
    let value = String::from_utf8_lossy(&data[*idx..*idx + len]).to_string();
    *idx += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tds_query_select() {
        let mut users = HashMap::new();
        users.insert("sa".to_string(), "moonlight".to_string());
        let server = crate::skip_if_perm!(TdsServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            TdsServerConfig {
                users,
                ..TdsServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = TdsClient::connect(
            &net::NetAddr::from_socket(addr),
            TdsClientConfig::default(),
        )
        .unwrap();
        let resp = client.query("SELECT 1").unwrap();
        assert!(!resp.tokens.is_empty());

        drop(handle);
    }
}
