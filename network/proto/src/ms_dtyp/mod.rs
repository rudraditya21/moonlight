use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub fn encode(&self) -> [u8; 16] {
        let mut out = self.0;
        out[..4].reverse();
        out[4..6].reverse();
        out[6..8].reverse();
        out
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        if bytes.len() != 16 {
            return Err(CoreError::Parse("guid length".to_string()));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        out[..4].reverse();
        out[4..6].reverse();
        out[6..8].reverse();
        Ok(Guid(out))
    }

    pub fn to_string(&self) -> String {
        let b = self.encode();
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTime(pub u64);

impl FileTime {
    pub fn now() -> Self {
        let unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let windows_ticks = unix.as_secs() * 10_000_000 + (unix.subsec_nanos() as u64 / 100);
        FileTime(windows_ticks + 11644473600u64 * 10_000_000)
    }

    pub fn to_unix_seconds(&self) -> u64 {
        if self.0 <= 11644473600u64 * 10_000_000 {
            return 0;
        }
        (self.0 - 11644473600u64 * 10_000_000) / 10_000_000
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.revision);
        out.push(self.sub_authorities.len() as u8);
        out.extend_from_slice(&self.identifier_authority);
        for sub in &self.sub_authorities {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 8 {
            return Err(CoreError::Parse("sid too short".to_string()));
        }
        let revision = data[0];
        let count = data[1] as usize;
        let mut auth = [0u8; 6];
        auth.copy_from_slice(&data[2..8]);
        let mut subs = Vec::new();
        let mut idx = 8;
        for _ in 0..count {
            if idx + 4 > data.len() {
                return Err(CoreError::Parse("sid subauthority".to_string()));
            }
            subs.push(u32::from_le_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]));
            idx += 4;
        }
        Ok(Self {
            revision,
            identifier_authority: auth,
            sub_authorities: subs,
        })
    }

    pub fn to_string(&self) -> String {
        let auth = u64::from_be_bytes([0, 0, self.identifier_authority[0], self.identifier_authority[1], self.identifier_authority[2], self.identifier_authority[3], self.identifier_authority[4], self.identifier_authority[5]]);
        let mut out = format!("S-{}-{}", self.revision, auth);
        for sub in &self.sub_authorities {
            out.push_str(&format!("-{}", sub));
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnicodeString {
    pub value: String,
}

impl UnicodeString {
    pub fn encode(&self) -> Vec<u8> {
        let utf16: Vec<u16> = self.value.encode_utf16().collect();
        let len_bytes = (utf16.len() * 2) as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&len_bytes.to_le_bytes());
        out.extend_from_slice(&len_bytes.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        for unit in utf16 {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 8 {
            return Err(CoreError::Parse("unicode string too short".to_string()));
        }
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut idx = 8;
        if idx + len > data.len() {
            return Err(CoreError::Parse("unicode string bounds".to_string()));
        }
        let mut units = Vec::new();
        while idx + 2 <= 8 + len {
            units.push(u16::from_le_bytes([data[idx], data[idx + 1]]));
            idx += 2;
        }
        let value = String::from_utf16(&units).map_err(|_| CoreError::Parse("unicode string utf16".to_string()))?;
        Ok(Self { value })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtypValue {
    Guid(Guid),
    FileTime(FileTime),
    Sid(Sid),
    UnicodeString(UnicodeString),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtypMessage {
    pub values: Vec<DtypValue>,
}

impl DtypMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.values.len() as u16).to_le_bytes());
        for value in &self.values {
            match value {
                DtypValue::Guid(g) => {
                    out.push(1);
                    out.extend_from_slice(&16u16.to_le_bytes());
                    out.extend_from_slice(&g.encode());
                }
                DtypValue::FileTime(ft) => {
                    out.push(2);
                    out.extend_from_slice(&8u16.to_le_bytes());
                    out.extend_from_slice(&ft.0.to_le_bytes());
                }
                DtypValue::Sid(sid) => {
                    let data = sid.encode();
                    out.push(3);
                    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                    out.extend_from_slice(&data);
                }
                DtypValue::UnicodeString(value) => {
                    let data = value.encode();
                    out.push(4);
                    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                    out.extend_from_slice(&data);
                }
                DtypValue::Raw(data) => {
                    out.push(255);
                    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
                    out.extend_from_slice(data);
                }
            }
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 2 {
            return Err(CoreError::Parse("dtyp message len".to_string()));
        }
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut idx = 2;
        let mut values = Vec::new();
        for _ in 0..count {
            if idx + 3 > data.len() {
                return Err(CoreError::Parse("dtyp item header".to_string()));
            }
            let kind = data[idx];
            let len = u16::from_le_bytes([data[idx + 1], data[idx + 2]]) as usize;
            idx += 3;
            if idx + len > data.len() {
                return Err(CoreError::Parse("dtyp item bounds".to_string()));
            }
            let slice = &data[idx..idx + len];
            let value = match kind {
                1 => DtypValue::Guid(Guid::decode(slice)?),
                2 => {
                    if slice.len() != 8 {
                        return Err(CoreError::Parse("dtyp filetime len".to_string()));
                    }
                    DtypValue::FileTime(FileTime(u64::from_le_bytes(slice.try_into().unwrap())))
                }
                3 => DtypValue::Sid(Sid::decode(slice)?),
                4 => DtypValue::UnicodeString(UnicodeString::decode(slice)?),
                _ => DtypValue::Raw(slice.to_vec()),
            };
            values.push(value);
            idx += len;
        }
        Ok(Self { values })
    }
}

#[derive(Debug, Clone)]
pub struct DtypServerConfig {
    pub timeouts: Timeouts,
}

impl Default for DtypServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct DtypServer {
    listener: TcpListener,
    config: DtypServerConfig,
}

impl DtypServer {
    pub fn bind(addr: SocketAddr, config: DtypServerConfig) -> CoreResult<Self> {
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
                let _ = handle_dtyp_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncDtypServer {
    listener: tokio::net::TcpListener,
    config: DtypServerConfig,
}

impl AsyncDtypServer {
    pub async fn bind(addr: SocketAddr, config: DtypServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_dtyp_stream_async(stream, config).await;
            });
        }
    }
}

pub struct DtypClient {
    transport: TcpTransport,
}

impl DtypClient {
    pub fn connect(addr: &net::NetAddr, config: DtypServerConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self { transport })
    }

    pub fn send(&mut self, message: &DtypMessage) -> CoreResult<DtypMessage> {
        write_message(&mut self.transport, message)?;
        read_message(&mut self.transport)
    }
}

pub struct AsyncDtypClient {
    transport: AsyncTcpTransport,
}

impl AsyncDtypClient {
    pub async fn connect(addr: &net::NetAddr, config: DtypServerConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self { transport })
    }

    pub async fn send(&mut self, message: &DtypMessage) -> CoreResult<DtypMessage> {
        write_message_async(&mut self.transport, message).await?;
        read_message_async(&mut self.transport).await
    }
}

fn handle_dtyp_stream(stream: TcpStream, config: DtypServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let msg = read_message(&mut transport)?;
        write_message(&mut transport, &msg)?;
    }
}

async fn handle_dtyp_stream_async(stream: tokio::net::TcpStream, _config: DtypServerConfig) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let msg = read_message_async(&mut transport).await?;
        write_message_async(&mut transport, &msg).await?;
    }
}

fn read_message<T: StreamTransport>(transport: &mut T) -> CoreResult<DtypMessage> {
    let mut len_bytes = [0u8; 4];
    transport.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    DtypMessage::decode(&payload)
}

async fn read_message_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<DtypMessage> {
    let mut len_bytes = [0u8; 4];
    transport.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    DtypMessage::decode(&payload)
}

fn write_message<T: StreamTransport>(transport: &mut T, message: &DtypMessage) -> CoreResult<()> {
    let payload = message.encode();
    transport.write_all(&(payload.len() as u32).to_be_bytes())?;
    transport.write_all(&payload)
}

async fn write_message_async<T: AsyncStreamTransport>(transport: &mut T, message: &DtypMessage) -> CoreResult<()> {
    let payload = message.encode();
    transport.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    transport.write_all(&payload).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtyp_roundtrip() {
        let server = crate::skip_if_perm!(DtypServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            DtypServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = DtypClient::connect(&net::NetAddr::from_socket(addr), DtypServerConfig::default()).unwrap();
        let message = DtypMessage {
            values: vec![
                DtypValue::Guid(Guid::decode(&[0; 16]).unwrap()),
                DtypValue::FileTime(FileTime::now()),
                DtypValue::UnicodeString(UnicodeString { value: "moon".to_string() }),
            ],
        };
        let resp = client.send(&message).unwrap();
        assert_eq!(resp.values.len(), 3);

        drop(handle);
    }
}
