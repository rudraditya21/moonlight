use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

pub const MSDNSP_DEFAULT_PORT: u16 = 5354;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MsDnspRecordType {
    A = 0x0001,
    NS = 0x0002,
    CNAME = 0x0005,
    SOA = 0x0006,
    PTR = 0x000c,
    MX = 0x000f,
    TXT = 0x0010,
    AAAA = 0x001c,
    SRV = 0x0021,
    WINS = 0xff01,
    WINSR = 0xff02,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsDnspRData {
    A([u8; 4]),
    AAAA([u8; 16]),
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsDnspRecord {
    pub record_type: MsDnspRecordType,
    pub version: u8,
    pub rank: u8,
    pub flags: u16,
    pub serial: u32,
    pub ttl_seconds: u32,
    pub reserved: u32,
    pub timestamp: u32,
    pub data: MsDnspRData,
}

impl MsDnspRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let data = match &self.data {
            MsDnspRData::A(bytes) => bytes.to_vec(),
            MsDnspRData::AAAA(bytes) => bytes.to_vec(),
            MsDnspRData::Raw(bytes) => bytes.clone(),
        };
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(&(self.record_type as u16).to_le_bytes());
        out.push(self.version);
        out.push(self.rank);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.serial.to_le_bytes());
        out.extend_from_slice(&self.ttl_seconds.to_be_bytes());
        out.extend_from_slice(&self.reserved.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&data);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<(Self, usize)> {
        if data.len() < 24 {
            return Err(CoreError::Parse("ms_dnsp record too short".to_string()));
        }
        let data_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let rtype = u16::from_le_bytes([data[2], data[3]]);
        let record_type = match rtype {
            0x0001 => MsDnspRecordType::A,
            0x0002 => MsDnspRecordType::NS,
            0x0005 => MsDnspRecordType::CNAME,
            0x0006 => MsDnspRecordType::SOA,
            0x000c => MsDnspRecordType::PTR,
            0x000f => MsDnspRecordType::MX,
            0x0010 => MsDnspRecordType::TXT,
            0x001c => MsDnspRecordType::AAAA,
            0x0021 => MsDnspRecordType::SRV,
            0xff01 => MsDnspRecordType::WINS,
            0xff02 => MsDnspRecordType::WINSR,
            _ => MsDnspRecordType::TXT,
        };
        let version = data[4];
        let rank = data[5];
        let flags = u16::from_le_bytes([data[6], data[7]]);
        let serial = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let ttl_seconds = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let reserved = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let timestamp = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let start = 24;
        let end = start + data_len;
        if end > data.len() {
            return Err(CoreError::Parse("ms_dnsp rdata out of bounds".to_string()));
        }
        let rdata = match record_type {
            MsDnspRecordType::A if data_len == 4 => {
                MsDnspRData::A([data[start], data[start + 1], data[start + 2], data[start + 3]])
            }
            MsDnspRecordType::AAAA if data_len == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&data[start..end]);
                MsDnspRData::AAAA(arr)
            }
            _ => MsDnspRData::Raw(data[start..end].to_vec()),
        };
        Ok((
            MsDnspRecord {
                record_type,
                version,
                rank,
                flags,
                serial,
                ttl_seconds,
                reserved,
                timestamp,
                data: rdata,
            },
            end,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsDnspEntry {
    pub name: String,
    pub record: MsDnspRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsDnspOpcode {
    Query = 1,
    Update = 2,
    Response = 3,
}

#[derive(Debug, Clone)]
pub struct MsDnspMessage {
    pub id: u16,
    pub opcode: MsDnspOpcode,
    pub flags: u16,
    pub entries: Vec<MsDnspEntry>,
}

impl MsDnspMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&(self.opcode as u16).to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            let name_bytes = entry.name.as_bytes();
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(name_bytes);
            let record = entry.record.encode();
            out.extend_from_slice(&(record.len() as u16).to_le_bytes());
            out.extend_from_slice(&record);
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 8 {
            return Err(CoreError::Parse("ms_dnsp message too short".to_string()));
        }
        let id = u16::from_le_bytes([data[0], data[1]]);
        let opcode_raw = u16::from_le_bytes([data[2], data[3]]);
        let opcode = match opcode_raw {
            1 => MsDnspOpcode::Query,
            2 => MsDnspOpcode::Update,
            3 => MsDnspOpcode::Response,
            _ => MsDnspOpcode::Query,
        };
        let flags = u16::from_le_bytes([data[4], data[5]]);
        let count = u16::from_le_bytes([data[6], data[7]]) as usize;
        let mut entries = Vec::new();
        let mut idx = 8;
        for _ in 0..count {
            if idx + 2 > data.len() {
                return Err(CoreError::Parse("ms_dnsp entry name len".to_string()));
            }
            let name_len = u16::from_le_bytes([data[idx], data[idx + 1]]) as usize;
            idx += 2;
            if idx + name_len > data.len() {
                return Err(CoreError::Parse("ms_dnsp entry name".to_string()));
            }
            let name = String::from_utf8_lossy(&data[idx..idx + name_len]).to_string();
            idx += name_len;
            if idx + 2 > data.len() {
                return Err(CoreError::Parse("ms_dnsp record len".to_string()));
            }
            let record_len = u16::from_le_bytes([data[idx], data[idx + 1]]) as usize;
            idx += 2;
            if idx + record_len > data.len() {
                return Err(CoreError::Parse("ms_dnsp record data".to_string()));
            }
            let (record, _) = MsDnspRecord::decode(&data[idx..idx + record_len])?;
            idx += record_len;
            entries.push(MsDnspEntry { name, record });
        }
        Ok(Self {
            id,
            opcode,
            flags,
            entries,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MsDnspServerConfig {
    pub timeouts: Timeouts,
    pub allow_updates: bool,
}

impl Default for MsDnspServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            allow_updates: true,
        }
    }
}

#[derive(Debug, Default)]
struct ZoneStore {
    records: HashMap<String, Vec<MsDnspRecord>>,
}

impl ZoneStore {
    fn get(&self, name: &str, rtype: MsDnspRecordType) -> Vec<MsDnspRecord> {
        self.records
            .get(name)
            .map(|items| items.iter().filter(|r| r.record_type == rtype).cloned().collect())
            .unwrap_or_default()
    }

    fn upsert(&mut self, name: String, record: MsDnspRecord) {
        let entry = self.records.entry(name).or_insert_with(Vec::new);
        entry.retain(|r| r.record_type != record.record_type);
        entry.push(record);
    }
}

pub struct MsDnspServer {
    socket: UdpTransport,
    config: MsDnspServerConfig,
    store: Arc<Mutex<ZoneStore>>,
}

impl MsDnspServer {
    pub fn bind(addr: SocketAddr, config: MsDnspServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            config,
            store: Arc::new(Mutex::new(ZoneStore::default())),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn insert_record(&self, name: &str, record: MsDnspRecord) {
        if let Ok(mut store) = self.store.lock() {
            store.upsert(name.to_string(), record);
        }
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(2048)?;
            let socket = self.socket.clone();
            let config = self.config.clone();
            let store = Arc::clone(&self.store);
            thread::spawn(move || {
                let _ = handle_dnsp_request(socket, config, store, &data, peer);
            });
        }
    }
}

pub struct AsyncMsDnspServer {
    socket: AsyncUdpTransport,
    config: MsDnspServerConfig,
    store: Arc<Mutex<ZoneStore>>,
}

impl AsyncMsDnspServer {
    pub async fn bind(addr: SocketAddr, config: MsDnspServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            config,
            store: Arc::new(Mutex::new(ZoneStore::default())),
        })
    }

    pub fn insert_record(&self, name: &str, record: MsDnspRecord) {
        if let Ok(mut store) = self.store.lock() {
            store.upsert(name.to_string(), record);
        }
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(2048).await?;
            let config = self.config.clone();
            let store = Arc::clone(&self.store);
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_dnsp_request_async(socket, config, store, &data, peer).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct MsDnspClientConfig {
    pub timeouts: Timeouts,
}

impl Default for MsDnspClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct MsDnspClient {
    socket: UdpTransport,
}

impl MsDnspClient {
    pub fn connect(config: MsDnspClientConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket })
    }

    pub fn query(&self, addr: SocketAddr, name: &str, rtype: MsDnspRecordType) -> CoreResult<Vec<MsDnspRecord>> {
        let msg = MsDnspMessage {
            id: rand_id(),
            opcode: MsDnspOpcode::Query,
            flags: 0,
            entries: vec![MsDnspEntry {
                name: name.to_string(),
                record: MsDnspRecord {
                    record_type: rtype,
                    version: 1,
                    rank: 0,
                    flags: 0,
                    serial: 0,
                    ttl_seconds: 0,
                    reserved: 0,
                    timestamp: 0,
                    data: MsDnspRData::Raw(Vec::new()),
                },
            }],
        };
        self.socket.send_to(&msg.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(4096)?;
        let message = MsDnspMessage::decode(&resp)?;
        Ok(message.entries.into_iter().map(|e| e.record).collect())
    }

    pub fn update(&self, addr: SocketAddr, name: &str, record: MsDnspRecord) -> CoreResult<()> {
        let msg = MsDnspMessage {
            id: rand_id(),
            opcode: MsDnspOpcode::Update,
            flags: 0,
            entries: vec![MsDnspEntry {
                name: name.to_string(),
                record,
            }],
        };
        self.socket.send_to(&msg.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let message = MsDnspMessage::decode(&resp)?;
        if message.flags & 0x1 == 0x1 {
            Ok(())
        } else {
            Err(CoreError::Message("ms_dnsp update failed".to_string()))
        }
    }
}

pub struct AsyncMsDnspClient {
    socket: AsyncUdpTransport,
}

impl AsyncMsDnspClient {
    pub async fn connect() -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self { socket })
    }

    pub async fn query(&self, addr: SocketAddr, name: &str, rtype: MsDnspRecordType) -> CoreResult<Vec<MsDnspRecord>> {
        let msg = MsDnspMessage {
            id: rand_id(),
            opcode: MsDnspOpcode::Query,
            flags: 0,
            entries: vec![MsDnspEntry {
                name: name.to_string(),
                record: MsDnspRecord {
                    record_type: rtype,
                    version: 1,
                    rank: 0,
                    flags: 0,
                    serial: 0,
                    ttl_seconds: 0,
                    reserved: 0,
                    timestamp: 0,
                    data: MsDnspRData::Raw(Vec::new()),
                },
            }],
        };
        self.socket.send_to(&msg.encode(), addr).await?;
        let (resp, _) = self.socket.recv_from(4096).await?;
        let message = MsDnspMessage::decode(&resp)?;
        Ok(message.entries.into_iter().map(|e| e.record).collect())
    }
}

fn handle_dnsp_request(
    socket: UdpTransport,
    config: MsDnspServerConfig,
    store: Arc<Mutex<ZoneStore>>,
    data: &[u8],
    peer: SocketAddr,
) -> CoreResult<()> {
    let msg = MsDnspMessage::decode(data)?;
    let response = handle_dnsp_message(config, store, msg);
    socket.send_to(&response.encode(), peer)?;
    Ok(())
}

async fn handle_dnsp_request_async(
    socket: AsyncUdpTransport,
    config: MsDnspServerConfig,
    store: Arc<Mutex<ZoneStore>>,
    data: &[u8],
    peer: SocketAddr,
) -> CoreResult<()> {
    let msg = MsDnspMessage::decode(data)?;
    let response = handle_dnsp_message(config, store, msg);
    socket.send_to(&response.encode(), peer).await?;
    Ok(())
}

fn handle_dnsp_message(
    config: MsDnspServerConfig,
    store: Arc<Mutex<ZoneStore>>,
    msg: MsDnspMessage,
) -> MsDnspMessage {
    match msg.opcode {
        MsDnspOpcode::Query => {
            let mut entries = Vec::new();
            if let Ok(store) = store.lock() {
                for entry in &msg.entries {
                    let records = store.get(&entry.name, entry.record.record_type);
                    for record in records {
                        entries.push(MsDnspEntry {
                            name: entry.name.clone(),
                            record,
                        });
                    }
                }
            }
            MsDnspMessage {
                id: msg.id,
                opcode: MsDnspOpcode::Response,
                flags: 0x1,
                entries,
            }
        }
        MsDnspOpcode::Update => {
            let ok = config.allow_updates;
            if ok {
                if let Ok(mut store) = store.lock() {
                    for entry in &msg.entries {
                        let mut record = entry.record.clone();
                        record.timestamp = current_timestamp();
                        store.upsert(entry.name.clone(), record);
                    }
                }
            }
            MsDnspMessage {
                id: msg.id,
                opcode: MsDnspOpcode::Response,
                flags: if ok { 0x1 } else { 0 },
                entries: Vec::new(),
            }
        }
        MsDnspOpcode::Response => msg,
    }
}

fn rand_id() -> u16 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_nanos() & 0xFFFF) as u16
}

fn current_timestamp() -> u32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    now.as_secs() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_dnsp_query_update() {
        let server = MsDnspServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            MsDnspServerConfig::default(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let client = MsDnspClient::connect(MsDnspClientConfig::default()).unwrap();
        let record = MsDnspRecord {
            record_type: MsDnspRecordType::A,
            version: 1,
            rank: 0,
            flags: 0,
            serial: 1,
            ttl_seconds: 60,
            reserved: 0,
            timestamp: 0,
            data: MsDnspRData::A([127, 0, 0, 1]),
        };
        client.update(addr, "example.local", record).unwrap();
        let result = client.query(addr, "example.local", MsDnspRecordType::A).unwrap();
        assert_eq!(result.len(), 1);

        drop(handle);
    }
}
