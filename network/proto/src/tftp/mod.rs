use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

const OPCODE_RRQ: u16 = 1;
const OPCODE_WRQ: u16 = 2;
const OPCODE_DATA: u16 = 3;
const OPCODE_ACK: u16 = 4;
const OPCODE_ERROR: u16 = 5;
const OPCODE_OACK: u16 = 6;

pub const TFTP_DEFAULT_PORT: u16 = 69;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpMode {
    NetAscii,
    Octet,
    Mail,
}

impl TftpMode {
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value.to_ascii_lowercase().as_str() {
            "netascii" => Ok(TftpMode::NetAscii),
            "octet" => Ok(TftpMode::Octet),
            "mail" => Ok(TftpMode::Mail),
            _ => Err(CoreError::Parse("invalid TFTP mode".to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TftpMode::NetAscii => "netascii",
            TftpMode::Octet => "octet",
            TftpMode::Mail => "mail",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TftpOptions {
    pub blksize: Option<u16>,
    pub timeout: Option<u16>,
    pub tsize: Option<u64>,
    pub windowsize: Option<u16>,
    pub other: HashMap<String, String>,
}

impl TftpOptions {
    pub fn is_empty(&self) -> bool {
        self.blksize.is_none()
            && self.timeout.is_none()
            && self.tsize.is_none()
            && self.windowsize.is_none()
            && self.other.is_empty()
    }

    fn to_pairs(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(value) = self.blksize {
            out.push(("blksize".to_string(), value.to_string()));
        }
        if let Some(value) = self.timeout {
            out.push(("timeout".to_string(), value.to_string()));
        }
        if let Some(value) = self.tsize {
            out.push(("tsize".to_string(), value.to_string()));
        }
        if let Some(value) = self.windowsize {
            out.push(("windowsize".to_string(), value.to_string()));
        }
        for (key, value) in &self.other {
            out.push((key.clone(), value.clone()));
        }
        out
    }

    fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        let mut out = TftpOptions::default();
        for (key, value) in pairs {
            match key.to_ascii_lowercase().as_str() {
                "blksize" => {
                    if let Ok(parsed) = value.parse::<u16>() {
                        out.blksize = Some(parsed);
                    }
                }
                "timeout" => {
                    if let Ok(parsed) = value.parse::<u16>() {
                        out.timeout = Some(parsed);
                    }
                }
                "tsize" => {
                    if let Ok(parsed) = value.parse::<u64>() {
                        out.tsize = Some(parsed);
                    }
                }
                "windowsize" => {
                    if let Ok(parsed) = value.parse::<u16>() {
                        out.windowsize = Some(parsed);
                    }
                }
                other => {
                    out.other.insert(other.to_string(), value);
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpErrorCode {
    NotDefined = 0,
    FileNotFound = 1,
    AccessViolation = 2,
    DiskFull = 3,
    IllegalOperation = 4,
    UnknownTransferId = 5,
    FileExists = 6,
    NoSuchUser = 7,
    OptionNegotiation = 8,
}

impl TftpErrorCode {
    fn from_u16(value: u16) -> CoreResult<Self> {
        match value {
            0 => Ok(TftpErrorCode::NotDefined),
            1 => Ok(TftpErrorCode::FileNotFound),
            2 => Ok(TftpErrorCode::AccessViolation),
            3 => Ok(TftpErrorCode::DiskFull),
            4 => Ok(TftpErrorCode::IllegalOperation),
            5 => Ok(TftpErrorCode::UnknownTransferId),
            6 => Ok(TftpErrorCode::FileExists),
            7 => Ok(TftpErrorCode::NoSuchUser),
            8 => Ok(TftpErrorCode::OptionNegotiation),
            _ => Err(CoreError::Parse("invalid TFTP error code".to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TftpPacket {
    ReadRequest {
        filename: String,
        mode: TftpMode,
        options: TftpOptions,
    },
    WriteRequest {
        filename: String,
        mode: TftpMode,
        options: TftpOptions,
    },
    Data {
        block: u16,
        data: Vec<u8>,
    },
    Ack {
        block: u16,
    },
    Error {
        code: TftpErrorCode,
        message: String,
    },
    OptionAck {
        options: TftpOptions,
    },
}

impl TftpPacket {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            TftpPacket::ReadRequest {
                filename,
                mode,
                options,
            } => {
                out.extend_from_slice(&OPCODE_RRQ.to_be_bytes());
                out.extend_from_slice(filename.as_bytes());
                out.push(0);
                out.extend_from_slice(mode.as_str().as_bytes());
                out.push(0);
                for (key, value) in options.to_pairs() {
                    out.extend_from_slice(key.as_bytes());
                    out.push(0);
                    out.extend_from_slice(value.as_bytes());
                    out.push(0);
                }
            }
            TftpPacket::WriteRequest {
                filename,
                mode,
                options,
            } => {
                out.extend_from_slice(&OPCODE_WRQ.to_be_bytes());
                out.extend_from_slice(filename.as_bytes());
                out.push(0);
                out.extend_from_slice(mode.as_str().as_bytes());
                out.push(0);
                for (key, value) in options.to_pairs() {
                    out.extend_from_slice(key.as_bytes());
                    out.push(0);
                    out.extend_from_slice(value.as_bytes());
                    out.push(0);
                }
            }
            TftpPacket::Data { block, data } => {
                out.extend_from_slice(&OPCODE_DATA.to_be_bytes());
                out.extend_from_slice(&block.to_be_bytes());
                out.extend_from_slice(data);
            }
            TftpPacket::Ack { block } => {
                out.extend_from_slice(&OPCODE_ACK.to_be_bytes());
                out.extend_from_slice(&block.to_be_bytes());
            }
            TftpPacket::Error { code, message } => {
                out.extend_from_slice(&OPCODE_ERROR.to_be_bytes());
                out.extend_from_slice(&(*code as u16).to_be_bytes());
                out.extend_from_slice(message.as_bytes());
                out.push(0);
            }
            TftpPacket::OptionAck { options } => {
                out.extend_from_slice(&OPCODE_OACK.to_be_bytes());
                for (key, value) in options.to_pairs() {
                    out.extend_from_slice(key.as_bytes());
                    out.push(0);
                    out.extend_from_slice(value.as_bytes());
                    out.push(0);
                }
            }
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 2 {
            return Err(CoreError::Parse("tftp packet too short".to_string()));
        }
        let opcode = u16::from_be_bytes([data[0], data[1]]);
        match opcode {
            OPCODE_RRQ | OPCODE_WRQ => {
                let parts = split_zstrings(&data[2..])?;
                if parts.len() < 2 {
                    return Err(CoreError::Parse("invalid request".to_string()));
                }
                let filename = parts[0].clone();
                let mode = TftpMode::parse(&parts[1])?;
                let options = parse_option_pairs(&parts[2..])?;
                if opcode == OPCODE_RRQ {
                    Ok(TftpPacket::ReadRequest {
                        filename,
                        mode,
                        options,
                    })
                } else {
                    Ok(TftpPacket::WriteRequest {
                        filename,
                        mode,
                        options,
                    })
                }
            }
            OPCODE_DATA => {
                if data.len() < 4 {
                    return Err(CoreError::Parse("data packet too short".to_string()));
                }
                let block = u16::from_be_bytes([data[2], data[3]]);
                Ok(TftpPacket::Data {
                    block,
                    data: data[4..].to_vec(),
                })
            }
            OPCODE_ACK => {
                if data.len() < 4 {
                    return Err(CoreError::Parse("ack packet too short".to_string()));
                }
                let block = u16::from_be_bytes([data[2], data[3]]);
                Ok(TftpPacket::Ack { block })
            }
            OPCODE_ERROR => {
                if data.len() < 4 {
                    return Err(CoreError::Parse("error packet too short".to_string()));
                }
                let code = TftpErrorCode::from_u16(u16::from_be_bytes([data[2], data[3]]))?;
                let message = parse_single_zstring(&data[4..])?;
                Ok(TftpPacket::Error { code, message })
            }
            OPCODE_OACK => {
                let pairs = split_zstrings(&data[2..])?;
                let options = parse_option_pairs(&pairs)?;
                Ok(TftpPacket::OptionAck { options })
            }
            _ => Err(CoreError::Parse("unknown TFTP opcode".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TftpClientConfig {
    pub timeouts: Timeouts,
    pub retries: usize,
    pub blksize: u16,
    pub timeout_secs: u16,
    pub windowsize: u16,
    pub mode: TftpMode,
    pub request_tsize: bool,
}

impl Default for TftpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            retries: 3,
            blksize: 512,
            timeout_secs: 5,
            windowsize: 1,
            mode: TftpMode::Octet,
            request_tsize: true,
        }
    }
}

pub struct TftpClient {
    config: TftpClientConfig,
}

impl TftpClient {
    pub fn new(config: TftpClientConfig) -> Self {
        Self { config }
    }

    pub fn read(&self, addr: SocketAddr, filename: &str) -> CoreResult<Vec<u8>> {
        let options = self.base_options(None);
        let request = TftpPacket::ReadRequest {
            filename: filename.to_string(),
            mode: self.config.mode,
            options,
        };
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(self.config.timeouts.read))?;
        let mut server_addr = addr;
        let request_bytes = request.encode()?;
        socket.send_to(&request_bytes, addr)?;
        let mut blksize = self.config.blksize;
        let mut output = Vec::new();
        let mut expected_block = 1u16;
        let mut resend = request_bytes.clone();
        loop {
            let (packet, source) =
                recv_with_retry(&socket, &resend, server_addr, self.config.retries)?;
            server_addr = source;
            match packet {
                TftpPacket::OptionAck { options: oack } => {
                    if let Some(value) = oack.blksize {
                        blksize = value;
                    }
                    if let Some(value) = oack.timeout {
                        socket.set_read_timeout(Some(Duration::from_secs(value as u64)))?;
                    }
                    resend = request_bytes.clone();
                }
                TftpPacket::Data { block, data } => {
                    if block == expected_block {
                        output.extend_from_slice(&data);
                        let ack = TftpPacket::Ack { block }.encode()?;
                        socket.send_to(&ack, server_addr)?;
                        resend = ack;
                        expected_block = expected_block.wrapping_add(1);
                        if data.len() < blksize as usize {
                            break;
                        }
                    } else if block < expected_block {
                        let ack = TftpPacket::Ack { block }.encode()?;
                        socket.send_to(&ack, server_addr)?;
                    }
                }
                TftpPacket::Error { code, message } => {
                    return Err(CoreError::Message(format!(
                        "tftp error {:?}: {}",
                        code, message
                    )));
                }
                _ => {}
            }
        }
        if self.config.mode == TftpMode::NetAscii {
            Ok(from_netascii(&output))
        } else {
            Ok(output)
        }
    }

    pub fn write(&self, addr: SocketAddr, filename: &str, data: &[u8]) -> CoreResult<()> {
        let payload = if self.config.mode == TftpMode::NetAscii {
            to_netascii(data)
        } else {
            data.to_vec()
        };
        let options = self.base_options(Some(payload.len() as u64));
        let request = TftpPacket::WriteRequest {
            filename: filename.to_string(),
            mode: self.config.mode,
            options,
        };
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(self.config.timeouts.read))?;
        let request_bytes = request.encode()?;
        socket.send_to(&request_bytes, addr)?;
        let mut server_addr: SocketAddr;
        let mut blksize = self.config.blksize;
        let mut expected_block = 1u16;
        let mut offset = 0usize;
        loop {
            let packet = recv_with_retry(&socket, &request_bytes, addr, self.config.retries)?;
            server_addr = packet.1;
            match packet.0 {
                TftpPacket::OptionAck { options: oack } => {
                    if let Some(value) = oack.blksize {
                        blksize = value;
                    }
                    if let Some(value) = oack.timeout {
                        socket.set_read_timeout(Some(Duration::from_secs(value as u64)))?;
                    }
                    break;
                }
                TftpPacket::Ack { block } if block == 0 => {
                    break;
                }
                TftpPacket::Error { code, message } => {
                    return Err(CoreError::Message(format!(
                        "tftp error {:?}: {}",
                        code, message
                    )));
                }
                _ => {}
            }
        }
        loop {
            let end = (offset + blksize as usize).min(payload.len());
            let chunk = &payload[offset..end];
            let data_packet = TftpPacket::Data {
                block: expected_block,
                data: chunk.to_vec(),
            }
            .encode()?;
            let mut attempts = self.config.retries;
            loop {
                socket.send_to(&data_packet, server_addr)?;
                match recv_with_timeout(&socket) {
                    Ok((packet, addr)) => {
                        if addr != server_addr {
                            send_error(
                                &socket,
                                addr,
                                TftpErrorCode::UnknownTransferId,
                                "unknown transfer",
                            )?;
                            continue;
                        }
                        match packet {
                            TftpPacket::Ack { block } if block == expected_block => break,
                            TftpPacket::Ack { block } if block < expected_block => break,
                            TftpPacket::Error { code, message } => {
                                return Err(CoreError::Message(format!(
                                    "tftp error {:?}: {}",
                                    code, message
                                )));
                            }
                            _ => {}
                        }
                    }
                    Err(err) => {
                        if is_timeout(&err) {
                            if attempts == 0 {
                                return Err(CoreError::Message("tftp write timeout".to_string()));
                            }
                            attempts -= 1;
                            continue;
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
            offset = end;
            expected_block = expected_block.wrapping_add(1);
            if chunk.len() < blksize as usize {
                break;
            }
        }
        Ok(())
    }

    fn base_options(&self, tsize: Option<u64>) -> TftpOptions {
        let mut options = TftpOptions::default();
        options.blksize = Some(self.config.blksize);
        options.timeout = Some(self.config.timeout_secs);
        options.windowsize = Some(self.config.windowsize);
        if self.config.request_tsize {
            options.tsize = Some(tsize.unwrap_or(0));
        }
        options
    }
}

pub struct AsyncTftpClient {
    config: TftpClientConfig,
}

impl AsyncTftpClient {
    pub fn new(config: TftpClientConfig) -> Self {
        Self { config }
    }

    pub async fn read(&self, addr: SocketAddr, filename: &str) -> CoreResult<Vec<u8>> {
        let options = self.base_options(None);
        let request = TftpPacket::ReadRequest {
            filename: filename.to_string(),
            mode: self.config.mode,
            options,
        };
        let socket = AsyncUdpTransport::bind_any().await?;
        let request_bytes = request.encode()?;
        socket.send_to(&request_bytes, addr).await?;
        let mut server_addr = addr;
        let mut blksize = self.config.blksize;
        let mut output = Vec::new();
        let mut expected_block = 1u16;
        let mut resend = request_bytes.clone();
        loop {
            let (packet, source) = recv_with_retry_async(
                &socket,
                &resend,
                server_addr,
                self.config.retries,
                self.config.timeouts.read,
            )
            .await?;
            server_addr = source;
            match packet {
                TftpPacket::OptionAck { options: oack } => {
                    if let Some(value) = oack.blksize {
                        blksize = value;
                    }
                    resend = request_bytes.clone();
                }
                TftpPacket::Data { block, data } => {
                    if block == expected_block {
                        output.extend_from_slice(&data);
                        let ack = TftpPacket::Ack { block }.encode()?;
                        socket.send_to(&ack, server_addr).await?;
                        resend = ack;
                        expected_block = expected_block.wrapping_add(1);
                        if data.len() < blksize as usize {
                            break;
                        }
                    } else if block < expected_block {
                        let ack = TftpPacket::Ack { block }.encode()?;
                        socket.send_to(&ack, server_addr).await?;
                    }
                }
                TftpPacket::Error { code, message } => {
                    return Err(CoreError::Message(format!(
                        "tftp error {:?}: {}",
                        code, message
                    )));
                }
                _ => {}
            }
        }
        if self.config.mode == TftpMode::NetAscii {
            Ok(from_netascii(&output))
        } else {
            Ok(output)
        }
    }

    pub async fn write(&self, addr: SocketAddr, filename: &str, data: &[u8]) -> CoreResult<()> {
        let payload = if self.config.mode == TftpMode::NetAscii {
            to_netascii(data)
        } else {
            data.to_vec()
        };
        let options = self.base_options(Some(payload.len() as u64));
        let request = TftpPacket::WriteRequest {
            filename: filename.to_string(),
            mode: self.config.mode,
            options,
        };
        let socket = AsyncUdpTransport::bind_any().await?;
        let request_bytes = request.encode()?;
        socket.send_to(&request_bytes, addr).await?;
        let (packet, server_addr) = recv_with_retry_async(
            &socket,
            &request_bytes,
            addr,
            self.config.retries,
            self.config.timeouts.read,
        )
        .await?;
        let mut blksize = self.config.blksize;
        match packet {
            TftpPacket::OptionAck { options: oack } => {
                if let Some(value) = oack.blksize {
                    blksize = value;
                }
            }
            TftpPacket::Ack { block } if block == 0 => {}
            TftpPacket::Error { code, message } => {
                return Err(CoreError::Message(format!(
                    "tftp error {:?}: {}",
                    code, message
                )));
            }
            _ => {}
        }
        let mut offset = 0usize;
        let mut expected_block = 1u16;
        loop {
            let end = (offset + blksize as usize).min(payload.len());
            let chunk = &payload[offset..end];
            let data_packet = TftpPacket::Data {
                block: expected_block,
                data: chunk.to_vec(),
            }
            .encode()?;
            let mut attempts = self.config.retries;
            loop {
                socket.send_to(&data_packet, server_addr).await?;
                match recv_with_timeout_async(&socket, self.config.timeouts.read).await {
                    Ok((packet, addr)) => {
                        if addr != server_addr {
                            let _ = send_error_async(
                                &socket,
                                addr,
                                TftpErrorCode::UnknownTransferId,
                                "unknown transfer",
                            )
                            .await;
                            continue;
                        }
                        match packet {
                            TftpPacket::Ack { block } if block == expected_block => break,
                            TftpPacket::Ack { block } if block < expected_block => break,
                            TftpPacket::Error { code, message } => {
                                return Err(CoreError::Message(format!(
                                    "tftp error {:?}: {}",
                                    code, message
                                )));
                            }
                            _ => {}
                        }
                    }
                    Err(err) => {
                        if is_timeout(&err) {
                            if attempts == 0 {
                                return Err(CoreError::Message("tftp write timeout".to_string()));
                            }
                            attempts -= 1;
                            continue;
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
            offset = end;
            expected_block = expected_block.wrapping_add(1);
            if chunk.len() < blksize as usize {
                break;
            }
        }
        Ok(())
    }

    fn base_options(&self, tsize: Option<u64>) -> TftpOptions {
        let mut options = TftpOptions::default();
        options.blksize = Some(self.config.blksize);
        options.timeout = Some(self.config.timeout_secs);
        options.windowsize = Some(self.config.windowsize);
        if self.config.request_tsize {
            options.tsize = Some(tsize.unwrap_or(0));
        }
        options
    }
}

#[derive(Debug, Clone)]
pub struct TftpServerConfig {
    pub timeouts: Timeouts,
    pub max_blksize: u16,
    pub max_windowsize: u16,
    pub allow_netascii: bool,
}

impl Default for TftpServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            max_blksize: 65464,
            max_windowsize: 1,
            allow_netascii: true,
        }
    }
}

pub trait TftpBackend: Send + Sync {
    fn read(&self, filename: &str) -> CoreResult<Vec<u8>>;
    fn write(&self, filename: &str, data: &[u8]) -> CoreResult<()>;
}

#[derive(Debug, Default)]
pub struct InMemoryTftpBackend {
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryTftpBackend {
    pub fn with_file(self, filename: &str, data: Vec<u8>) -> Self {
        let mut guard = self.files.lock().expect("files");
        guard.insert(filename.to_string(), data);
        drop(guard);
        self
    }
}

impl TftpBackend for InMemoryTftpBackend {
    fn read(&self, filename: &str) -> CoreResult<Vec<u8>> {
        let guard = self
            .files
            .lock()
            .map_err(|_| CoreError::Message("files poisoned".to_string()))?;
        guard
            .get(filename)
            .cloned()
            .ok_or_else(|| CoreError::Message("file not found".to_string()))
    }

    fn write(&self, filename: &str, data: &[u8]) -> CoreResult<()> {
        let mut guard = self
            .files
            .lock()
            .map_err(|_| CoreError::Message("files poisoned".to_string()))?;
        guard.insert(filename.to_string(), data.to_vec());
        Ok(())
    }
}

pub struct TftpServer {
    socket: UdpTransport,
    config: TftpServerConfig,
    backend: Arc<dyn TftpBackend>,
}

impl TftpServer {
    pub fn bind(
        addr: SocketAddr,
        config: TftpServerConfig,
        backend: Arc<dyn TftpBackend>,
    ) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            config,
            backend,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(65536)?;
            let packet = match TftpPacket::decode(&data) {
                Ok(packet) => packet,
                Err(_) => {
                    let _ = send_error(
                        &self.socket,
                        addr,
                        TftpErrorCode::IllegalOperation,
                        "invalid packet",
                    );
                    continue;
                }
            };
            let backend = Arc::clone(&self.backend);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_request(packet, addr, backend, config);
            });
        }
    }
}

pub struct AsyncTftpServer {
    socket: AsyncUdpTransport,
    config: TftpServerConfig,
    backend: Arc<dyn TftpBackend>,
}

impl AsyncTftpServer {
    pub async fn bind(
        addr: SocketAddr,
        config: TftpServerConfig,
        backend: Arc<dyn TftpBackend>,
    ) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            config,
            backend,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(65536).await?;
            let packet = match TftpPacket::decode(&data) {
                Ok(packet) => packet,
                Err(_) => {
                    let _ = send_error_async(
                        &self.socket,
                        addr,
                        TftpErrorCode::IllegalOperation,
                        "invalid packet",
                    )
                    .await;
                    continue;
                }
            };
            let backend = Arc::clone(&self.backend);
            let config = self.config.clone();
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_request_async(socket, packet, addr, backend, config).await;
            });
        }
    }
}

fn handle_request(
    packet: TftpPacket,
    addr: SocketAddr,
    backend: Arc<dyn TftpBackend>,
    config: TftpServerConfig,
) -> CoreResult<()> {
    let socket = UdpTransport::bind_any()?;
    socket.set_read_timeout(Some(config.timeouts.read))?;
    match packet {
        TftpPacket::ReadRequest {
            filename,
            mode,
            options,
        } => handle_rrq(socket, addr, backend, config, filename, mode, options),
        TftpPacket::WriteRequest {
            filename,
            mode,
            options,
        } => handle_wrq(socket, addr, backend, config, filename, mode, options),
        _ => {
            send_error(
                &socket,
                addr,
                TftpErrorCode::IllegalOperation,
                "unexpected packet",
            )?;
            Ok(())
        }
    }
}

async fn handle_request_async(
    socket: AsyncUdpTransport,
    packet: TftpPacket,
    addr: SocketAddr,
    backend: Arc<dyn TftpBackend>,
    config: TftpServerConfig,
) -> CoreResult<()> {
    match packet {
        TftpPacket::ReadRequest {
            filename,
            mode,
            options,
        } => handle_rrq_async(socket, addr, backend, config, filename, mode, options).await,
        TftpPacket::WriteRequest {
            filename,
            mode,
            options,
        } => handle_wrq_async(socket, addr, backend, config, filename, mode, options).await,
        _ => {
            send_error_async(
                &socket,
                addr,
                TftpErrorCode::IllegalOperation,
                "unexpected packet",
            )
            .await?;
            Ok(())
        }
    }
}

fn handle_rrq(
    socket: UdpTransport,
    addr: SocketAddr,
    backend: Arc<dyn TftpBackend>,
    config: TftpServerConfig,
    filename: String,
    mode: TftpMode,
    options: TftpOptions,
) -> CoreResult<()> {
    let mut data = backend.read(&filename).map_err(|_| {
        send_error(&socket, addr, TftpErrorCode::FileNotFound, "file not found").ok();
        CoreError::Message("file not found".to_string())
    })?;
    if mode == TftpMode::NetAscii {
        if !config.allow_netascii {
            send_error(
                &socket,
                addr,
                TftpErrorCode::IllegalOperation,
                "netascii disabled",
            )?;
            return Ok(());
        }
        data = to_netascii(&data);
    }
    let (oack, mut blksize, timeout) = negotiate_options(&options, &config, data.len() as u64);
    if let Some(value) = timeout {
        socket.set_read_timeout(Some(Duration::from_secs(value as u64)))?;
    }
    if !oack.is_empty() {
        let packet = TftpPacket::OptionAck { options: oack }.encode()?;
        socket.send_to(&packet, addr)?;
    }
    if blksize == 0 {
        blksize = 512;
    }
    let mut offset = 0usize;
    let mut block = 1u16;
    loop {
        let end = (offset + blksize as usize).min(data.len());
        let chunk = &data[offset..end];
        let packet = TftpPacket::Data {
            block,
            data: chunk.to_vec(),
        }
        .encode()?;
        let mut attempts = 3;
        loop {
            socket.send_to(&packet, addr)?;
            match recv_with_timeout(&socket) {
                Ok((resp, peer)) => {
                    if peer != addr {
                        let _ = send_error(
                            &socket,
                            peer,
                            TftpErrorCode::UnknownTransferId,
                            "unknown transfer",
                        );
                        continue;
                    }
                    match resp {
                        TftpPacket::Ack { block: ack_block } if ack_block == block => break,
                        TftpPacket::Ack { block: ack_block } if ack_block < block => continue,
                        TftpPacket::Error { .. } => return Ok(()),
                        _ => {}
                    }
                }
                Err(err) => {
                    if is_timeout(&err) {
                        if attempts == 0 {
                            return Ok(());
                        }
                        attempts -= 1;
                        continue;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
        offset = end;
        block = block.wrapping_add(1);
        if chunk.len() < blksize as usize {
            break;
        }
    }
    Ok(())
}

fn handle_wrq(
    socket: UdpTransport,
    addr: SocketAddr,
    backend: Arc<dyn TftpBackend>,
    config: TftpServerConfig,
    filename: String,
    mode: TftpMode,
    options: TftpOptions,
) -> CoreResult<()> {
    if mode == TftpMode::NetAscii && !config.allow_netascii {
        send_error(
            &socket,
            addr,
            TftpErrorCode::IllegalOperation,
            "netascii disabled",
        )?;
        return Ok(());
    }
    let (oack, mut blksize, timeout) =
        negotiate_options(&options, &config, options.tsize.unwrap_or(0));
    if let Some(value) = timeout {
        socket.set_read_timeout(Some(Duration::from_secs(value as u64)))?;
    }
    let mut last_ack = if !oack.is_empty() {
        let packet = TftpPacket::OptionAck { options: oack }.encode()?;
        socket.send_to(&packet, addr)?;
        packet
    } else {
        let packet = TftpPacket::Ack { block: 0 }.encode()?;
        socket.send_to(&packet, addr)?;
        packet
    };
    if blksize == 0 {
        blksize = 512;
    }
    let mut expected_block = 1u16;
    let mut output = Vec::new();
    let mut attempts = 3usize;
    loop {
        let (packet, peer) = match recv_with_timeout(&socket) {
            Ok(packet) => {
                attempts = 3;
                packet
            }
            Err(err) => {
                if is_timeout(&err) {
                    if attempts == 0 {
                        return Ok(());
                    }
                    attempts -= 1;
                    socket.send_to(&last_ack, addr)?;
                    continue;
                }
                return Err(err);
            }
        };
        if peer != addr {
            let _ = send_error(
                &socket,
                peer,
                TftpErrorCode::UnknownTransferId,
                "unknown transfer",
            );
            continue;
        }
        match packet {
            TftpPacket::Data { block, data } => {
                if block == expected_block {
                    output.extend_from_slice(&data);
                    let ack = TftpPacket::Ack { block }.encode()?;
                    socket.send_to(&ack, addr)?;
                    last_ack = ack;
                    expected_block = expected_block.wrapping_add(1);
                    if data.len() < blksize as usize {
                        break;
                    }
                } else if block < expected_block {
                    let ack = TftpPacket::Ack { block }.encode()?;
                    socket.send_to(&ack, addr)?;
                }
            }
            TftpPacket::Error { .. } => return Ok(()),
            _ => {}
        }
    }
    let data = if mode == TftpMode::NetAscii {
        from_netascii(&output)
    } else {
        output
    };
    backend.write(&filename, &data)?;
    Ok(())
}

async fn handle_rrq_async(
    socket: AsyncUdpTransport,
    addr: SocketAddr,
    backend: Arc<dyn TftpBackend>,
    config: TftpServerConfig,
    filename: String,
    mode: TftpMode,
    options: TftpOptions,
) -> CoreResult<()> {
    let mut data = backend
        .read(&filename)
        .map_err(|_| CoreError::Message("file not found".to_string()))?;
    if mode == TftpMode::NetAscii {
        if !config.allow_netascii {
            let _ = send_error_async(
                &socket,
                addr,
                TftpErrorCode::IllegalOperation,
                "netascii disabled",
            )
            .await;
            return Ok(());
        }
        data = to_netascii(&data);
    }
    let (oack, mut blksize, _timeout) = negotiate_options(&options, &config, data.len() as u64);
    if !oack.is_empty() {
        let packet = TftpPacket::OptionAck { options: oack }.encode()?;
        socket.send_to(&packet, addr).await?;
    }
    if blksize == 0 {
        blksize = 512;
    }
    let mut offset = 0usize;
    let mut block = 1u16;
    loop {
        let end = (offset + blksize as usize).min(data.len());
        let chunk = &data[offset..end];
        let packet = TftpPacket::Data {
            block,
            data: chunk.to_vec(),
        }
        .encode()?;
        let mut attempts = 3;
        loop {
            socket.send_to(&packet, addr).await?;
            match recv_with_timeout_async(&socket, config.timeouts.read).await {
                Ok((resp, peer)) => {
                    if peer != addr {
                        let _ = send_error_async(
                            &socket,
                            peer,
                            TftpErrorCode::UnknownTransferId,
                            "unknown transfer",
                        )
                        .await;
                        continue;
                    }
                    match resp {
                        TftpPacket::Ack { block: ack_block } if ack_block == block => break,
                        TftpPacket::Ack { block: ack_block } if ack_block < block => continue,
                        TftpPacket::Error { .. } => return Ok(()),
                        _ => {}
                    }
                }
                Err(err) => {
                    if is_timeout(&err) {
                        if attempts == 0 {
                            return Ok(());
                        }
                        attempts -= 1;
                        continue;
                    } else {
                        return Err(err);
                    }
                }
            }
        }
        offset = end;
        block = block.wrapping_add(1);
        if chunk.len() < blksize as usize {
            break;
        }
    }
    Ok(())
}

async fn handle_wrq_async(
    socket: AsyncUdpTransport,
    addr: SocketAddr,
    backend: Arc<dyn TftpBackend>,
    config: TftpServerConfig,
    filename: String,
    mode: TftpMode,
    options: TftpOptions,
) -> CoreResult<()> {
    if mode == TftpMode::NetAscii && !config.allow_netascii {
        let _ = send_error_async(
            &socket,
            addr,
            TftpErrorCode::IllegalOperation,
            "netascii disabled",
        )
        .await;
        return Ok(());
    }
    let (oack, mut blksize, _timeout) =
        negotiate_options(&options, &config, options.tsize.unwrap_or(0));
    let mut last_ack = if !oack.is_empty() {
        let packet = TftpPacket::OptionAck { options: oack }.encode()?;
        socket.send_to(&packet, addr).await?;
        packet
    } else {
        let packet = TftpPacket::Ack { block: 0 }.encode()?;
        socket.send_to(&packet, addr).await?;
        packet
    };
    if blksize == 0 {
        blksize = 512;
    }
    let mut expected_block = 1u16;
    let mut output = Vec::new();
    let mut attempts = 3usize;
    loop {
        let (packet, peer) = match recv_with_timeout_async(&socket, config.timeouts.read).await {
            Ok(packet) => {
                attempts = 3;
                packet
            }
            Err(err) => {
                if is_timeout(&err) {
                    if attempts == 0 {
                        return Ok(());
                    }
                    attempts -= 1;
                    let _ = socket.send_to(&last_ack, addr).await;
                    continue;
                }
                return Err(err);
            }
        };
        if peer != addr {
            let _ = send_error_async(
                &socket,
                peer,
                TftpErrorCode::UnknownTransferId,
                "unknown transfer",
            )
            .await;
            continue;
        }
        match packet {
            TftpPacket::Data { block, data } => {
                if block == expected_block {
                    output.extend_from_slice(&data);
                    let ack = TftpPacket::Ack { block }.encode()?;
                    socket.send_to(&ack, addr).await?;
                    last_ack = ack;
                    expected_block = expected_block.wrapping_add(1);
                    if data.len() < blksize as usize {
                        break;
                    }
                } else if block < expected_block {
                    let ack = TftpPacket::Ack { block }.encode()?;
                    socket.send_to(&ack, addr).await?;
                }
            }
            TftpPacket::Error { .. } => return Ok(()),
            _ => {}
        }
    }
    let data = if mode == TftpMode::NetAscii {
        from_netascii(&output)
    } else {
        output
    };
    backend.write(&filename, &data)?;
    Ok(())
}

fn negotiate_options(
    requested: &TftpOptions,
    config: &TftpServerConfig,
    file_size: u64,
) -> (TftpOptions, u16, Option<u16>) {
    let mut response = TftpOptions::default();
    let mut blksize = 512u16;
    let mut timeout = None;
    if let Some(req) = requested.blksize {
        let value = req.clamp(8, config.max_blksize);
        response.blksize = Some(value);
        blksize = value;
    }
    if let Some(req) = requested.timeout {
        let value = req.clamp(1, 255);
        response.timeout = Some(value);
        timeout = Some(value);
    }
    if let Some(req) = requested.windowsize {
        let value = req.clamp(1, config.max_windowsize);
        response.windowsize = Some(value);
    }
    if requested.tsize.is_some() {
        response.tsize = Some(file_size);
    }
    (response, blksize, timeout)
}

fn recv_with_retry(
    socket: &UdpTransport,
    resend: &[u8],
    addr: SocketAddr,
    retries: usize,
) -> CoreResult<(TftpPacket, SocketAddr)> {
    let mut attempts = retries;
    loop {
        match recv_with_timeout(socket) {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                if is_timeout(&err) {
                    if attempts == 0 {
                        return Err(CoreError::Message("tftp timeout".to_string()));
                    }
                    attempts -= 1;
                    socket.send_to(resend, addr)?;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

fn recv_with_timeout(socket: &UdpTransport) -> CoreResult<(TftpPacket, SocketAddr)> {
    let (data, addr) = socket.recv_from(65536)?;
    let packet = TftpPacket::decode(&data)?;
    Ok((packet, addr))
}

async fn recv_with_retry_async(
    socket: &AsyncUdpTransport,
    resend: &[u8],
    addr: SocketAddr,
    retries: usize,
    timeout: Duration,
) -> CoreResult<(TftpPacket, SocketAddr)> {
    let mut attempts = retries;
    loop {
        match recv_with_timeout_async(socket, timeout).await {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                if is_timeout(&err) {
                    if attempts == 0 {
                        return Err(CoreError::Message("tftp timeout".to_string()));
                    }
                    attempts -= 1;
                    socket.send_to(resend, addr).await?;
                    continue;
                }
                return Err(err);
            }
        }
    }
}

async fn recv_with_timeout_async(
    socket: &AsyncUdpTransport,
    timeout: Duration,
) -> CoreResult<(TftpPacket, SocketAddr)> {
    let result = tokio::time::timeout(timeout, socket.recv_from(65536)).await;
    let (data, addr) = match result {
        Ok(res) => res?,
        Err(_) => {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timeout",
            )))
        }
    };
    let packet = TftpPacket::decode(&data)?;
    Ok((packet, addr))
}

fn send_error(
    socket: &UdpTransport,
    addr: SocketAddr,
    code: TftpErrorCode,
    message: &str,
) -> CoreResult<()> {
    let packet = TftpPacket::Error {
        code,
        message: message.to_string(),
    }
    .encode()?;
    socket.send_to(&packet, addr)?;
    Ok(())
}

async fn send_error_async(
    socket: &AsyncUdpTransport,
    addr: SocketAddr,
    code: TftpErrorCode,
    message: &str,
) -> CoreResult<()> {
    let packet = TftpPacket::Error {
        code,
        message: message.to_string(),
    }
    .encode()?;
    socket.send_to(&packet, addr).await?;
    Ok(())
}

fn parse_option_pairs(parts: &[String]) -> CoreResult<TftpOptions> {
    if parts.is_empty() {
        return Ok(TftpOptions::default());
    }
    if parts.len() % 2 != 0 {
        return Err(CoreError::Parse("invalid option pairs".to_string()));
    }
    let mut pairs = Vec::new();
    let mut idx = 0;
    while idx < parts.len() {
        pairs.push((parts[idx].clone(), parts[idx + 1].clone()));
        idx += 2;
    }
    Ok(TftpOptions::from_pairs(pairs))
}

fn split_zstrings(data: &[u8]) -> CoreResult<Vec<String>> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for i in 0..data.len() {
        if data[i] == 0 {
            let slice = &data[start..i];
            let value = std::str::from_utf8(slice)
                .map_err(|_| CoreError::Parse("invalid string".to_string()))?;
            out.push(value.to_string());
            start = i + 1;
        }
    }
    if start != data.len() {
        return Err(CoreError::Parse("unterminated string".to_string()));
    }
    Ok(out)
}

fn parse_single_zstring(data: &[u8]) -> CoreResult<String> {
    let mut end = None;
    for (idx, byte) in data.iter().enumerate() {
        if *byte == 0 {
            end = Some(idx);
            break;
        }
    }
    let end = end.ok_or_else(|| CoreError::Parse("unterminated string".to_string()))?;
    let value = std::str::from_utf8(&data[..end])
        .map_err(|_| CoreError::Parse("invalid string".to_string()))?;
    Ok(value.to_string())
}

fn to_netascii(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        match b {
            b'\n' => {
                out.push(b'\r');
                out.push(b'\n');
            }
            b'\r' => {
                out.push(b'\r');
                out.push(0);
            }
            _ => out.push(b),
        }
    }
    out
}

fn from_netascii(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut idx = 0;
    while idx < data.len() {
        if data[idx] == b'\r' {
            if idx + 1 < data.len() {
                let next = data[idx + 1];
                if next == b'\n' {
                    out.push(b'\n');
                    idx += 2;
                    continue;
                } else if next == 0 {
                    out.push(b'\r');
                    idx += 2;
                    continue;
                }
            }
            out.push(b'\r');
            idx += 1;
        } else {
            out.push(data[idx]);
            idx += 1;
        }
    }
    out
}

fn is_timeout(err: &CoreError) -> bool {
    matches!(
        err,
        CoreError::Io(io)
            if io.kind() == std::io::ErrorKind::WouldBlock
                || io.kind() == std::io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_roundtrip_rrq() {
        let mut options = TftpOptions::default();
        options.blksize = Some(1024);
        options.timeout = Some(3);
        let packet = TftpPacket::ReadRequest {
            filename: "file.txt".to_string(),
            mode: TftpMode::Octet,
            options: options.clone(),
        };
        let encoded = packet.encode().unwrap();
        let decoded = TftpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn client_server_rrq() {
        let backend =
            Arc::new(InMemoryTftpBackend::default().with_file("hello.txt", b"hello".to_vec()));
        let server = crate::skip_if_perm!(TftpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            TftpServerConfig::default(),
            backend.clone(),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        let client = TftpClient::new(TftpClientConfig::default());
        let data = client.read(addr, "hello.txt").unwrap();
        assert_eq!(data, b"hello".to_vec());
    }

    #[test]
    fn client_server_wrq() {
        let backend = Arc::new(InMemoryTftpBackend::default());
        let server = crate::skip_if_perm!(TftpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            TftpServerConfig::default(),
            backend.clone(),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        let client = TftpClient::new(TftpClientConfig::default());
        client.write(addr, "upload.bin", b"payload").unwrap();
        let stored = backend.read("upload.bin").unwrap();
        assert_eq!(stored, b"payload".to_vec());
    }
}
