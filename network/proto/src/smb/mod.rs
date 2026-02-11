use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::ntlm::{NtlmClient, NtlmClientConfig, NtlmMessage, NtlmServer, NtlmServerConfig};
use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const SMB2_PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
const SMB2_HEADER_SIZE: usize = 64;

const STATUS_SUCCESS: u32 = 0x00000000;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc0000016;
const STATUS_ACCESS_DENIED: u32 = 0xc0000022;
const STATUS_INVALID_PARAMETER: u32 = 0xc000000d;
const STATUS_NOT_FOUND: u32 = 0xc0000225;

const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_LOGOFF: u16 = 0x0002;
const SMB2_TREE_CONNECT: u16 = 0x0003;
const SMB2_TREE_DISCONNECT: u16 = 0x0004;
const SMB2_CREATE: u16 = 0x0005;
const SMB2_CLOSE: u16 = 0x0006;
const SMB2_READ: u16 = 0x0008;
const SMB2_WRITE: u16 = 0x0009;
const SMB2_ECHO: u16 = 0x000b;

const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

const DIALECT_2_1: u16 = 0x0210;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Header {
    pub command: u16,
    pub status: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub flags: u32,
    pub signature: [u8; 16],
}

impl Smb2Header {
    pub fn new(command: u16, message_id: u64) -> Self {
        Self {
            command,
            status: STATUS_SUCCESS,
            message_id,
            tree_id: 0,
            session_id: 0,
            flags: 0,
            signature: [0u8; 16],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SMB2_HEADER_SIZE);
        out.extend_from_slice(&SMB2_PROTOCOL_ID);
        out.extend_from_slice(&64u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.command.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.message_id.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.tree_id.to_le_bytes());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < SMB2_HEADER_SIZE {
            return Err(CoreError::Parse("smb2 header too short".to_string()));
        }
        if data[..4] != SMB2_PROTOCOL_ID {
            return Err(CoreError::Parse("invalid smb2 protocol".to_string()));
        }
        let status = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let command = u16::from_le_bytes([data[12], data[13]]);
        let flags = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let message_id = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let tree_id = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let session_id = u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
        ]);
        let mut signature = [0u8; 16];
        signature.copy_from_slice(&data[48..64]);
        Ok(Self {
            command,
            status,
            message_id,
            tree_id,
            session_id,
            flags,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Smb2Packet {
    pub header: Smb2Header,
    pub body: Vec<u8>,
}

impl Smb2Packet {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header.encode();
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        let header = Smb2Header::decode(data)?;
        let body = data[SMB2_HEADER_SIZE..].to_vec();
        Ok(Self { header, body })
    }
}

#[derive(Debug, Clone)]
pub struct SmbClientConfig {
    pub timeouts: Timeouts,
    pub signing_required: bool,
}

impl Default for SmbClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            signing_required: false,
        }
    }
}

pub struct SmbClient {
    transport: TcpTransport,
    config: SmbClientConfig,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    session_key: Option<[u8; 16]>,
    dialect: u16,
}

impl SmbClient {
    pub fn connect(addr: &NetAddr, config: SmbClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self {
            transport,
            config,
            message_id: 1,
            session_id: 0,
            tree_id: 0,
            session_key: None,
            dialect: DIALECT_2_1,
        })
    }

    pub fn negotiate(&mut self) -> CoreResult<()> {
        let msg_id = self.next_id();
        let body = encode_negotiate_request(&[DIALECT_2_1]);
        let header = Smb2Header::new(SMB2_NEGOTIATE, msg_id);
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("negotiate failed".to_string()));
        }
        let dialect = decode_negotiate_response(&resp.body)?;
        self.dialect = dialect;
        Ok(())
    }

    pub fn session_setup_ntlm(&mut self, config: NtlmClientConfig) -> CoreResult<()> {
        let ntlm = NtlmClient::new(config);
        let negotiate = ntlm.negotiate();
        let blob = NtlmMessage::Negotiate(negotiate).encode();
        let msg_id = self.next_id();
        let body = encode_session_setup_request(&blob);
        let header = Smb2Header::new(SMB2_SESSION_SETUP, msg_id);
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(CoreError::Message("session setup failed".to_string()));
        }
        let session_id = resp.header.session_id;
        let challenge = decode_session_setup_response(&resp.body)?;
        let challenge_msg = NtlmMessage::decode(&challenge)?;
        let challenge = match challenge_msg {
            NtlmMessage::Challenge(ch) => ch,
            _ => return Err(CoreError::Parse("invalid NTLM challenge".to_string())),
        };
        let (auth, session) = ntlm.respond(&challenge)?;
        self.session_key = Some(session.exported_session_key);
        self.session_id = session_id;
        let auth_blob = NtlmMessage::Authenticate(auth).encode();
        let msg_id = self.next_id();
        let body = encode_session_setup_request(&auth_blob);
        let mut header = Smb2Header::new(SMB2_SESSION_SETUP, msg_id);
        header.session_id = session_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("session setup failed".to_string()));
        }
        Ok(())
    }

    pub fn tree_connect(&mut self, share: &str) -> CoreResult<()> {
        let msg_id = self.next_id();
        let path = format!("\\\\MOONLIGHT\\{}", share);
        let body = encode_tree_connect_request(&path);
        let mut header = Smb2Header::new(SMB2_TREE_CONNECT, msg_id);
        header.session_id = self.session_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("tree connect failed".to_string()));
        }
        self.tree_id = resp.header.tree_id;
        Ok(())
    }

    pub fn create(&mut self, path: &str) -> CoreResult<[u8; 16]> {
        let msg_id = self.next_id();
        let body = encode_create_request(path);
        let mut header = Smb2Header::new(SMB2_CREATE, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("create failed".to_string()));
        }
        decode_create_response(&resp.body)
    }

    pub fn read(&mut self, file_id: [u8; 16], offset: u64, length: u32) -> CoreResult<Vec<u8>> {
        let msg_id = self.next_id();
        let body = encode_read_request(file_id, offset, length);
        let mut header = Smb2Header::new(SMB2_READ, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("read failed".to_string()));
        }
        decode_read_response(&resp.body)
    }

    pub fn write(&mut self, file_id: [u8; 16], offset: u64, data: &[u8]) -> CoreResult<u32> {
        let msg_id = self.next_id();
        let body = encode_write_request(file_id, offset, data);
        let mut header = Smb2Header::new(SMB2_WRITE, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("write failed".to_string()));
        }
        decode_write_response(&resp.body)
    }

    pub fn close(&mut self, file_id: [u8; 16]) -> CoreResult<()> {
        let msg_id = self.next_id();
        let body = encode_close_request(file_id);
        let mut header = Smb2Header::new(SMB2_CLOSE, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("close failed".to_string()));
        }
        Ok(())
    }

    pub fn logoff(&mut self) -> CoreResult<()> {
        let msg_id = self.next_id();
        let body = encode_logoff_request();
        let mut header = Smb2Header::new(SMB2_LOGOFF, msg_id);
        header.session_id = self.session_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet)?;
        let resp = self.recv_packet()?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("logoff failed".to_string()));
        }
        Ok(())
    }

    fn send_packet(&mut self, mut packet: Smb2Packet) -> CoreResult<()> {
        if self.config.signing_required || self.session_key.is_some() {
            if let Some(key) = self.session_key {
                packet.header.flags |= SMB2_FLAGS_SIGNED;
                let signature = sign_packet(&packet, &key);
                packet.header.signature = signature;
            }
        }
        let payload = packet.encode();
        let framed = encode_nbss(&payload);
        self.transport.write_all(&framed)
    }

    fn recv_packet(&mut self) -> CoreResult<Smb2Packet> {
        let data = read_nbss(&mut self.transport)?;
        let packet = Smb2Packet::decode(&data)?;
        if packet.header.flags & SMB2_FLAGS_SIGNED != 0 {
            if let Some(key) = self.session_key {
                if !verify_packet(&packet, &key) {
                    return Err(CoreError::Message("invalid smb signature".to_string()));
                }
            }
        }
        Ok(packet)
    }

    fn next_id(&mut self) -> u64 {
        let id = self.message_id;
        self.message_id = self.message_id.wrapping_add(1);
        id
    }
}

pub struct AsyncSmbClient {
    transport: AsyncTcpTransport,
    config: SmbClientConfig,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    session_key: Option<[u8; 16]>,
    dialect: u16,
}

impl AsyncSmbClient {
    pub async fn connect(addr: &NetAddr, config: SmbClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self {
            transport,
            config,
            message_id: 1,
            session_id: 0,
            tree_id: 0,
            session_key: None,
            dialect: DIALECT_2_1,
        })
    }

    pub async fn negotiate(&mut self) -> CoreResult<()> {
        let msg_id = self.next_id();
        let body = encode_negotiate_request(&[DIALECT_2_1]);
        let header = Smb2Header::new(SMB2_NEGOTIATE, msg_id);
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("negotiate failed".to_string()));
        }
        let dialect = decode_negotiate_response(&resp.body)?;
        self.dialect = dialect;
        Ok(())
    }

    pub async fn session_setup_ntlm(&mut self, config: NtlmClientConfig) -> CoreResult<()> {
        let ntlm = NtlmClient::new(config);
        let negotiate = ntlm.negotiate();
        let blob = NtlmMessage::Negotiate(negotiate).encode();
        let msg_id = self.next_id();
        let body = encode_session_setup_request(&blob);
        let header = Smb2Header::new(SMB2_SESSION_SETUP, msg_id);
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(CoreError::Message("session setup failed".to_string()));
        }
        let session_id = resp.header.session_id;
        let challenge = decode_session_setup_response(&resp.body)?;
        let challenge_msg = NtlmMessage::decode(&challenge)?;
        let challenge = match challenge_msg {
            NtlmMessage::Challenge(ch) => ch,
            _ => return Err(CoreError::Parse("invalid NTLM challenge".to_string())),
        };
        let (auth, session) = ntlm.respond(&challenge)?;
        self.session_key = Some(session.exported_session_key);
        self.session_id = session_id;
        let auth_blob = NtlmMessage::Authenticate(auth).encode();
        let msg_id = self.next_id();
        let body = encode_session_setup_request(&auth_blob);
        let mut header = Smb2Header::new(SMB2_SESSION_SETUP, msg_id);
        header.session_id = session_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("session setup failed".to_string()));
        }
        Ok(())
    }

    pub async fn tree_connect(&mut self, share: &str) -> CoreResult<()> {
        let msg_id = self.next_id();
        let path = format!("\\\\MOONLIGHT\\{}", share);
        let body = encode_tree_connect_request(&path);
        let mut header = Smb2Header::new(SMB2_TREE_CONNECT, msg_id);
        header.session_id = self.session_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("tree connect failed".to_string()));
        }
        self.tree_id = resp.header.tree_id;
        Ok(())
    }

    pub async fn create(&mut self, path: &str) -> CoreResult<[u8; 16]> {
        let msg_id = self.next_id();
        let body = encode_create_request(path);
        let mut header = Smb2Header::new(SMB2_CREATE, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("create failed".to_string()));
        }
        decode_create_response(&resp.body)
    }

    pub async fn read(
        &mut self,
        file_id: [u8; 16],
        offset: u64,
        length: u32,
    ) -> CoreResult<Vec<u8>> {
        let msg_id = self.next_id();
        let body = encode_read_request(file_id, offset, length);
        let mut header = Smb2Header::new(SMB2_READ, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("read failed".to_string()));
        }
        decode_read_response(&resp.body)
    }

    pub async fn write(&mut self, file_id: [u8; 16], offset: u64, data: &[u8]) -> CoreResult<u32> {
        let msg_id = self.next_id();
        let body = encode_write_request(file_id, offset, data);
        let mut header = Smb2Header::new(SMB2_WRITE, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("write failed".to_string()));
        }
        decode_write_response(&resp.body)
    }

    pub async fn close(&mut self, file_id: [u8; 16]) -> CoreResult<()> {
        let msg_id = self.next_id();
        let body = encode_close_request(file_id);
        let mut header = Smb2Header::new(SMB2_CLOSE, msg_id);
        header.session_id = self.session_id;
        header.tree_id = self.tree_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("close failed".to_string()));
        }
        Ok(())
    }

    pub async fn logoff(&mut self) -> CoreResult<()> {
        let msg_id = self.next_id();
        let body = encode_logoff_request();
        let mut header = Smb2Header::new(SMB2_LOGOFF, msg_id);
        header.session_id = self.session_id;
        let packet = Smb2Packet { header, body };
        self.send_packet(packet).await?;
        let resp = self.recv_packet().await?;
        if resp.header.status != STATUS_SUCCESS {
            return Err(CoreError::Message("logoff failed".to_string()));
        }
        Ok(())
    }

    async fn send_packet(&mut self, mut packet: Smb2Packet) -> CoreResult<()> {
        if self.config.signing_required || self.session_key.is_some() {
            if let Some(key) = self.session_key {
                packet.header.flags |= SMB2_FLAGS_SIGNED;
                let signature = sign_packet(&packet, &key);
                packet.header.signature = signature;
            }
        }
        let payload = packet.encode();
        let framed = encode_nbss(&payload);
        self.transport.write_all(&framed).await
    }

    async fn recv_packet(&mut self) -> CoreResult<Smb2Packet> {
        let data = read_nbss_async(&mut self.transport).await?;
        let packet = Smb2Packet::decode(&data)?;
        if packet.header.flags & SMB2_FLAGS_SIGNED != 0 {
            if let Some(key) = self.session_key {
                if !verify_packet(&packet, &key) {
                    return Err(CoreError::Message("invalid smb signature".to_string()));
                }
            }
        }
        Ok(packet)
    }

    fn next_id(&mut self) -> u64 {
        let id = self.message_id;
        self.message_id = self.message_id.wrapping_add(1);
        id
    }
}

#[derive(Debug, Clone)]
pub struct SmbServerConfig {
    pub timeouts: Timeouts,
    pub require_signing: bool,
    pub share_name: String,
    pub users: HashMap<String, String>,
}

impl Default for SmbServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            require_signing: false,
            share_name: "share".to_string(),
            users: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmbShare {
    pub name: String,
    pub files: HashMap<String, Vec<u8>>,
}

impl SmbShare {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            files: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct SmbSession {
    id: u64,
    session_key: [u8; 16],
    tree_id: u32,
}

#[derive(Debug, Clone)]
struct SmbFile {
    id: [u8; 16],
    path: String,
}

#[derive(Debug, Clone)]
struct SmbState {
    sessions: HashMap<u64, SmbSession>,
    pending: HashMap<u64, crate::ntlm::ChallengeMessage>,
    files: HashMap<[u8; 16], SmbFile>,
    next_session: u64,
    next_tree: u32,
    next_file: u64,
    share: SmbShare,
}

impl SmbState {
    fn new(share: SmbShare) -> Self {
        Self {
            sessions: HashMap::new(),
            pending: HashMap::new(),
            files: HashMap::new(),
            next_session: 1,
            next_tree: 1,
            next_file: 1,
            share,
        }
    }

    fn allocate_session_id(&mut self) -> u64 {
        let id = self.next_session;
        self.next_session = self.next_session.wrapping_add(1);
        id
    }

    fn insert_session(&mut self, session_id: u64, session_key: [u8; 16]) -> SmbSession {
        let tree_id = self.next_tree;
        self.next_tree = self.next_tree.wrapping_add(1);
        let session = SmbSession {
            id: session_id,
            session_key,
            tree_id,
        };
        self.sessions.insert(session_id, session.clone());
        session
    }

    fn allocate_file(&mut self, path: String) -> SmbFile {
        let file_id = self.next_file;
        self.next_file = self.next_file.wrapping_add(1);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&file_id.to_le_bytes());
        let file = SmbFile { id, path };
        self.files.insert(id, file.clone());
        file
    }
}

pub struct SmbServer {
    listener: TcpListener,
    config: SmbServerConfig,
    state: Arc<Mutex<SmbState>>,
    ntlm: NtlmServer,
}

impl SmbServer {
    pub fn bind(addr: SocketAddr, config: SmbServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        let share = SmbShare::new(&config.share_name);
        let mut ntlm_cfg = NtlmServerConfig::default();
        for (user, pass) in &config.users {
            ntlm_cfg.credentials.insert(
                user.to_ascii_uppercase(),
                crate::ntlm::NtlmSecret::Plaintext(pass.clone()),
            );
        }
        let ntlm = NtlmServer::new(ntlm_cfg);
        Ok(Self {
            listener,
            config,
            state: Arc::new(Mutex::new(SmbState::new(share))),
            ntlm,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let state = Arc::clone(&self.state);
            let config = self.config.clone();
            let ntlm = self.ntlm.clone();
            thread::spawn(move || {
                let _ = handle_client(stream, state, config, ntlm);
            });
        }
        Ok(())
    }
}

pub struct AsyncSmbServer {
    listener: tokio::net::TcpListener,
    config: SmbServerConfig,
    state: Arc<Mutex<SmbState>>,
    ntlm: NtlmServer,
}

impl AsyncSmbServer {
    pub async fn bind(addr: SocketAddr, config: SmbServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        let share = SmbShare::new(&config.share_name);
        let mut ntlm_cfg = NtlmServerConfig::default();
        for (user, pass) in &config.users {
            ntlm_cfg.credentials.insert(
                user.to_ascii_uppercase(),
                crate::ntlm::NtlmSecret::Plaintext(pass.clone()),
            );
        }
        let ntlm = NtlmServer::new(ntlm_cfg);
        Ok(Self {
            listener,
            config,
            state: Arc::new(Mutex::new(SmbState::new(share))),
            ntlm,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let state = Arc::clone(&self.state);
            let config = self.config.clone();
            let ntlm = self.ntlm.clone();
            tokio::spawn(async move {
                let _ = handle_client_async(stream, state, config, ntlm).await;
            });
        }
    }
}

fn handle_client(
    stream: TcpStream,
    state: Arc<Mutex<SmbState>>,
    config: SmbServerConfig,
    ntlm: NtlmServer,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let data = match read_nbss(&mut transport) {
            Ok(data) => data,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(())
            }
            Err(err) => return Err(err),
        };
        let packet = Smb2Packet::decode(&data)?;
        let response = handle_request(packet, &state, &config, &ntlm)?;
        let payload = response.encode();
        let framed = encode_nbss(&payload);
        transport.write_all(&framed)?;
    }
}

async fn handle_client_async(
    stream: tokio::net::TcpStream,
    state: Arc<Mutex<SmbState>>,
    config: SmbServerConfig,
    ntlm: NtlmServer,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let data = match read_nbss_async(&mut transport).await {
            Ok(data) => data,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(())
            }
            Err(err) => return Err(err),
        };
        let packet = Smb2Packet::decode(&data)?;
        let response = handle_request(packet, &state, &config, &ntlm)?;
        let payload = response.encode();
        let framed = encode_nbss(&payload);
        transport.write_all(&framed).await?;
    }
}

fn handle_request(
    packet: Smb2Packet,
    state: &Arc<Mutex<SmbState>>,
    config: &SmbServerConfig,
    ntlm: &NtlmServer,
) -> CoreResult<Smb2Packet> {
    let mut header = packet.header;
    let response: Vec<u8>;
    match header.command {
        SMB2_NEGOTIATE => {
            response = encode_negotiate_response();
            header.status = STATUS_SUCCESS;
        }
        SMB2_SESSION_SETUP => {
            let (session_id, resp, status) =
                handle_session_setup(&packet.body, header.session_id, state, ntlm)?;
            response = resp;
            header.status = status;
            header.session_id = session_id;
        }
        SMB2_TREE_CONNECT => {
            let tree_id = handle_tree_connect(&packet.body, state)?;
            response = encode_tree_connect_response();
            header.status = STATUS_SUCCESS;
            header.tree_id = tree_id;
        }
        SMB2_CREATE => {
            let (file_id, status) = handle_create(&packet.body, state)?;
            response = encode_create_response(file_id);
            header.status = status;
        }
        SMB2_READ => {
            let (data, status) = handle_read(&packet.body, state)?;
            response = encode_read_response(&data);
            header.status = status;
        }
        SMB2_WRITE => {
            let (count, status) = handle_write(&packet.body, state)?;
            response = encode_write_response(count);
            header.status = status;
        }
        SMB2_CLOSE => {
            let status = handle_close(&packet.body, state)?;
            response = encode_close_response();
            header.status = status;
        }
        SMB2_LOGOFF => {
            response = encode_logoff_response();
            header.status = STATUS_SUCCESS;
        }
        SMB2_ECHO => {
            response = encode_echo_response();
            header.status = STATUS_SUCCESS;
        }
        _ => {
            header.status = STATUS_INVALID_PARAMETER;
            response = vec![0u8; 4];
        }
    }
    header.flags = 0;
    header.signature = [0u8; 16];
    let mut packet = Smb2Packet {
        header,
        body: response,
    };
    if config.require_signing {
        if let Some(key) = session_key_for(state, header.session_id) {
            packet.header.flags |= SMB2_FLAGS_SIGNED;
            packet.header.signature = sign_packet(&packet, &key);
        }
    }
    Ok(packet)
}

fn session_key_for(state: &Arc<Mutex<SmbState>>, session_id: u64) -> Option<[u8; 16]> {
    let guard = state.lock().ok()?;
    guard.sessions.get(&session_id).map(|s| s.session_key)
}

fn handle_session_setup(
    body: &[u8],
    header_session_id: u64,
    state: &Arc<Mutex<SmbState>>,
    ntlm: &NtlmServer,
) -> CoreResult<(u64, Vec<u8>, u32)> {
    let (security_blob, prev_session) = decode_session_setup_request(body)?;
    let session_id = if header_session_id != 0 {
        header_session_id
    } else {
        prev_session
    };
    if security_blob.is_empty() {
        return Ok((0, encode_session_setup_response(&[]), STATUS_ACCESS_DENIED));
    }
    let msg = NtlmMessage::decode(&security_blob)?;
    match msg {
        NtlmMessage::Negotiate(negotiate) => {
            let challenge = ntlm.challenge(&negotiate);
            let challenge_blob = NtlmMessage::Challenge(challenge.clone()).encode();
            let mut guard = state
                .lock()
                .map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            let session_id = guard.allocate_session_id();
            guard.pending.insert(session_id, challenge);
            let resp = encode_session_setup_response(&challenge_blob);
            Ok((session_id, resp, STATUS_MORE_PROCESSING_REQUIRED))
        }
        NtlmMessage::Authenticate(auth) => {
            let mut guard = state
                .lock()
                .map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            let challenge = guard
                .pending
                .remove(&session_id)
                .ok_or_else(|| CoreError::Message("missing NTLM challenge".to_string()))?;
            let session = ntlm.authenticate(&challenge, &auth)?;
            let session_entry = guard.insert_session(session_id, session.exported_session_key);
            let resp = encode_session_setup_response(&[]);
            Ok((session_entry.id, resp, STATUS_SUCCESS))
        }
        _ => Ok((0, encode_session_setup_response(&[]), STATUS_ACCESS_DENIED)),
    }
}

fn handle_tree_connect(body: &[u8], state: &Arc<Mutex<SmbState>>) -> CoreResult<u32> {
    let path = decode_tree_connect_request(body)?;
    let share = path.split('\\').last().unwrap_or("");
    let mut guard = state
        .lock()
        .map_err(|_| CoreError::Message("state poisoned".to_string()))?;
    if share.eq_ignore_ascii_case(&guard.share.name) {
        let tree_id = guard.next_tree;
        guard.next_tree = guard.next_tree.wrapping_add(1);
        Ok(tree_id)
    } else {
        Err(CoreError::Message("share not found".to_string()))
    }
}

fn handle_create(body: &[u8], state: &Arc<Mutex<SmbState>>) -> CoreResult<([u8; 16], u32)> {
    let path = decode_create_request(body)?;
    let mut guard = state
        .lock()
        .map_err(|_| CoreError::Message("state poisoned".to_string()))?;
    let file = guard.allocate_file(path.clone());
    guard.share.files.entry(path).or_insert_with(Vec::new);
    Ok((file.id, STATUS_SUCCESS))
}

fn handle_read(body: &[u8], state: &Arc<Mutex<SmbState>>) -> CoreResult<(Vec<u8>, u32)> {
    let (file_id, offset, length) = decode_read_request(body)?;
    let guard = state
        .lock()
        .map_err(|_| CoreError::Message("state poisoned".to_string()))?;
    let file = guard
        .files
        .get(&file_id)
        .ok_or_else(|| CoreError::Message("file not found".to_string()))?;
    let data = guard
        .share
        .files
        .get(&file.path)
        .ok_or_else(|| CoreError::Message("file not found".to_string()))?;
    let start = offset as usize;
    if start >= data.len() {
        return Ok((Vec::new(), STATUS_SUCCESS));
    }
    let end = (start + length as usize).min(data.len());
    Ok((data[start..end].to_vec(), STATUS_SUCCESS))
}

fn handle_write(body: &[u8], state: &Arc<Mutex<SmbState>>) -> CoreResult<(u32, u32)> {
    let (file_id, offset, data) = decode_write_request(body)?;
    let mut guard = state
        .lock()
        .map_err(|_| CoreError::Message("state poisoned".to_string()))?;
    let file_path = guard
        .files
        .get(&file_id)
        .ok_or_else(|| CoreError::Message("file not found".to_string()))?
        .path
        .clone();
    let entry = guard.share.files.entry(file_path).or_insert_with(Vec::new);
    let start = offset as usize;
    if entry.len() < start {
        entry.resize(start, 0);
    }
    if entry.len() < start + data.len() {
        entry.resize(start + data.len(), 0);
    }
    entry[start..start + data.len()].copy_from_slice(&data);
    Ok((data.len() as u32, STATUS_SUCCESS))
}

fn handle_close(body: &[u8], state: &Arc<Mutex<SmbState>>) -> CoreResult<u32> {
    let file_id = decode_close_request(body)?;
    let mut guard = state
        .lock()
        .map_err(|_| CoreError::Message("state poisoned".to_string()))?;
    guard.files.remove(&file_id);
    Ok(STATUS_SUCCESS)
}

fn encode_negotiate_request(dialects: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&36u16.to_le_bytes());
    out.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&0u64.to_le_bytes());
    for dialect in dialects {
        out.extend_from_slice(&dialect.to_le_bytes());
    }
    out
}

fn encode_negotiate_response() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&65u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn decode_negotiate_response(body: &[u8]) -> CoreResult<u16> {
    if body.len() < 4 {
        return Err(CoreError::Parse("negotiate response too short".to_string()));
    }
    Ok(u16::from_le_bytes([body[2], body[3]]))
}

fn encode_session_setup_request(security_blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&25u16.to_le_bytes());
    out.push(0);
    out.push(0);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let offset = (SMB2_HEADER_SIZE + 24) as u16;
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&(security_blob.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(security_blob);
    out
}

fn decode_session_setup_request(body: &[u8]) -> CoreResult<(Vec<u8>, u64)> {
    if body.len() < 24 {
        return Err(CoreError::Parse(
            "session setup request too short".to_string(),
        ));
    }
    let security_offset = u16::from_le_bytes([body[12], body[13]]) as usize;
    let security_len = u16::from_le_bytes([body[14], body[15]]) as usize;
    let prev_session = u64::from_le_bytes([
        body[16], body[17], body[18], body[19], body[20], body[21], body[22], body[23],
    ]);
    if security_offset < SMB2_HEADER_SIZE {
        return Ok((Vec::new(), prev_session));
    }
    let start = security_offset - SMB2_HEADER_SIZE;
    if body.len() < start + security_len {
        return Err(CoreError::Parse("invalid security buffer".to_string()));
    }
    Ok((body[start..start + security_len].to_vec(), prev_session))
}

fn encode_session_setup_response(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&9u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let offset = (SMB2_HEADER_SIZE + 8) as u16;
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&(blob.len() as u16).to_le_bytes());
    out.extend_from_slice(blob);
    out
}

fn decode_session_setup_response(body: &[u8]) -> CoreResult<Vec<u8>> {
    if body.len() < 8 {
        return Err(CoreError::Parse(
            "session setup response too short".to_string(),
        ));
    }
    let offset = u16::from_le_bytes([body[4], body[5]]) as usize;
    let len = u16::from_le_bytes([body[6], body[7]]) as usize;
    if offset < SMB2_HEADER_SIZE {
        return Ok(Vec::new());
    }
    let start = offset - SMB2_HEADER_SIZE;
    if body.len() < start + len {
        return Err(CoreError::Parse("invalid session setup blob".to_string()));
    }
    Ok(body[start..start + len].to_vec())
}

fn encode_tree_connect_request(path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&9u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let path_bytes = encode_utf16le(path);
    let offset = (SMB2_HEADER_SIZE + 8) as u16;
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&path_bytes);
    out
}

fn decode_tree_connect_request(body: &[u8]) -> CoreResult<String> {
    if body.len() < 8 {
        return Err(CoreError::Parse(
            "tree connect request too short".to_string(),
        ));
    }
    let offset = u16::from_le_bytes([body[4], body[5]]) as usize;
    let len = u16::from_le_bytes([body[6], body[7]]) as usize;
    if offset < SMB2_HEADER_SIZE {
        return Ok(String::new());
    }
    let start = offset - SMB2_HEADER_SIZE;
    decode_utf16le(&body[start..start + len])
}

fn encode_tree_connect_response() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn encode_create_request(path: &str) -> Vec<u8> {
    let name = encode_utf16le(path);
    let mut out = Vec::new();
    out.extend_from_slice(&57u16.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let name_offset = (SMB2_HEADER_SIZE + 56) as u16;
    out.extend_from_slice(&name_offset.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&name);
    out
}

fn decode_create_request(body: &[u8]) -> CoreResult<String> {
    if body.len() < 56 {
        return Err(CoreError::Parse("create request too short".to_string()));
    }
    let offset = u16::from_le_bytes([body[44], body[45]]) as usize;
    let len = u16::from_le_bytes([body[46], body[47]]) as usize;
    if offset < SMB2_HEADER_SIZE {
        return Ok(String::new());
    }
    let start = offset - SMB2_HEADER_SIZE;
    decode_utf16le(&body[start..start + len])
}

fn encode_create_response(file_id: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&89u16.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&file_id);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn decode_create_response(body: &[u8]) -> CoreResult<[u8; 16]> {
    if body.len() < 56 {
        return Err(CoreError::Parse("create response too short".to_string()));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&body[40..56]);
    Ok(id)
}

fn encode_read_request(file_id: [u8; 16], offset: u64, length: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&49u16.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&0u8.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&file_id);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn decode_read_request(body: &[u8]) -> CoreResult<([u8; 16], u64, u32)> {
    if body.len() < 48 {
        return Err(CoreError::Parse("read request too short".to_string()));
    }
    let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let offset = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&body[16..32]);
    Ok((id, offset, length))
}

fn encode_read_response(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&17u16.to_le_bytes());
    let offset = (SMB2_HEADER_SIZE + 16) as u16;
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&data);
    out
}

fn decode_read_response(body: &[u8]) -> CoreResult<Vec<u8>> {
    if body.len() < 16 {
        return Err(CoreError::Parse("read response too short".to_string()));
    }
    let offset = u16::from_le_bytes([body[2], body[3]]) as usize;
    let len = u32::from_le_bytes([body[4], body[5], body[6], body[7]]) as usize;
    if offset < SMB2_HEADER_SIZE {
        return Ok(Vec::new());
    }
    let start = offset - SMB2_HEADER_SIZE;
    if body.len() < start + len {
        return Err(CoreError::Parse("read data out of bounds".to_string()));
    }
    Ok(body[start..start + len].to_vec())
}

fn encode_write_request(file_id: [u8; 16], offset: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&49u16.to_le_bytes());
    let data_offset = (SMB2_HEADER_SIZE + 48) as u16;
    out.extend_from_slice(&data_offset.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&file_id);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn decode_write_request(body: &[u8]) -> CoreResult<([u8; 16], u64, Vec<u8>)> {
    if body.len() < 48 {
        return Err(CoreError::Parse("write request too short".to_string()));
    }
    let data_offset = u16::from_le_bytes([body[2], body[3]]) as usize;
    let len = u32::from_le_bytes([body[4], body[5], body[6], body[7]]) as usize;
    let offset = u64::from_le_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    let mut id = [0u8; 16];
    id.copy_from_slice(&body[16..32]);
    if data_offset < SMB2_HEADER_SIZE {
        return Err(CoreError::Parse("invalid write data offset".to_string()));
    }
    let start = data_offset - SMB2_HEADER_SIZE;
    if body.len() < start + len {
        return Err(CoreError::Parse("write data out of bounds".to_string()));
    }
    let data = body[start..start + len].to_vec();
    Ok((id, offset, data))
}

fn encode_write_response(count: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&17u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

fn decode_write_response(body: &[u8]) -> CoreResult<u32> {
    if body.len() < 8 {
        return Err(CoreError::Parse("write response too short".to_string()));
    }
    Ok(u32::from_le_bytes([body[4], body[5], body[6], body[7]]))
}

fn encode_close_request(file_id: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&24u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&file_id);
    out
}

fn decode_close_request(body: &[u8]) -> CoreResult<[u8; 16]> {
    if body.len() < 24 {
        return Err(CoreError::Parse("close request too short".to_string()));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&body[8..24]);
    Ok(id)
}

fn encode_close_response() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&60u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 56]);
    out
}

fn encode_logoff_request() -> Vec<u8> {
    4u16.to_le_bytes().to_vec()
}

fn encode_logoff_response() -> Vec<u8> {
    4u16.to_le_bytes().to_vec()
}

fn encode_echo_response() -> Vec<u8> {
    4u16.to_le_bytes().to_vec()
}

fn encode_nbss(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut out = Vec::with_capacity(4 + data.len());
    out.push(0);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.extend_from_slice(data);
    out
}

fn read_nbss<T: StreamTransport>(transport: &mut T) -> CoreResult<Vec<u8>> {
    let mut hdr = [0u8; 4];
    transport.read_exact(&mut hdr)?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    let mut buf = vec![0u8; len];
    transport.read_exact(&mut buf)?;
    Ok(buf)
}

async fn read_nbss_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<Vec<u8>> {
    let mut hdr = [0u8; 4];
    transport.read_exact(&mut hdr).await?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    let mut buf = vec![0u8; len];
    transport.read_exact(&mut buf).await?;
    Ok(buf)
}

fn encode_utf16le(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn decode_utf16le(data: &[u8]) -> CoreResult<String> {
    if data.len() % 2 != 0 {
        return Err(CoreError::Parse("invalid utf16".to_string()));
    }
    let mut words = Vec::with_capacity(data.len() / 2);
    for chunk in data.chunks(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&words).map_err(|_| CoreError::Parse("invalid utf16".to_string()))
}

fn sign_packet(packet: &Smb2Packet, key: &[u8; 16]) -> [u8; 16] {
    let mut packet = packet.clone();
    packet.header.signature = [0u8; 16];
    let data = packet.encode();
    let digest = hmac_sha256(key, &data);
    let mut sig = [0u8; 16];
    sig.copy_from_slice(&digest[..16]);
    sig
}

fn verify_packet(packet: &Smb2Packet, key: &[u8; 16]) -> bool {
    let expected = sign_packet(packet, key);
    expected == packet.header.signature
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut o_key = [0u8; 64];
    let mut i_key = [0u8; 64];
    for i in 0..64 {
        o_key[i] = key_block[i] ^ 0x5c;
        i_key[i] = key_block[i] ^ 0x36;
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&i_key);
    inner.extend_from_slice(data);
    let inner_hash = sha256::digest(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&o_key);
    outer.extend_from_slice(&inner_hash);
    sha256::digest(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut hdr = Smb2Header::new(SMB2_NEGOTIATE, 42);
        hdr.status = STATUS_SUCCESS;
        hdr.tree_id = 7;
        hdr.session_id = 9;
        hdr.flags = SMB2_FLAGS_SIGNED;
        hdr.signature = [0x11; 16];
        let encoded = hdr.encode();
        let decoded = Smb2Header::decode(&encoded).unwrap();
        assert_eq!(decoded.command, hdr.command);
        assert_eq!(decoded.message_id, hdr.message_id);
        assert_eq!(decoded.tree_id, hdr.tree_id);
        assert_eq!(decoded.session_id, hdr.session_id);
        assert_eq!(decoded.signature, hdr.signature);
    }

    #[test]
    fn server_client_roundtrip() {
        let mut config = SmbServerConfig::default();
        config.share_name = "test".to_string();
        config.users.insert("user".to_string(), "pass".to_string());
        let server = match SmbServer::bind("127.0.0.1:0".parse().unwrap(), config) {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {err:?}"),
        };
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client =
            SmbClient::connect(&NetAddr::from_socket(addr), SmbClientConfig::default()).unwrap();
        client.negotiate().unwrap();
        let mut ntlm_cfg = NtlmClientConfig::default();
        ntlm_cfg.username = "user".to_string();
        ntlm_cfg.password = crate::ntlm::NtlmSecret::Plaintext("pass".to_string());
        client.session_setup_ntlm(ntlm_cfg).unwrap();
        client.tree_connect("test").unwrap();
        let file_id = client.create("/file.txt").unwrap();
        client.write(file_id, 0, b"hello").unwrap();
        let data = client.read(file_id, 0, 5).unwrap();
        assert_eq!(data, b"hello".to_vec());
        client.close(file_id).unwrap();
        client.logoff().unwrap();
    }
}
