use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

const FULL_FRAME_MARKER: u16 = 0x8000;
const FRAME_HEADER_LEN: usize = 12;

pub const IAX2_DEFAULT_PORT: u16 = 4569;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IaxFrameType {
    Iax = 0x06,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IaxSubclass {
    New = 0x01,
    Accept = 0x02,
    AuthReq = 0x03,
    AuthRep = 0x04,
    Hangup = 0x05,
    Ping = 0x06,
    Pong = 0x07,
}

#[derive(Debug, Clone)]
pub struct IaxFrame {
    pub src_call: u16,
    pub dst_call: u16,
    pub timestamp: u32,
    pub oseq: u8,
    pub iseq: u8,
    pub frame_type: IaxFrameType,
    pub subclass: IaxSubclass,
    pub payload: Vec<u8>,
}

impl IaxFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        let src = self.src_call | FULL_FRAME_MARKER;
        out.extend_from_slice(&src.to_be_bytes());
        out.extend_from_slice(&self.dst_call.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.push(self.oseq);
        out.push(self.iseq);
        out.push(self.frame_type as u8);
        out.push(self.subclass as u8);
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < FRAME_HEADER_LEN {
            return Err(CoreError::Parse("iax2 frame too short".to_string()));
        }
        let src_raw = u16::from_be_bytes([data[0], data[1]]);
        if (src_raw & FULL_FRAME_MARKER) == 0 {
            return Err(CoreError::Parse("iax2 mini frame not supported".to_string()));
        }
        let src_call = src_raw & !FULL_FRAME_MARKER;
        let dst_call = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let oseq = data[8];
        let iseq = data[9];
        let frame_type = match data[10] {
            0x06 => IaxFrameType::Iax,
            value => return Err(CoreError::Parse(format!("iax2 unsupported frame type {value}"))),
        };
        let subclass = match data[11] {
            0x01 => IaxSubclass::New,
            0x02 => IaxSubclass::Accept,
            0x03 => IaxSubclass::AuthReq,
            0x04 => IaxSubclass::AuthRep,
            0x05 => IaxSubclass::Hangup,
            0x06 => IaxSubclass::Ping,
            0x07 => IaxSubclass::Pong,
            value => return Err(CoreError::Parse(format!("iax2 unsupported subclass {value}"))),
        };
        let payload = data[FRAME_HEADER_LEN..].to_vec();
        Ok(Self {
            src_call,
            dst_call,
            timestamp,
            oseq,
            iseq,
            frame_type,
            subclass,
            payload,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Plain,
    Md5,
}

impl AuthMethod {
    fn bit(self) -> u16 {
        match self {
            AuthMethod::Plain => 0x0001,
            AuthMethod::Md5 => 0x0002,
        }
    }

    fn from_bits(bits: u16) -> Vec<AuthMethod> {
        let mut out = Vec::new();
        if bits & 0x0001 != 0 {
            out.push(AuthMethod::Plain);
        }
        if bits & 0x0002 != 0 {
            out.push(AuthMethod::Md5);
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IaxIe {
    CalledNumber(String),
    Username(String),
    Password(String),
    Challenge(Vec<u8>),
    AuthMethods(u16),
    Md5Result(Vec<u8>),
    Cause(String),
    Unknown(u8, Vec<u8>),
}

const IE_CALLED_NUMBER: u8 = 1;
const IE_USERNAME: u8 = 5;
const IE_PASSWORD: u8 = 6;
const IE_CHALLENGE: u8 = 15;
const IE_AUTHMETHODS: u8 = 14;
const IE_MD5_RESULT: u8 = 31;
const IE_CAUSE: u8 = 21;

fn encode_ies(ies: &[IaxIe]) -> Vec<u8> {
    let mut out = Vec::new();
    for ie in ies {
        let (kind, value) = match ie {
            IaxIe::CalledNumber(value) => (IE_CALLED_NUMBER, value.as_bytes().to_vec()),
            IaxIe::Username(value) => (IE_USERNAME, value.as_bytes().to_vec()),
            IaxIe::Password(value) => (IE_PASSWORD, value.as_bytes().to_vec()),
            IaxIe::Challenge(value) => (IE_CHALLENGE, value.clone()),
            IaxIe::AuthMethods(bits) => (IE_AUTHMETHODS, bits.to_be_bytes().to_vec()),
            IaxIe::Md5Result(value) => (IE_MD5_RESULT, value.clone()),
            IaxIe::Cause(value) => (IE_CAUSE, value.as_bytes().to_vec()),
            IaxIe::Unknown(kind, value) => (*kind, value.clone()),
        };
        out.push(kind);
        out.push(value.len() as u8);
        out.extend_from_slice(&value);
    }
    out
}

fn decode_ies(payload: &[u8]) -> CoreResult<Vec<IaxIe>> {
    let mut ies = Vec::new();
    let mut idx = 0;
    while idx + 2 <= payload.len() {
        let kind = payload[idx];
        let len = payload[idx + 1] as usize;
        idx += 2;
        if idx + len > payload.len() {
            return Err(CoreError::Parse("iax2 IE length exceeds payload".to_string()));
        }
        let value = payload[idx..idx + len].to_vec();
        idx += len;
        let ie = match kind {
            IE_CALLED_NUMBER => IaxIe::CalledNumber(String::from_utf8_lossy(&value).to_string()),
            IE_USERNAME => IaxIe::Username(String::from_utf8_lossy(&value).to_string()),
            IE_PASSWORD => IaxIe::Password(String::from_utf8_lossy(&value).to_string()),
            IE_CHALLENGE => IaxIe::Challenge(value),
            IE_AUTHMETHODS => {
                if value.len() != 2 {
                    return Err(CoreError::Parse("iax2 authmethods length invalid".to_string()));
                }
                IaxIe::AuthMethods(u16::from_be_bytes([value[0], value[1]]))
            }
            IE_MD5_RESULT => IaxIe::Md5Result(value),
            IE_CAUSE => IaxIe::Cause(String::from_utf8_lossy(&value).to_string()),
            _ => IaxIe::Unknown(kind, value),
        };
        ies.push(ie);
    }
    Ok(ies)
}

fn timestamp_now() -> u32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_millis() & 0xFFFF_FFFF) as u32
}

#[derive(Debug, Clone)]
pub struct IaxClientConfig {
    pub timeouts: Timeouts,
    pub username: String,
    pub password: String,
    pub prefer_auth: AuthMethod,
}

impl Default for IaxClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: "user".to_string(),
            password: "secret".to_string(),
            prefer_auth: AuthMethod::Md5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IaxServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
    pub auth_methods: Vec<AuthMethod>,
    pub require_auth: bool,
}

impl Default for IaxServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: HashMap::new(),
            auth_methods: vec![AuthMethod::Md5, AuthMethod::Plain],
            require_auth: true,
        }
    }
}

#[derive(Debug, Clone)]
struct SessionState {
    client_call: u16,
    server_call: u16,
    username: Option<String>,
    challenge: Option<Vec<u8>>,
    authenticated: bool,
}

#[derive(Debug)]
struct IaxState {
    next_call: u16,
    sessions: HashMap<SocketAddr, SessionState>,
}

impl IaxState {
    fn new() -> Self {
        Self {
            next_call: 1,
            sessions: HashMap::new(),
        }
    }

    fn alloc_call(&mut self) -> u16 {
        let call = self.next_call;
        self.next_call = self.next_call.wrapping_add(1).max(1);
        call
    }
}

pub struct IaxServer {
    socket: UdpTransport,
    config: IaxServerConfig,
    state: Arc<Mutex<IaxState>>,
}

impl IaxServer {
    pub fn bind(addr: SocketAddr, config: IaxServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            config,
            state: Arc::new(Mutex::new(IaxState::new())),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(1500)?;
            let socket = self.socket.clone();
            let config = self.config.clone();
            let state = Arc::clone(&self.state);
            thread::spawn(move || {
                let _ = handle_iax_request(socket, config, state, &data, addr);
            });
        }
    }
}

pub struct AsyncIaxServer {
    socket: AsyncUdpTransport,
    config: IaxServerConfig,
    state: Arc<Mutex<IaxState>>,
}

impl AsyncIaxServer {
    pub async fn bind(addr: SocketAddr, config: IaxServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            config,
            state: Arc::new(Mutex::new(IaxState::new())),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(1500).await?;
            let config = self.config.clone();
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_iax_request_async(socket, config, state, &data, addr).await;
            });
        }
    }
}

pub struct IaxClient {
    socket: UdpTransport,
    config: IaxClientConfig,
    call_id: u16,
    server_call: u16,
}

impl IaxClient {
    pub fn connect(config: IaxClientConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            config,
            call_id: 1,
            server_call: 0,
        })
    }

    pub fn start_call(&mut self, addr: SocketAddr, called_number: &str) -> CoreResult<()> {
        let mut ies = Vec::new();
        ies.push(IaxIe::CalledNumber(called_number.to_string()));
        ies.push(IaxIe::Username(self.config.username.clone()));
        let frame = IaxFrame {
            src_call: self.call_id,
            dst_call: 0,
            timestamp: timestamp_now(),
            oseq: 0,
            iseq: 0,
            frame_type: IaxFrameType::Iax,
            subclass: IaxSubclass::New,
            payload: encode_ies(&ies),
        };
        self.socket.send_to(&frame.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(1500)?;
        let frame = IaxFrame::decode(&resp)?;
        match frame.subclass {
            IaxSubclass::Accept => {
                self.server_call = frame.src_call;
                Ok(())
            }
            IaxSubclass::AuthReq => {
                let ies = decode_ies(&frame.payload)?;
                self.server_call = frame.src_call;
                self.respond_auth(addr, &ies)
            }
            IaxSubclass::Hangup => Err(CoreError::Message("iax2 hangup".to_string())),
            _ => Err(CoreError::Parse("iax2 unexpected response".to_string())),
        }
    }

    fn respond_auth(&mut self, addr: SocketAddr, ies: &[IaxIe]) -> CoreResult<()> {
        let mut challenge = None;
        let mut methods = Vec::new();
        for ie in ies {
            match ie {
                IaxIe::Challenge(value) => challenge = Some(value.clone()),
                IaxIe::AuthMethods(bits) => methods = AuthMethod::from_bits(*bits),
                _ => {}
            }
        }
        let chosen = if methods.contains(&self.config.prefer_auth) {
            self.config.prefer_auth
        } else if methods.contains(&AuthMethod::Md5) {
            AuthMethod::Md5
        } else if methods.contains(&AuthMethod::Plain) {
            AuthMethod::Plain
        } else {
            return Err(CoreError::Message("iax2 no supported auth".to_string()));
        };
        let mut auth_ies = Vec::new();
        auth_ies.push(IaxIe::Username(self.config.username.clone()));
        match chosen {
            AuthMethod::Plain => auth_ies.push(IaxIe::Password(self.config.password.clone())),
            AuthMethod::Md5 => {
                let challenge = challenge.ok_or_else(|| CoreError::Message("iax2 missing challenge".to_string()))?;
                let mut md5 = md5::Md5::new();
                md5.update(&challenge);
                md5.update(self.config.password.as_bytes());
                auth_ies.push(IaxIe::Md5Result(md5.finalize().to_vec()));
            }
        }
        let frame = IaxFrame {
            src_call: self.call_id,
            dst_call: self.server_call,
            timestamp: timestamp_now(),
            oseq: 1,
            iseq: 0,
            frame_type: IaxFrameType::Iax,
            subclass: IaxSubclass::AuthRep,
            payload: encode_ies(&auth_ies),
        };
        self.socket.send_to(&frame.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(1500)?;
        let frame = IaxFrame::decode(&resp)?;
        match frame.subclass {
            IaxSubclass::Accept => Ok(()),
            IaxSubclass::Hangup => Err(CoreError::Message("iax2 auth failed".to_string())),
            _ => Err(CoreError::Parse("iax2 unexpected auth response".to_string())),
        }
    }

    pub fn ping(&self, addr: SocketAddr) -> CoreResult<()> {
        let frame = IaxFrame {
            src_call: self.call_id,
            dst_call: self.server_call,
            timestamp: timestamp_now(),
            oseq: 0,
            iseq: 0,
            frame_type: IaxFrameType::Iax,
            subclass: IaxSubclass::Ping,
            payload: Vec::new(),
        };
        self.socket.send_to(&frame.encode(), addr)?;
        let (resp, _) = self.socket.recv_from(1500)?;
        let frame = IaxFrame::decode(&resp)?;
        if frame.subclass == IaxSubclass::Pong {
            Ok(())
        } else {
            Err(CoreError::Parse("iax2 ping failed".to_string()))
        }
    }
}

pub struct AsyncIaxClient {
    socket: AsyncUdpTransport,
    config: IaxClientConfig,
    call_id: u16,
    server_call: u16,
}

impl AsyncIaxClient {
    pub async fn connect(config: IaxClientConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self {
            socket,
            config,
            call_id: 1,
            server_call: 0,
        })
    }

    pub async fn start_call(&mut self, addr: SocketAddr, called_number: &str) -> CoreResult<()> {
        let mut ies = Vec::new();
        ies.push(IaxIe::CalledNumber(called_number.to_string()));
        ies.push(IaxIe::Username(self.config.username.clone()));
        let frame = IaxFrame {
            src_call: self.call_id,
            dst_call: 0,
            timestamp: timestamp_now(),
            oseq: 0,
            iseq: 0,
            frame_type: IaxFrameType::Iax,
            subclass: IaxSubclass::New,
            payload: encode_ies(&ies),
        };
        self.socket.send_to(&frame.encode(), addr).await?;
        let (resp, _) = self.socket.recv_from(1500).await?;
        let frame = IaxFrame::decode(&resp)?;
        match frame.subclass {
            IaxSubclass::Accept => {
                self.server_call = frame.src_call;
                Ok(())
            }
            IaxSubclass::AuthReq => {
                let ies = decode_ies(&frame.payload)?;
                self.server_call = frame.src_call;
                self.respond_auth(addr, &ies).await
            }
            IaxSubclass::Hangup => Err(CoreError::Message("iax2 hangup".to_string())),
            _ => Err(CoreError::Parse("iax2 unexpected response".to_string())),
        }
    }

    async fn respond_auth(&mut self, addr: SocketAddr, ies: &[IaxIe]) -> CoreResult<()> {
        let mut challenge = None;
        let mut methods = Vec::new();
        for ie in ies {
            match ie {
                IaxIe::Challenge(value) => challenge = Some(value.clone()),
                IaxIe::AuthMethods(bits) => methods = AuthMethod::from_bits(*bits),
                _ => {}
            }
        }
        let chosen = if methods.contains(&self.config.prefer_auth) {
            self.config.prefer_auth
        } else if methods.contains(&AuthMethod::Md5) {
            AuthMethod::Md5
        } else if methods.contains(&AuthMethod::Plain) {
            AuthMethod::Plain
        } else {
            return Err(CoreError::Message("iax2 no supported auth".to_string()));
        };
        let mut auth_ies = Vec::new();
        auth_ies.push(IaxIe::Username(self.config.username.clone()));
        match chosen {
            AuthMethod::Plain => auth_ies.push(IaxIe::Password(self.config.password.clone())),
            AuthMethod::Md5 => {
                let challenge = challenge.ok_or_else(|| CoreError::Message("iax2 missing challenge".to_string()))?;
                let mut md5 = md5::Md5::new();
                md5.update(&challenge);
                md5.update(self.config.password.as_bytes());
                auth_ies.push(IaxIe::Md5Result(md5.finalize().to_vec()));
            }
        }
        let frame = IaxFrame {
            src_call: self.call_id,
            dst_call: self.server_call,
            timestamp: timestamp_now(),
            oseq: 1,
            iseq: 0,
            frame_type: IaxFrameType::Iax,
            subclass: IaxSubclass::AuthRep,
            payload: encode_ies(&auth_ies),
        };
        self.socket.send_to(&frame.encode(), addr).await?;
        let (resp, _) = self.socket.recv_from(1500).await?;
        let frame = IaxFrame::decode(&resp)?;
        match frame.subclass {
            IaxSubclass::Accept => Ok(()),
            IaxSubclass::Hangup => Err(CoreError::Message("iax2 auth failed".to_string())),
            _ => Err(CoreError::Parse("iax2 unexpected auth response".to_string())),
        }
    }

    pub async fn ping(&self, addr: SocketAddr) -> CoreResult<()> {
        let frame = IaxFrame {
            src_call: self.call_id,
            dst_call: self.server_call,
            timestamp: timestamp_now(),
            oseq: 0,
            iseq: 0,
            frame_type: IaxFrameType::Iax,
            subclass: IaxSubclass::Ping,
            payload: Vec::new(),
        };
        self.socket.send_to(&frame.encode(), addr).await?;
        let (resp, _) = self.socket.recv_from(1500).await?;
        let frame = IaxFrame::decode(&resp)?;
        if frame.subclass == IaxSubclass::Pong {
            Ok(())
        } else {
            Err(CoreError::Parse("iax2 ping failed".to_string()))
        }
    }
}

fn handle_iax_request(
    socket: UdpTransport,
    config: IaxServerConfig,
    state: Arc<Mutex<IaxState>>,
    data: &[u8],
    addr: SocketAddr,
) -> CoreResult<()> {
    let frame = IaxFrame::decode(data)?;
    if frame.frame_type != IaxFrameType::Iax {
        return Ok(());
    }
    let mut state = state.lock().map_err(|_| CoreError::Message("iax2 state poisoned".to_string()))?;
    match frame.subclass {
        IaxSubclass::New => {
            let ies = decode_ies(&frame.payload)?;
            let mut username = None;
            for ie in &ies {
                if let IaxIe::Username(name) = ie {
                    username = Some(name.clone());
                }
            }
            let server_call = state.alloc_call();
            state.sessions.insert(
                addr,
                SessionState {
                    client_call: frame.src_call,
                    server_call,
                    username,
                    challenge: None,
                    authenticated: !config.require_auth,
                },
            );
            if config.require_auth {
                let challenge = format!("{:x}", timestamp_now()).into_bytes();
                let methods_bits: u16 = config.auth_methods.iter().map(|m| m.bit()).sum();
                let auth_frame = IaxFrame {
                    src_call: server_call,
                    dst_call: frame.src_call,
                    timestamp: timestamp_now(),
                    oseq: 0,
                    iseq: 0,
                    frame_type: IaxFrameType::Iax,
                    subclass: IaxSubclass::AuthReq,
                    payload: encode_ies(&[IaxIe::Challenge(challenge.clone()), IaxIe::AuthMethods(methods_bits)]),
                };
                if let Some(session) = state.sessions.get_mut(&addr) {
                    session.challenge = Some(challenge);
                }
                socket.send_to(&auth_frame.encode(), addr)?;
            } else {
                let accept = IaxFrame {
                    src_call: server_call,
                    dst_call: frame.src_call,
                    timestamp: timestamp_now(),
                    oseq: 0,
                    iseq: 0,
                    frame_type: IaxFrameType::Iax,
                    subclass: IaxSubclass::Accept,
                    payload: Vec::new(),
                };
                socket.send_to(&accept.encode(), addr)?;
            }
        }
        IaxSubclass::AuthRep => {
            let ies = decode_ies(&frame.payload)?;
            let session = state.sessions.get_mut(&addr).ok_or_else(|| CoreError::Message("iax2 no session".to_string()))?;
            let username = session.username.clone().unwrap_or_else(|| "".to_string());
            let stored = config.users.get(&username).cloned().unwrap_or_default();
            let mut ok = false;
            let mut password = None;
            let mut md5_result = None;
            for ie in ies {
                match ie {
                    IaxIe::Password(value) => password = Some(value),
                    IaxIe::Md5Result(value) => md5_result = Some(value),
                    _ => {}
                }
            }
            if let Some(value) = password {
                if config.auth_methods.contains(&AuthMethod::Plain) && value == stored {
                    ok = true;
                }
            }
            if !ok {
                if let (Some(challenge), Some(result)) = (session.challenge.clone(), md5_result) {
                    if config.auth_methods.contains(&AuthMethod::Md5) {
                        let mut md5 = md5::Md5::new();
                        md5.update(&challenge);
                        md5.update(stored.as_bytes());
                        ok = md5.finalize().to_vec() == result;
                    }
                }
            }
            if ok {
                session.authenticated = true;
                let accept = IaxFrame {
                    src_call: session.server_call,
                    dst_call: session.client_call,
                    timestamp: timestamp_now(),
                    oseq: 0,
                    iseq: 0,
                    frame_type: IaxFrameType::Iax,
                    subclass: IaxSubclass::Accept,
                    payload: Vec::new(),
                };
                socket.send_to(&accept.encode(), addr)?;
            } else {
                let hangup = IaxFrame {
                    src_call: session.server_call,
                    dst_call: session.client_call,
                    timestamp: timestamp_now(),
                    oseq: 0,
                    iseq: 0,
                    frame_type: IaxFrameType::Iax,
                    subclass: IaxSubclass::Hangup,
                    payload: encode_ies(&[IaxIe::Cause("auth failed".to_string())]),
                };
                socket.send_to(&hangup.encode(), addr)?;
            }
        }
        IaxSubclass::Ping => {
            if let Some(session) = state.sessions.get(&addr) {
                let pong = IaxFrame {
                    src_call: session.server_call,
                    dst_call: session.client_call,
                    timestamp: timestamp_now(),
                    oseq: 0,
                    iseq: 0,
                    frame_type: IaxFrameType::Iax,
                    subclass: IaxSubclass::Pong,
                    payload: Vec::new(),
                };
                socket.send_to(&pong.encode(), addr)?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_iax_request_async(
    socket: AsyncUdpTransport,
    config: IaxServerConfig,
    state: Arc<Mutex<IaxState>>,
    data: &[u8],
    addr: SocketAddr,
) -> CoreResult<()> {
    let frame = IaxFrame::decode(data)?;
    if frame.frame_type != IaxFrameType::Iax {
        return Ok(());
    }
    let response = {
        let mut state = state.lock().map_err(|_| CoreError::Message("iax2 state poisoned".to_string()))?;
        match frame.subclass {
            IaxSubclass::New => {
                let ies = decode_ies(&frame.payload)?;
                let mut username = None;
                for ie in &ies {
                    if let IaxIe::Username(name) = ie {
                        username = Some(name.clone());
                    }
                }
                let server_call = state.alloc_call();
                state.sessions.insert(
                    addr,
                    SessionState {
                        client_call: frame.src_call,
                        server_call,
                        username,
                        challenge: None,
                        authenticated: !config.require_auth,
                    },
                );
                if config.require_auth {
                    let challenge = format!("{:x}", timestamp_now()).into_bytes();
                    let methods_bits: u16 = config.auth_methods.iter().map(|m| m.bit()).sum();
                    if let Some(session) = state.sessions.get_mut(&addr) {
                        session.challenge = Some(challenge.clone());
                    }
                    Some(IaxFrame {
                        src_call: server_call,
                        dst_call: frame.src_call,
                        timestamp: timestamp_now(),
                        oseq: 0,
                        iseq: 0,
                        frame_type: IaxFrameType::Iax,
                        subclass: IaxSubclass::AuthReq,
                        payload: encode_ies(&[IaxIe::Challenge(challenge), IaxIe::AuthMethods(methods_bits)]),
                    })
                } else {
                    Some(IaxFrame {
                        src_call: server_call,
                        dst_call: frame.src_call,
                        timestamp: timestamp_now(),
                        oseq: 0,
                        iseq: 0,
                        frame_type: IaxFrameType::Iax,
                        subclass: IaxSubclass::Accept,
                        payload: Vec::new(),
                    })
                }
            }
            IaxSubclass::AuthRep => {
                let ies = decode_ies(&frame.payload)?;
                let session = state.sessions.get_mut(&addr).ok_or_else(|| CoreError::Message("iax2 no session".to_string()))?;
                let username = session.username.clone().unwrap_or_else(|| "".to_string());
                let stored = config.users.get(&username).cloned().unwrap_or_default();
                let mut ok = false;
                let mut password = None;
                let mut md5_result = None;
                for ie in ies {
                    match ie {
                        IaxIe::Password(value) => password = Some(value),
                        IaxIe::Md5Result(value) => md5_result = Some(value),
                        _ => {}
                    }
                }
                if let Some(value) = password {
                    if config.auth_methods.contains(&AuthMethod::Plain) && value == stored {
                        ok = true;
                    }
                }
                if !ok {
                    if let (Some(challenge), Some(result)) = (session.challenge.clone(), md5_result) {
                        if config.auth_methods.contains(&AuthMethod::Md5) {
                            let mut md5 = md5::Md5::new();
                            md5.update(&challenge);
                            md5.update(stored.as_bytes());
                            ok = md5.finalize().to_vec() == result;
                        }
                    }
                }
                if ok {
                    session.authenticated = true;
                    Some(IaxFrame {
                        src_call: session.server_call,
                        dst_call: session.client_call,
                        timestamp: timestamp_now(),
                        oseq: 0,
                        iseq: 0,
                        frame_type: IaxFrameType::Iax,
                        subclass: IaxSubclass::Accept,
                        payload: Vec::new(),
                    })
                } else {
                    Some(IaxFrame {
                        src_call: session.server_call,
                        dst_call: session.client_call,
                        timestamp: timestamp_now(),
                        oseq: 0,
                        iseq: 0,
                        frame_type: IaxFrameType::Iax,
                        subclass: IaxSubclass::Hangup,
                        payload: encode_ies(&[IaxIe::Cause("auth failed".to_string())]),
                    })
                }
            }
            IaxSubclass::Ping => state.sessions.get(&addr).map(|session| IaxFrame {
                src_call: session.server_call,
                dst_call: session.client_call,
                timestamp: timestamp_now(),
                oseq: 0,
                iseq: 0,
                frame_type: IaxFrameType::Iax,
                subclass: IaxSubclass::Pong,
                payload: Vec::new(),
            }),
            _ => None,
        }
    };
    if let Some(frame) = response {
        socket.send_to(&frame.encode(), addr).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iax2_auth_md5_flow() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "s3cret".to_string());
        let server = IaxServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            IaxServerConfig {
                users,
                ..IaxServerConfig::default()
            },
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = IaxClient::connect(IaxClientConfig {
            username: "alice".to_string(),
            password: "s3cret".to_string(),
            prefer_auth: AuthMethod::Md5,
            ..IaxClientConfig::default()
        })
        .unwrap();
        client.start_call(addr, "1000").unwrap();
        client.ping(addr).unwrap();

        drop(handle);
    }

    #[test]
    fn iax2_plain_auth_flow() {
        let mut users = HashMap::new();
        users.insert("bob".to_string(), "pw".to_string());
        let server = IaxServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            IaxServerConfig {
                users,
                auth_methods: vec![AuthMethod::Plain],
                ..IaxServerConfig::default()
            },
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = IaxClient::connect(IaxClientConfig {
            username: "bob".to_string(),
            password: "pw".to_string(),
            prefer_auth: AuthMethod::Plain,
            ..IaxClientConfig::default()
        })
        .unwrap();
        client.start_call(addr, "2000").unwrap();

        drop(handle);
    }
}
