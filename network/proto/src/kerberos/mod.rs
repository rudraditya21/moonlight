use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use corelib::error::{CoreError, CoreResult};
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const FRAME_HEADER: usize = 6;
const MAX_FRAME: usize = 256 * 1024;
const KERB_VERSION: u8 = 5;
const DEFAULT_TICKET_LIFETIME_SECS: u64 = 8 * 60 * 60;
const CLOCK_SKEW_SECS: u64 = 300;

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KerbMsgType {
    AsReq = 1,
    AsRep = 2,
    TgsReq = 3,
    TgsRep = 4,
    ApReq = 5,
    ApRep = 6,
    Error = 7,
}

impl KerbMsgType {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            1 => Ok(KerbMsgType::AsReq),
            2 => Ok(KerbMsgType::AsRep),
            3 => Ok(KerbMsgType::TgsReq),
            4 => Ok(KerbMsgType::TgsRep),
            5 => Ok(KerbMsgType::ApReq),
            6 => Ok(KerbMsgType::ApRep),
            7 => Ok(KerbMsgType::Error),
            _ => Err(CoreError::Parse("kerberos message type".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KerbFrame {
    pub version: u8,
    pub msg_type: KerbMsgType,
    pub payload: Vec<u8>,
}

impl KerbFrame {
    pub fn new(msg_type: KerbMsgType, payload: Vec<u8>) -> Self {
        Self {
            version: KERB_VERSION,
            msg_type,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER + self.payload.len());
        out.push(self.version);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < FRAME_HEADER {
            return Err(CoreError::Parse("kerberos frame".to_string()));
        }
        let version = data[0];
        let msg_type = KerbMsgType::from_u8(data[1])?;
        let len = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
        if len > MAX_FRAME || data.len() < FRAME_HEADER + len {
            return Err(CoreError::Parse("kerberos frame length".to_string()));
        }
        Ok(Self {
            version,
            msg_type,
            payload: data[FRAME_HEADER..FRAME_HEADER + len].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct KerbPrincipal {
    pub name: String,
    pub realm: String,
}

impl KerbPrincipal {
    pub fn new(name: &str, realm: &str) -> Self {
        Self {
            name: name.to_string(),
            realm: realm.to_string(),
        }
    }

    pub fn as_string(&self) -> String {
        format!("{}@{}", self.name, self.realm)
    }
}

#[derive(Debug, Clone)]
pub struct KerbTicket {
    pub client: KerbPrincipal,
    pub service: KerbPrincipal,
    pub start_time: u64,
    pub end_time: u64,
    pub session_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct KerbEncryptedTicket {
    pub blob: CryptoBlob,
}

#[derive(Debug, Clone)]
pub struct KerbAuthenticator {
    pub client: KerbPrincipal,
    pub timestamp: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct KerbAsReq {
    pub client: KerbPrincipal,
    pub realm: String,
    pub nonce: u64,
    pub preauth: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct KerbAsRep {
    pub ticket: KerbEncryptedTicket,
    pub enc_part: CryptoBlob,
}

#[derive(Debug, Clone)]
pub struct KerbTgsReq {
    pub service: KerbPrincipal,
    pub ticket: KerbEncryptedTicket,
    pub authenticator: CryptoBlob,
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct KerbTgsRep {
    pub ticket: KerbEncryptedTicket,
    pub enc_part: CryptoBlob,
}

#[derive(Debug, Clone)]
pub struct KerbApReq {
    pub ticket: KerbEncryptedTicket,
    pub authenticator: CryptoBlob,
    pub mutual: bool,
}

impl KerbApReq {
    pub fn encode(&self) -> Vec<u8> {
        encode_ap_req(self)
    }
}

#[derive(Debug, Clone)]
pub struct KerbApRep {
    pub timestamp: u64,
}

impl KerbApRep {
    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        decode_ap_rep(data)
    }
}

#[derive(Debug, Clone)]
pub struct KerbError {
    pub code: u16,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct KerbKdcConfig {
    pub timeouts: Timeouts,
    pub realm: String,
    pub krbtgt_key: [u8; 32],
    pub users: HashMap<String, [u8; 32]>,
    pub services: HashMap<String, [u8; 32]>,
    pub ticket_lifetime: u64,
}

impl Default for KerbKdcConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            realm: "MOONLIGHT".to_string(),
            krbtgt_key: derive_key(b"krbtgt", b"moonlight"),
            users: HashMap::new(),
            services: HashMap::new(),
            ticket_lifetime: DEFAULT_TICKET_LIFETIME_SECS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KerbServiceConfig {
    pub timeouts: Timeouts,
    pub realm: String,
    pub service: String,
    pub key: [u8; 32],
}

impl KerbServiceConfig {
    pub fn new(service: &str, realm: &str, password: &str) -> Self {
        Self {
            timeouts: Timeouts::default(),
            realm: realm.to_string(),
            service: service.to_string(),
            key: derive_key(password.as_bytes(), realm.as_bytes()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KerbClientConfig {
    pub timeouts: Timeouts,
    pub realm: String,
    pub username: String,
    pub password: String,
}

impl Default for KerbClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            realm: "MOONLIGHT".to_string(),
            username: "user".to_string(),
            password: "password".to_string(),
        }
    }
}

pub struct KerbKdcServer {
    listener: TcpListener,
    state: Arc<Mutex<KerbKdcConfig>>,
}

impl KerbKdcServer {
    pub fn bind(addr: SocketAddr, config: KerbKdcConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            state: Arc::new(Mutex::new(config)),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn add_user(&self, username: &str, password: &str) {
        let mut state = self.state.lock().unwrap();
        let realm = state.realm.clone();
        state.users.insert(
            username.to_string(),
            derive_key(password.as_bytes(), realm.as_bytes()),
        );
    }

    pub fn add_service(&self, service: &str, password: &str) {
        let mut state = self.state.lock().unwrap();
        let realm = state.realm.clone();
        state.services.insert(
            service.to_string(),
            derive_key(password.as_bytes(), realm.as_bytes()),
        );
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let state = Arc::clone(&self.state);
            thread::spawn(move || {
                let _ = handle_kdc_stream(stream, state);
            });
        }
        Ok(())
    }
}

pub struct AsyncKerbKdcServer {
    listener: tokio::net::TcpListener,
    state: Arc<Mutex<KerbKdcConfig>>,
}

impl AsyncKerbKdcServer {
    pub async fn bind(addr: SocketAddr, config: KerbKdcConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            state: Arc::new(Mutex::new(config)),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let _ = handle_kdc_stream_async(stream, state).await;
            });
        }
    }
}

pub struct KerbServiceServer {
    listener: TcpListener,
    config: KerbServiceConfig,
}

impl KerbServiceServer {
    pub fn bind(addr: SocketAddr, config: KerbServiceConfig) -> CoreResult<Self> {
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
                let _ = handle_service_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncKerbServiceServer {
    listener: tokio::net::TcpListener,
    config: KerbServiceConfig,
}

impl AsyncKerbServiceServer {
    pub async fn bind(addr: SocketAddr, config: KerbServiceConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_service_stream_async(stream, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct KerbClientState {
    pub tgt: KerbEncryptedTicket,
    pub tgt_session: [u8; 32],
    pub realm: String,
    pub client: KerbPrincipal,
}

pub struct KerbClient {
    transport: TcpTransport,
    config: KerbClientConfig,
    pub state: KerbClientState,
}

impl KerbClient {
    pub fn connect(addr: &net::NetAddr, config: KerbClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let (tgt, session) = request_tgt(&mut transport, &config)?;
        let client = KerbPrincipal::new(&config.username, &config.realm);
        Ok(Self {
            transport,
            config: config.clone(),
            state: KerbClientState {
                tgt,
                tgt_session: session,
                realm: config.realm.clone(),
                client,
            },
        })
    }

    pub fn request_service_ticket(
        &mut self,
        service: &str,
    ) -> CoreResult<(KerbEncryptedTicket, [u8; 32])> {
        let service_principal = KerbPrincipal::new(service, &self.config.realm);
        let req = KerbTgsReq {
            service: service_principal,
            ticket: self.state.tgt.clone(),
            authenticator: encrypt_authenticator(&self.state.tgt_session, &self.state.client)?,
            nonce: next_nonce(),
        };
        let frame = KerbFrame::new(KerbMsgType::TgsReq, encode_tgs_req(&req));
        write_frame(&mut self.transport, &frame)?;
        let response = read_frame(&mut self.transport)?;
        match response.msg_type {
            KerbMsgType::TgsRep => {
                let rep = decode_tgs_rep(&response.payload)?;
                let session = decrypt_session_key(&rep.enc_part, &self.state.tgt_session)?;
                Ok((rep.ticket, session))
            }
            KerbMsgType::Error => Err(CoreError::Message(decode_error(&response.payload)?.message)),
            _ => Err(CoreError::Parse("kerberos tgs response".to_string())),
        }
    }

    pub fn build_ap_req(
        &self,
        service_ticket: KerbEncryptedTicket,
        service_session: [u8; 32],
        mutual: bool,
    ) -> CoreResult<KerbApReq> {
        Ok(KerbApReq {
            ticket: service_ticket,
            authenticator: encrypt_authenticator(&service_session, &self.state.client)?,
            mutual,
        })
    }
}

pub struct AsyncKerbClient {
    transport: AsyncTcpTransport,
    config: KerbClientConfig,
    pub state: KerbClientState,
}

impl AsyncKerbClient {
    pub async fn connect(addr: &net::NetAddr, config: KerbClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let (tgt, session) = request_tgt_async(&mut transport, &config).await?;
        let client = KerbPrincipal::new(&config.username, &config.realm);
        Ok(Self {
            transport,
            config: config.clone(),
            state: KerbClientState {
                tgt,
                tgt_session: session,
                realm: config.realm.clone(),
                client,
            },
        })
    }

    pub async fn request_service_ticket(
        &mut self,
        service: &str,
    ) -> CoreResult<(KerbEncryptedTicket, [u8; 32])> {
        let service_principal = KerbPrincipal::new(service, &self.config.realm);
        let req = KerbTgsReq {
            service: service_principal,
            ticket: self.state.tgt.clone(),
            authenticator: encrypt_authenticator(&self.state.tgt_session, &self.state.client)?,
            nonce: next_nonce(),
        };
        let frame = KerbFrame::new(KerbMsgType::TgsReq, encode_tgs_req(&req));
        write_frame_async(&mut self.transport, &frame).await?;
        let response = read_frame_async(&mut self.transport).await?;
        match response.msg_type {
            KerbMsgType::TgsRep => {
                let rep = decode_tgs_rep(&response.payload)?;
                let session = decrypt_session_key(&rep.enc_part, &self.state.tgt_session)?;
                Ok((rep.ticket, session))
            }
            KerbMsgType::Error => Err(CoreError::Message(decode_error(&response.payload)?.message)),
            _ => Err(CoreError::Parse("kerberos tgs response".to_string())),
        }
    }

    pub fn build_ap_req(
        &self,
        service_ticket: KerbEncryptedTicket,
        service_session: [u8; 32],
        mutual: bool,
    ) -> CoreResult<KerbApReq> {
        Ok(KerbApReq {
            ticket: service_ticket,
            authenticator: encrypt_authenticator(&service_session, &self.state.client)?,
            mutual,
        })
    }
}

fn handle_kdc_stream(stream: TcpStream, state: Arc<Mutex<KerbKdcConfig>>) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, Timeouts::default())?;
    loop {
        let frame = match read_frame(&mut transport) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        let response = match frame.msg_type {
            KerbMsgType::AsReq => handle_as_req(&frame.payload, &state),
            KerbMsgType::TgsReq => handle_tgs_req(&frame.payload, &state),
            _ => Err(CoreError::Parse("kerberos unsupported".to_string())),
        };
        let payload = match response {
            Ok(frame) => frame.encode(),
            Err(err) => {
                KerbFrame::new(KerbMsgType::Error, encode_error(1, &err.to_string())).encode()
            }
        };
        transport.write_all(&payload)?;
    }
    Ok(())
}

async fn handle_kdc_stream_async(
    stream: tokio::net::TcpStream,
    state: Arc<Mutex<KerbKdcConfig>>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let frame = match read_frame_async(&mut transport).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        let response = match frame.msg_type {
            KerbMsgType::AsReq => handle_as_req(&frame.payload, &state),
            KerbMsgType::TgsReq => handle_tgs_req(&frame.payload, &state),
            _ => Err(CoreError::Parse("kerberos unsupported".to_string())),
        };
        let payload = match response {
            Ok(frame) => frame.encode(),
            Err(err) => {
                KerbFrame::new(KerbMsgType::Error, encode_error(1, &err.to_string())).encode()
            }
        };
        transport.write_all(&payload).await?;
    }
    Ok(())
}

fn handle_service_stream(stream: TcpStream, config: KerbServiceConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let frame = match read_frame(&mut transport) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        if frame.msg_type != KerbMsgType::ApReq {
            continue;
        }
        let req = decode_ap_req(&frame.payload)?;
        let ap_rep = validate_ap_req(&req, &config)?;
        let response = KerbFrame::new(KerbMsgType::ApRep, encode_ap_rep(&ap_rep));
        transport.write_all(&response.encode())?;
    }
    Ok(())
}

async fn handle_service_stream_async(
    stream: tokio::net::TcpStream,
    config: KerbServiceConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let frame = match read_frame_async(&mut transport).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        if frame.msg_type != KerbMsgType::ApReq {
            continue;
        }
        let req = decode_ap_req(&frame.payload)?;
        let ap_rep = validate_ap_req(&req, &config)?;
        let response = KerbFrame::new(KerbMsgType::ApRep, encode_ap_rep(&ap_rep));
        transport.write_all(&response.encode()).await?;
    }
    Ok(())
}

fn request_tgt(
    transport: &mut TcpTransport,
    config: &KerbClientConfig,
) -> CoreResult<(KerbEncryptedTicket, [u8; 32])> {
    let client = KerbPrincipal::new(&config.username, &config.realm);
    let nonce = next_nonce();
    let preauth = hmac_sha256(
        &derive_key(config.password.as_bytes(), config.realm.as_bytes()),
        &nonce.to_be_bytes(),
    );
    let req = KerbAsReq {
        client,
        realm: config.realm.clone(),
        nonce,
        preauth: preauth.to_vec(),
    };
    let frame = KerbFrame::new(KerbMsgType::AsReq, encode_as_req(&req));
    write_frame(transport, &frame)?;
    let response = read_frame(transport)?;
    match response.msg_type {
        KerbMsgType::AsRep => {
            let rep = decode_as_rep(&response.payload)?;
            let session = decrypt_session_key(
                &rep.enc_part,
                &derive_key(config.password.as_bytes(), config.realm.as_bytes()),
            )?;
            Ok((rep.ticket, session))
        }
        KerbMsgType::Error => Err(CoreError::Message(decode_error(&response.payload)?.message)),
        _ => Err(CoreError::Parse("kerberos as response".to_string())),
    }
}

async fn request_tgt_async(
    transport: &mut AsyncTcpTransport,
    config: &KerbClientConfig,
) -> CoreResult<(KerbEncryptedTicket, [u8; 32])> {
    let client = KerbPrincipal::new(&config.username, &config.realm);
    let nonce = next_nonce();
    let preauth = hmac_sha256(
        &derive_key(config.password.as_bytes(), config.realm.as_bytes()),
        &nonce.to_be_bytes(),
    );
    let req = KerbAsReq {
        client,
        realm: config.realm.clone(),
        nonce,
        preauth: preauth.to_vec(),
    };
    let frame = KerbFrame::new(KerbMsgType::AsReq, encode_as_req(&req));
    write_frame_async(transport, &frame).await?;
    let response = read_frame_async(transport).await?;
    match response.msg_type {
        KerbMsgType::AsRep => {
            let rep = decode_as_rep(&response.payload)?;
            let session = decrypt_session_key(
                &rep.enc_part,
                &derive_key(config.password.as_bytes(), config.realm.as_bytes()),
            )?;
            Ok((rep.ticket, session))
        }
        KerbMsgType::Error => Err(CoreError::Message(decode_error(&response.payload)?.message)),
        _ => Err(CoreError::Parse("kerberos as response".to_string())),
    }
}

fn handle_as_req(payload: &[u8], state: &Arc<Mutex<KerbKdcConfig>>) -> CoreResult<KerbFrame> {
    let req = decode_as_req(payload)?;
    let now = now_secs();
    let state = state.lock().unwrap();
    if req.realm != state.realm {
        return Err(CoreError::Parse("kerberos realm".to_string()));
    }
    let key = state
        .users
        .get(&req.client.name)
        .ok_or_else(|| CoreError::Message("unknown user".to_string()))?
        .to_vec();
    let expected = hmac_sha256(&key_bytes(&key), &req.nonce.to_be_bytes());
    if !constant_time_eq(&expected, &req.preauth) {
        return Err(CoreError::Message("preauth failed".to_string()));
    }
    let session_key = random_key();
    let service = KerbPrincipal::new("krbtgt", &state.realm);
    let ticket = KerbTicket {
        client: req.client.clone(),
        service,
        start_time: now,
        end_time: now + state.ticket_lifetime,
        session_key,
    };
    let encrypted_ticket = KerbEncryptedTicket {
        blob: encrypt_ticket(&ticket, &state.krbtgt_key),
    };
    let enc_part = encrypt_session_key(&session_key, &key_bytes(&key));
    let rep = KerbAsRep {
        ticket: encrypted_ticket,
        enc_part,
    };
    Ok(KerbFrame::new(KerbMsgType::AsRep, encode_as_rep(&rep)))
}

fn handle_tgs_req(payload: &[u8], state: &Arc<Mutex<KerbKdcConfig>>) -> CoreResult<KerbFrame> {
    let req = decode_tgs_req(payload)?;
    let now = now_secs();
    let state = state.lock().unwrap();
    let tgt = decrypt_ticket(&req.ticket.blob, &state.krbtgt_key)?;
    if now > tgt.end_time {
        return Err(CoreError::Message("ticket expired".to_string()));
    }
    let auth = decrypt_authenticator(&req.authenticator, &tgt.session_key)?;
    if !validate_authenticator(&auth, &tgt.client) {
        return Err(CoreError::Message("invalid authenticator".to_string()));
    }
    let service_key = state
        .services
        .get(&req.service.name)
        .ok_or_else(|| CoreError::Message("unknown service".to_string()))?
        .to_vec();
    let session_key = random_key();
    let ticket = KerbTicket {
        client: tgt.client,
        service: req.service,
        start_time: now,
        end_time: now + state.ticket_lifetime,
        session_key,
    };
    let encrypted_ticket = KerbEncryptedTicket {
        blob: encrypt_ticket(&ticket, &key_bytes(&service_key)),
    };
    let enc_part = encrypt_session_key(&session_key, &tgt.session_key);
    let rep = KerbTgsRep {
        ticket: encrypted_ticket,
        enc_part,
    };
    Ok(KerbFrame::new(KerbMsgType::TgsRep, encode_tgs_rep(&rep)))
}

fn validate_ap_req(req: &KerbApReq, config: &KerbServiceConfig) -> CoreResult<KerbApRep> {
    let ticket = decrypt_ticket(&req.ticket.blob, &config.key)?;
    let now = now_secs();
    if now > ticket.end_time {
        return Err(CoreError::Message("ticket expired".to_string()));
    }
    let auth = decrypt_authenticator(&req.authenticator, &ticket.session_key)?;
    if !validate_authenticator(&auth, &ticket.client) {
        return Err(CoreError::Message("invalid authenticator".to_string()));
    }
    if req.mutual {
        Ok(KerbApRep {
            timestamp: auth.timestamp,
        })
    } else {
        Ok(KerbApRep { timestamp: now })
    }
}

fn encode_as_req(req: &KerbAsReq) -> Vec<u8> {
    let mut out = Vec::new();
    write_principal(&mut out, &req.client);
    write_string(&mut out, &req.realm);
    out.extend_from_slice(&req.nonce.to_be_bytes());
    write_bytes(&mut out, &req.preauth);
    out
}

fn decode_as_req(data: &[u8]) -> CoreResult<KerbAsReq> {
    let mut idx = 0;
    let client = read_principal(data, &mut idx)?;
    let realm = read_string(data, &mut idx)?;
    let nonce = read_u64(data, &mut idx)?;
    let preauth = read_bytes(data, &mut idx)?;
    Ok(KerbAsReq {
        client,
        realm,
        nonce,
        preauth,
    })
}

fn encode_as_rep(rep: &KerbAsRep) -> Vec<u8> {
    let mut out = Vec::new();
    write_blob(&mut out, &rep.ticket.blob);
    write_blob(&mut out, &rep.enc_part);
    out
}

fn decode_as_rep(data: &[u8]) -> CoreResult<KerbAsRep> {
    let mut idx = 0;
    let ticket = KerbEncryptedTicket {
        blob: read_blob(data, &mut idx)?,
    };
    let enc_part = read_blob(data, &mut idx)?;
    Ok(KerbAsRep { ticket, enc_part })
}

fn encode_tgs_req(req: &KerbTgsReq) -> Vec<u8> {
    let mut out = Vec::new();
    write_principal(&mut out, &req.service);
    write_blob(&mut out, &req.ticket.blob);
    write_blob(&mut out, &req.authenticator);
    out.extend_from_slice(&req.nonce.to_be_bytes());
    out
}

fn decode_tgs_req(data: &[u8]) -> CoreResult<KerbTgsReq> {
    let mut idx = 0;
    let service = read_principal(data, &mut idx)?;
    let ticket = KerbEncryptedTicket {
        blob: read_blob(data, &mut idx)?,
    };
    let authenticator = read_blob(data, &mut idx)?;
    let nonce = read_u64(data, &mut idx)?;
    Ok(KerbTgsReq {
        service,
        ticket,
        authenticator,
        nonce,
    })
}

fn encode_tgs_rep(rep: &KerbTgsRep) -> Vec<u8> {
    let mut out = Vec::new();
    write_blob(&mut out, &rep.ticket.blob);
    write_blob(&mut out, &rep.enc_part);
    out
}

fn decode_tgs_rep(data: &[u8]) -> CoreResult<KerbTgsRep> {
    let mut idx = 0;
    let ticket = KerbEncryptedTicket {
        blob: read_blob(data, &mut idx)?,
    };
    let enc_part = read_blob(data, &mut idx)?;
    Ok(KerbTgsRep { ticket, enc_part })
}

fn encode_ap_req(req: &KerbApReq) -> Vec<u8> {
    let mut out = Vec::new();
    write_blob(&mut out, &req.ticket.blob);
    write_blob(&mut out, &req.authenticator);
    out.push(if req.mutual { 1 } else { 0 });
    out
}

fn decode_ap_req(data: &[u8]) -> CoreResult<KerbApReq> {
    let mut idx = 0;
    let ticket = KerbEncryptedTicket {
        blob: read_blob(data, &mut idx)?,
    };
    let authenticator = read_blob(data, &mut idx)?;
    let mutual = read_u8(data, &mut idx)? == 1;
    Ok(KerbApReq {
        ticket,
        authenticator,
        mutual,
    })
}

fn encode_ap_rep(rep: &KerbApRep) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&rep.timestamp.to_be_bytes());
    out
}

fn decode_ap_rep(data: &[u8]) -> CoreResult<KerbApRep> {
    let mut idx = 0;
    let timestamp = read_u64(data, &mut idx)?;
    Ok(KerbApRep { timestamp })
}

fn encode_error(code: u16, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&code.to_be_bytes());
    write_string(&mut out, message);
    out
}

fn decode_error(data: &[u8]) -> CoreResult<KerbError> {
    let mut idx = 0;
    let code = read_u16(data, &mut idx)?;
    let message = read_string(data, &mut idx)?;
    Ok(KerbError { code, message })
}

fn encrypt_ticket(ticket: &KerbTicket, key: &[u8; 32]) -> CryptoBlob {
    let mut data = Vec::new();
    write_principal(&mut data, &ticket.client);
    write_principal(&mut data, &ticket.service);
    data.extend_from_slice(&ticket.start_time.to_be_bytes());
    data.extend_from_slice(&ticket.end_time.to_be_bytes());
    data.extend_from_slice(&ticket.session_key);
    encrypt_blob(key, &data)
}

fn decrypt_ticket(blob: &CryptoBlob, key: &[u8; 32]) -> CoreResult<KerbTicket> {
    let data = decrypt_blob(key, blob)?;
    let mut idx = 0;
    let client = read_principal(&data, &mut idx)?;
    let service = read_principal(&data, &mut idx)?;
    let start_time = read_u64(&data, &mut idx)?;
    let end_time = read_u64(&data, &mut idx)?;
    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(read_fixed(&data, &mut idx, 32)?);
    Ok(KerbTicket {
        client,
        service,
        start_time,
        end_time,
        session_key,
    })
}

fn encrypt_session_key(session_key: &[u8; 32], key: &[u8; 32]) -> CryptoBlob {
    encrypt_blob(key, session_key)
}

fn decrypt_session_key(blob: &CryptoBlob, key: &[u8; 32]) -> CoreResult<[u8; 32]> {
    let data = decrypt_blob(key, blob)?;
    if data.len() != 32 {
        return Err(CoreError::Parse("kerberos session key".to_string()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Ok(out)
}

fn encrypt_authenticator(key: &[u8; 32], client: &KerbPrincipal) -> CoreResult<CryptoBlob> {
    let auth = KerbAuthenticator {
        client: client.clone(),
        timestamp: now_secs(),
        nonce: next_nonce(),
    };
    let mut data = Vec::new();
    write_principal(&mut data, &auth.client);
    data.extend_from_slice(&auth.timestamp.to_be_bytes());
    data.extend_from_slice(&auth.nonce.to_be_bytes());
    Ok(encrypt_blob(key, &data))
}

fn decrypt_authenticator(blob: &CryptoBlob, key: &[u8; 32]) -> CoreResult<KerbAuthenticator> {
    let data = decrypt_blob(key, blob)?;
    let mut idx = 0;
    let client = read_principal(&data, &mut idx)?;
    let timestamp = read_u64(&data, &mut idx)?;
    let nonce = read_u64(&data, &mut idx)?;
    Ok(KerbAuthenticator {
        client,
        timestamp,
        nonce,
    })
}

fn validate_authenticator(auth: &KerbAuthenticator, client: &KerbPrincipal) -> bool {
    if auth.client.name != client.name || auth.client.realm != client.realm {
        return false;
    }
    let now = now_secs();
    let diff = if now > auth.timestamp {
        now - auth.timestamp
    } else {
        auth.timestamp - now
    };
    diff <= CLOCK_SKEW_SECS
}

fn write_principal(out: &mut Vec<u8>, principal: &KerbPrincipal) {
    write_string(out, &principal.name);
    write_string(out, &principal.realm);
}

fn read_principal(data: &[u8], idx: &mut usize) -> CoreResult<KerbPrincipal> {
    let name = read_string(data, idx)?;
    let realm = read_string(data, idx)?;
    Ok(KerbPrincipal { name, realm })
}

#[derive(Debug, Clone)]
pub struct CryptoBlob {
    pub iv: [u8; 16],
    pub ciphertext: Vec<u8>,
    pub mac: [u8; 32],
}

fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> CryptoBlob {
    let iv = random_iv();
    let mut buf = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new(key.into(), &iv.into());
    cipher.apply_keystream(&mut buf);
    let mac = hmac_sha256(key, &buf);
    CryptoBlob {
        iv,
        ciphertext: buf,
        mac,
    }
}

fn decrypt_blob(key: &[u8; 32], blob: &CryptoBlob) -> CoreResult<Vec<u8>> {
    let mac = hmac_sha256(key, &blob.ciphertext);
    if !constant_time_eq(&mac, &blob.mac) {
        return Err(CoreError::Parse("kerberos mac".to_string()));
    }
    let mut buf = blob.ciphertext.clone();
    let mut cipher = Aes256Ctr::new(key.into(), &blob.iv.into());
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

fn write_blob(out: &mut Vec<u8>, blob: &CryptoBlob) {
    out.extend_from_slice(&blob.iv);
    out.extend_from_slice(&(blob.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.ciphertext);
    out.extend_from_slice(&blob.mac);
}

fn read_blob(data: &[u8], idx: &mut usize) -> CoreResult<CryptoBlob> {
    let iv = read_fixed(data, idx, 16)?;
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(iv);
    let len = read_u32(data, idx)? as usize;
    let ciphertext = read_fixed(data, idx, len)?.to_vec();
    let mac = read_fixed(data, idx, 32)?;
    let mut mac_arr = [0u8; 32];
    mac_arr.copy_from_slice(mac);
    Ok(CryptoBlob {
        iv: iv_arr,
        ciphertext,
        mac: mac_arr,
    })
}

fn read_frame<T: StreamTransport>(transport: &mut T) -> CoreResult<KerbFrame> {
    let mut header = [0u8; FRAME_HEADER];
    transport.read_exact(&mut header)?;
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len > MAX_FRAME {
        return Err(CoreError::Parse("kerberos frame too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = Vec::with_capacity(FRAME_HEADER + len);
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    KerbFrame::decode(&data)
}

async fn read_frame_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<KerbFrame> {
    let mut header = [0u8; FRAME_HEADER];
    transport.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len > MAX_FRAME {
        return Err(CoreError::Parse("kerberos frame too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = Vec::with_capacity(FRAME_HEADER + len);
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    KerbFrame::decode(&data)
}

fn write_frame<T: StreamTransport>(transport: &mut T, frame: &KerbFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode())
}

async fn write_frame_async<T: AsyncStreamTransport>(
    transport: &mut T,
    frame: &KerbFrame,
) -> CoreResult<()> {
    transport.write_all(&frame.encode()).await
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn read_string(data: &[u8], idx: &mut usize) -> CoreResult<String> {
    let len = read_u16(data, idx)? as usize;
    let bytes = read_fixed(data, idx, len)?;
    Ok(String::from_utf8_lossy(bytes).to_string())
}

fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn read_bytes(data: &[u8], idx: &mut usize) -> CoreResult<Vec<u8>> {
    let len = read_u32(data, idx)? as usize;
    Ok(read_fixed(data, idx, len)?.to_vec())
}

fn read_fixed<'a>(data: &'a [u8], idx: &mut usize, len: usize) -> CoreResult<&'a [u8]> {
    if *idx + len > data.len() {
        return Err(CoreError::Parse("kerberos parse".to_string()));
    }
    let slice = &data[*idx..*idx + len];
    *idx += len;
    Ok(slice)
}

fn read_u8(data: &[u8], idx: &mut usize) -> CoreResult<u8> {
    if *idx >= data.len() {
        return Err(CoreError::Parse("kerberos u8".to_string()));
    }
    let value = data[*idx];
    *idx += 1;
    Ok(value)
}

fn read_u16(data: &[u8], idx: &mut usize) -> CoreResult<u16> {
    let bytes = read_fixed(data, idx, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], idx: &mut usize) -> CoreResult<u32> {
    let bytes = read_fixed(data, idx, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], idx: &mut usize) -> CoreResult<u64> {
    let bytes = read_fixed(data, idx, 8)?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn next_nonce() -> u64 {
    NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    let now = now_secs();
    let mut seed = now ^ NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    for byte in &mut iv {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = (seed & 0xff) as u8;
    }
    iv
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let now = now_secs();
    let mut seed = now ^ NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    for byte in &mut key {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = (seed & 0xff) as u8;
    }
    key
}

fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(password.len() + salt.len());
    input.extend_from_slice(password);
    input.extend_from_slice(salt);
    sha256::digest(&input)
}

fn key_bytes(key: &Vec<u8>) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = std::cmp::min(32, key.len());
    out[..len].copy_from_slice(&key[..len]);
    out
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256::digest(&inner);

    let mut outer = Vec::with_capacity(64 + inner_hash.len());
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256::digest(&outer)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kerberos_roundtrip() {
        let kdc = crate::skip_if_perm!(KerbKdcServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            KerbKdcConfig::default(),
        ));
        kdc.add_user("user", "password");
        kdc.add_service("http", "servicepass");
        let kdc_addr = kdc.local_addr().unwrap();
        thread::spawn(move || {
            let _ = kdc.serve();
        });

        let service = KerbServiceServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            KerbServiceConfig::new("http", "MOONLIGHT", "servicepass"),
        )
        .unwrap();
        let svc_addr = service.local_addr().unwrap();
        thread::spawn(move || {
            let _ = service.serve();
        });

        let mut client = KerbClient::connect(
            &net::NetAddr::from_socket(kdc_addr),
            KerbClientConfig::default(),
        )
        .unwrap();
        let (ticket, session) = client.request_service_ticket("http").unwrap();
        let ap_req = client.build_ap_req(ticket, session, true).unwrap();
        let mut svc_transport =
            TcpTransport::connect(&net::NetAddr::from_socket(svc_addr), Timeouts::default())
                .unwrap();
        let frame = KerbFrame::new(KerbMsgType::ApReq, ap_req.encode());
        write_frame(&mut svc_transport, &frame).unwrap();
        let response = read_frame(&mut svc_transport).unwrap();
        assert_eq!(response.msg_type, KerbMsgType::ApRep);
        let rep = KerbApRep::decode(&response.payload).unwrap();
        assert!(rep.timestamp > 0);
    }
}
