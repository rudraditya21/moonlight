use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};
use md5::digest_hex;

use crate::transport::{
    AsyncStreamTransport, AsyncTcpTransport, AsyncUdpTransport, StreamTransport, TcpTransport,
    UdpTransport,
};
use crate::util::Timeouts;

pub const SIP_DEFAULT_PORT: u16 = 5060;
const MAX_MESSAGE: usize = 64 * 1024;
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipMethod {
    Options,
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Message,
}

impl SipMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            SipMethod::Options => "OPTIONS",
            SipMethod::Register => "REGISTER",
            SipMethod::Invite => "INVITE",
            SipMethod::Ack => "ACK",
            SipMethod::Bye => "BYE",
            SipMethod::Cancel => "CANCEL",
            SipMethod::Message => "MESSAGE",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "OPTIONS" => Some(SipMethod::Options),
            "REGISTER" => Some(SipMethod::Register),
            "INVITE" => Some(SipMethod::Invite),
            "ACK" => Some(SipMethod::Ack),
            "BYE" => Some(SipMethod::Bye),
            "CANCEL" => Some(SipMethod::Cancel),
            "MESSAGE" => Some(SipMethod::Message),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SipHeaders {
    items: Vec<(String, String)>,
}

impl SipHeaders {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.items.iter().find_map(|(k, v)| {
            if k.eq_ignore_ascii_case(name) {
                Some(v.as_str())
            } else {
                None
            }
        })
    }

    pub fn set(&mut self, name: &str, value: String) {
        for (k, v) in &mut self.items {
            if k.eq_ignore_ascii_case(name) {
                *v = value;
                return;
            }
        }
        self.items.push((name.to_string(), value));
    }

    pub fn push(&mut self, name: &str, value: String) {
        self.items.push((name.to_string(), value));
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, String)> {
        self.items.iter()
    }
}

impl Default for SipHeaders {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SipRequest {
    pub method: SipMethod,
    pub uri: String,
    pub version: String,
    pub headers: SipHeaders,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SipResponse {
    pub version: String,
    pub code: u16,
    pub reason: String,
    pub headers: SipHeaders,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum SipMessage {
    Request(SipRequest),
    Response(SipResponse),
}

impl SipRequest {
    pub fn new(method: SipMethod, uri: &str) -> Self {
        Self {
            method,
            uri: uri.to_string(),
            version: "SIP/2.0".to_string(),
            headers: SipHeaders::new(),
            body: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(
            format!("{} {} {}\r\n", self.method.as_str(), self.uri, self.version).as_bytes(),
        );
        for (k, v) in self.headers.iter() {
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

impl SipResponse {
    pub fn new(code: u16, reason: &str) -> Self {
        Self {
            version: "SIP/2.0".to_string(),
            code,
            reason: reason.to_string(),
            headers: SipHeaders::new(),
            body: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(
            format!("{} {} {}\r\n", self.version, self.code, self.reason).as_bytes(),
        );
        for (k, v) in self.headers.iter() {
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct SipServerConfig {
    pub timeouts: Timeouts,
    pub realm: String,
    pub users: HashMap<String, String>,
    pub allow_unauthenticated: bool,
    pub server_name: String,
}

impl Default for SipServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            realm: "moonlight".to_string(),
            users: HashMap::new(),
            allow_unauthenticated: true,
            server_name: "Moonlight SIP".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SipClientConfig {
    pub timeouts: Timeouts,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,
    pub user_agent: String,
}

impl Default for SipClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: None,
            password: None,
            realm: None,
            user_agent: "Moonlight SIP Client".to_string(),
        }
    }
}

pub struct SipUdpServer {
    socket: UdpTransport,
    config: SipServerConfig,
}

impl SipUdpServer {
    pub fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(MAX_MESSAGE)?;
            let message = match parse_message(&data) {
                Ok(msg) => msg,
                Err(_) => continue,
            };
            if let SipMessage::Request(request) = message {
                let response = handle_request(&self.config, &request, Some(peer));
                let bytes = response.to_bytes()?;
                let _ = self.socket.send_to(&bytes, peer);
            }
        }
    }
}

pub struct SipTcpServer {
    listener: TcpListener,
    config: SipServerConfig,
}

impl SipTcpServer {
    pub fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self> {
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
                let _ = handle_tcp_session(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncSipUdpServer {
    socket: AsyncUdpTransport,
    config: SipServerConfig,
}

impl AsyncSipUdpServer {
    pub async fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self { socket, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(MAX_MESSAGE).await?;
            let message = match parse_message(&data) {
                Ok(msg) => msg,
                Err(_) => continue,
            };
            if let SipMessage::Request(request) = message {
                let response = handle_request(&self.config, &request, Some(peer));
                let bytes = response.to_bytes()?;
                let _ = self.socket.send_to(&bytes, peer).await;
            }
        }
    }
}

pub struct AsyncSipTcpServer {
    listener: tokio::net::TcpListener,
    config: SipServerConfig,
}

impl AsyncSipTcpServer {
    pub async fn bind(addr: SocketAddr, config: SipServerConfig) -> CoreResult<Self> {
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
                let _ = handle_tcp_session_async(stream, config).await;
            });
        }
    }
}

pub struct SipUdpClient {
    socket: UdpTransport,
    server: SocketAddr,
    config: SipClientConfig,
}

impl SipUdpClient {
    pub fn new(server: SocketAddr, config: SipClientConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            server,
            config,
        })
    }

    pub fn options(&self, uri: &str) -> CoreResult<SipResponse> {
        let request = build_request(&self.config, SipMethod::Options, uri);
        self.send_request(request)
    }

    pub fn register(&self, uri: &str) -> CoreResult<SipResponse> {
        let request = build_request(&self.config, SipMethod::Register, uri);
        self.send_request(request)
    }

    fn send_request(&self, mut request: SipRequest) -> CoreResult<SipResponse> {
        request
            .headers
            .set("Content-Length", request.body.len().to_string());
        let bytes = request.to_bytes()?;
        self.socket.send_to(&bytes, self.server)?;
        let (resp, _) = self.socket.recv_from(MAX_MESSAGE)?;
        let message = parse_message(&resp)?;
        let response = match message {
            SipMessage::Response(resp) => resp,
            _ => return Err(CoreError::Parse("sip response".to_string())),
        };
        if response.code == 401 {
            if let Some(auth) = self.build_authorization(&response, &request) {
                request.headers.set("Authorization", auth);
                let bytes = request.to_bytes()?;
                self.socket.send_to(&bytes, self.server)?;
                let (resp, _) = self.socket.recv_from(MAX_MESSAGE)?;
                return match parse_message(&resp)? {
                    SipMessage::Response(resp) => Ok(resp),
                    _ => Err(CoreError::Parse("sip response".to_string())),
                };
            }
        }
        Ok(response)
    }

    fn build_authorization(&self, response: &SipResponse, request: &SipRequest) -> Option<String> {
        let username = self.config.username.as_ref()?;
        let password = self.config.password.as_ref()?;
        let challenge = response.headers.get("www-authenticate")?;
        build_digest_authorization(
            username,
            password,
            request.method.as_str(),
            &request.uri,
            challenge,
        )
    }
}

pub struct SipTcpClient {
    transport: TcpTransport,
    config: SipClientConfig,
}

impl SipTcpClient {
    pub fn connect(addr: &net::NetAddr, config: SipClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self { transport, config })
    }

    pub fn options(&mut self, uri: &str) -> CoreResult<SipResponse> {
        let request = build_request(&self.config, SipMethod::Options, uri);
        self.send_request(request)
    }

    fn send_request(&mut self, mut request: SipRequest) -> CoreResult<SipResponse> {
        request
            .headers
            .set("Content-Length", request.body.len().to_string());
        let bytes = request.to_bytes()?;
        self.transport.write_all(&bytes)?;
        let message = read_message_stream(&mut self.transport)?;
        let response = match message {
            SipMessage::Response(resp) => resp,
            _ => return Err(CoreError::Parse("sip response".to_string())),
        };
        if response.code == 401 {
            if let Some(auth) = self.build_authorization(&response, &request) {
                request.headers.set("Authorization", auth);
                let bytes = request.to_bytes()?;
                self.transport.write_all(&bytes)?;
                let message = read_message_stream(&mut self.transport)?;
                return match message {
                    SipMessage::Response(resp) => Ok(resp),
                    _ => Err(CoreError::Parse("sip response".to_string())),
                };
            }
        }
        Ok(response)
    }

    fn build_authorization(&self, response: &SipResponse, request: &SipRequest) -> Option<String> {
        let username = self.config.username.as_ref()?;
        let password = self.config.password.as_ref()?;
        let challenge = response.headers.get("www-authenticate")?;
        build_digest_authorization(
            username,
            password,
            request.method.as_str(),
            &request.uri,
            challenge,
        )
    }
}

pub struct AsyncSipUdpClient {
    socket: AsyncUdpTransport,
    server: SocketAddr,
    config: SipClientConfig,
}

impl AsyncSipUdpClient {
    pub async fn new(server: SocketAddr, config: SipClientConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self {
            socket,
            server,
            config,
        })
    }

    pub async fn options(&self, uri: &str) -> CoreResult<SipResponse> {
        let request = build_request(&self.config, SipMethod::Options, uri);
        self.send_request(request).await
    }

    async fn send_request(&self, mut request: SipRequest) -> CoreResult<SipResponse> {
        request
            .headers
            .set("Content-Length", request.body.len().to_string());
        let bytes = request.to_bytes()?;
        self.socket.send_to(&bytes, self.server).await?;
        let (resp, _) = self.socket.recv_from(MAX_MESSAGE).await?;
        let message = parse_message(&resp)?;
        let response = match message {
            SipMessage::Response(resp) => resp,
            _ => return Err(CoreError::Parse("sip response".to_string())),
        };
        if response.code == 401 {
            if let Some(auth) = self.build_authorization(&response, &request) {
                request.headers.set("Authorization", auth);
                let bytes = request.to_bytes()?;
                self.socket.send_to(&bytes, self.server).await?;
                let (resp, _) = self.socket.recv_from(MAX_MESSAGE).await?;
                return match parse_message(&resp)? {
                    SipMessage::Response(resp) => Ok(resp),
                    _ => Err(CoreError::Parse("sip response".to_string())),
                };
            }
        }
        Ok(response)
    }

    fn build_authorization(&self, response: &SipResponse, request: &SipRequest) -> Option<String> {
        let username = self.config.username.as_ref()?;
        let password = self.config.password.as_ref()?;
        let challenge = response.headers.get("www-authenticate")?;
        build_digest_authorization(
            username,
            password,
            request.method.as_str(),
            &request.uri,
            challenge,
        )
    }
}

pub struct AsyncSipTcpClient {
    transport: AsyncTcpTransport,
    config: SipClientConfig,
}

impl AsyncSipTcpClient {
    pub async fn connect(addr: &net::NetAddr, config: SipClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self { transport, config })
    }

    pub async fn options(&mut self, uri: &str) -> CoreResult<SipResponse> {
        let request = build_request(&self.config, SipMethod::Options, uri);
        self.send_request(request).await
    }

    async fn send_request(&mut self, mut request: SipRequest) -> CoreResult<SipResponse> {
        request
            .headers
            .set("Content-Length", request.body.len().to_string());
        let bytes = request.to_bytes()?;
        self.transport.write_all(&bytes).await?;
        let message = read_message_stream_async(&mut self.transport).await?;
        let response = match message {
            SipMessage::Response(resp) => resp,
            _ => return Err(CoreError::Parse("sip response".to_string())),
        };
        if response.code == 401 {
            if let Some(auth) = self.build_authorization(&response, &request) {
                request.headers.set("Authorization", auth);
                let bytes = request.to_bytes()?;
                self.transport.write_all(&bytes).await?;
                let message = read_message_stream_async(&mut self.transport).await?;
                return match message {
                    SipMessage::Response(resp) => Ok(resp),
                    _ => Err(CoreError::Parse("sip response".to_string())),
                };
            }
        }
        Ok(response)
    }

    fn build_authorization(&self, response: &SipResponse, request: &SipRequest) -> Option<String> {
        let username = self.config.username.as_ref()?;
        let password = self.config.password.as_ref()?;
        let challenge = response.headers.get("www-authenticate")?;
        build_digest_authorization(
            username,
            password,
            request.method.as_str(),
            &request.uri,
            challenge,
        )
    }
}

fn handle_tcp_session(stream: TcpStream, config: SipServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let message = match read_message_stream(&mut transport) {
            Ok(msg) => msg,
            Err(_) => break,
        };
        if let SipMessage::Request(request) = message {
            let response = handle_request(&config, &request, None);
            let bytes = response.to_bytes()?;
            transport.write_all(&bytes)?;
        }
    }
    Ok(())
}

async fn handle_tcp_session_async(
    stream: tokio::net::TcpStream,
    config: SipServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let message = match read_message_stream_async(&mut transport).await {
            Ok(msg) => msg,
            Err(_) => break,
        };
        if let SipMessage::Request(request) = message {
            let response = handle_request(&config, &request, None);
            let bytes = response.to_bytes()?;
            transport.write_all(&bytes).await?;
        }
    }
    Ok(())
}

fn handle_request(
    config: &SipServerConfig,
    request: &SipRequest,
    source: Option<SocketAddr>,
) -> SipResponse {
    if !config.allow_unauthenticated && !config.users.is_empty() {
        if let Some(auth) = request.headers.get("authorization") {
            if !verify_authorization(auth, request, config) {
                return build_challenge_response(config, request);
            }
        } else {
            return build_challenge_response(config, request);
        }
    }

    let mut response = match request.method {
        SipMethod::Options => SipResponse::new(200, "OK"),
        SipMethod::Register => SipResponse::new(200, "OK"),
        SipMethod::Invite => SipResponse::new(200, "OK"),
        SipMethod::Ack => SipResponse::new(200, "OK"),
        SipMethod::Bye => SipResponse::new(200, "OK"),
        SipMethod::Cancel => SipResponse::new(200, "OK"),
        SipMethod::Message => SipResponse::new(202, "Accepted"),
    };
    copy_core_headers(request, &mut response, source, config);
    response
}

fn build_request(config: &SipClientConfig, method: SipMethod, uri: &str) -> SipRequest {
    let mut request = SipRequest::new(method, uri);
    request.headers.set("User-Agent", config.user_agent.clone());
    request.headers.set(
        "Via",
        format!("SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK{}", generate_branch()),
    );
    request.headers.set(
        "From",
        format!("<sip:client@moonlight>;tag={}", generate_tag()),
    );
    request.headers.set("To", format!("<{}>", uri));
    request.headers.set("Call-ID", generate_call_id());
    request
        .headers
        .set("CSeq", format!("1 {}", method.as_str()));
    request
}

fn copy_core_headers(
    request: &SipRequest,
    response: &mut SipResponse,
    source: Option<SocketAddr>,
    config: &SipServerConfig,
) {
    if let Some(via) = request.headers.get("via") {
        response.headers.set("Via", via.to_string());
    }
    if let Some(from) = request.headers.get("from") {
        response.headers.set("From", from.to_string());
    }
    if let Some(to) = request.headers.get("to") {
        let mut value = to.to_string();
        if !value.contains("tag=") {
            value.push_str(&format!(";tag={}", generate_tag()));
        }
        response.headers.set("To", value);
    }
    if let Some(call_id) = request.headers.get("call-id") {
        response.headers.set("Call-ID", call_id.to_string());
    }
    if let Some(cseq) = request.headers.get("cseq") {
        response.headers.set("CSeq", cseq.to_string());
    }
    if let Some(addr) = source {
        response.headers.set("Received", addr.ip().to_string());
    }
    response.headers.set("Server", config.server_name.clone());
    response
        .headers
        .set("Content-Length", response.body.len().to_string());
}

fn build_challenge_response(config: &SipServerConfig, request: &SipRequest) -> SipResponse {
    let mut response = SipResponse::new(401, "Unauthorized");
    let nonce = generate_nonce();
    let www = format!(
        "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"",
        config.realm, nonce
    );
    response.headers.set("WWW-Authenticate", www);
    copy_core_headers(request, &mut response, None, config);
    response
}

fn verify_authorization(auth: &str, request: &SipRequest, config: &SipServerConfig) -> bool {
    let parsed = parse_digest(auth);
    let username = match parsed.get("username") {
        Some(value) => value,
        None => return false,
    };
    let realm = parsed
        .get("realm")
        .map(|s| s.as_str())
        .unwrap_or(&config.realm);
    let nonce = match parsed.get("nonce") {
        Some(value) => value,
        None => return false,
    };
    let uri = match parsed.get("uri") {
        Some(value) => value,
        None => return false,
    };
    let response = match parsed.get("response") {
        Some(value) => value,
        None => return false,
    };
    let password = match config.users.get(username) {
        Some(value) => value,
        None => return false,
    };
    let qop = parsed.get("qop").map(|s| s.as_str());
    let nc = parsed.get("nc").map(|s| s.as_str());
    let cnonce = parsed.get("cnonce").map(|s| s.as_str());
    let expected = compute_digest_response(
        username,
        realm,
        password,
        nonce,
        request.method.as_str(),
        uri,
        qop,
        nc,
        cnonce,
    );
    response.eq_ignore_ascii_case(&expected)
}

fn build_digest_authorization(
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    challenge: &str,
) -> Option<String> {
    let parsed = parse_digest(challenge);
    let realm = parsed.get("realm")?;
    let nonce = parsed.get("nonce")?;
    let qop = parsed.get("qop").map(|s| s.as_str());
    let nc = if qop.is_some() {
        Some("00000001")
    } else {
        None
    };
    let cnonce = if qop.is_some() {
        Some("abcdef123456")
    } else {
        None
    };
    let response = compute_digest_response(
        username, realm, password, nonce, method, uri, qop, nc, cnonce,
    );
    let mut auth = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
        username, realm, nonce, uri, response
    );
    if let Some(qop) = qop {
        let nc = nc.unwrap_or("00000001");
        let cnonce = cnonce.unwrap_or("abcdef123456");
        auth.push_str(&format!(", qop={}, nc={}, cnonce=\"{}\"", qop, nc, cnonce));
    }
    Some(auth)
}

fn compute_digest_response(
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    qop: Option<&str>,
    nc: Option<&str>,
    cnonce: Option<&str>,
) -> String {
    let ha1 = digest_hex(format!("{}:{}:{}", username, realm, password).as_bytes());
    let ha2 = digest_hex(format!("{}:{}", method, uri).as_bytes());
    if let Some(qop) = qop {
        let nc = nc.unwrap_or("00000001");
        let cnonce = cnonce.unwrap_or("");
        digest_hex(format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2).as_bytes())
    } else {
        digest_hex(format!("{}:{}:{}", ha1, nonce, ha2).as_bytes())
    }
}

fn parse_digest(header: &str) -> HashMap<String, String> {
    let header = header.trim();
    let header = header.strip_prefix("Digest").unwrap_or(header).trim();
    let mut map = HashMap::new();
    for part in header.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim().trim_matches('"');
            map.insert(key.trim().to_string(), value.to_string());
        }
    }
    map
}

fn parse_message(data: &[u8]) -> CoreResult<SipMessage> {
    if data.len() > MAX_MESSAGE {
        return Err(CoreError::Parse("sip message too large".to_string()));
    }
    let text = String::from_utf8_lossy(data);
    let mut parts = text.split("\r\n\r\n");
    let header_block = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").as_bytes().to_vec();
    let mut lines = header_block.lines();
    let start = lines.next().unwrap_or("");
    let mut headers = SipHeaders::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.push(key.trim(), value.trim().to_string());
        }
    }
    if start.to_ascii_uppercase().starts_with("SIP/") {
        let mut parts = start.splitn(3, ' ');
        let version = parts.next().unwrap_or("SIP/2.0").to_string();
        let code = parts.next().unwrap_or("500").parse::<u16>().unwrap_or(500);
        let reason = parts.next().unwrap_or("").to_string();
        Ok(SipMessage::Response(SipResponse {
            version,
            code,
            reason,
            headers,
            body,
        }))
    } else {
        let mut parts = start.splitn(3, ' ');
        let method = parts.next().unwrap_or("OPTIONS");
        let uri = parts.next().unwrap_or("").to_string();
        let version = parts.next().unwrap_or("SIP/2.0").to_string();
        let method =
            SipMethod::parse(method).ok_or_else(|| CoreError::Parse("sip method".to_string()))?;
        Ok(SipMessage::Request(SipRequest {
            method,
            uri,
            version,
            headers,
            body,
        }))
    }
}

fn read_message_stream<T: StreamTransport>(transport: &mut T) -> CoreResult<SipMessage> {
    let mut buffer = Vec::new();
    loop {
        if let Some(pos) = find_double_crlf(&buffer) {
            let header = buffer[..pos + 4].to_vec();
            let header_text = String::from_utf8_lossy(&header);
            let length = parse_content_length(&header_text);
            let total = pos + 4 + length;
            while buffer.len() < total {
                let mut temp = [0u8; 1024];
                let read = transport.read(&mut temp)?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&temp[..read]);
            }
            return parse_message(&buffer[..total]);
        }
        let mut temp = [0u8; 1024];
        let read = transport.read(&mut temp)?;
        if read == 0 {
            return Err(CoreError::Parse("sip eof".to_string()));
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_MESSAGE {
            return Err(CoreError::Parse("sip too large".to_string()));
        }
    }
}

async fn read_message_stream_async<T: AsyncStreamTransport>(
    transport: &mut T,
) -> CoreResult<SipMessage> {
    let mut buffer = Vec::new();
    loop {
        if let Some(pos) = find_double_crlf(&buffer) {
            let header = buffer[..pos + 4].to_vec();
            let header_text = String::from_utf8_lossy(&header);
            let length = parse_content_length(&header_text);
            let total = pos + 4 + length;
            while buffer.len() < total {
                let mut temp = [0u8; 1024];
                let read = transport.read(&mut temp).await?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&temp[..read]);
            }
            return parse_message(&buffer[..total]);
        }
        let mut temp = [0u8; 1024];
        let read = transport.read(&mut temp).await?;
        if read == 0 {
            return Err(CoreError::Parse("sip eof".to_string()));
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_MESSAGE {
            return Err(CoreError::Parse("sip too large".to_string()));
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_content_length(header: &str) -> usize {
    for line in header.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                if let Ok(parsed) = value.trim().parse::<usize>() {
                    return parsed;
                }
            }
        }
    }
    0
}

fn generate_nonce() -> String {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    format!("{}{}", counter, now)
}

fn generate_tag() -> String {
    format!("ml{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn generate_branch() -> String {
    format!("ml{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn generate_call_id() -> String {
    format!(
        "{}@moonlight",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_options_udp() {
        let server = crate::skip_if_perm!(SipUdpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            SipServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let client = SipUdpClient::new(addr, SipClientConfig::default()).unwrap();
        let response = client.options("sip:127.0.0.1").unwrap();
        assert_eq!(response.code, 200);
    }

    #[test]
    fn sip_register_digest() {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "secret".to_string());
        let server = crate::skip_if_perm!(SipUdpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            SipServerConfig {
                allow_unauthenticated: false,
                users,
                ..SipServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let client = SipUdpClient::new(
            addr,
            SipClientConfig {
                username: Some("alice".to_string()),
                password: Some("secret".to_string()),
                ..SipClientConfig::default()
            },
        )
        .unwrap();
        let response = client.register("sip:127.0.0.1").unwrap();
        assert_eq!(response.code, 200);
    }
}
