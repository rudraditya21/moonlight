use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

#[derive(Debug, Clone)]
pub struct CertificateTemplate {
    pub name: String,
    pub oid: String,
    pub eku: Vec<String>,
    pub flags: u32,
    pub validity_days: u32,
    pub renewal_days: u32,
}

#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub template: String,
    pub csr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CertificateResponse {
    pub template: String,
    pub issued_at: u64,
    pub serial: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrtdMessageType {
    ListTemplates = 1,
    GetTemplate = 2,
    Enroll = 3,
    Response = 4,
    Error = 5,
    Auth = 6,
}

#[derive(Debug, Clone)]
pub struct CrtdMessage {
    pub msg_type: CrtdMessageType,
    pub payload: Vec<u8>,
}

impl CrtdMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.msg_type as u8);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 5 {
            return Err(CoreError::Parse("ms_crtd message too short".to_string()));
        }
        let msg_type = match data[0] {
            1 => CrtdMessageType::ListTemplates,
            2 => CrtdMessageType::GetTemplate,
            3 => CrtdMessageType::Enroll,
            4 => CrtdMessageType::Response,
            5 => CrtdMessageType::Error,
            6 => CrtdMessageType::Auth,
            _ => return Err(CoreError::Parse("ms_crtd unknown type".to_string())),
        };
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < 5 + len {
            return Err(CoreError::Parse("ms_crtd payload length".to_string()));
        }
        Ok(Self {
            msg_type,
            payload: data[5..5 + len].to_vec(),
        })
    }
}

fn encode_template(template: &CertificateTemplate) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string(&mut out, &template.name);
    encode_string(&mut out, &template.oid);
    out.extend_from_slice(&template.flags.to_be_bytes());
    out.extend_from_slice(&template.validity_days.to_be_bytes());
    out.extend_from_slice(&template.renewal_days.to_be_bytes());
    out.extend_from_slice(&(template.eku.len() as u16).to_be_bytes());
    for eku in &template.eku {
        encode_string(&mut out, eku);
    }
    out
}

fn decode_template(data: &[u8], idx: &mut usize) -> CoreResult<CertificateTemplate> {
    let name = decode_string(data, idx)?;
    let oid = decode_string(data, idx)?;
    if *idx + 12 > data.len() {
        return Err(CoreError::Parse("ms_crtd template bounds".to_string()));
    }
    let flags = u32::from_be_bytes([data[*idx], data[*idx + 1], data[*idx + 2], data[*idx + 3]]);
    *idx += 4;
    let validity_days = u32::from_be_bytes([data[*idx], data[*idx + 1], data[*idx + 2], data[*idx + 3]]);
    *idx += 4;
    let renewal_days = u32::from_be_bytes([data[*idx], data[*idx + 1], data[*idx + 2], data[*idx + 3]]);
    *idx += 4;
    if *idx + 2 > data.len() {
        return Err(CoreError::Parse("ms_crtd template eku count".to_string()));
    }
    let eku_count = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
    *idx += 2;
    let mut eku = Vec::new();
    for _ in 0..eku_count {
        eku.push(decode_string(data, idx)?);
    }
    Ok(CertificateTemplate {
        name,
        oid,
        eku,
        flags,
        validity_days,
        renewal_days,
    })
}

fn encode_certificate(cert: &CertificateResponse) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string(&mut out, &cert.template);
    out.extend_from_slice(&cert.issued_at.to_be_bytes());
    out.extend_from_slice(&cert.serial.to_be_bytes());
    out.extend_from_slice(&(cert.data.len() as u32).to_be_bytes());
    out.extend_from_slice(&cert.data);
    out
}

fn decode_certificate(data: &[u8]) -> CoreResult<CertificateResponse> {
    let mut idx = 0;
    let template = decode_string(data, &mut idx)?;
    if idx + 16 > data.len() {
        return Err(CoreError::Parse("ms_crtd certificate bounds".to_string()));
    }
    let issued_at = u64::from_be_bytes(data[idx..idx + 8].try_into().unwrap());
    idx += 8;
    let serial = u64::from_be_bytes(data[idx..idx + 8].try_into().unwrap());
    idx += 8;
    if idx + 4 > data.len() {
        return Err(CoreError::Parse("ms_crtd cert data len".to_string()));
    }
    let len = u32::from_be_bytes(data[idx..idx + 4].try_into().unwrap()) as usize;
    idx += 4;
    if idx + len > data.len() {
        return Err(CoreError::Parse("ms_crtd cert data".to_string()));
    }
    Ok(CertificateResponse {
        template,
        issued_at,
        serial,
        data: data[idx..idx + len].to_vec(),
    })
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn decode_string(data: &[u8], idx: &mut usize) -> CoreResult<String> {
    if *idx + 2 > data.len() {
        return Err(CoreError::Parse("ms_crtd string len".to_string()));
    }
    let len = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
    *idx += 2;
    if *idx + len > data.len() {
        return Err(CoreError::Parse("ms_crtd string bounds".to_string()));
    }
    let value = String::from_utf8_lossy(&data[*idx..*idx + len]).to_string();
    *idx += len;
    Ok(value)
}

#[derive(Debug, Clone)]
pub struct CrtdServerConfig {
    pub timeouts: Timeouts,
    pub require_auth: bool,
    pub users: HashMap<String, String>,
}

impl Default for CrtdServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            require_auth: false,
            users: HashMap::new(),
        }
    }
}

pub struct CrtdServer {
    listener: TcpListener,
    templates: Arc<HashMap<String, CertificateTemplate>>,
    config: CrtdServerConfig,
}

impl CrtdServer {
    pub fn bind(addr: SocketAddr, templates: Vec<CertificateTemplate>, config: CrtdServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        let mut map = HashMap::new();
        for template in templates {
            map.insert(template.name.clone(), template);
        }
        Ok(Self {
            listener,
            templates: Arc::new(map),
            config,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let templates = Arc::clone(&self.templates);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_crtd_stream(stream, templates, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncCrtdServer {
    listener: tokio::net::TcpListener,
    templates: Arc<HashMap<String, CertificateTemplate>>,
    config: CrtdServerConfig,
}

impl AsyncCrtdServer {
    pub async fn bind(addr: SocketAddr, templates: Vec<CertificateTemplate>, config: CrtdServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        let mut map = HashMap::new();
        for template in templates {
            map.insert(template.name.clone(), template);
        }
        Ok(Self {
            listener,
            templates: Arc::new(map),
            config,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let templates = Arc::clone(&self.templates);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_crtd_stream_async(stream, templates, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct CrtdClientConfig {
    pub timeouts: Timeouts,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for CrtdClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: None,
            password: None,
        }
    }
}

pub struct CrtdClient {
    transport: TcpTransport,
}

impl CrtdClient {
    pub fn connect(addr: &net::NetAddr, config: CrtdClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        if let Some(user) = config.username {
            let pass = config.password.unwrap_or_default();
            send_auth(&mut transport, &user, &pass)?;
        }
        Ok(Self { transport })
    }

    pub fn list_templates(&mut self) -> CoreResult<Vec<CertificateTemplate>> {
        let msg = CrtdMessage {
            msg_type: CrtdMessageType::ListTemplates,
            payload: Vec::new(),
        };
        write_message(&mut self.transport, &msg)?;
        let resp = read_message(&mut self.transport)?;
        decode_templates(&resp.payload)
    }

    pub fn get_template(&mut self, name: &str) -> CoreResult<CertificateTemplate> {
        let mut payload = Vec::new();
        encode_string(&mut payload, name);
        let msg = CrtdMessage {
            msg_type: CrtdMessageType::GetTemplate,
            payload,
        };
        write_message(&mut self.transport, &msg)?;
        let resp = read_message(&mut self.transport)?;
        let mut idx = 0;
        decode_template(&resp.payload, &mut idx)
    }

    pub fn enroll(&mut self, request: CertificateRequest) -> CoreResult<CertificateResponse> {
        let mut payload = Vec::new();
        encode_string(&mut payload, &request.template);
        payload.extend_from_slice(&(request.csr.len() as u32).to_be_bytes());
        payload.extend_from_slice(&request.csr);
        let msg = CrtdMessage {
            msg_type: CrtdMessageType::Enroll,
            payload,
        };
        write_message(&mut self.transport, &msg)?;
        let resp = read_message(&mut self.transport)?;
        decode_certificate(&resp.payload)
    }
}

pub struct AsyncCrtdClient {
    transport: AsyncTcpTransport,
}

impl AsyncCrtdClient {
    pub async fn connect(addr: &net::NetAddr, config: CrtdClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        if let Some(user) = config.username {
            let pass = config.password.unwrap_or_default();
            send_auth_async(&mut transport, &user, &pass).await?;
        }
        Ok(Self { transport })
    }

    pub async fn enroll(&mut self, request: CertificateRequest) -> CoreResult<CertificateResponse> {
        let mut payload = Vec::new();
        encode_string(&mut payload, &request.template);
        payload.extend_from_slice(&(request.csr.len() as u32).to_be_bytes());
        payload.extend_from_slice(&request.csr);
        let msg = CrtdMessage {
            msg_type: CrtdMessageType::Enroll,
            payload,
        };
        write_message_async(&mut self.transport, &msg).await?;
        let resp = read_message_async(&mut self.transport).await?;
        decode_certificate(&resp.payload)
    }
}

fn send_auth(transport: &mut TcpTransport, user: &str, pass: &str) -> CoreResult<()> {
    let mut payload = Vec::new();
    encode_string(&mut payload, user);
    encode_string(&mut payload, pass);
    let msg = CrtdMessage {
        msg_type: CrtdMessageType::Auth,
        payload,
    };
    write_message(transport, &msg)?;
    let _ = read_message(transport)?;
    Ok(())
}

async fn send_auth_async(transport: &mut AsyncTcpTransport, user: &str, pass: &str) -> CoreResult<()> {
    let mut payload = Vec::new();
    encode_string(&mut payload, user);
    encode_string(&mut payload, pass);
    let msg = CrtdMessage {
        msg_type: CrtdMessageType::Auth,
        payload,
    };
    write_message_async(transport, &msg).await?;
    let _ = read_message_async(transport).await?;
    Ok(())
}

fn handle_crtd_stream(
    stream: TcpStream,
    templates: Arc<HashMap<String, CertificateTemplate>>,
    config: CrtdServerConfig,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    if config.require_auth {
        let auth = read_message(&mut transport)?;
        if auth.msg_type != CrtdMessageType::Auth || !validate_auth(&auth.payload, &config.users)? {
            let err = CrtdMessage {
                msg_type: CrtdMessageType::Error,
                payload: b"auth failed".to_vec(),
            };
            write_message(&mut transport, &err)?;
            return Ok(());
        }
        let ok = CrtdMessage {
            msg_type: CrtdMessageType::Response,
            payload: b"ok".to_vec(),
        };
        write_message(&mut transport, &ok)?;
    }
    loop {
        let msg = read_message(&mut transport)?;
        let response = handle_crtd_message(msg, &templates, &config)?;
        write_message(&mut transport, &response)?;
    }
}

async fn handle_crtd_stream_async(
    stream: tokio::net::TcpStream,
    templates: Arc<HashMap<String, CertificateTemplate>>,
    config: CrtdServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    if config.require_auth {
        let auth = read_message_async(&mut transport).await?;
        if auth.msg_type != CrtdMessageType::Auth || !validate_auth(&auth.payload, &config.users)? {
            let err = CrtdMessage {
                msg_type: CrtdMessageType::Error,
                payload: b"auth failed".to_vec(),
            };
            write_message_async(&mut transport, &err).await?;
            return Ok(());
        }
        let ok = CrtdMessage {
            msg_type: CrtdMessageType::Response,
            payload: b"ok".to_vec(),
        };
        write_message_async(&mut transport, &ok).await?;
    }
    loop {
        let msg = read_message_async(&mut transport).await?;
        let response = handle_crtd_message(msg, &templates, &config)?;
        write_message_async(&mut transport, &response).await?;
    }
}

fn handle_crtd_message(
    msg: CrtdMessage,
    templates: &HashMap<String, CertificateTemplate>,
    _config: &CrtdServerConfig,
) -> CoreResult<CrtdMessage> {
    match msg.msg_type {
        CrtdMessageType::ListTemplates => {
            let payload = encode_templates(templates.values());
            Ok(CrtdMessage {
                msg_type: CrtdMessageType::Response,
                payload,
            })
        }
        CrtdMessageType::GetTemplate => {
            let mut idx = 0;
            let name = decode_string(&msg.payload, &mut idx)?;
            let template = templates.get(&name).ok_or_else(|| CoreError::Message("template not found".to_string()))?;
            Ok(CrtdMessage {
                msg_type: CrtdMessageType::Response,
                payload: encode_template(template),
            })
        }
        CrtdMessageType::Enroll => {
            let mut idx = 0;
            let template_name = decode_string(&msg.payload, &mut idx)?;
            if idx + 4 > msg.payload.len() {
                return Err(CoreError::Parse("ms_crtd csr len".to_string()));
            }
            let csr_len = u32::from_be_bytes(msg.payload[idx..idx + 4].try_into().unwrap()) as usize;
            idx += 4;
            if idx + csr_len > msg.payload.len() {
                return Err(CoreError::Parse("ms_crtd csr bounds".to_string()));
            }
            let csr = msg.payload[idx..idx + csr_len].to_vec();
            if csr.is_empty() {
                return Err(CoreError::Message("empty csr".to_string()));
            }
            let template = templates.get(&template_name).ok_or_else(|| CoreError::Message("template not found".to_string()))?;
            let cert = issue_certificate(template, &csr);
            Ok(CrtdMessage {
                msg_type: CrtdMessageType::Response,
                payload: encode_certificate(&cert),
            })
        }
        CrtdMessageType::Auth => Ok(CrtdMessage {
            msg_type: CrtdMessageType::Error,
            payload: b"unexpected auth".to_vec(),
        }),
        CrtdMessageType::Response | CrtdMessageType::Error => Ok(msg),
    }
}

fn encode_templates<'a>(templates: impl Iterator<Item = &'a CertificateTemplate>) -> Vec<u8> {
    let mut out = Vec::new();
    let collected: Vec<&CertificateTemplate> = templates.collect();
    out.extend_from_slice(&(collected.len() as u16).to_be_bytes());
    for template in collected {
        out.extend_from_slice(&encode_template(template));
    }
    out
}

fn decode_templates(data: &[u8]) -> CoreResult<Vec<CertificateTemplate>> {
    if data.len() < 2 {
        return Err(CoreError::Parse("ms_crtd templates len".to_string()));
    }
    let count = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut idx = 2;
    let mut templates = Vec::new();
    for _ in 0..count {
        templates.push(decode_template(data, &mut idx)?);
    }
    Ok(templates)
}

fn issue_certificate(template: &CertificateTemplate, csr: &[u8]) -> CertificateResponse {
    let issued_at = current_timestamp();
    let serial = issued_at ^ (template.flags as u64);
    let mut sha = sha256::Sha256::new();
    sha.update(template.name.as_bytes());
    sha.update(csr);
    sha.update(&issued_at.to_be_bytes());
    let digest = sha.finalize();
    let mut data = Vec::new();
    data.extend_from_slice(b"MLCERT");
    data.extend_from_slice(&digest);
    CertificateResponse {
        template: template.name.clone(),
        issued_at,
        serial,
        data,
    }
}

fn validate_auth(payload: &[u8], users: &HashMap<String, String>) -> CoreResult<bool> {
    let mut idx = 0;
    let user = decode_string(payload, &mut idx)?;
    let pass = decode_string(payload, &mut idx)?;
    Ok(users.get(&user).map(|p| p == &pass).unwrap_or(false))
}

fn read_message<T: StreamTransport>(transport: &mut T) -> CoreResult<CrtdMessage> {
    let mut header = [0u8; 5];
    transport.read_exact(&mut header)?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    CrtdMessage::decode(&data)
}

async fn read_message_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<CrtdMessage> {
    let mut header = [0u8; 5];
    transport.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    CrtdMessage::decode(&data)
}

fn write_message<T: StreamTransport>(transport: &mut T, msg: &CrtdMessage) -> CoreResult<()> {
    transport.write_all(&msg.encode())
}

async fn write_message_async<T: AsyncStreamTransport>(transport: &mut T, msg: &CrtdMessage) -> CoreResult<()> {
    transport.write_all(&msg.encode()).await
}

fn current_timestamp() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    now.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crtd_enroll_flow() {
        let template = CertificateTemplate {
            name: "User".to_string(),
            oid: "1.2.3.4".to_string(),
            eku: vec!["1.3.6.1.5.5.7.3.2".to_string()],
            flags: 0,
            validity_days: 365,
            renewal_days: 30,
        };
        let server = crate::skip_if_perm!(CrtdServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            vec![template.clone()],
            CrtdServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = CrtdClient::connect(&net::NetAddr::from_socket(addr), CrtdClientConfig::default()).unwrap();
        let templates = client.list_templates().unwrap();
        assert_eq!(templates.len(), 1);

        let cert = client
            .enroll(CertificateRequest {
                template: "User".to_string(),
                csr: b"dummy".to_vec(),
            })
            .unwrap();
        assert_eq!(cert.template, "User");

        drop(handle);
    }
}
