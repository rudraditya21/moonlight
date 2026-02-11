use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const MAX_PAYLOAD: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecAuthzMessageType {
    Hello = 0x01,
    Authorize = 0x02,
    Decision = 0x03,
    Error = 0x04,
    Ping = 0x05,
    Pong = 0x06,
}

impl SecAuthzMessageType {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            0x01 => Ok(SecAuthzMessageType::Hello),
            0x02 => Ok(SecAuthzMessageType::Authorize),
            0x03 => Ok(SecAuthzMessageType::Decision),
            0x04 => Ok(SecAuthzMessageType::Error),
            0x05 => Ok(SecAuthzMessageType::Ping),
            0x06 => Ok(SecAuthzMessageType::Pong),
            _ => Err(CoreError::Parse("secauthz type".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecAuthzFrame {
    pub version: u8,
    pub msg_type: SecAuthzMessageType,
    pub payload: Vec<u8>,
}

impl SecAuthzFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.payload.len());
        out.push(self.version);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 6 {
            return Err(CoreError::Parse("secauthz frame".to_string()));
        }
        let version = data[0];
        let msg_type = SecAuthzMessageType::from_u8(data[1])?;
        let len = u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as usize;
        if len > MAX_PAYLOAD || data.len() < 6 + len {
            return Err(CoreError::Parse("secauthz length".to_string()));
        }
        Ok(Self {
            version,
            msg_type,
            payload: data[6..6 + len].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecAuthzDecision {
    Permit,
    Deny,
}

impl SecAuthzDecision {
    fn as_str(&self) -> &'static str {
        match self {
            SecAuthzDecision::Permit => "permit",
            SecAuthzDecision::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecAuthzPolicy {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub decision: SecAuthzDecision,
}

#[derive(Debug, Clone)]
pub struct SecAuthzServerConfig {
    pub timeouts: Timeouts,
    pub policies: Vec<SecAuthzPolicy>,
    pub tokens: HashMap<String, String>,
}

impl Default for SecAuthzServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            policies: Vec::new(),
            tokens: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecAuthzClientConfig {
    pub timeouts: Timeouts,
}

impl Default for SecAuthzClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub trait SecAuthzHandler: Send + Sync {
    fn decide(&self, subject: &str, action: &str, resource: &str) -> SecAuthzDecision;
}

#[derive(Default)]
pub struct PolicyHandler {
    policies: Vec<SecAuthzPolicy>,
}

impl PolicyHandler {
    pub fn new(policies: Vec<SecAuthzPolicy>) -> Self {
        Self { policies }
    }
}

impl SecAuthzHandler for PolicyHandler {
    fn decide(&self, subject: &str, action: &str, resource: &str) -> SecAuthzDecision {
        for policy in &self.policies {
            if policy.subject == subject && policy.action == action && policy.resource == resource {
                return policy.decision.clone();
            }
        }
        SecAuthzDecision::Deny
    }
}

pub struct SecAuthzServer {
    listener: TcpListener,
    config: SecAuthzServerConfig,
    handler: Arc<dyn SecAuthzHandler>,
}

impl SecAuthzServer {
    pub fn bind(addr: SocketAddr, config: SecAuthzServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        let handler = Arc::new(PolicyHandler::new(config.policies.clone()));
        Ok(Self {
            listener,
            config,
            handler,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_secauthz_stream(stream, config, handler);
            });
        }
        Ok(())
    }
}

pub struct AsyncSecAuthzServer {
    listener: tokio::net::TcpListener,
    config: SecAuthzServerConfig,
    handler: Arc<dyn SecAuthzHandler>,
}

impl AsyncSecAuthzServer {
    pub async fn bind(addr: SocketAddr, config: SecAuthzServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        let handler = Arc::new(PolicyHandler::new(config.policies.clone()));
        Ok(Self {
            listener,
            config,
            handler,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_secauthz_stream_async(stream, config, handler).await;
            });
        }
    }
}

pub struct SecAuthzClient {
    transport: TcpTransport,
}

impl SecAuthzClient {
    pub fn connect(addr: &net::NetAddr, config: SecAuthzClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let hello = SecAuthzFrame {
            version: 1,
            msg_type: SecAuthzMessageType::Hello,
            payload: b"client".to_vec(),
        };
        write_frame(&mut transport, &hello)?;
        Ok(Self { transport })
    }

    pub fn authorize(
        &mut self,
        subject: &str,
        action: &str,
        resource: &str,
        token: Option<&str>,
    ) -> CoreResult<SecAuthzDecision> {
        let payload = build_authorize_payload(subject, action, resource, token);
        let frame = SecAuthzFrame {
            version: 1,
            msg_type: SecAuthzMessageType::Authorize,
            payload,
        };
        write_frame(&mut self.transport, &frame)?;
        let response = read_frame(&mut self.transport)?;
        parse_decision(&response)
    }
}

pub struct AsyncSecAuthzClient {
    transport: AsyncTcpTransport,
}

impl AsyncSecAuthzClient {
    pub async fn connect(addr: &net::NetAddr, config: SecAuthzClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let hello = SecAuthzFrame {
            version: 1,
            msg_type: SecAuthzMessageType::Hello,
            payload: b"client".to_vec(),
        };
        write_frame_async(&mut transport, &hello).await?;
        Ok(Self { transport })
    }

    pub async fn authorize(
        &mut self,
        subject: &str,
        action: &str,
        resource: &str,
        token: Option<&str>,
    ) -> CoreResult<SecAuthzDecision> {
        let payload = build_authorize_payload(subject, action, resource, token);
        let frame = SecAuthzFrame {
            version: 1,
            msg_type: SecAuthzMessageType::Authorize,
            payload,
        };
        write_frame_async(&mut self.transport, &frame).await?;
        let response = read_frame_async(&mut self.transport).await?;
        parse_decision(&response)
    }
}

fn handle_secauthz_stream(
    stream: TcpStream,
    config: SecAuthzServerConfig,
    handler: Arc<dyn SecAuthzHandler>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let _ = read_frame(&mut transport)?;
    loop {
        let frame = match read_frame(&mut transport) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame.msg_type {
            SecAuthzMessageType::Authorize => {
                let request = parse_authorize_payload(&frame.payload);
                let subject =
                    resolve_subject(&config.tokens, &request.subject, request.token.as_deref());
                let decision = handler.decide(&subject, &request.action, &request.resource);
                let response = build_decision_frame(decision, "ok");
                write_frame(&mut transport, &response)?;
            }
            SecAuthzMessageType::Ping => {
                let pong = SecAuthzFrame {
                    version: 1,
                    msg_type: SecAuthzMessageType::Pong,
                    payload: Vec::new(),
                };
                write_frame(&mut transport, &pong)?;
            }
            _ => {
                let err = SecAuthzFrame {
                    version: 1,
                    msg_type: SecAuthzMessageType::Error,
                    payload: b"unsupported".to_vec(),
                };
                write_frame(&mut transport, &err)?;
            }
        }
    }
    Ok(())
}

async fn handle_secauthz_stream_async(
    stream: tokio::net::TcpStream,
    config: SecAuthzServerConfig,
    handler: Arc<dyn SecAuthzHandler>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let _ = read_frame_async(&mut transport).await?;
    loop {
        let frame = match read_frame_async(&mut transport).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame.msg_type {
            SecAuthzMessageType::Authorize => {
                let request = parse_authorize_payload(&frame.payload);
                let subject =
                    resolve_subject(&config.tokens, &request.subject, request.token.as_deref());
                let decision = handler.decide(&subject, &request.action, &request.resource);
                let response = build_decision_frame(decision, "ok");
                write_frame_async(&mut transport, &response).await?;
            }
            SecAuthzMessageType::Ping => {
                let pong = SecAuthzFrame {
                    version: 1,
                    msg_type: SecAuthzMessageType::Pong,
                    payload: Vec::new(),
                };
                write_frame_async(&mut transport, &pong).await?;
            }
            _ => {
                let err = SecAuthzFrame {
                    version: 1,
                    msg_type: SecAuthzMessageType::Error,
                    payload: b"unsupported".to_vec(),
                };
                write_frame_async(&mut transport, &err).await?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct AuthzRequest {
    subject: String,
    action: String,
    resource: String,
    token: Option<String>,
}

fn build_authorize_payload(
    subject: &str,
    action: &str,
    resource: &str,
    token: Option<&str>,
) -> Vec<u8> {
    let mut lines = Vec::new();
    lines.push(format!("subject={subject}"));
    lines.push(format!("action={action}"));
    lines.push(format!("resource={resource}"));
    if let Some(token) = token {
        lines.push(format!("token={token}"));
    }
    lines.join("\n").into_bytes()
}

fn parse_authorize_payload(data: &[u8]) -> AuthzRequest {
    let text = String::from_utf8_lossy(data);
    let mut subject = String::new();
    let mut action = String::new();
    let mut resource = String::new();
    let mut token = None;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "subject" => subject = value.to_string(),
                "action" => action = value.to_string(),
                "resource" => resource = value.to_string(),
                "token" => token = Some(value.to_string()),
                _ => {}
            }
        }
    }
    AuthzRequest {
        subject,
        action,
        resource,
        token,
    }
}

fn resolve_subject(tokens: &HashMap<String, String>, subject: &str, token: Option<&str>) -> String {
    if !subject.is_empty() {
        return subject.to_string();
    }
    if let Some(token) = token {
        if let Some(mapped) = tokens.get(token) {
            return mapped.clone();
        }
    }
    "anonymous".to_string()
}

fn build_decision_frame(decision: SecAuthzDecision, reason: &str) -> SecAuthzFrame {
    let payload = format!("decision={}\nreason={}", decision.as_str(), reason).into_bytes();
    SecAuthzFrame {
        version: 1,
        msg_type: SecAuthzMessageType::Decision,
        payload,
    }
}

fn parse_decision(frame: &SecAuthzFrame) -> CoreResult<SecAuthzDecision> {
    if frame.msg_type != SecAuthzMessageType::Decision {
        return Err(CoreError::Parse("secauthz decision".to_string()));
    }
    let text = String::from_utf8_lossy(&frame.payload);
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key == "decision" {
                return Ok(if value == "permit" {
                    SecAuthzDecision::Permit
                } else {
                    SecAuthzDecision::Deny
                });
            }
        }
    }
    Err(CoreError::Parse("secauthz decision missing".to_string()))
}

fn read_frame<T: StreamTransport>(transport: &mut T) -> CoreResult<SecAuthzFrame> {
    let mut header = [0u8; 6];
    transport.read_exact(&mut header)?;
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(CoreError::Parse("secauthz payload".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = Vec::with_capacity(6 + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    SecAuthzFrame::decode(&data)
}

async fn read_frame_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<SecAuthzFrame> {
    let mut header = [0u8; 6];
    transport.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(CoreError::Parse("secauthz payload".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = Vec::with_capacity(6 + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    SecAuthzFrame::decode(&data)
}

fn write_frame<T: StreamTransport>(transport: &mut T, frame: &SecAuthzFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode())
}

async fn write_frame_async<T: AsyncStreamTransport>(
    transport: &mut T,
    frame: &SecAuthzFrame,
) -> CoreResult<()> {
    transport.write_all(&frame.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secauthz_authorize() {
        let policy = SecAuthzPolicy {
            subject: "alice".to_string(),
            action: "read".to_string(),
            resource: "vault".to_string(),
            decision: SecAuthzDecision::Permit,
        };
        let server = crate::skip_if_perm!(SecAuthzServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            SecAuthzServerConfig {
                policies: vec![policy],
                ..SecAuthzServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = SecAuthzClient::connect(
            &net::NetAddr::from_socket(addr),
            SecAuthzClientConfig::default(),
        )
        .unwrap();
        let decision = client.authorize("alice", "read", "vault", None).unwrap();
        assert_eq!(decision, SecAuthzDecision::Permit);
    }
}
