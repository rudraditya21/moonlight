use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const MAX_FRAME: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMessageType {
    ClientFirst = 0x01,
    ServerChallenge = 0x02,
    ClientResponse = 0x03,
    ServerOutcome = 0x04,
}

impl SaslMessageType {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            0x01 => Ok(SaslMessageType::ClientFirst),
            0x02 => Ok(SaslMessageType::ServerChallenge),
            0x03 => Ok(SaslMessageType::ClientResponse),
            0x04 => Ok(SaslMessageType::ServerOutcome),
            _ => Err(CoreError::Parse("sasl message type".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SaslFrame {
    pub msg_type: SaslMessageType,
    pub payload: Vec<u8>,
}

impl SaslFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.payload.len());
        out.push(self.msg_type as u8);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 3 {
            return Err(CoreError::Parse("sasl frame".to_string()));
        }
        let msg_type = SaslMessageType::from_u8(data[0])?;
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + len {
            return Err(CoreError::Parse("sasl frame len".to_string()));
        }
        Ok(Self {
            msg_type,
            payload: data[3..3 + len].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SaslServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
    pub allow_anonymous: bool,
}

impl Default for SaslServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: HashMap::new(),
            allow_anonymous: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SaslClientConfig {
    pub timeouts: Timeouts,
    pub mechanism: String,
    pub username: String,
    pub password: String,
    pub authzid: Option<String>,
}

impl Default for SaslClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            mechanism: "PLAIN".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            authzid: None,
        }
    }
}

pub struct SaslServer {
    listener: TcpListener,
    config: SaslServerConfig,
}

impl SaslServer {
    pub fn bind(addr: SocketAddr, config: SaslServerConfig) -> CoreResult<Self> {
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
                let _ = handle_sasl_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncSaslServer {
    listener: tokio::net::TcpListener,
    config: SaslServerConfig,
}

impl AsyncSaslServer {
    pub async fn bind(addr: SocketAddr, config: SaslServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_sasl_stream_async(stream, config).await;
            });
        }
    }
}

pub struct SaslClient {
    transport: TcpTransport,
}

impl SaslClient {
    pub fn connect(addr: &net::NetAddr, config: SaslClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let auth = build_plain_message(&config.username, &config.password, config.authzid.as_deref());
        let first = build_client_first(&config.mechanism, &auth);
        write_frame(&mut transport, &first)?;
        let response = read_frame(&mut transport)?;
        let ok = match response.msg_type {
            SaslMessageType::ServerChallenge => {
                let reply = SaslFrame {
                    msg_type: SaslMessageType::ClientResponse,
                    payload: auth,
                };
                write_frame(&mut transport, &reply)?;
                let outcome = read_frame(&mut transport)?;
                parse_outcome(outcome)
            }
            SaslMessageType::ServerOutcome => parse_outcome(response),
            _ => Err(CoreError::Parse("sasl response".to_string())),
        }?;
        if !ok {
            return Err(CoreError::Message("sasl authentication failed".to_string()));
        }
        Ok(Self { transport })
    }
}

pub struct AsyncSaslClient {
    transport: AsyncTcpTransport,
}

impl AsyncSaslClient {
    pub async fn connect(addr: &net::NetAddr, config: SaslClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let auth = build_plain_message(&config.username, &config.password, config.authzid.as_deref());
        let first = build_client_first(&config.mechanism, &auth);
        write_frame_async(&mut transport, &first).await?;
        let response = read_frame_async(&mut transport).await?;
        let ok = match response.msg_type {
            SaslMessageType::ServerChallenge => {
                let reply = SaslFrame {
                    msg_type: SaslMessageType::ClientResponse,
                    payload: auth,
                };
                write_frame_async(&mut transport, &reply).await?;
                let outcome = read_frame_async(&mut transport).await?;
                parse_outcome(outcome)
            }
            SaslMessageType::ServerOutcome => parse_outcome(response),
            _ => Err(CoreError::Parse("sasl response".to_string())),
        }?;
        if !ok {
            return Err(CoreError::Message("sasl authentication failed".to_string()));
        }
        Ok(Self { transport })
    }
}

fn handle_sasl_stream(stream: TcpStream, config: SaslServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let first = read_frame(&mut transport)?;
    if first.msg_type != SaslMessageType::ClientFirst {
        return Err(CoreError::Parse("sasl expected client first".to_string()));
    }
    let (mechanism, initial) = parse_client_first(&first.payload)?;
    if mechanism.to_ascii_uppercase() != "PLAIN" {
        let outcome = build_outcome(false, "unsupported mechanism");
        write_frame(&mut transport, &outcome)?;
        return Ok(());
    }
    let auth_data = if initial.is_empty() {
        let challenge = SaslFrame {
            msg_type: SaslMessageType::ServerChallenge,
            payload: Vec::new(),
        };
        write_frame(&mut transport, &challenge)?;
        let response = read_frame(&mut transport)?;
        if response.msg_type != SaslMessageType::ClientResponse {
            let outcome = build_outcome(false, "expected response");
            write_frame(&mut transport, &outcome)?;
            return Ok(());
        }
        response.payload
    } else {
        initial
    };
    let ok = validate_plain(&config, &auth_data);
    let outcome = build_outcome(ok, if ok { "ok" } else { "invalid" });
    write_frame(&mut transport, &outcome)?;
    Ok(())
}

async fn handle_sasl_stream_async(
    stream: tokio::net::TcpStream,
    config: SaslServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let first = read_frame_async(&mut transport).await?;
    if first.msg_type != SaslMessageType::ClientFirst {
        return Err(CoreError::Parse("sasl expected client first".to_string()));
    }
    let (mechanism, initial) = parse_client_first(&first.payload)?;
    if mechanism.to_ascii_uppercase() != "PLAIN" {
        let outcome = build_outcome(false, "unsupported mechanism");
        write_frame_async(&mut transport, &outcome).await?;
        return Ok(());
    }
    let auth_data = if initial.is_empty() {
        let challenge = SaslFrame {
            msg_type: SaslMessageType::ServerChallenge,
            payload: Vec::new(),
        };
        write_frame_async(&mut transport, &challenge).await?;
        let response = read_frame_async(&mut transport).await?;
        if response.msg_type != SaslMessageType::ClientResponse {
            let outcome = build_outcome(false, "expected response");
            write_frame_async(&mut transport, &outcome).await?;
            return Ok(());
        }
        response.payload
    } else {
        initial
    };
    let ok = validate_plain(&config, &auth_data);
    let outcome = build_outcome(ok, if ok { "ok" } else { "invalid" });
    write_frame_async(&mut transport, &outcome).await?;
    Ok(())
}

fn build_client_first(mechanism: &str, initial: &[u8]) -> SaslFrame {
    let mut payload = Vec::new();
    payload.extend_from_slice(mechanism.as_bytes());
    payload.push(0);
    payload.extend_from_slice(initial);
    SaslFrame {
        msg_type: SaslMessageType::ClientFirst,
        payload,
    }
}

fn parse_client_first(data: &[u8]) -> CoreResult<(String, Vec<u8>)> {
    let mut parts = data.splitn(2, |b| *b == 0);
    let mechanism = parts.next().unwrap_or_default();
    let initial = parts.next().unwrap_or_default();
    if mechanism.is_empty() {
        return Err(CoreError::Parse("sasl mechanism".to_string()));
    }
    Ok((String::from_utf8_lossy(mechanism).to_string(), initial.to_vec()))
}

fn build_plain_message(username: &str, password: &str, authzid: Option<&str>) -> Vec<u8> {
    let authzid = authzid.unwrap_or("");
    let mut out = Vec::new();
    out.extend_from_slice(authzid.as_bytes());
    out.push(0);
    out.extend_from_slice(username.as_bytes());
    out.push(0);
    out.extend_from_slice(password.as_bytes());
    out
}

fn validate_plain(config: &SaslServerConfig, payload: &[u8]) -> bool {
    let mut parts = payload.split(|b| *b == 0);
    let _authz = parts.next();
    let authcid = parts.next().unwrap_or_default();
    let passwd = parts.next().unwrap_or_default();
    if authcid.is_empty() {
        return config.allow_anonymous;
    }
    let user = String::from_utf8_lossy(authcid).to_string();
    let pass = String::from_utf8_lossy(passwd).to_string();
    if config.users.is_empty() {
        return !user.is_empty();
    }
    config.users.get(&user).map(|p| p == &pass).unwrap_or(false)
}

fn build_outcome(success: bool, message: &str) -> SaslFrame {
    let mut payload = Vec::new();
    payload.push(if success { 1 } else { 0 });
    payload.extend_from_slice(message.as_bytes());
    SaslFrame {
        msg_type: SaslMessageType::ServerOutcome,
        payload,
    }
}

fn parse_outcome(frame: SaslFrame) -> CoreResult<bool> {
    if frame.msg_type != SaslMessageType::ServerOutcome {
        return Err(CoreError::Parse("sasl outcome".to_string()));
    }
    if frame.payload.is_empty() {
        return Err(CoreError::Parse("sasl outcome payload".to_string()));
    }
    Ok(frame.payload[0] == 1)
}

fn read_frame<T: StreamTransport>(transport: &mut T) -> CoreResult<SaslFrame> {
    let mut header = [0u8; 3];
    transport.read_exact(&mut header)?;
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    if len > MAX_FRAME {
        return Err(CoreError::Parse("sasl frame too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = Vec::with_capacity(3 + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    SaslFrame::decode(&data)
}

async fn read_frame_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<SaslFrame> {
    let mut header = [0u8; 3];
    transport.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;
    if len > MAX_FRAME {
        return Err(CoreError::Parse("sasl frame too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = Vec::with_capacity(3 + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    SaslFrame::decode(&data)
}

fn write_frame<T: StreamTransport>(transport: &mut T, frame: &SaslFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode())
}

async fn write_frame_async<T: AsyncStreamTransport>(
    transport: &mut T,
    frame: &SaslFrame,
) -> CoreResult<()> {
    transport.write_all(&frame.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sasl_plain_auth() {
        let mut users = HashMap::new();
        users.insert("user".to_string(), "pass".to_string());
        let server = crate::skip_if_perm!(SaslServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            SaslServerConfig {
                users,
                ..SaslServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let _client = SaslClient::connect(
            &net::NetAddr::from_socket(addr),
            SaslClientConfig::default(),
        )
        .unwrap();
    }
}
