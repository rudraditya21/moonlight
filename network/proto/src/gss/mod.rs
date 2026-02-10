use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GssMessageType {
    Init = 1,
    Accept = 2,
    Mic = 3,
    Wrap = 4,
    Error = 5,
}

#[derive(Debug, Clone)]
pub struct GssMessage {
    pub msg_type: GssMessageType,
    pub context_id: u32,
    pub payload: Vec<u8>,
    pub checksum: Option<[u8; 32]>,
}

impl GssMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.msg_type as u8);
        out.extend_from_slice(&self.context_id.to_be_bytes());
        match self.checksum {
            Some(sum) => {
                out.push(1);
                out.extend_from_slice(&sum);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 10 {
            return Err(CoreError::Parse("gss message too short".to_string()));
        }
        let msg_type = match data[0] {
            1 => GssMessageType::Init,
            2 => GssMessageType::Accept,
            3 => GssMessageType::Mic,
            4 => GssMessageType::Wrap,
            5 => GssMessageType::Error,
            _ => return Err(CoreError::Parse("gss message type".to_string())),
        };
        let context_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let has_checksum = data[5] != 0;
        let mut idx = 6;
        let checksum = if has_checksum {
            if idx + 32 > data.len() {
                return Err(CoreError::Parse("gss checksum".to_string()));
            }
            let mut sum = [0u8; 32];
            sum.copy_from_slice(&data[idx..idx + 32]);
            idx += 32;
            Some(sum)
        } else {
            None
        };
        if idx + 4 > data.len() {
            return Err(CoreError::Parse("gss len".to_string()));
        }
        let len = u32::from_be_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]) as usize;
        idx += 4;
        if idx + len > data.len() {
            return Err(CoreError::Parse("gss payload".to_string()));
        }
        Ok(Self {
            msg_type,
            context_id,
            payload: data[idx..idx + len].to_vec(),
            checksum,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GssServerConfig {
    pub timeouts: Timeouts,
    pub secret: Vec<u8>,
}

impl Default for GssServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            secret: b"moonlight".to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GssClientConfig {
    pub timeouts: Timeouts,
    pub secret: Vec<u8>,
    pub client_name: String,
}

impl Default for GssClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            secret: b"moonlight".to_vec(),
            client_name: "client".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct GssState {
    context_id: u32,
    nonce: Vec<u8>,
    established: bool,
}

pub struct GssServer {
    listener: TcpListener,
    config: GssServerConfig,
}

impl GssServer {
    pub fn bind(addr: SocketAddr, config: GssServerConfig) -> CoreResult<Self> {
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
                let _ = handle_gss_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncGssServer {
    listener: tokio::net::TcpListener,
    config: GssServerConfig,
}

impl AsyncGssServer {
    pub async fn bind(addr: SocketAddr, config: GssServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_gss_stream_async(stream, config).await;
            });
        }
    }
}

pub struct GssClient {
    transport: TcpTransport,
    context_id: u32,
    secret: Vec<u8>,
}

impl GssClient {
    pub fn connect(addr: &NetAddr, config: GssClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let context_id = rand_id();
        let init = GssMessage {
            msg_type: GssMessageType::Init,
            context_id,
            payload: config.client_name.into_bytes(),
            checksum: None,
        };
        write_message(&mut transport, &init)?;
        let accept = read_message(&mut transport)?;
        if accept.msg_type != GssMessageType::Accept {
            return Err(CoreError::Parse("gss expected accept".to_string()));
        }
        let nonce = accept.payload;
        let mic = make_checksum(&config.secret, context_id, &nonce);
        let mic_msg = GssMessage {
            msg_type: GssMessageType::Mic,
            context_id,
            payload: Vec::new(),
            checksum: Some(mic),
        };
        write_message(&mut transport, &mic_msg)?;
        let resp = read_message(&mut transport)?;
        if resp.msg_type != GssMessageType::Accept {
            return Err(CoreError::Parse("gss mic failed".to_string()));
        }
        Ok(Self {
            transport,
            context_id,
            secret: config.secret,
        })
    }

    pub fn wrap(&mut self, data: &[u8]) -> CoreResult<Vec<u8>> {
        let checksum = make_checksum(&self.secret, self.context_id, data);
        let msg = GssMessage {
            msg_type: GssMessageType::Wrap,
            context_id: self.context_id,
            payload: data.to_vec(),
            checksum: Some(checksum),
        };
        write_message(&mut self.transport, &msg)?;
        let resp = read_message(&mut self.transport)?;
        if resp.msg_type != GssMessageType::Wrap {
            return Err(CoreError::Parse("gss wrap response".to_string()));
        }
        Ok(resp.payload)
    }
}

pub struct AsyncGssClient {
    transport: AsyncTcpTransport,
    context_id: u32,
    secret: Vec<u8>,
}

impl AsyncGssClient {
    pub async fn connect(addr: &NetAddr, config: GssClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let context_id = rand_id();
        let init = GssMessage {
            msg_type: GssMessageType::Init,
            context_id,
            payload: config.client_name.into_bytes(),
            checksum: None,
        };
        write_message_async(&mut transport, &init).await?;
        let accept = read_message_async(&mut transport).await?;
        if accept.msg_type != GssMessageType::Accept {
            return Err(CoreError::Parse("gss expected accept".to_string()));
        }
        let nonce = accept.payload;
        let mic = make_checksum(&config.secret, context_id, &nonce);
        let mic_msg = GssMessage {
            msg_type: GssMessageType::Mic,
            context_id,
            payload: Vec::new(),
            checksum: Some(mic),
        };
        write_message_async(&mut transport, &mic_msg).await?;
        let resp = read_message_async(&mut transport).await?;
        if resp.msg_type != GssMessageType::Accept {
            return Err(CoreError::Parse("gss mic failed".to_string()));
        }
        Ok(Self {
            transport,
            context_id,
            secret: config.secret,
        })
    }

    pub async fn wrap(&mut self, data: &[u8]) -> CoreResult<Vec<u8>> {
        let checksum = make_checksum(&self.secret, self.context_id, data);
        let msg = GssMessage {
            msg_type: GssMessageType::Wrap,
            context_id: self.context_id,
            payload: data.to_vec(),
            checksum: Some(checksum),
        };
        write_message_async(&mut self.transport, &msg).await?;
        let resp = read_message_async(&mut self.transport).await?;
        if resp.msg_type != GssMessageType::Wrap {
            return Err(CoreError::Parse("gss wrap response".to_string()));
        }
        Ok(resp.payload)
    }
}

fn handle_gss_stream(stream: TcpStream, config: GssServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let init = read_message(&mut transport)?;
    if init.msg_type != GssMessageType::Init {
        return Err(CoreError::Parse("gss expected init".to_string()));
    }
    let mut state = GssState {
        context_id: init.context_id,
        nonce: rand_nonce(),
        established: false,
    };
    let accept = GssMessage {
        msg_type: GssMessageType::Accept,
        context_id: state.context_id,
        payload: state.nonce.clone(),
        checksum: None,
    };
    write_message(&mut transport, &accept)?;
    let mic = read_message(&mut transport)?;
    if mic.msg_type != GssMessageType::Mic {
        return Err(CoreError::Parse("gss expected mic".to_string()));
    }
    let expected = make_checksum(&config.secret, state.context_id, &state.nonce);
    if mic.checksum != Some(expected) {
        let err = GssMessage {
            msg_type: GssMessageType::Error,
            context_id: state.context_id,
            payload: b"bad mic".to_vec(),
            checksum: None,
        };
        write_message(&mut transport, &err)?;
        return Ok(());
    }
    state.established = true;
    let ok = GssMessage {
        msg_type: GssMessageType::Accept,
        context_id: state.context_id,
        payload: Vec::new(),
        checksum: None,
    };
    write_message(&mut transport, &ok)?;
    loop {
        let msg = read_message(&mut transport)?;
        match msg.msg_type {
            GssMessageType::Wrap => {
                if !state.established {
                    continue;
                }
                let expected = make_checksum(&config.secret, state.context_id, &msg.payload);
                if msg.checksum != Some(expected) {
                    continue;
                }
                let resp = GssMessage {
                    msg_type: GssMessageType::Wrap,
                    context_id: state.context_id,
                    payload: msg.payload,
                    checksum: Some(expected),
                };
                write_message(&mut transport, &resp)?;
            }
            _ => {}
        }
    }
}

async fn handle_gss_stream_async(stream: tokio::net::TcpStream, config: GssServerConfig) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let init = read_message_async(&mut transport).await?;
    if init.msg_type != GssMessageType::Init {
        return Err(CoreError::Parse("gss expected init".to_string()));
    }
    let mut state = GssState {
        context_id: init.context_id,
        nonce: rand_nonce(),
        established: false,
    };
    let accept = GssMessage {
        msg_type: GssMessageType::Accept,
        context_id: state.context_id,
        payload: state.nonce.clone(),
        checksum: None,
    };
    write_message_async(&mut transport, &accept).await?;
    let mic = read_message_async(&mut transport).await?;
    if mic.msg_type != GssMessageType::Mic {
        return Err(CoreError::Parse("gss expected mic".to_string()));
    }
    let expected = make_checksum(&config.secret, state.context_id, &state.nonce);
    if mic.checksum != Some(expected) {
        let err = GssMessage {
            msg_type: GssMessageType::Error,
            context_id: state.context_id,
            payload: b"bad mic".to_vec(),
            checksum: None,
        };
        write_message_async(&mut transport, &err).await?;
        return Ok(());
    }
    state.established = true;
    let ok = GssMessage {
        msg_type: GssMessageType::Accept,
        context_id: state.context_id,
        payload: Vec::new(),
        checksum: None,
    };
    write_message_async(&mut transport, &ok).await?;
    loop {
        let msg = read_message_async(&mut transport).await?;
        match msg.msg_type {
            GssMessageType::Wrap => {
                if !state.established {
                    continue;
                }
                let expected = make_checksum(&config.secret, state.context_id, &msg.payload);
                if msg.checksum != Some(expected) {
                    continue;
                }
                let resp = GssMessage {
                    msg_type: GssMessageType::Wrap,
                    context_id: state.context_id,
                    payload: msg.payload,
                    checksum: Some(expected),
                };
                write_message_async(&mut transport, &resp).await?;
            }
            _ => {}
        }
    }
}

fn make_checksum(secret: &[u8], context_id: u32, data: &[u8]) -> [u8; 32] {
    let mut sha = sha256::Sha256::new();
    sha.update(secret);
    sha.update(&context_id.to_be_bytes());
    sha.update(data);
    sha.finalize()
}

fn read_message<T: StreamTransport>(transport: &mut T) -> CoreResult<GssMessage> {
    let mut header = [0u8; 6];
    transport.read_exact(&mut header)?;
    let has_checksum = header[5] != 0;
    let mut data = header.to_vec();
    if has_checksum {
        let mut sum = [0u8; 32];
        transport.read_exact(&mut sum)?;
        data.extend_from_slice(&sum);
    }
    let mut len_bytes = [0u8; 4];
    transport.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    data.extend_from_slice(&len_bytes);
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    data.extend_from_slice(&payload);
    GssMessage::decode(&data)
}

async fn read_message_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<GssMessage> {
    let mut header = [0u8; 6];
    transport.read_exact(&mut header).await?;
    let has_checksum = header[5] != 0;
    let mut data = header.to_vec();
    if has_checksum {
        let mut sum = [0u8; 32];
        transport.read_exact(&mut sum).await?;
        data.extend_from_slice(&sum);
    }
    let mut len_bytes = [0u8; 4];
    transport.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    data.extend_from_slice(&len_bytes);
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    data.extend_from_slice(&payload);
    GssMessage::decode(&data)
}

fn write_message<T: StreamTransport>(transport: &mut T, msg: &GssMessage) -> CoreResult<()> {
    transport.write_all(&msg.encode())
}

async fn write_message_async<T: AsyncStreamTransport>(transport: &mut T, msg: &GssMessage) -> CoreResult<()> {
    transport.write_all(&msg.encode()).await
}

fn rand_id() -> u32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_nanos() & 0xFFFF_FFFF) as u32
}

fn rand_nonce() -> Vec<u8> {
    let mut sha = sha256::Sha256::new();
    sha.update(&rand_id().to_be_bytes());
    sha.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gss_wrap_roundtrip() {
        let server = GssServer::bind("127.0.0.1:0".parse().unwrap(), GssServerConfig::default()).unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = GssClient::connect(&NetAddr::from_socket(addr), GssClientConfig::default()).unwrap();
        let resp = client.wrap(b"hello").unwrap();
        assert_eq!(resp, b"hello".to_vec());

        drop(handle);
    }
}
