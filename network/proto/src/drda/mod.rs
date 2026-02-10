use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const MAGIC: [u8; 4] = *b"DRDA";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrdaMessageType {
    Excsat = 1,
    Accsec = 2,
    Secchk = 3,
    Sql = 4,
    Response = 5,
    Error = 6,
}

#[derive(Debug, Clone)]
pub struct DrdaMessage {
    pub msg_type: DrdaMessageType,
    pub payload: Vec<u8>,
}

impl DrdaMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 9 {
            return Err(CoreError::Parse("drda message too short".to_string()));
        }
        if &data[0..4] != MAGIC {
            return Err(CoreError::Parse("drda magic".to_string()));
        }
        let msg_type = match data[4] {
            1 => DrdaMessageType::Excsat,
            2 => DrdaMessageType::Accsec,
            3 => DrdaMessageType::Secchk,
            4 => DrdaMessageType::Sql,
            5 => DrdaMessageType::Response,
            6 => DrdaMessageType::Error,
            _ => return Err(CoreError::Parse("drda type".to_string())),
        };
        let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
        if data.len() < 9 + len {
            return Err(CoreError::Parse("drda len".to_string()));
        }
        Ok(Self {
            msg_type,
            payload: data[9..9 + len].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DrdaServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
}

impl Default for DrdaServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: HashMap::new(),
        }
    }
}

pub struct DrdaServer {
    listener: TcpListener,
    config: DrdaServerConfig,
}

impl DrdaServer {
    pub fn bind(addr: SocketAddr, config: DrdaServerConfig) -> CoreResult<Self> {
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
                let _ = handle_drda_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncDrdaServer {
    listener: tokio::net::TcpListener,
    config: DrdaServerConfig,
}

impl AsyncDrdaServer {
    pub async fn bind(addr: SocketAddr, config: DrdaServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_drda_stream_async(stream, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct DrdaClientConfig {
    pub timeouts: Timeouts,
    pub username: String,
    pub password: String,
}

impl Default for DrdaClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: "db2".to_string(),
            password: "moonlight".to_string(),
        }
    }
}

pub struct DrdaClient {
    transport: TcpTransport,
}

impl DrdaClient {
    pub fn connect(addr: &net::NetAddr, config: DrdaClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let excsat = DrdaMessage {
            msg_type: DrdaMessageType::Excsat,
            payload: config.username.as_bytes().to_vec(),
        };
        write_message(&mut transport, &excsat)?;
        let resp = read_message(&mut transport)?;
        if resp.msg_type != DrdaMessageType::Accsec {
            return Err(CoreError::Parse("drda expected accsec".to_string()));
        }
        let mut payload = Vec::new();
        encode_string(&mut payload, &config.username);
        encode_string(&mut payload, &config.password);
        write_message(
            &mut transport,
            &DrdaMessage {
                msg_type: DrdaMessageType::Secchk,
                payload,
            },
        )?;
        let resp = read_message(&mut transport)?;
        if resp.msg_type != DrdaMessageType::Response {
            return Err(CoreError::Parse("drda auth failed".to_string()));
        }
        Ok(Self { transport })
    }

    pub fn query(&mut self, sql: &str) -> CoreResult<String> {
        let msg = DrdaMessage {
            msg_type: DrdaMessageType::Sql,
            payload: sql.as_bytes().to_vec(),
        };
        write_message(&mut self.transport, &msg)?;
        let resp = read_message(&mut self.transport)?;
        if resp.msg_type != DrdaMessageType::Response {
            return Err(CoreError::Parse("drda response".to_string()));
        }
        Ok(String::from_utf8_lossy(&resp.payload).to_string())
    }
}

pub struct AsyncDrdaClient {
    transport: AsyncTcpTransport,
}

impl AsyncDrdaClient {
    pub async fn connect(addr: &net::NetAddr, config: DrdaClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let excsat = DrdaMessage {
            msg_type: DrdaMessageType::Excsat,
            payload: config.username.as_bytes().to_vec(),
        };
        write_message_async(&mut transport, &excsat).await?;
        let resp = read_message_async(&mut transport).await?;
        if resp.msg_type != DrdaMessageType::Accsec {
            return Err(CoreError::Parse("drda expected accsec".to_string()));
        }
        let mut payload = Vec::new();
        encode_string(&mut payload, &config.username);
        encode_string(&mut payload, &config.password);
        write_message_async(
            &mut transport,
            &DrdaMessage {
                msg_type: DrdaMessageType::Secchk,
                payload,
            },
        )
        .await?;
        let resp = read_message_async(&mut transport).await?;
        if resp.msg_type != DrdaMessageType::Response {
            return Err(CoreError::Parse("drda auth failed".to_string()));
        }
        Ok(Self { transport })
    }

    pub async fn query(&mut self, sql: &str) -> CoreResult<String> {
        let msg = DrdaMessage {
            msg_type: DrdaMessageType::Sql,
            payload: sql.as_bytes().to_vec(),
        };
        write_message_async(&mut self.transport, &msg).await?;
        let resp = read_message_async(&mut self.transport).await?;
        if resp.msg_type != DrdaMessageType::Response {
            return Err(CoreError::Parse("drda response".to_string()));
        }
        Ok(String::from_utf8_lossy(&resp.payload).to_string())
    }
}

fn handle_drda_stream(stream: TcpStream, config: DrdaServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let mut authenticated = false;
    loop {
        let msg = read_message(&mut transport)?;
        match msg.msg_type {
            DrdaMessageType::Excsat => {
                write_message(
                    &mut transport,
                    &DrdaMessage {
                        msg_type: DrdaMessageType::Accsec,
                        payload: Vec::new(),
                    },
                )?;
            }
            DrdaMessageType::Secchk => {
                let mut idx = 0;
                let user = decode_string(&msg.payload, &mut idx)?;
                let pass = decode_string(&msg.payload, &mut idx)?;
                let ok = config.users.get(&user).map(|p| p == &pass).unwrap_or(config.users.is_empty());
                authenticated = ok;
                let resp_type = if ok { DrdaMessageType::Response } else { DrdaMessageType::Error };
                write_message(
                    &mut transport,
                    &DrdaMessage {
                        msg_type: resp_type,
                        payload: Vec::new(),
                    },
                )?;
            }
            DrdaMessageType::Sql => {
                if !authenticated {
                    write_message(
                        &mut transport,
                        &DrdaMessage {
                            msg_type: DrdaMessageType::Error,
                            payload: b"not authenticated".to_vec(),
                        },
                    )?;
                    continue;
                }
                let sql = String::from_utf8_lossy(&msg.payload).to_string();
                let resp = execute_sql(&sql);
                write_message(
                    &mut transport,
                    &DrdaMessage {
                        msg_type: DrdaMessageType::Response,
                        payload: resp.into_bytes(),
                    },
                )?;
            }
            _ => {}
        }
    }
}

async fn handle_drda_stream_async(stream: tokio::net::TcpStream, config: DrdaServerConfig) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut authenticated = false;
    loop {
        let msg = read_message_async(&mut transport).await?;
        match msg.msg_type {
            DrdaMessageType::Excsat => {
                write_message_async(
                    &mut transport,
                    &DrdaMessage {
                        msg_type: DrdaMessageType::Accsec,
                        payload: Vec::new(),
                    },
                )
                .await?;
            }
            DrdaMessageType::Secchk => {
                let mut idx = 0;
                let user = decode_string(&msg.payload, &mut idx)?;
                let pass = decode_string(&msg.payload, &mut idx)?;
                let ok = config.users.get(&user).map(|p| p == &pass).unwrap_or(config.users.is_empty());
                authenticated = ok;
                let resp_type = if ok { DrdaMessageType::Response } else { DrdaMessageType::Error };
                write_message_async(
                    &mut transport,
                    &DrdaMessage {
                        msg_type: resp_type,
                        payload: Vec::new(),
                    },
                )
                .await?;
            }
            DrdaMessageType::Sql => {
                if !authenticated {
                    write_message_async(
                        &mut transport,
                        &DrdaMessage {
                            msg_type: DrdaMessageType::Error,
                            payload: b"not authenticated".to_vec(),
                        },
                    )
                    .await?;
                    continue;
                }
                let sql = String::from_utf8_lossy(&msg.payload).to_string();
                let resp = execute_sql(&sql);
                write_message_async(
                    &mut transport,
                    &DrdaMessage {
                        msg_type: DrdaMessageType::Response,
                        payload: resp.into_bytes(),
                    },
                )
                .await?;
            }
            _ => {}
        }
    }
}

fn execute_sql(sql: &str) -> String {
    let lower = sql.to_lowercase();
    if lower.contains("select") {
        if lower.contains("1") {
            return "1".to_string();
        }
        if lower.contains("version") {
            return "moonlight-drda".to_string();
        }
    }
    "ok".to_string()
}

fn read_message<T: StreamTransport>(transport: &mut T) -> CoreResult<DrdaMessage> {
    let mut header = [0u8; 9];
    transport.read_exact(&mut header)?;
    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    DrdaMessage::decode(&data)
}

async fn read_message_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<DrdaMessage> {
    let mut header = [0u8; 9];
    transport.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = header.to_vec();
    data.extend_from_slice(&payload);
    DrdaMessage::decode(&data)
}

fn write_message<T: StreamTransport>(transport: &mut T, msg: &DrdaMessage) -> CoreResult<()> {
    transport.write_all(&msg.encode())
}

async fn write_message_async<T: AsyncStreamTransport>(transport: &mut T, msg: &DrdaMessage) -> CoreResult<()> {
    transport.write_all(&msg.encode()).await
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn decode_string(data: &[u8], idx: &mut usize) -> CoreResult<String> {
    if *idx + 2 > data.len() {
        return Err(CoreError::Parse("drda string len".to_string()));
    }
    let len = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
    *idx += 2;
    if *idx + len > data.len() {
        return Err(CoreError::Parse("drda string bounds".to_string()));
    }
    let value = String::from_utf8_lossy(&data[*idx..*idx + len]).to_string();
    *idx += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drda_query() {
        let mut users = HashMap::new();
        users.insert("db2".to_string(), "moonlight".to_string());
        let server = DrdaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            DrdaServerConfig { users, ..DrdaServerConfig::default() },
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = DrdaClient::connect(&net::NetAddr::from_socket(addr), DrdaClientConfig::default()).unwrap();
        let resp = client.query("select 1").unwrap();
        assert_eq!(resp, "1");

        drop(handle);
    }
}
