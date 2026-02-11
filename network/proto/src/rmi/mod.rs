use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const MAGIC: &[u8; 4] = b"JRMI";
const VERSION: u16 = 2;
const PROTOCOL_STREAM: u8 = 0x4b;

static CALL_COUNTER: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmiOp {
    Call = 0x50,
    Return = 0x51,
    Ping = 0x52,
    Error = 0x53,
}

impl RmiOp {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            0x50 => Ok(RmiOp::Call),
            0x51 => Ok(RmiOp::Return),
            0x52 => Ok(RmiOp::Ping),
            0x53 => Ok(RmiOp::Error),
            _ => Err(CoreError::Parse("rmi unknown op".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RmiFrame {
    pub op: RmiOp,
    pub call_id: u32,
    pub payload: Vec<u8>,
}

impl RmiFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.payload.len());
        out.push(self.op as u8);
        out.extend_from_slice(&self.call_id.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 9 {
            return Err(CoreError::Parse("rmi frame".to_string()));
        }
        let op = RmiOp::from_u8(data[0])?;
        let call_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
        if data.len() < 9 + len {
            return Err(CoreError::Parse("rmi payload".to_string()));
        }
        Ok(Self {
            op,
            call_id,
            payload: data[9..9 + len].to_vec(),
        })
    }
}

pub trait RmiHandler: Send + Sync {
    fn handle_call(&self, method: &str, args: &[String]) -> CoreResult<String>;
}

#[derive(Default)]
pub struct EchoRmiHandler;

impl RmiHandler for EchoRmiHandler {
    fn handle_call(&self, method: &str, args: &[String]) -> CoreResult<String> {
        let joined = if args.is_empty() {
            "".to_string()
        } else {
            format!(":{}", args.join(","))
        };
        Ok(format!("{method}{joined}"))
    }
}

#[derive(Clone)]
pub struct RmiServerConfig {
    pub timeouts: Timeouts,
    pub handler: Arc<dyn RmiHandler>,
}

impl Default for RmiServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            handler: Arc::new(EchoRmiHandler),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RmiClientConfig {
    pub timeouts: Timeouts,
}

impl Default for RmiClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct RmiServer {
    listener: TcpListener,
    config: RmiServerConfig,
}

impl RmiServer {
    pub fn bind(addr: SocketAddr, config: RmiServerConfig) -> CoreResult<Self> {
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
                let _ = handle_rmi_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncRmiServer {
    listener: tokio::net::TcpListener,
    config: RmiServerConfig,
}

impl AsyncRmiServer {
    pub async fn bind(addr: SocketAddr, config: RmiServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_rmi_stream_async(stream, config).await;
            });
        }
    }
}

pub struct RmiClient {
    transport: TcpTransport,
}

impl RmiClient {
    pub fn connect(addr: &net::NetAddr, config: RmiClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        write_handshake(&mut transport)?;
        read_handshake(&mut transport)?;
        Ok(Self { transport })
    }

    pub fn call(&mut self, method: &str, args: &[String]) -> CoreResult<String> {
        let call_id = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let payload = encode_call_payload(method, args);
        let frame = RmiFrame {
            op: RmiOp::Call,
            call_id,
            payload,
        };
        write_frame(&mut self.transport, &frame)?;
        loop {
            let response = read_frame(&mut self.transport)?;
            if response.call_id != call_id {
                continue;
            }
            return match response.op {
                RmiOp::Return => Ok(String::from_utf8_lossy(&response.payload).to_string()),
                RmiOp::Error => Err(CoreError::Message(
                    String::from_utf8_lossy(&response.payload).to_string(),
                )),
                _ => Err(CoreError::Parse("rmi unexpected response".to_string())),
            };
        }
    }

    pub fn ping(&mut self) -> CoreResult<()> {
        let call_id = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let frame = RmiFrame {
            op: RmiOp::Ping,
            call_id,
            payload: Vec::new(),
        };
        write_frame(&mut self.transport, &frame)?;
        let response = read_frame(&mut self.transport)?;
        if response.op != RmiOp::Return {
            return Err(CoreError::Parse("rmi ping".to_string()));
        }
        Ok(())
    }
}

pub struct AsyncRmiClient {
    transport: AsyncTcpTransport,
}

impl AsyncRmiClient {
    pub async fn connect(addr: &net::NetAddr, config: RmiClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        write_handshake_async(&mut transport).await?;
        read_handshake_async(&mut transport).await?;
        Ok(Self { transport })
    }

    pub async fn call(&mut self, method: &str, args: &[String]) -> CoreResult<String> {
        let call_id = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let payload = encode_call_payload(method, args);
        let frame = RmiFrame {
            op: RmiOp::Call,
            call_id,
            payload,
        };
        write_frame_async(&mut self.transport, &frame).await?;
        loop {
            let response = read_frame_async(&mut self.transport).await?;
            if response.call_id != call_id {
                continue;
            }
            return match response.op {
                RmiOp::Return => Ok(String::from_utf8_lossy(&response.payload).to_string()),
                RmiOp::Error => Err(CoreError::Message(
                    String::from_utf8_lossy(&response.payload).to_string(),
                )),
                _ => Err(CoreError::Parse("rmi unexpected response".to_string())),
            };
        }
    }

    pub async fn ping(&mut self) -> CoreResult<()> {
        let call_id = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let frame = RmiFrame {
            op: RmiOp::Ping,
            call_id,
            payload: Vec::new(),
        };
        write_frame_async(&mut self.transport, &frame).await?;
        let response = read_frame_async(&mut self.transport).await?;
        if response.op != RmiOp::Return {
            return Err(CoreError::Parse("rmi ping".to_string()));
        }
        Ok(())
    }
}

fn write_handshake<T: StreamTransport>(transport: &mut T) -> CoreResult<()> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(PROTOCOL_STREAM);
    transport.write_all(&out)
}

fn read_handshake<T: StreamTransport>(transport: &mut T) -> CoreResult<()> {
    let mut header = [0u8; 7];
    transport.read_exact(&mut header)?;
    if &header[0..4] != MAGIC {
        return Err(CoreError::Parse("rmi magic".to_string()));
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(CoreError::Parse("rmi version".to_string()));
    }
    if header[6] != PROTOCOL_STREAM {
        return Err(CoreError::Parse("rmi protocol".to_string()));
    }
    Ok(())
}

async fn write_handshake_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<()> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(PROTOCOL_STREAM);
    transport.write_all(&out).await
}

async fn read_handshake_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<()> {
    let mut header = [0u8; 7];
    transport.read_exact(&mut header).await?;
    if &header[0..4] != MAGIC {
        return Err(CoreError::Parse("rmi magic".to_string()));
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(CoreError::Parse("rmi version".to_string()));
    }
    if header[6] != PROTOCOL_STREAM {
        return Err(CoreError::Parse("rmi protocol".to_string()));
    }
    Ok(())
}

fn handle_rmi_stream(stream: TcpStream, config: RmiServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    read_handshake(&mut transport)?;
    write_handshake(&mut transport)?;
    loop {
        let frame = match read_frame(&mut transport) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame.op {
            RmiOp::Ping => {
                let response = RmiFrame {
                    op: RmiOp::Return,
                    call_id: frame.call_id,
                    payload: b"pong".to_vec(),
                };
                write_frame(&mut transport, &response)?;
            }
            RmiOp::Call => {
                let (method, args) = decode_call_payload(&frame.payload)?;
                let response = match config.handler.handle_call(&method, &args) {
                    Ok(value) => RmiFrame {
                        op: RmiOp::Return,
                        call_id: frame.call_id,
                        payload: value.into_bytes(),
                    },
                    Err(err) => RmiFrame {
                        op: RmiOp::Error,
                        call_id: frame.call_id,
                        payload: err.to_string().into_bytes(),
                    },
                };
                write_frame(&mut transport, &response)?;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn handle_rmi_stream_async(
    stream: tokio::net::TcpStream,
    config: RmiServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    read_handshake_async(&mut transport).await?;
    write_handshake_async(&mut transport).await?;
    loop {
        let frame = match read_frame_async(&mut transport).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        match frame.op {
            RmiOp::Ping => {
                let response = RmiFrame {
                    op: RmiOp::Return,
                    call_id: frame.call_id,
                    payload: b"pong".to_vec(),
                };
                write_frame_async(&mut transport, &response).await?;
            }
            RmiOp::Call => {
                let (method, args) = decode_call_payload(&frame.payload)?;
                let response = match config.handler.handle_call(&method, &args) {
                    Ok(value) => RmiFrame {
                        op: RmiOp::Return,
                        call_id: frame.call_id,
                        payload: value.into_bytes(),
                    },
                    Err(err) => RmiFrame {
                        op: RmiOp::Error,
                        call_id: frame.call_id,
                        payload: err.to_string().into_bytes(),
                    },
                };
                write_frame_async(&mut transport, &response).await?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn encode_call_payload(method: &str, args: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(method.as_bytes());
    for arg in args {
        out.push(0);
        out.extend_from_slice(arg.as_bytes());
    }
    out
}

fn decode_call_payload(data: &[u8]) -> CoreResult<(String, Vec<String>)> {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.split('\0');
    let method = parts.next().unwrap_or("").to_string();
    if method.is_empty() {
        return Err(CoreError::Parse("rmi method".to_string()));
    }
    let args = parts.map(|s| s.to_string()).collect();
    Ok((method, args))
}

fn read_frame<T: StreamTransport>(transport: &mut T) -> CoreResult<RmiFrame> {
    let mut header = [0u8; 9];
    transport.read_exact(&mut header)?;
    let op = RmiOp::from_u8(header[0])?;
    let call_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    Ok(RmiFrame { op, call_id, payload })
}

async fn read_frame_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<RmiFrame> {
    let mut header = [0u8; 9];
    transport.read_exact(&mut header).await?;
    let op = RmiOp::from_u8(header[0])?;
    let call_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    Ok(RmiFrame { op, call_id, payload })
}

fn write_frame<T: StreamTransport>(transport: &mut T, frame: &RmiFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode())
}

async fn write_frame_async<T: AsyncStreamTransport>(
    transport: &mut T,
    frame: &RmiFrame,
) -> CoreResult<()> {
    transport.write_all(&frame.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestHandler;

    impl RmiHandler for TestHandler {
        fn handle_call(&self, method: &str, args: &[String]) -> CoreResult<String> {
            if method == "sum" {
                let total: i32 = args.iter().filter_map(|s| s.parse::<i32>().ok()).sum();
                return Ok(total.to_string());
            }
            Ok("ok".to_string())
        }
    }

    #[test]
    fn rmi_call_roundtrip() {
        let server = crate::skip_if_perm!(RmiServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            RmiServerConfig {
                handler: Arc::new(TestHandler),
                ..RmiServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = RmiClient::connect(&net::NetAddr::from_socket(addr), RmiClientConfig::default()).unwrap();
        let result = client.call("sum", &["2".to_string(), "5".to_string()]).unwrap();
        assert_eq!(result, "7");
    }
}
