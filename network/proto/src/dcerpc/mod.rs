use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    Request = 0,
    Response = 2,
    Fault = 3,
    Bind = 11,
    BindAck = 12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    pub fn encode_le(&self) -> [u8; 16] {
        let mut out = self.0;
        out[..4].reverse();
        out[4..6].reverse();
        out[6..8].reverse();
        out
    }
}

#[derive(Debug, Clone)]
pub struct DceRpcHeader {
    pub version: u8,
    pub minor: u8,
    pub pdu_type: PduType,
    pub flags: u8,
    pub data_rep: [u8; 4],
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl DceRpcHeader {
    pub fn encode(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0] = self.version;
        out[1] = self.minor;
        out[2] = self.pdu_type as u8;
        out[3] = self.flags;
        out[4..8].copy_from_slice(&self.data_rep);
        out[8..10].copy_from_slice(&self.frag_length.to_le_bytes());
        out[10..12].copy_from_slice(&self.auth_length.to_le_bytes());
        out[12..16].copy_from_slice(&self.call_id.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 16 {
            return Err(CoreError::Parse("dcerpc header too short".to_string()));
        }
        let pdu_type = match data[2] {
            0 => PduType::Request,
            2 => PduType::Response,
            3 => PduType::Fault,
            11 => PduType::Bind,
            12 => PduType::BindAck,
            _ => return Err(CoreError::Parse("dcerpc unknown pdu".to_string())),
        };
        Ok(Self {
            version: data[0],
            minor: data[1],
            pdu_type,
            flags: data[3],
            data_rep: [data[4], data[5], data[6], data[7]],
            frag_length: u16::from_le_bytes([data[8], data[9]]),
            auth_length: u16::from_le_bytes([data[10], data[11]]),
            call_id: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DceRpcPdu {
    pub header: DceRpcHeader,
    pub payload: Vec<u8>,
}

impl DceRpcPdu {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        let header = DceRpcHeader::decode(data)?;
        let len = header.frag_length as usize;
        if data.len() < len {
            return Err(CoreError::Parse("dcerpc frag length".to_string()));
        }
        Ok(Self {
            header,
            payload: data[16..len].to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct BindContext {
    pub iface: Uuid,
    pub iface_ver: u16,
    pub iface_ver_minor: u16,
    pub transfer_syntax: Uuid,
    pub transfer_ver: u32,
}

fn encode_bind(context: &BindContext, call_id: u32) -> DceRpcPdu {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x10u16.to_le_bytes()); // max xmit
    payload.extend_from_slice(&0x10u16.to_le_bytes()); // max recv
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(1); // num ctx
    payload.push(0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.push(0);
    payload.push(1); // num transfer syntaxes
    payload.extend_from_slice(&context.iface.encode_le());
    payload.extend_from_slice(&context.iface_ver.to_le_bytes());
    payload.extend_from_slice(&context.iface_ver_minor.to_le_bytes());
    payload.extend_from_slice(&context.transfer_syntax.encode_le());
    payload.extend_from_slice(&context.transfer_ver.to_le_bytes());

    let header = DceRpcHeader {
        version: 5,
        minor: 0,
        pdu_type: PduType::Bind,
        flags: 0x03,
        data_rep: [0x10, 0x00, 0x00, 0x00],
        frag_length: (16 + payload.len()) as u16,
        auth_length: 0,
        call_id,
    };
    DceRpcPdu { header, payload }
}

fn encode_bind_ack(call_id: u32) -> DceRpcPdu {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x10u16.to_le_bytes());
    payload.extend_from_slice(&0x10u16.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(1);
    payload.push(0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.push(0);
    payload.push(0); // acceptance

    let header = DceRpcHeader {
        version: 5,
        minor: 0,
        pdu_type: PduType::BindAck,
        flags: 0x03,
        data_rep: [0x10, 0x00, 0x00, 0x00],
        frag_length: (16 + payload.len()) as u16,
        auth_length: 0,
        call_id,
    };
    DceRpcPdu { header, payload }
}

fn encode_request(call_id: u32, opnum: u16, stub: &[u8]) -> DceRpcPdu {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(&opnum.to_le_bytes());
    payload.extend_from_slice(stub);
    let header = DceRpcHeader {
        version: 5,
        minor: 0,
        pdu_type: PduType::Request,
        flags: 0x03,
        data_rep: [0x10, 0x00, 0x00, 0x00],
        frag_length: (16 + payload.len()) as u16,
        auth_length: 0,
        call_id,
    };
    DceRpcPdu { header, payload }
}

fn decode_request(payload: &[u8]) -> CoreResult<(u16, Vec<u8>)> {
    if payload.len() < 8 {
        return Err(CoreError::Parse("dcerpc request short".to_string()));
    }
    let opnum = u16::from_le_bytes([payload[6], payload[7]]);
    Ok((opnum, payload[8..].to_vec()))
}

fn encode_response(call_id: u32, stub: &[u8]) -> DceRpcPdu {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.push(0);
    payload.push(0);
    payload.extend_from_slice(stub);
    let header = DceRpcHeader {
        version: 5,
        minor: 0,
        pdu_type: PduType::Response,
        flags: 0x03,
        data_rep: [0x10, 0x00, 0x00, 0x00],
        frag_length: (16 + payload.len()) as u16,
        auth_length: 0,
        call_id,
    };
    DceRpcPdu { header, payload }
}

pub trait DceRpcHandler: Send + Sync {
    fn call(&self, opnum: u16, stub: &[u8]) -> CoreResult<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct EchoDceRpcHandler;

impl DceRpcHandler for EchoDceRpcHandler {
    fn call(&self, _opnum: u16, stub: &[u8]) -> CoreResult<Vec<u8>> {
        Ok(stub.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct DceRpcServerConfig {
    pub timeouts: Timeouts,
}

impl Default for DceRpcServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct DceRpcServer {
    listener: TcpListener,
    handler: Arc<dyn DceRpcHandler>,
    config: DceRpcServerConfig,
}

impl DceRpcServer {
    pub fn bind(addr: SocketAddr, config: DceRpcServerConfig, handler: Arc<dyn DceRpcHandler>) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            handler,
            config,
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
                let _ = handle_dcerpc_stream(stream, handler, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncDceRpcServer {
    listener: tokio::net::TcpListener,
    handler: Arc<dyn DceRpcHandler>,
    config: DceRpcServerConfig,
}

impl AsyncDceRpcServer {
    pub async fn bind(addr: SocketAddr, config: DceRpcServerConfig, handler: Arc<dyn DceRpcHandler>) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            handler,
            config,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_dcerpc_stream_async(stream, handler, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct DceRpcClientConfig {
    pub timeouts: Timeouts,
}

impl Default for DceRpcClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct DceRpcClient {
    transport: TcpTransport,
    call_id: u32,
}

impl DceRpcClient {
    pub fn connect(addr: &net::NetAddr, config: DceRpcClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let context = BindContext {
            iface: Uuid([1; 16]),
            iface_ver: 1,
            iface_ver_minor: 0,
            transfer_syntax: Uuid([2; 16]),
            transfer_ver: 2,
        };
        let bind = encode_bind(&context, 1);
        write_pdu(&mut transport, &bind)?;
        let ack = read_pdu(&mut transport)?;
        if ack.header.pdu_type != PduType::BindAck {
            return Err(CoreError::Parse("dcerpc expected bind_ack".to_string()));
        }
        Ok(Self { transport, call_id: 1 })
    }

    pub fn request(&mut self, opnum: u16, stub: &[u8]) -> CoreResult<Vec<u8>> {
        self.call_id = self.call_id.wrapping_add(1);
        let pdu = encode_request(self.call_id, opnum, stub);
        write_pdu(&mut self.transport, &pdu)?;
        let resp = read_pdu(&mut self.transport)?;
        if resp.header.pdu_type != PduType::Response {
            return Err(CoreError::Parse("dcerpc expected response".to_string()));
        }
        Ok(resp.payload[8..].to_vec())
    }
}

pub struct AsyncDceRpcClient {
    transport: AsyncTcpTransport,
    call_id: u32,
}

impl AsyncDceRpcClient {
    pub async fn connect(addr: &net::NetAddr, config: DceRpcClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let context = BindContext {
            iface: Uuid([1; 16]),
            iface_ver: 1,
            iface_ver_minor: 0,
            transfer_syntax: Uuid([2; 16]),
            transfer_ver: 2,
        };
        let bind = encode_bind(&context, 1);
        write_pdu_async(&mut transport, &bind).await?;
        let ack = read_pdu_async(&mut transport).await?;
        if ack.header.pdu_type != PduType::BindAck {
            return Err(CoreError::Parse("dcerpc expected bind_ack".to_string()));
        }
        Ok(Self { transport, call_id: 1 })
    }

    pub async fn request(&mut self, opnum: u16, stub: &[u8]) -> CoreResult<Vec<u8>> {
        self.call_id = self.call_id.wrapping_add(1);
        let pdu = encode_request(self.call_id, opnum, stub);
        write_pdu_async(&mut self.transport, &pdu).await?;
        let resp = read_pdu_async(&mut self.transport).await?;
        if resp.header.pdu_type != PduType::Response {
            return Err(CoreError::Parse("dcerpc expected response".to_string()));
        }
        Ok(resp.payload[8..].to_vec())
    }
}

fn handle_dcerpc_stream(stream: TcpStream, handler: Arc<dyn DceRpcHandler>, config: DceRpcServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let pdu = read_pdu(&mut transport)?;
        match pdu.header.pdu_type {
            PduType::Bind => {
                let ack = encode_bind_ack(pdu.header.call_id);
                write_pdu(&mut transport, &ack)?;
            }
            PduType::Request => {
                let (opnum, stub) = decode_request(&pdu.payload)?;
                let response = handler.call(opnum, &stub)?;
                let resp_pdu = encode_response(pdu.header.call_id, &response);
                write_pdu(&mut transport, &resp_pdu)?;
            }
            _ => {}
        }
    }
}

async fn handle_dcerpc_stream_async(
    stream: tokio::net::TcpStream,
    handler: Arc<dyn DceRpcHandler>,
    _config: DceRpcServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let pdu = read_pdu_async(&mut transport).await?;
        match pdu.header.pdu_type {
            PduType::Bind => {
                let ack = encode_bind_ack(pdu.header.call_id);
                write_pdu_async(&mut transport, &ack).await?;
            }
            PduType::Request => {
                let (opnum, stub) = decode_request(&pdu.payload)?;
                let response = handler.call(opnum, &stub)?;
                let resp_pdu = encode_response(pdu.header.call_id, &response);
                write_pdu_async(&mut transport, &resp_pdu).await?;
            }
            _ => {}
        }
    }
}

fn read_pdu<T: StreamTransport>(transport: &mut T) -> CoreResult<DceRpcPdu> {
    let mut header = [0u8; 16];
    transport.read_exact(&mut header)?;
    let hdr = DceRpcHeader::decode(&header)?;
    let len = hdr.frag_length as usize;
    if len < 16 {
        return Err(CoreError::Parse("dcerpc invalid length".to_string()));
    }
    let mut payload = vec![0u8; len - 16];
    if !payload.is_empty() {
        transport.read_exact(&mut payload)?;
    }
    Ok(DceRpcPdu {
        header: hdr,
        payload,
    })
}

async fn read_pdu_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<DceRpcPdu> {
    let mut header = [0u8; 16];
    transport.read_exact(&mut header).await?;
    let hdr = DceRpcHeader::decode(&header)?;
    let len = hdr.frag_length as usize;
    if len < 16 {
        return Err(CoreError::Parse("dcerpc invalid length".to_string()));
    }
    let mut payload = vec![0u8; len - 16];
    if !payload.is_empty() {
        transport.read_exact(&mut payload).await?;
    }
    Ok(DceRpcPdu {
        header: hdr,
        payload,
    })
}

fn write_pdu<T: StreamTransport>(transport: &mut T, pdu: &DceRpcPdu) -> CoreResult<()> {
    transport.write_all(&pdu.encode())
}

async fn write_pdu_async<T: AsyncStreamTransport>(transport: &mut T, pdu: &DceRpcPdu) -> CoreResult<()> {
    transport.write_all(&pdu.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcerpc_bind_request() {
        let server = DceRpcServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            DceRpcServerConfig::default(),
            Arc::new(EchoDceRpcHandler),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut client = DceRpcClient::connect(&net::NetAddr::from_socket(addr), DceRpcClientConfig::default()).unwrap();
        let resp = client.request(0, b"ping").unwrap();
        assert_eq!(resp, b"ping".to_vec());

        drop(handle);
    }
}
