use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, AsyncUdpTransport, StreamTransport, TcpTransport, UdpTransport};
use crate::util::Timeouts;

const RPC_VERSION: u32 = 2;

const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;

const REPLY_ACCEPTED: u32 = 0;
const REPLY_DENIED: u32 = 1;

const ACCEPT_SUCCESS: u32 = 0;
const ACCEPT_PROG_UNAVAIL: u32 = 1;
const ACCEPT_PROC_UNAVAIL: u32 = 3;
const ACCEPT_GARBAGE_ARGS: u32 = 4;

const AUTH_NULL: u32 = 0;

#[derive(Debug, Clone)]
pub struct RpcAuth {
    pub flavor: u32,
    pub body: Vec<u8>,
}

impl RpcAuth {
    pub fn null() -> Self {
        Self {
            flavor: AUTH_NULL,
            body: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcCall {
    pub xid: u32,
    pub program: u32,
    pub version: u32,
    pub procedure: u32,
    pub cred: RpcAuth,
    pub verf: RpcAuth,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RpcReply {
    pub xid: u32,
    pub accepted: bool,
    pub accept_stat: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum RpcServiceResult {
    Success(Vec<u8>),
    ProcUnavailable,
    GarbageArgs,
}

pub trait RpcService: Send + Sync {
    fn call(&self, procedure: u32, payload: &[u8]) -> RpcServiceResult;
}

#[derive(Debug, Clone)]
pub struct RpcClientConfig {
    pub timeouts: Timeouts,
    pub use_tcp: bool,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            use_tcp: true,
        }
    }
}

pub struct RpcClient {
    transport: RpcTransport,
    xid: u32,
}

enum RpcTransport {
    Tcp(TcpTransport),
    Udp(UdpTransport, SocketAddr),
}

impl RpcClient {
    pub fn connect(addr: &NetAddr, config: RpcClientConfig) -> CoreResult<Self> {
        if config.use_tcp {
            let transport = TcpTransport::connect(addr, config.timeouts)?;
            Ok(Self {
                transport: RpcTransport::Tcp(transport),
                xid: 1,
            })
        } else {
            let socket = UdpTransport::bind_any()?;
            socket.set_read_timeout(Some(config.timeouts.read))?;
            let addr = addr.resolve()?.first().copied().ok_or_else(|| CoreError::Parse("no address".to_string()))?;
            Ok(Self {
                transport: RpcTransport::Udp(socket, addr),
                xid: 1,
            })
        }
    }

    pub fn call(
        &mut self,
        program: u32,
        version: u32,
        procedure: u32,
        payload: &[u8],
    ) -> CoreResult<Vec<u8>> {
        let xid = self.xid;
        self.xid = self.xid.wrapping_add(1);
        let call = RpcCall {
            xid,
            program,
            version,
            procedure,
            cred: RpcAuth::null(),
            verf: RpcAuth::null(),
            payload: payload.to_vec(),
        };
        let msg = encode_call(&call);
        match &mut self.transport {
            RpcTransport::Tcp(transport) => {
                write_record(transport, &msg)?;
                let data = read_record(transport)?;
                let reply = decode_reply(&data)?;
                if reply.accepted && reply.accept_stat == ACCEPT_SUCCESS {
                    Ok(reply.payload)
                } else {
                    Err(CoreError::Message("rpc call failed".to_string()))
                }
            }
            RpcTransport::Udp(socket, addr) => {
                socket.send_to(&msg, *addr)?;
                let (data, _) = socket.recv_from(4096)?;
                let reply = decode_reply(&data)?;
                if reply.accepted && reply.accept_stat == ACCEPT_SUCCESS {
                    Ok(reply.payload)
                } else {
                    Err(CoreError::Message("rpc call failed".to_string()))
                }
            }
        }
    }
}

pub struct AsyncRpcClient {
    transport: AsyncRpcTransport,
    xid: u32,
}

enum AsyncRpcTransport {
    Tcp(AsyncTcpTransport),
    Udp(AsyncUdpTransport, SocketAddr),
}

impl AsyncRpcClient {
    pub async fn connect(addr: &NetAddr, config: RpcClientConfig) -> CoreResult<Self> {
        if config.use_tcp {
            let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
            Ok(Self {
                transport: AsyncRpcTransport::Tcp(transport),
                xid: 1,
            })
        } else {
            let socket = AsyncUdpTransport::bind_any().await?;
            let addr = addr.resolve()?.first().copied().ok_or_else(|| CoreError::Parse("no address".to_string()))?;
            Ok(Self {
                transport: AsyncRpcTransport::Udp(socket, addr),
                xid: 1,
            })
        }
    }

    pub async fn call(
        &mut self,
        program: u32,
        version: u32,
        procedure: u32,
        payload: &[u8],
    ) -> CoreResult<Vec<u8>> {
        let xid = self.xid;
        self.xid = self.xid.wrapping_add(1);
        let call = RpcCall {
            xid,
            program,
            version,
            procedure,
            cred: RpcAuth::null(),
            verf: RpcAuth::null(),
            payload: payload.to_vec(),
        };
        let msg = encode_call(&call);
        match &mut self.transport {
            AsyncRpcTransport::Tcp(transport) => {
                write_record_async(transport, &msg).await?;
                let data = read_record_async(transport).await?;
                let reply = decode_reply(&data)?;
                if reply.accepted && reply.accept_stat == ACCEPT_SUCCESS {
                    Ok(reply.payload)
                } else {
                    Err(CoreError::Message("rpc call failed".to_string()))
                }
            }
            AsyncRpcTransport::Udp(socket, addr) => {
                socket.send_to(&msg, *addr).await?;
                let (data, _) = socket.recv_from(4096).await?;
                let reply = decode_reply(&data)?;
                if reply.accepted && reply.accept_stat == ACCEPT_SUCCESS {
                    Ok(reply.payload)
                } else {
                    Err(CoreError::Message("rpc call failed".to_string()))
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcServerConfig {
    pub timeouts: Timeouts,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct RpcServer {
    listener: TcpListener,
    services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>,
    config: RpcServerConfig,
}

impl RpcServer {
    pub fn bind(addr: SocketAddr, config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            services: Arc::new(services),
            config,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let services = Arc::clone(&self.services);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_tcp(stream, config, services);
            });
        }
        Ok(())
    }
}

pub struct AsyncRpcServer {
    listener: tokio::net::TcpListener,
    services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>,
    config: RpcServerConfig,
}

impl AsyncRpcServer {
    pub async fn bind(addr: SocketAddr, config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            services: Arc::new(services),
            config,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let services = Arc::clone(&self.services);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_tcp_async(stream, config, services).await;
            });
        }
    }
}

pub struct RpcUdpServer {
    socket: UdpTransport,
    services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>,
}

impl RpcUdpServer {
    pub fn bind(addr: SocketAddr, config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            services: Arc::new(services),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(4096)?;
            let services = Arc::clone(&self.services);
            let socket = self.socket.clone();
            thread::spawn(move || {
                let _ = handle_udp(socket, services, data, addr);
            });
        }
    }
}

pub struct AsyncRpcUdpServer {
    socket: AsyncUdpTransport,
    services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>,
}

impl AsyncRpcUdpServer {
    pub async fn bind(addr: SocketAddr, _config: RpcServerConfig, services: HashMap<(u32, u32), Arc<dyn RpcService>>) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            services: Arc::new(services),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(4096).await?;
            let services = Arc::clone(&self.services);
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_udp_async(socket, services, data, addr).await;
            });
        }
    }
}

fn handle_tcp(stream: TcpStream, config: RpcServerConfig, services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let data = match read_record(&mut transport) {
            Ok(data) => data,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let call = decode_call(&data)?;
        let reply = handle_call(&call, &services);
        let msg = encode_reply(&reply);
        write_record(&mut transport, &msg)?;
    }
}

async fn handle_tcp_async(
    stream: tokio::net::TcpStream,
    _config: RpcServerConfig,
    services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let data = match read_record_async(&mut transport).await {
            Ok(data) => data,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let call = decode_call(&data)?;
        let reply = handle_call(&call, &services);
        let msg = encode_reply(&reply);
        write_record_async(&mut transport, &msg).await?;
    }
}

fn handle_udp(
    socket: UdpTransport,
    services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>,
    data: Vec<u8>,
    addr: SocketAddr,
) -> CoreResult<()> {
    let call = decode_call(&data)?;
    let reply = handle_call(&call, &services);
    let msg = encode_reply(&reply);
    socket.send_to(&msg, addr)?;
    Ok(())
}

async fn handle_udp_async(
    socket: AsyncUdpTransport,
    services: Arc<HashMap<(u32, u32), Arc<dyn RpcService>>>,
    data: Vec<u8>,
    addr: SocketAddr,
) -> CoreResult<()> {
    let call = decode_call(&data)?;
    let reply = handle_call(&call, &services);
    let msg = encode_reply(&reply);
    socket.send_to(&msg, addr).await?;
    Ok(())
}

fn handle_call(call: &RpcCall, services: &HashMap<(u32, u32), Arc<dyn RpcService>>) -> RpcReply {
    let service = services.get(&(call.program, call.version));
    let (accepted, stat, payload) = if let Some(handler) = service {
        match handler.call(call.procedure, &call.payload) {
            RpcServiceResult::Success(payload) => (true, ACCEPT_SUCCESS, payload),
            RpcServiceResult::ProcUnavailable => (true, ACCEPT_PROC_UNAVAIL, Vec::new()),
            RpcServiceResult::GarbageArgs => (true, ACCEPT_GARBAGE_ARGS, Vec::new()),
        }
    } else {
        (true, ACCEPT_PROG_UNAVAIL, Vec::new())
    };
    RpcReply {
        xid: call.xid,
        accepted,
        accept_stat: stat,
        payload,
    }
}

fn encode_call(call: &RpcCall) -> Vec<u8> {
    let mut out = Vec::new();
    xdr_u32(&mut out, call.xid);
    xdr_u32(&mut out, MSG_CALL);
    xdr_u32(&mut out, RPC_VERSION);
    xdr_u32(&mut out, call.program);
    xdr_u32(&mut out, call.version);
    xdr_u32(&mut out, call.procedure);
    xdr_auth(&mut out, &call.cred);
    xdr_auth(&mut out, &call.verf);
    out.extend_from_slice(&call.payload);
    out
}

fn decode_call(data: &[u8]) -> CoreResult<RpcCall> {
    let mut cursor = XdrCursor::new(data);
    let xid = cursor.read_u32()?;
    let msg_type = cursor.read_u32()?;
    if msg_type != MSG_CALL {
        return Err(CoreError::Parse("not an rpc call".to_string()));
    }
    let rpcvers = cursor.read_u32()?;
    if rpcvers != RPC_VERSION {
        return Err(CoreError::Parse("unsupported rpc version".to_string()));
    }
    let program = cursor.read_u32()?;
    let version = cursor.read_u32()?;
    let procedure = cursor.read_u32()?;
    let cred = cursor.read_auth()?;
    let verf = cursor.read_auth()?;
    let payload = cursor.read_remaining();
    Ok(RpcCall {
        xid,
        program,
        version,
        procedure,
        cred,
        verf,
        payload,
    })
}

fn encode_reply(reply: &RpcReply) -> Vec<u8> {
    let mut out = Vec::new();
    xdr_u32(&mut out, reply.xid);
    xdr_u32(&mut out, MSG_REPLY);
    if reply.accepted {
        xdr_u32(&mut out, REPLY_ACCEPTED);
        xdr_auth(&mut out, &RpcAuth::null());
        xdr_u32(&mut out, reply.accept_stat);
        if reply.accept_stat == ACCEPT_SUCCESS {
            out.extend_from_slice(&reply.payload);
        }
    } else {
        xdr_u32(&mut out, REPLY_DENIED);
    }
    out
}

fn decode_reply(data: &[u8]) -> CoreResult<RpcReply> {
    let mut cursor = XdrCursor::new(data);
    let xid = cursor.read_u32()?;
    let msg_type = cursor.read_u32()?;
    if msg_type != MSG_REPLY {
        return Err(CoreError::Parse("not an rpc reply".to_string()));
    }
    let reply_stat = cursor.read_u32()?;
    if reply_stat == REPLY_ACCEPTED {
        let _verf = cursor.read_auth()?;
        let accept_stat = cursor.read_u32()?;
        let payload = cursor.read_remaining();
        Ok(RpcReply {
            xid,
            accepted: true,
            accept_stat,
            payload,
        })
    } else {
        Ok(RpcReply {
            xid,
            accepted: false,
            accept_stat: 0,
            payload: Vec::new(),
        })
    }
}

fn xdr_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn xdr_auth(out: &mut Vec<u8>, auth: &RpcAuth) {
    xdr_u32(out, auth.flavor);
    xdr_opaque(out, &auth.body);
}

fn xdr_opaque(out: &mut Vec<u8>, data: &[u8]) {
    xdr_u32(out, data.len() as u32);
    out.extend_from_slice(data);
    let pad = (4 - (data.len() % 4)) % 4;
    for _ in 0..pad {
        out.push(0);
    }
}

struct XdrCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> XdrCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u32(&mut self) -> CoreResult<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(CoreError::Parse("xdr eof".to_string()));
        }
        let out = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(out)
    }

    fn read_opaque(&mut self) -> CoreResult<Vec<u8>> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.data.len() {
            return Err(CoreError::Parse("xdr opaque out of bounds".to_string()));
        }
        let out = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        let pad = (4 - (len % 4)) % 4;
        self.pos = self.pos.saturating_add(pad);
        Ok(out)
    }

    fn read_auth(&mut self) -> CoreResult<RpcAuth> {
        let flavor = self.read_u32()?;
        let body = self.read_opaque()?;
        Ok(RpcAuth { flavor, body })
    }

    fn read_remaining(&self) -> Vec<u8> {
        self.data[self.pos..].to_vec()
    }
}

fn write_record(transport: &mut TcpTransport, data: &[u8]) -> CoreResult<()> {
    let mut out = Vec::with_capacity(4 + data.len());
    let header = 0x80000000u32 | (data.len() as u32);
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(data);
    transport.write_all(&out)
}

async fn write_record_async(transport: &mut AsyncTcpTransport, data: &[u8]) -> CoreResult<()> {
    let mut out = Vec::with_capacity(4 + data.len());
    let header = 0x80000000u32 | (data.len() as u32);
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(data);
    transport.write_all(&out).await
}

fn read_record(transport: &mut TcpTransport) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut header = [0u8; 4];
        transport.read_exact(&mut header)?;
        let value = u32::from_be_bytes(header);
        let last = (value & 0x80000000) != 0;
        let len = (value & 0x7FFFFFFF) as usize;
        let mut buf = vec![0u8; len];
        transport.read_exact(&mut buf)?;
        out.extend_from_slice(&buf);
        if last {
            break;
        }
    }
    Ok(out)
}

async fn read_record_async(transport: &mut AsyncTcpTransport) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut header = [0u8; 4];
        transport.read_exact(&mut header).await?;
        let value = u32::from_be_bytes(header);
        let last = (value & 0x80000000) != 0;
        let len = (value & 0x7FFFFFFF) as usize;
        let mut buf = vec![0u8; len];
        transport.read_exact(&mut buf).await?;
        out.extend_from_slice(&buf);
        if last {
            break;
        }
    }
    Ok(out)
}

#[derive(Debug, Default)]
pub struct PortmapRegistry {
    entries: HashMap<(u32, u32, u32), u32>,
}

impl PortmapRegistry {
    pub fn set(&mut self, program: u32, version: u32, protocol: u32, port: u32) {
        self.entries.insert((program, version, protocol), port);
    }

    pub fn get(&self, program: u32, version: u32, protocol: u32) -> u32 {
        *self.entries.get(&(program, version, protocol)).unwrap_or(&0)
    }
}

pub struct PortmapService {
    registry: Arc<std::sync::Mutex<PortmapRegistry>>,
}

impl PortmapService {
    pub fn new(registry: Arc<std::sync::Mutex<PortmapRegistry>>) -> Self {
        Self { registry }
    }
}

impl RpcService for PortmapService {
    fn call(&self, procedure: u32, payload: &[u8]) -> RpcServiceResult {
        let mut cursor = XdrCursor::new(payload);
        match procedure {
            1 => {
                let program = cursor.read_u32().unwrap_or(0);
                let version = cursor.read_u32().unwrap_or(0);
                let protocol = cursor.read_u32().unwrap_or(0);
                let port = cursor.read_u32().unwrap_or(0);
                if let Ok(mut guard) = self.registry.lock() {
                    guard.set(program, version, protocol, port);
                }
                RpcServiceResult::Success(encode_u32(1))
            }
            3 => {
                let program = cursor.read_u32().unwrap_or(0);
                let version = cursor.read_u32().unwrap_or(0);
                let protocol = cursor.read_u32().unwrap_or(0);
                let port = if let Ok(guard) = self.registry.lock() {
                    guard.get(program, version, protocol)
                } else {
                    0
                };
                RpcServiceResult::Success(encode_u32(port))
            }
            _ => RpcServiceResult::ProcUnavailable,
        }
    }
}

fn encode_u32(value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    xdr_u32(&mut out, value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoService;

    impl RpcService for EchoService {
        fn call(&self, procedure: u32, payload: &[u8]) -> RpcServiceResult {
            if procedure == 1 {
                RpcServiceResult::Success(payload.to_vec())
            } else {
                RpcServiceResult::ProcUnavailable
            }
        }
    }

    #[test]
    fn rpc_tcp_roundtrip() {
        let mut services = HashMap::new();
        services.insert((0x20000001, 1), Arc::new(EchoService) as Arc<dyn RpcService>);
        let server = RpcServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            RpcServerConfig::default(),
            services,
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        let mut client = RpcClient::connect(&NetAddr::from_socket(addr), RpcClientConfig::default()).unwrap();
        let payload = xdr_string("hello");
        let response = client.call(0x20000001, 1, 1, &payload).unwrap();
        assert_eq!(response, payload);
    }

    #[test]
    fn rpc_udp_roundtrip() {
        let mut services = HashMap::new();
        services.insert((0x20000002, 1), Arc::new(EchoService) as Arc<dyn RpcService>);
        let server = RpcUdpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            RpcServerConfig::default(),
            services,
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        let mut client = RpcClient::connect(&NetAddr::from_socket(addr), RpcClientConfig { use_tcp: false, ..Default::default() }).unwrap();
        let payload = xdr_string("hello");
        let response = client.call(0x20000002, 1, 1, &payload).unwrap();
        assert_eq!(response, payload);
    }

    #[test]
    fn portmap_getport() {
        let registry = Arc::new(std::sync::Mutex::new(PortmapRegistry::default()));
        let service = Arc::new(PortmapService::new(registry.clone())) as Arc<dyn RpcService>;
        let mut services = HashMap::new();
        services.insert((100000, 2), service);
        let server = RpcServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            RpcServerConfig::default(),
            services,
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        let mut client = RpcClient::connect(&NetAddr::from_socket(addr), RpcClientConfig::default()).unwrap();
        let mut payload = Vec::new();
        xdr_u32(&mut payload, 200);
        xdr_u32(&mut payload, 1);
        xdr_u32(&mut payload, 6);
        xdr_u32(&mut payload, 9999);
        let _ = client.call(100000, 2, 1, &payload).unwrap();
        let mut get = Vec::new();
        xdr_u32(&mut get, 200);
        xdr_u32(&mut get, 1);
        xdr_u32(&mut get, 6);
        xdr_u32(&mut get, 0);
        let response = client.call(100000, 2, 3, &get).unwrap();
        let mut cursor = XdrCursor::new(&response);
        assert_eq!(cursor.read_u32().unwrap(), 9999);
    }
}

fn xdr_string(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    xdr_opaque(&mut out, value.as_bytes());
    out
}
