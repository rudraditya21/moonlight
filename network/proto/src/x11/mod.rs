use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const X11_MAJOR_VERSION: u16 = 11;
const X11_MINOR_VERSION: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn from_byte(value: u8) -> CoreResult<Self> {
        match value {
            b'l' => Ok(ByteOrder::Little),
            b'B' => Ok(ByteOrder::Big),
            _ => Err(CoreError::Parse("invalid X11 byte order".to_string())),
        }
    }

    fn encode_u16(self, value: u16) -> [u8; 2] {
        match self {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        }
    }

    fn encode_u32(self, value: u32) -> [u8; 4] {
        match self {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        }
    }

    fn decode_u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            ByteOrder::Little => u16::from_le_bytes(bytes),
            ByteOrder::Big => u16::from_be_bytes(bytes),
        }
    }

    fn decode_u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            ByteOrder::Little => u32::from_le_bytes(bytes),
            ByteOrder::Big => u32::from_be_bytes(bytes),
        }
    }
}

#[derive(Debug, Clone)]
pub struct X11ClientConfig {
    pub timeouts: Timeouts,
}

impl Default for X11ClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct X11Client {
    transport: TcpTransport,
    order: ByteOrder,
    seq: u16,
    resource_id_base: u32,
}

impl X11Client {
    pub fn connect(addr: &NetAddr, config: X11ClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self {
            transport,
            order: ByteOrder::Little,
            seq: 1,
            resource_id_base: 0,
        })
    }

    pub fn handshake(&mut self) -> CoreResult<()> {
        let request = X11SetupRequest::new(self.order);
        self.transport.write_all(&request.encode())?;
        let reply = read_setup_reply(&mut self.transport, self.order)?;
        self.resource_id_base = reply.resource_id_base;
        Ok(())
    }

    pub fn intern_atom(&mut self, name: &str) -> CoreResult<u32> {
        let request = X11Request::InternAtom {
            only_if_exists: false,
            name: name.to_string(),
        };
        let payload = request.encode(self.order);
        self.send_request(&payload)?;
        let reply = read_reply(&mut self.transport, self.order)?;
        let atom = self.order.decode_u32([reply[8], reply[9], reply[10], reply[11]]);
        Ok(atom)
    }

    pub fn create_window(&mut self, parent: u32, width: u16, height: u16) -> CoreResult<u32> {
        let window_id = self.resource_id_base.wrapping_add(self.seq as u32);
        let request = X11Request::CreateWindow {
            window_id,
            parent,
            width,
            height,
        };
        let payload = request.encode(self.order);
        self.send_request(&payload)?;
        Ok(window_id)
    }

    pub fn map_window(&mut self, window_id: u32) -> CoreResult<()> {
        let request = X11Request::MapWindow { window_id };
        let payload = request.encode(self.order);
        self.send_request(&payload)?;
        Ok(())
    }

    pub fn change_property(&mut self, window_id: u32, property: u32, data: &[u8]) -> CoreResult<()> {
        let request = X11Request::ChangeProperty {
            window_id,
            property,
            data: data.to_vec(),
        };
        let payload = request.encode(self.order);
        self.send_request(&payload)?;
        Ok(())
    }

    pub fn get_property(&mut self, window_id: u32, property: u32) -> CoreResult<Vec<u8>> {
        let request = X11Request::GetProperty {
            window_id,
            property,
        };
        let payload = request.encode(self.order);
        self.send_request(&payload)?;
        let reply = read_reply(&mut self.transport, self.order)?;
        let len = self.order.decode_u32([reply[16], reply[17], reply[18], reply[19]]) as usize;
        let format = reply[1];
        if format == 0 {
            return Ok(Vec::new());
        }
        let data_len = match format {
            8 => len,
            16 => len * 2,
            32 => len * 4,
            _ => 0,
        };
        Ok(reply[32..32 + data_len].to_vec())
    }

    pub fn query_extension(&mut self, name: &str) -> CoreResult<bool> {
        let request = X11Request::QueryExtension { name: name.to_string() };
        let payload = request.encode(self.order);
        self.send_request(&payload)?;
        let reply = read_reply(&mut self.transport, self.order)?;
        Ok(reply[8] != 0)
    }

    fn send_request(&mut self, payload: &[u8]) -> CoreResult<()> {
        self.transport.write_all(payload)?;
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }
}

pub struct AsyncX11Client {
    transport: AsyncTcpTransport,
    order: ByteOrder,
    seq: u16,
    resource_id_base: u32,
}

impl AsyncX11Client {
    pub async fn connect(addr: &NetAddr, config: X11ClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self {
            transport,
            order: ByteOrder::Little,
            seq: 1,
            resource_id_base: 0,
        })
    }

    pub async fn handshake(&mut self) -> CoreResult<()> {
        let request = X11SetupRequest::new(self.order);
        self.transport.write_all(&request.encode()).await?;
        let reply = read_setup_reply_async(&mut self.transport, self.order).await?;
        self.resource_id_base = reply.resource_id_base;
        Ok(())
    }

    pub async fn intern_atom(&mut self, name: &str) -> CoreResult<u32> {
        let request = X11Request::InternAtom {
            only_if_exists: false,
            name: name.to_string(),
        };
        let payload = request.encode(self.order);
        self.send_request(&payload).await?;
        let reply = read_reply_async(&mut self.transport, self.order).await?;
        let atom = self.order.decode_u32([reply[8], reply[9], reply[10], reply[11]]);
        Ok(atom)
    }

    pub async fn create_window(&mut self, parent: u32, width: u16, height: u16) -> CoreResult<u32> {
        let window_id = self.resource_id_base.wrapping_add(self.seq as u32);
        let request = X11Request::CreateWindow {
            window_id,
            parent,
            width,
            height,
        };
        let payload = request.encode(self.order);
        self.send_request(&payload).await?;
        Ok(window_id)
    }

    pub async fn map_window(&mut self, window_id: u32) -> CoreResult<()> {
        let request = X11Request::MapWindow { window_id };
        let payload = request.encode(self.order);
        self.send_request(&payload).await?;
        Ok(())
    }

    pub async fn change_property(&mut self, window_id: u32, property: u32, data: &[u8]) -> CoreResult<()> {
        let request = X11Request::ChangeProperty {
            window_id,
            property,
            data: data.to_vec(),
        };
        let payload = request.encode(self.order);
        self.send_request(&payload).await?;
        Ok(())
    }

    pub async fn get_property(&mut self, window_id: u32, property: u32) -> CoreResult<Vec<u8>> {
        let request = X11Request::GetProperty {
            window_id,
            property,
        };
        let payload = request.encode(self.order);
        self.send_request(&payload).await?;
        let reply = read_reply_async(&mut self.transport, self.order).await?;
        let len = self.order.decode_u32([reply[16], reply[17], reply[18], reply[19]]) as usize;
        let format = reply[1];
        if format == 0 {
            return Ok(Vec::new());
        }
        let data_len = match format {
            8 => len,
            16 => len * 2,
            32 => len * 4,
            _ => 0,
        };
        Ok(reply[32..32 + data_len].to_vec())
    }

    pub async fn query_extension(&mut self, name: &str) -> CoreResult<bool> {
        let request = X11Request::QueryExtension { name: name.to_string() };
        let payload = request.encode(self.order);
        self.send_request(&payload).await?;
        let reply = read_reply_async(&mut self.transport, self.order).await?;
        Ok(reply[8] != 0)
    }

    async fn send_request(&mut self, payload: &[u8]) -> CoreResult<()> {
        self.transport.write_all(payload).await?;
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct X11ServerConfig {
    pub timeouts: Timeouts,
}

impl Default for X11ServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct X11Property {
    prop_type: u32,
    format: u8,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct X11State {
    next_resource: u32,
    atoms: HashMap<String, u32>,
    atom_names: HashMap<u32, String>,
    windows: HashMap<u32, HashMap<u32, X11Property>>,
}

impl X11State {
    fn new() -> Self {
        Self {
            next_resource: 0x10000000,
            atoms: HashMap::new(),
            atom_names: HashMap::new(),
            windows: HashMap::new(),
        }
    }

    fn intern_atom(&mut self, name: &str) -> u32 {
        if let Some(atom) = self.atoms.get(name) {
            return *atom;
        }
        let atom = self.next_resource;
        self.next_resource = self.next_resource.wrapping_add(1);
        self.atoms.insert(name.to_string(), atom);
        self.atom_names.insert(atom, name.to_string());
        atom
    }
}

pub struct X11Server {
    listener: TcpListener,
    config: X11ServerConfig,
    state: Arc<Mutex<X11State>>,
}

impl X11Server {
    pub fn bind(addr: SocketAddr, config: X11ServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            state: Arc::new(Mutex::new(X11State::new())),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let config = self.config.clone();
            let state = Arc::clone(&self.state);
            thread::spawn(move || {
                let _ = handle_connection(stream, config, state);
            });
        }
        Ok(())
    }
}

pub struct AsyncX11Server {
    listener: tokio::net::TcpListener,
    config: X11ServerConfig,
    state: Arc<Mutex<X11State>>,
}

impl AsyncX11Server {
    pub async fn bind(addr: SocketAddr, config: X11ServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            state: Arc::new(Mutex::new(X11State::new())),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let _ = handle_connection_async(stream, config, state).await;
            });
        }
    }
}

fn handle_connection(stream: TcpStream, config: X11ServerConfig, state: Arc<Mutex<X11State>>) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let (order, setup) = read_setup_request(&mut transport)?;
    let reply = X11SetupReply::new(order, setup);
    transport.write_all(&reply.encode(order))?;
    let mut seq = 1u16;
    loop {
        let (opcode, data, payload) = match read_request(&mut transport, order) {
            Ok(msg) => msg,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let response = handle_request(opcode, data, &payload, order, seq, &state)?;
        if let Some(reply) = response {
            transport.write_all(&reply)?;
        }
        seq = seq.wrapping_add(1);
    }
}

async fn handle_connection_async(
    stream: tokio::net::TcpStream,
    _config: X11ServerConfig,
    state: Arc<Mutex<X11State>>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let (order, setup) = read_setup_request_async(&mut transport).await?;
    let reply = X11SetupReply::new(order, setup);
    transport.write_all(&reply.encode(order)).await?;
    let mut seq = 1u16;
    loop {
        let (opcode, data, payload) = match read_request_async(&mut transport, order).await {
            Ok(msg) => msg,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let response = handle_request(opcode, data, &payload, order, seq, &state)?;
        if let Some(reply) = response {
            transport.write_all(&reply).await?;
        }
        seq = seq.wrapping_add(1);
    }
}

fn handle_request(
    opcode: u8,
    _data: u8,
    payload: &[u8],
    order: ByteOrder,
    seq: u16,
    state: &Arc<Mutex<X11State>>,
) -> CoreResult<Option<Vec<u8>>> {
    match opcode {
        1 => {
            let window_id = order.decode_u32([payload[0], payload[1], payload[2], payload[3]]);
            let mut guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            guard.windows.entry(window_id).or_insert_with(HashMap::new);
            Ok(None)
        }
        8 => Ok(None),
        16 => {
            let name_len = order.decode_u16([payload[0], payload[1]]) as usize;
            let name = std::str::from_utf8(&payload[4..4 + name_len])
                .map_err(|_| CoreError::Parse("invalid atom name".to_string()))?;
            let mut guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            let atom = guard.intern_atom(name);
            let reply = encode_intern_atom_reply(order, seq, atom);
            Ok(Some(reply))
        }
        18 => {
            let window_id = order.decode_u32([payload[0], payload[1], payload[2], payload[3]]);
            let property = order.decode_u32([payload[4], payload[5], payload[6], payload[7]]);
            let prop_type = order.decode_u32([payload[8], payload[9], payload[10], payload[11]]);
            let format = payload[12];
            let data_len = order.decode_u32([payload[16], payload[17], payload[18], payload[19]]) as usize;
            let bytes = match format {
                8 => data_len,
                16 => data_len * 2,
                32 => data_len * 4,
                _ => 0,
            };
            let mut guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            let window = guard.windows.entry(window_id).or_insert_with(HashMap::new);
            window.insert(
                property,
                X11Property {
                    prop_type,
                    format,
                    data: payload[20..20 + bytes].to_vec(),
                },
            );
            Ok(None)
        }
        20 => {
            let window_id = order.decode_u32([payload[0], payload[1], payload[2], payload[3]]);
            let property = order.decode_u32([payload[4], payload[5], payload[6], payload[7]]);
            let guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            let value = guard
                .windows
                .get(&window_id)
                .and_then(|props| props.get(&property))
                .cloned();
            let reply = encode_get_property_reply(order, seq, value);
            Ok(Some(reply))
        }
        98 => Ok(Some(encode_query_extension_reply(order, seq, false))),
        _ => Ok(None),
    }
}

#[derive(Debug, Clone)]
struct X11SetupRequest {
    order: ByteOrder,
}

impl X11SetupRequest {
    fn new(order: ByteOrder) -> Self {
        Self { order }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(match self.order {
            ByteOrder::Little => b'l',
            ByteOrder::Big => b'B',
        });
        out.push(0);
        out.extend_from_slice(&self.order.encode_u16(X11_MAJOR_VERSION));
        out.extend_from_slice(&self.order.encode_u16(X11_MINOR_VERSION));
        out.extend_from_slice(&self.order.encode_u16(0));
        out.extend_from_slice(&self.order.encode_u16(0));
        out.extend_from_slice(&self.order.encode_u16(0));
        out
    }
}

#[derive(Debug, Clone)]
struct X11SetupReply {
    resource_id_base: u32,
    resource_id_mask: u32,
}

impl X11SetupReply {
    fn new(order: ByteOrder, _request: X11SetupRequest) -> Self {
        let _ = order;
        Self {
            resource_id_base: 0x10000000,
            resource_id_mask: 0x0FFFFFFF,
        }
    }

    fn encode(&self, order: ByteOrder) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1);
        out.push(0);
        out.extend_from_slice(&order.encode_u16(X11_MAJOR_VERSION));
        out.extend_from_slice(&order.encode_u16(X11_MINOR_VERSION));
        out.extend_from_slice(&order.encode_u16(0));
        out.extend_from_slice(&order.encode_u32(1));
        out.extend_from_slice(&order.encode_u32(self.resource_id_base));
        out.extend_from_slice(&order.encode_u32(self.resource_id_mask));
        out.extend_from_slice(&order.encode_u32(0));
        out.extend_from_slice(&order.encode_u16(0));
        out.extend_from_slice(&order.encode_u16(0));
        out.push(1);
        out.push(0);
        out.push(0);
        out.push(0);
        out.push(8);
        out.push(8);
        out.extend_from_slice(&[0u8; 4]);
        while out.len() < 40 {
            out.push(0);
        }
        out
    }
}

enum X11Request {
    CreateWindow {
        window_id: u32,
        parent: u32,
        width: u16,
        height: u16,
    },
    MapWindow {
        window_id: u32,
    },
    InternAtom {
        only_if_exists: bool,
        name: String,
    },
    ChangeProperty {
        window_id: u32,
        property: u32,
        data: Vec<u8>,
    },
    GetProperty {
        window_id: u32,
        property: u32,
    },
    QueryExtension {
        name: String,
    },
}

impl X11Request {
    fn encode(&self, order: ByteOrder) -> Vec<u8> {
        match self {
            X11Request::CreateWindow {
                window_id,
                parent,
                width,
                height,
            } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&order.encode_u32(*window_id));
                payload.extend_from_slice(&order.encode_u32(*parent));
                payload.extend_from_slice(&order.encode_u16(0));
                payload.extend_from_slice(&order.encode_u16(0));
                payload.extend_from_slice(&order.encode_u16(*width));
                payload.extend_from_slice(&order.encode_u16(*height));
                payload.extend_from_slice(&order.encode_u16(0));
                payload.extend_from_slice(&order.encode_u16(0));
                payload.extend_from_slice(&order.encode_u32(0));
                payload.extend_from_slice(&order.encode_u32(0));
                wrap_request(order, 1, 0, payload)
            }
            X11Request::MapWindow { window_id } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&order.encode_u32(*window_id));
                wrap_request(order, 8, 0, payload)
            }
            X11Request::InternAtom {
                only_if_exists,
                name,
            } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&order.encode_u16(name.len() as u16));
                payload.extend_from_slice(&[0u8; 2]);
                payload.extend_from_slice(name.as_bytes());
                pad_to_4(&mut payload);
                wrap_request(order, 16, if *only_if_exists { 1 } else { 0 }, payload)
            }
            X11Request::ChangeProperty {
                window_id,
                property,
                data,
            } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&order.encode_u32(*window_id));
                payload.extend_from_slice(&order.encode_u32(*property));
                payload.extend_from_slice(&order.encode_u32(*property));
                payload.push(8);
                payload.extend_from_slice(&[0u8; 3]);
                payload.extend_from_slice(&order.encode_u32(data.len() as u32));
                payload.extend_from_slice(data);
                pad_to_4(&mut payload);
                wrap_request(order, 18, 0, payload)
            }
            X11Request::GetProperty { window_id, property } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&order.encode_u32(*window_id));
                payload.extend_from_slice(&order.encode_u32(*property));
                payload.extend_from_slice(&order.encode_u32(0));
                payload.extend_from_slice(&order.encode_u32(0));
                payload.extend_from_slice(&order.encode_u32(0xFFFFFFFF));
                wrap_request(order, 20, 0, payload)
            }
            X11Request::QueryExtension { name } => {
                let mut payload = Vec::new();
                payload.extend_from_slice(&order.encode_u16(name.len() as u16));
                payload.extend_from_slice(&[0u8; 2]);
                payload.extend_from_slice(name.as_bytes());
                pad_to_4(&mut payload);
                wrap_request(order, 98, 0, payload)
            }
        }
    }
}

fn wrap_request(order: ByteOrder, opcode: u8, data: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(opcode);
    out.push(data);
    let length = ((payload.len() + 4) / 4) as u16;
    out.extend_from_slice(&order.encode_u16(length));
    out.extend_from_slice(&payload);
    out
}

fn read_setup_request(transport: &mut TcpTransport) -> CoreResult<(ByteOrder, X11SetupRequest)> {
    let mut header = [0u8; 12];
    transport.read_exact(&mut header)?;
    let order = ByteOrder::from_byte(header[0])?;
    Ok((order, X11SetupRequest::new(order)))
}

async fn read_setup_request_async(transport: &mut AsyncTcpTransport) -> CoreResult<(ByteOrder, X11SetupRequest)> {
    let mut header = [0u8; 12];
    transport.read_exact(&mut header).await?;
    let order = ByteOrder::from_byte(header[0])?;
    Ok((order, X11SetupRequest::new(order)))
}

fn read_setup_reply(transport: &mut TcpTransport, order: ByteOrder) -> CoreResult<X11SetupReply> {
    let mut header = [0u8; 40];
    transport.read_exact(&mut header)?;
    let resource_id_base = order.decode_u32([header[12], header[13], header[14], header[15]]);
    let resource_id_mask = order.decode_u32([header[16], header[17], header[18], header[19]]);
    Ok(X11SetupReply {
        resource_id_base,
        resource_id_mask,
    })
}

async fn read_setup_reply_async(transport: &mut AsyncTcpTransport, order: ByteOrder) -> CoreResult<X11SetupReply> {
    let mut header = [0u8; 40];
    transport.read_exact(&mut header).await?;
    let resource_id_base = order.decode_u32([header[12], header[13], header[14], header[15]]);
    let resource_id_mask = order.decode_u32([header[16], header[17], header[18], header[19]]);
    Ok(X11SetupReply {
        resource_id_base,
        resource_id_mask,
    })
}

fn read_request(transport: &mut TcpTransport, order: ByteOrder) -> CoreResult<(u8, u8, Vec<u8>)> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header)?;
    let opcode = header[0];
    let data = header[1];
    let length = order.decode_u16([header[2], header[3]]) as usize;
    let payload_len = length * 4 - 4;
    let mut payload = vec![0u8; payload_len];
    transport.read_exact(&mut payload)?;
    Ok((opcode, data, payload))
}

async fn read_request_async(transport: &mut AsyncTcpTransport, order: ByteOrder) -> CoreResult<(u8, u8, Vec<u8>)> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header).await?;
    let opcode = header[0];
    let data = header[1];
    let length = order.decode_u16([header[2], header[3]]) as usize;
    let payload_len = length * 4 - 4;
    let mut payload = vec![0u8; payload_len];
    transport.read_exact(&mut payload).await?;
    Ok((opcode, data, payload))
}

fn read_reply(transport: &mut TcpTransport, order: ByteOrder) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 32];
    transport.read_exact(&mut header)?;
    let length = order.decode_u32([header[4], header[5], header[6], header[7]]) as usize;
    let mut extra = vec![0u8; length * 4];
    if !extra.is_empty() {
        transport.read_exact(&mut extra)?;
    }
    let mut out = header.to_vec();
    out.extend_from_slice(&extra);
    Ok(out)
}

async fn read_reply_async(transport: &mut AsyncTcpTransport, order: ByteOrder) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 32];
    transport.read_exact(&mut header).await?;
    let length = order.decode_u32([header[4], header[5], header[6], header[7]]) as usize;
    let mut extra = vec![0u8; length * 4];
    if !extra.is_empty() {
        transport.read_exact(&mut extra).await?;
    }
    let mut out = header.to_vec();
    out.extend_from_slice(&extra);
    Ok(out)
}

fn encode_intern_atom_reply(order: ByteOrder, seq: u16, atom: u32) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[0] = 1;
    out[1] = 0;
    out[2..4].copy_from_slice(&order.encode_u16(seq));
    out[4..8].copy_from_slice(&order.encode_u32(0));
    out[8..12].copy_from_slice(&order.encode_u32(atom));
    out
}

fn encode_get_property_reply(order: ByteOrder, seq: u16, value: Option<X11Property>) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[0] = 1;
    out[2..4].copy_from_slice(&order.encode_u16(seq));
    if let Some(prop) = value {
        out[1] = prop.format;
        out[4..8].copy_from_slice(&order.encode_u32(((prop.data.len() + 3) / 4) as u32));
        out[8..12].copy_from_slice(&order.encode_u32(prop.prop_type));
        let units = match prop.format {
            8 => prop.data.len() as u32,
            16 => (prop.data.len() / 2) as u32,
            32 => (prop.data.len() / 4) as u32,
            _ => 0,
        };
        out[16..20].copy_from_slice(&order.encode_u32(units));
        let mut data = prop.data;
        pad_to_4(&mut data);
        out.extend_from_slice(&data);
    }
    out
}

fn encode_query_extension_reply(order: ByteOrder, seq: u16, present: bool) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[0] = 1;
    out[1] = if present { 1 } else { 0 };
    out[2..4].copy_from_slice(&order.encode_u16(seq));
    out[4..8].copy_from_slice(&order.encode_u32(0));
    out
}

fn pad_to_4(buf: &mut Vec<u8>) {
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x11_roundtrip() {
        let server = X11Server::bind("127.0.0.1:0".parse().unwrap(), X11ServerConfig::default()).unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = X11Client::connect(&NetAddr::from_socket(addr), X11ClientConfig::default()).unwrap();
        client.handshake().unwrap();
        let atom = client.intern_atom("XTEST").unwrap();
        let window = client.create_window(1, 100, 100).unwrap();
        client.change_property(window, atom, b"hello").unwrap();
        let data = client.get_property(window, atom).unwrap();
        assert_eq!(data, b"hello".to_vec());
        let present = client.query_extension("RANDR").unwrap();
        assert!(!present);
    }
}
