use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

pub const KADEMLIA_DEFAULT_PORT: u16 = 6881;

const MAX_DEPTH: usize = 32;
const NODE_ID_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; NODE_ID_LEN]);

impl NodeId {
    pub fn from_seed(seed: u64) -> Self {
        let mut out = [0u8; NODE_ID_LEN];
        let mut x = seed ^ 0x9e3779b97f4a7c15;
        for byte in &mut out {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x = x.wrapping_mul(0x2545f4914f6cdd1d);
            *byte = (x & 0xFF) as u8;
        }
        Self(out)
    }

    pub fn xor_distance(&self, other: &NodeId) -> [u8; NODE_ID_LEN] {
        let mut out = [0u8; NODE_ID_LEN];
        for i in 0..NODE_ID_LEN {
            out[i] = self.0[i] ^ other.0[i];
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct KademliaConfig {
    pub timeouts: Timeouts,
    pub node_id: NodeId,
    pub k_bucket_size: usize,
    pub allow_store_without_token: bool,
    pub secret: [u8; 20],
}

impl Default for KademliaConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            node_id: NodeId::from_seed(0xdead_beef),
            k_bucket_size: 16,
            allow_store_without_token: true,
            secret: [0u8; 20],
        }
    }
}

pub trait KademliaStore: Send + Sync {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn put(&self, key: Vec<u8>, value: Vec<u8>);
}

#[derive(Debug, Default)]
pub struct InMemoryStore {
    map: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl KademliaStore for InMemoryStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.map.lock().ok().and_then(|m| m.get(key).cloned())
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) {
        if let Ok(mut map) = self.map.lock() {
            map.insert(key, value);
        }
    }
}

#[derive(Debug)]
struct RoutingTable {
    nodes: Vec<NodeInfo>,
}

impl RoutingTable {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    fn update(&mut self, node: NodeInfo, k: usize) {
        if let Some(pos) = self.nodes.iter().position(|n| n.addr == node.addr) {
            self.nodes.remove(pos);
        }
        self.nodes.push(node);
        if self.nodes.len() > k {
            self.nodes.remove(0);
        }
    }

    fn closest(&self, target: &NodeId, k: usize) -> Vec<NodeInfo> {
        let mut nodes = self.nodes.clone();
        nodes.sort_by_key(|n| target.xor_distance(&n.id));
        nodes.into_iter().take(k).collect()
    }
}

#[derive(Debug, Clone)]
pub enum Bencode {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Bencode>),
    Dict(BTreeMap<Vec<u8>, Bencode>),
}

fn bencode_encode(value: &Bencode, out: &mut Vec<u8>) {
    match value {
        Bencode::Int(v) => {
            out.push(b'i');
            out.extend_from_slice(v.to_string().as_bytes());
            out.push(b'e');
        }
        Bencode::Bytes(bytes) => {
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(bytes);
        }
        Bencode::List(items) => {
            out.push(b'l');
            for item in items {
                bencode_encode(item, out);
            }
            out.push(b'e');
        }
        Bencode::Dict(map) => {
            out.push(b'd');
            for (key, value) in map {
                bencode_encode(&Bencode::Bytes(key.clone()), out);
                bencode_encode(value, out);
            }
            out.push(b'e');
        }
    }
}

fn bencode_decode(data: &[u8]) -> CoreResult<Bencode> {
    let (value, idx) = bencode_decode_at(data, 0, 0)?;
    if idx != data.len() {
        return Err(CoreError::Parse("bencode trailing data".to_string()));
    }
    Ok(value)
}

fn bencode_decode_at(data: &[u8], idx: usize, depth: usize) -> CoreResult<(Bencode, usize)> {
    if depth > MAX_DEPTH {
        return Err(CoreError::Parse("bencode depth exceeded".to_string()));
    }
    if idx >= data.len() {
        return Err(CoreError::Parse("bencode out of bounds".to_string()));
    }
    match data[idx] {
        b'i' => {
            let end = data[idx + 1..].iter().position(|&b| b == b'e').ok_or_else(|| CoreError::Parse("bencode int missing end".to_string()))? + idx + 1;
            let number = std::str::from_utf8(&data[idx + 1..end]).map_err(|_| CoreError::Parse("bencode int utf8".to_string()))?;
            let value = number.parse::<i64>().map_err(|_| CoreError::Parse("bencode int parse".to_string()))?;
            Ok((Bencode::Int(value), end + 1))
        }
        b'l' => {
            let mut list = Vec::new();
            let mut cursor = idx + 1;
            while cursor < data.len() && data[cursor] != b'e' {
                let (value, next) = bencode_decode_at(data, cursor, depth + 1)?;
                list.push(value);
                cursor = next;
            }
            if cursor >= data.len() {
                return Err(CoreError::Parse("bencode list missing end".to_string()));
            }
            Ok((Bencode::List(list), cursor + 1))
        }
        b'd' => {
            let mut map = BTreeMap::new();
            let mut cursor = idx + 1;
            while cursor < data.len() && data[cursor] != b'e' {
                let (key, next) = bencode_decode_at(data, cursor, depth + 1)?;
                let key_bytes = match key {
                    Bencode::Bytes(bytes) => bytes,
                    _ => return Err(CoreError::Parse("bencode dict key not bytes".to_string())),
                };
                let (value, next_value) = bencode_decode_at(data, next, depth + 1)?;
                map.insert(key_bytes, value);
                cursor = next_value;
            }
            if cursor >= data.len() {
                return Err(CoreError::Parse("bencode dict missing end".to_string()));
            }
            Ok((Bencode::Dict(map), cursor + 1))
        }
        b'0'..=b'9' => {
            let mut cursor = idx;
            while cursor < data.len() && data[cursor] != b':' {
                cursor += 1;
            }
            if cursor >= data.len() {
                return Err(CoreError::Parse("bencode bytes missing colon".to_string()));
            }
            let len_str = std::str::from_utf8(&data[idx..cursor]).map_err(|_| CoreError::Parse("bencode len utf8".to_string()))?;
            let len = len_str.parse::<usize>().map_err(|_| CoreError::Parse("bencode len parse".to_string()))?;
            let start = cursor + 1;
            let end = start + len;
            if end > data.len() {
                return Err(CoreError::Parse("bencode bytes length overflow".to_string()));
            }
            Ok((Bencode::Bytes(data[start..end].to_vec()), end))
        }
        _ => Err(CoreError::Parse("bencode invalid token".to_string())),
    }
}

#[derive(Debug, Clone)]
pub enum KrpcMessage {
    Query {
        tid: Vec<u8>,
        query: String,
        args: BTreeMap<Vec<u8>, Bencode>,
    },
    Response {
        tid: Vec<u8>,
        resp: BTreeMap<Vec<u8>, Bencode>,
    },
    Error {
        tid: Vec<u8>,
        code: i64,
        message: String,
    },
}

fn encode_krpc(message: &KrpcMessage) -> Vec<u8> {
    let mut dict = BTreeMap::new();
    match message {
        KrpcMessage::Query { tid, query, args } => {
            dict.insert(b"t".to_vec(), Bencode::Bytes(tid.clone()));
            dict.insert(b"y".to_vec(), Bencode::Bytes(b"q".to_vec()));
            dict.insert(b"q".to_vec(), Bencode::Bytes(query.as_bytes().to_vec()));
            dict.insert(b"a".to_vec(), Bencode::Dict(args.clone()));
        }
        KrpcMessage::Response { tid, resp } => {
            dict.insert(b"t".to_vec(), Bencode::Bytes(tid.clone()));
            dict.insert(b"y".to_vec(), Bencode::Bytes(b"r".to_vec()));
            dict.insert(b"r".to_vec(), Bencode::Dict(resp.clone()));
        }
        KrpcMessage::Error { tid, code, message } => {
            dict.insert(b"t".to_vec(), Bencode::Bytes(tid.clone()));
            dict.insert(b"y".to_vec(), Bencode::Bytes(b"e".to_vec()));
            dict.insert(
                b"e".to_vec(),
                Bencode::List(vec![Bencode::Int(*code), Bencode::Bytes(message.as_bytes().to_vec())]),
            );
        }
    }
    let mut out = Vec::new();
    bencode_encode(&Bencode::Dict(dict), &mut out);
    out
}

fn decode_krpc(data: &[u8]) -> CoreResult<KrpcMessage> {
    let value = bencode_decode(data)?;
    let map = match value {
        Bencode::Dict(map) => map,
        _ => return Err(CoreError::Parse("krpc not a dict".to_string())),
    };
    let tid = match map.get(b"t".as_ref()) {
        Some(Bencode::Bytes(value)) => value.clone(),
        _ => return Err(CoreError::Parse("krpc missing tid".to_string())),
    };
    let kind = match map.get(b"y".as_ref()) {
        Some(Bencode::Bytes(value)) => value.clone(),
        _ => return Err(CoreError::Parse("krpc missing type".to_string())),
    };
    match kind.as_slice() {
        b"q" => {
            let query = match map.get(b"q".as_ref()) {
                Some(Bencode::Bytes(value)) => String::from_utf8_lossy(value).to_string(),
                _ => return Err(CoreError::Parse("krpc missing query".to_string())),
            };
            let args = match map.get(b"a".as_ref()) {
                Some(Bencode::Dict(value)) => value.clone(),
                _ => return Err(CoreError::Parse("krpc missing args".to_string())),
            };
            Ok(KrpcMessage::Query { tid, query, args })
        }
        b"r" => {
            let resp = match map.get(b"r".as_ref()) {
                Some(Bencode::Dict(value)) => value.clone(),
                _ => return Err(CoreError::Parse("krpc missing resp".to_string())),
            };
            Ok(KrpcMessage::Response { tid, resp })
        }
        b"e" => {
            let list = match map.get(b"e".as_ref()) {
                Some(Bencode::List(value)) => value,
                _ => return Err(CoreError::Parse("krpc missing error".to_string())),
            };
            if list.len() != 2 {
                return Err(CoreError::Parse("krpc error invalid".to_string()));
            }
            let code = match &list[0] {
                Bencode::Int(value) => *value,
                _ => return Err(CoreError::Parse("krpc error code".to_string())),
            };
            let message = match &list[1] {
                Bencode::Bytes(value) => String::from_utf8_lossy(value).to_string(),
                _ => return Err(CoreError::Parse("krpc error message".to_string())),
            };
            Ok(KrpcMessage::Error { tid, code, message })
        }
        _ => Err(CoreError::Parse("krpc unknown type".to_string())),
    }
}

fn token_for(addr: SocketAddr, secret: &[u8; 20]) -> Vec<u8> {
    let mut sha = sha1::Sha1::new();
    sha.update(secret);
    match addr.ip() {
        IpAddr::V4(ip) => sha.update(&ip.octets()),
        IpAddr::V6(ip) => sha.update(&ip.octets()),
    }
    sha.finalize().to_vec()
}

fn compact_nodes(nodes: &[NodeInfo]) -> Vec<u8> {
    let mut out = Vec::new();
    for node in nodes {
        if let IpAddr::V4(ip) = node.addr.ip() {
            out.extend_from_slice(&node.id.0);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&node.addr.port().to_be_bytes());
        }
    }
    out
}

fn parse_nodes(bytes: &[u8]) -> Vec<NodeInfo> {
    let mut nodes = Vec::new();
    let mut idx = 0;
    while idx + 26 <= bytes.len() {
        let id = NodeId(bytes[idx..idx + 20].try_into().unwrap());
        idx += 20;
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(bytes[idx], bytes[idx + 1], bytes[idx + 2], bytes[idx + 3]));
        idx += 4;
        let port = u16::from_be_bytes([bytes[idx], bytes[idx + 1]]);
        idx += 2;
        nodes.push(NodeInfo {
            id,
            addr: SocketAddr::new(ip, port),
        });
    }
    nodes
}

pub struct KademliaServer {
    socket: UdpTransport,
    config: KademliaConfig,
    store: Arc<dyn KademliaStore>,
    routing: Arc<Mutex<RoutingTable>>,
}

impl KademliaServer {
    pub fn bind(addr: SocketAddr, config: KademliaConfig, store: Arc<dyn KademliaStore>) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            config,
            store,
            routing: Arc::new(Mutex::new(RoutingTable::new())),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(2048)?;
            let socket = self.socket.clone();
            let config = self.config.clone();
            let store = Arc::clone(&self.store);
            let routing = Arc::clone(&self.routing);
            thread::spawn(move || {
                let _ = handle_krpc_request(socket, config, store, routing, &data, addr);
            });
        }
    }
}

pub struct AsyncKademliaServer {
    socket: AsyncUdpTransport,
    config: KademliaConfig,
    store: Arc<dyn KademliaStore>,
    routing: Arc<Mutex<RoutingTable>>,
}

impl AsyncKademliaServer {
    pub async fn bind(addr: SocketAddr, config: KademliaConfig, store: Arc<dyn KademliaStore>) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            config,
            store,
            routing: Arc::new(Mutex::new(RoutingTable::new())),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(2048).await?;
            let config = self.config.clone();
            let store = Arc::clone(&self.store);
            let routing = Arc::clone(&self.routing);
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_krpc_request_async(socket, config, store, routing, &data, addr).await;
            });
        }
    }
}

pub struct KademliaClient {
    socket: UdpTransport,
    config: KademliaConfig,
}

impl KademliaClient {
    pub fn connect(config: KademliaConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket, config })
    }

    pub fn ping(&self, addr: SocketAddr) -> CoreResult<NodeId> {
        let tid = b"aa".to_vec();
        let mut args = BTreeMap::new();
        args.insert(b"id".to_vec(), Bencode::Bytes(self.config.node_id.0.to_vec()));
        let msg = KrpcMessage::Query {
            tid,
            query: "ping".to_string(),
            args,
        };
        let data = encode_krpc(&msg);
        self.socket.send_to(&data, addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let msg = decode_krpc(&resp)?;
        match msg {
            KrpcMessage::Response { resp, .. } => match resp.get(b"id".as_ref()) {
                Some(Bencode::Bytes(value)) if value.len() == NODE_ID_LEN => {
                    Ok(NodeId(value.clone().try_into().unwrap()))
                }
                _ => Err(CoreError::Parse("krpc missing id".to_string())),
            },
            _ => Err(CoreError::Parse("krpc unexpected response".to_string())),
        }
    }

    pub fn find_node(&self, addr: SocketAddr, target: NodeId) -> CoreResult<Vec<NodeInfo>> {
        let tid = b"fn".to_vec();
        let mut args = BTreeMap::new();
        args.insert(b"id".to_vec(), Bencode::Bytes(self.config.node_id.0.to_vec()));
        args.insert(b"target".to_vec(), Bencode::Bytes(target.0.to_vec()));
        let msg = KrpcMessage::Query {
            tid,
            query: "find_node".to_string(),
            args,
        };
        self.socket.send_to(&encode_krpc(&msg), addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let msg = decode_krpc(&resp)?;
        match msg {
            KrpcMessage::Response { resp, .. } => match resp.get(b"nodes".as_ref()) {
                Some(Bencode::Bytes(value)) => Ok(parse_nodes(value)),
                _ => Ok(Vec::new()),
            },
            _ => Err(CoreError::Parse("krpc unexpected response".to_string())),
        }
    }

    pub fn find_value(&self, addr: SocketAddr, key: &[u8]) -> CoreResult<Option<Vec<u8>>> {
        let tid = b"fv".to_vec();
        let mut args = BTreeMap::new();
        args.insert(b"id".to_vec(), Bencode::Bytes(self.config.node_id.0.to_vec()));
        args.insert(b"key".to_vec(), Bencode::Bytes(key.to_vec()));
        let msg = KrpcMessage::Query {
            tid,
            query: "find_value".to_string(),
            args,
        };
        self.socket.send_to(&encode_krpc(&msg), addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let msg = decode_krpc(&resp)?;
        match msg {
            KrpcMessage::Response { resp, .. } => match resp.get(b"value".as_ref()) {
                Some(Bencode::Bytes(value)) => Ok(Some(value.clone())),
                _ => Ok(None),
            },
            _ => Err(CoreError::Parse("krpc unexpected response".to_string())),
        }
    }

    pub fn store(&self, addr: SocketAddr, key: &[u8], value: &[u8], token: Option<Vec<u8>>) -> CoreResult<()> {
        let tid = b"st".to_vec();
        let mut args = BTreeMap::new();
        args.insert(b"id".to_vec(), Bencode::Bytes(self.config.node_id.0.to_vec()));
        args.insert(b"key".to_vec(), Bencode::Bytes(key.to_vec()));
        args.insert(b"value".to_vec(), Bencode::Bytes(value.to_vec()));
        if let Some(token) = token {
            args.insert(b"token".to_vec(), Bencode::Bytes(token));
        }
        let msg = KrpcMessage::Query {
            tid,
            query: "store".to_string(),
            args,
        };
        self.socket.send_to(&encode_krpc(&msg), addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        let msg = decode_krpc(&resp)?;
        match msg {
            KrpcMessage::Response { .. } => Ok(()),
            KrpcMessage::Error { code, message, .. } => Err(CoreError::Message(format!("krpc error {code}: {message}"))),
            _ => Err(CoreError::Parse("krpc unexpected response".to_string())),
        }
    }
}

pub struct AsyncKademliaClient {
    socket: AsyncUdpTransport,
    config: KademliaConfig,
}

impl AsyncKademliaClient {
    pub async fn connect(config: KademliaConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self { socket, config })
    }

    pub async fn ping(&self, addr: SocketAddr) -> CoreResult<NodeId> {
        let tid = b"aa".to_vec();
        let mut args = BTreeMap::new();
        args.insert(b"id".to_vec(), Bencode::Bytes(self.config.node_id.0.to_vec()));
        let msg = KrpcMessage::Query {
            tid,
            query: "ping".to_string(),
            args,
        };
        let data = encode_krpc(&msg);
        self.socket.send_to(&data, addr).await?;
        let (resp, _) = self.socket.recv_from(2048).await?;
        let msg = decode_krpc(&resp)?;
        match msg {
            KrpcMessage::Response { resp, .. } => match resp.get(b"id".as_ref()) {
                Some(Bencode::Bytes(value)) if value.len() == NODE_ID_LEN => {
                    Ok(NodeId(value.clone().try_into().unwrap()))
                }
                _ => Err(CoreError::Parse("krpc missing id".to_string())),
            },
            _ => Err(CoreError::Parse("krpc unexpected response".to_string())),
        }
    }
}

fn handle_krpc_request(
    socket: UdpTransport,
    config: KademliaConfig,
    store: Arc<dyn KademliaStore>,
    routing: Arc<Mutex<RoutingTable>>,
    data: &[u8],
    addr: SocketAddr,
) -> CoreResult<()> {
    let msg = decode_krpc(data)?;
    let response = handle_krpc_message(config, store, routing, msg, addr);
    if let Some(resp) = response {
        socket.send_to(&encode_krpc(&resp), addr)?;
    }
    Ok(())
}

async fn handle_krpc_request_async(
    socket: AsyncUdpTransport,
    config: KademliaConfig,
    store: Arc<dyn KademliaStore>,
    routing: Arc<Mutex<RoutingTable>>,
    data: &[u8],
    addr: SocketAddr,
) -> CoreResult<()> {
    let msg = decode_krpc(data)?;
    let response = handle_krpc_message(config, store, routing, msg, addr);
    if let Some(resp) = response {
        socket.send_to(&encode_krpc(&resp), addr).await?;
    }
    Ok(())
}

fn handle_krpc_message(
    config: KademliaConfig,
    store: Arc<dyn KademliaStore>,
    routing: Arc<Mutex<RoutingTable>>,
    msg: KrpcMessage,
    addr: SocketAddr,
) -> Option<KrpcMessage> {
    match msg {
        KrpcMessage::Query { tid, query, args } => {
            let node_id = match args.get(b"id".as_ref()) {
                Some(Bencode::Bytes(value)) if value.len() == NODE_ID_LEN => NodeId(value.clone().try_into().unwrap()),
                _ => return Some(KrpcMessage::Error { tid, code: 201, message: "missing id".to_string() }),
            };
            if let Ok(mut routing) = routing.lock() {
                routing.update(NodeInfo { id: node_id, addr }, config.k_bucket_size);
            }
            match query.as_str() {
                "ping" => {
                    let mut resp = BTreeMap::new();
                    resp.insert(b"id".to_vec(), Bencode::Bytes(config.node_id.0.to_vec()));
                    Some(KrpcMessage::Response { tid, resp })
                }
                "find_node" => {
                    let target = match args.get(b"target".as_ref()) {
                        Some(Bencode::Bytes(value)) if value.len() == NODE_ID_LEN => NodeId(value.clone().try_into().unwrap()),
                        _ => return Some(KrpcMessage::Error { tid, code: 203, message: "missing target".to_string() }),
                    };
                    let nodes = routing.lock().map(|r| r.closest(&target, config.k_bucket_size)).unwrap_or_default();
                    let mut resp = BTreeMap::new();
                    resp.insert(b"id".to_vec(), Bencode::Bytes(config.node_id.0.to_vec()));
                    resp.insert(b"nodes".to_vec(), Bencode::Bytes(compact_nodes(&nodes)));
                    Some(KrpcMessage::Response { tid, resp })
                }
                "find_value" => {
                    let key = match args.get(b"key".as_ref()) {
                        Some(Bencode::Bytes(value)) => value.clone(),
                        _ => return Some(KrpcMessage::Error { tid, code: 203, message: "missing key".to_string() }),
                    };
                    let mut resp = BTreeMap::new();
                    resp.insert(b"id".to_vec(), Bencode::Bytes(config.node_id.0.to_vec()));
                    if let Some(value) = store.get(&key) {
                        resp.insert(b"value".to_vec(), Bencode::Bytes(value));
                    } else {
                        let nodes = routing.lock().map(|r| r.closest(&config.node_id, config.k_bucket_size)).unwrap_or_default();
                        resp.insert(b"nodes".to_vec(), Bencode::Bytes(compact_nodes(&nodes)));
                    }
                    resp.insert(b"token".to_vec(), Bencode::Bytes(token_for(addr, &config.secret)));
                    Some(KrpcMessage::Response { tid, resp })
                }
                "store" => {
                    let key = match args.get(b"key".as_ref()) {
                        Some(Bencode::Bytes(value)) => value.clone(),
                        _ => return Some(KrpcMessage::Error { tid, code: 203, message: "missing key".to_string() }),
                    };
                    let value = match args.get(b"value".as_ref()) {
                        Some(Bencode::Bytes(value)) => value.clone(),
                        _ => return Some(KrpcMessage::Error { tid, code: 203, message: "missing value".to_string() }),
                    };
                    let token_ok = match args.get(b"token".as_ref()) {
                        Some(Bencode::Bytes(token)) => *token == token_for(addr, &config.secret),
                        _ => config.allow_store_without_token,
                    };
                    if !token_ok {
                        return Some(KrpcMessage::Error { tid, code: 204, message: "invalid token".to_string() });
                    }
                    store.put(key, value);
                    let mut resp = BTreeMap::new();
                    resp.insert(b"id".to_vec(), Bencode::Bytes(config.node_id.0.to_vec()));
                    Some(KrpcMessage::Response { tid, resp })
                }
                _ => Some(KrpcMessage::Error { tid, code: 204, message: "unknown query".to_string() }),
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::fuzz_bytes;

    #[test]
    fn krpc_store_and_find() {
        let config = KademliaConfig::default();
        let store = Arc::new(InMemoryStore::new());
        let server = crate::skip_if_perm!(KademliaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            config.clone(),
            store,
        ));
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let client = KademliaClient::connect(config).unwrap();
        client.ping(addr).unwrap();
        client.store(addr, b"key", b"value", None).unwrap();
        let value = client.find_value(addr, b"key").unwrap();
        assert_eq!(value, Some(b"value".to_vec()));

        drop(handle);
    }

    #[test]
    fn krpc_decode_negative() {
        assert!(decode_krpc(&[]).is_err());
    }

    #[test]
    fn krpc_decode_fuzz() {
        fuzz_bytes(128, 512, 0x4BDE, |data| {
            let _ = decode_krpc(data);
        });
    }
}
