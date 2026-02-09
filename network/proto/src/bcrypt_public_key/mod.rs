use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

pub const BCRYPT_PUBLIC_KEY_MAGIC: u32 = 0x31415352;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BcryptPublicKey {
    pub key_length: u32,
    pub exponent: Vec<u8>,
    pub modulus: Vec<u8>,
    pub prime1: Vec<u8>,
    pub prime2: Vec<u8>,
}

impl BcryptPublicKey {
    pub fn new(exponent: Vec<u8>, modulus: Vec<u8>) -> Self {
        let key_length = (modulus.len() as u32) * 8;
        Self {
            key_length,
            exponent,
            modulus,
            prime1: Vec::new(),
            prime2: Vec::new(),
        }
    }

    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&BCRYPT_PUBLIC_KEY_MAGIC.to_le_bytes());
        out.extend_from_slice(&self.key_length.to_le_bytes());
        out.extend_from_slice(&(self.exponent.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.modulus.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.prime1.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.prime2.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.exponent);
        out.extend_from_slice(&self.modulus);
        out.extend_from_slice(&self.prime1);
        out.extend_from_slice(&self.prime2);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 24 {
            return Err(CoreError::Parse("bcrypt public key too short".to_string()));
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != BCRYPT_PUBLIC_KEY_MAGIC {
            return Err(CoreError::Parse("invalid bcrypt public key magic".to_string()));
        }
        let key_length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let exponent_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let modulus_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let prime1_len = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let prime2_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;
        let mut offset = 24;
        let exponent = read_slice(data, &mut offset, exponent_len)?;
        let modulus = read_slice(data, &mut offset, modulus_len)?;
        let prime1 = read_slice(data, &mut offset, prime1_len)?;
        let prime2 = read_slice(data, &mut offset, prime2_len)?;
        Ok(Self {
            key_length,
            exponent,
            modulus,
            prime1,
            prime2,
        })
    }
}

fn read_slice(data: &[u8], offset: &mut usize, len: usize) -> CoreResult<Vec<u8>> {
    if *offset + len > data.len() {
        return Err(CoreError::Parse("bcrypt public key out of bounds".to_string()));
    }
    let out = data[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct BcryptPublicKeyClientConfig {
    pub timeouts: Timeouts,
}

impl Default for BcryptPublicKeyClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct BcryptPublicKeyClient {
    transport: TcpTransport,
}

impl BcryptPublicKeyClient {
    pub fn connect(addr: &NetAddr, config: BcryptPublicKeyClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self { transport })
    }

    pub fn send_key(&mut self, key: &BcryptPublicKey) -> CoreResult<()> {
        let msg = BcryptPublicKeyMessage::Put(key.clone());
        write_message(&mut self.transport, &msg)?;
        let response = read_message(&mut self.transport)?;
        match response {
            BcryptPublicKeyMessage::Ok => Ok(()),
            BcryptPublicKeyMessage::Error(msg) => Err(CoreError::Message(msg)),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }
}

pub struct AsyncBcryptPublicKeyClient {
    transport: AsyncTcpTransport,
}

impl AsyncBcryptPublicKeyClient {
    pub async fn connect(addr: &NetAddr, config: BcryptPublicKeyClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self { transport })
    }

    pub async fn send_key(&mut self, key: &BcryptPublicKey) -> CoreResult<()> {
        let msg = BcryptPublicKeyMessage::Put(key.clone());
        write_message_async(&mut self.transport, &msg).await?;
        let response = read_message_async(&mut self.transport).await?;
        match response {
            BcryptPublicKeyMessage::Ok => Ok(()),
            BcryptPublicKeyMessage::Error(msg) => Err(CoreError::Message(msg)),
            _ => Err(CoreError::Parse("unexpected response".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BcryptPublicKeyServerConfig {
    pub timeouts: Timeouts,
}

impl Default for BcryptPublicKeyServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub trait BcryptPublicKeyHandler: Send + Sync {
    fn on_key(&self, key: BcryptPublicKey) -> CoreResult<()>;
}

#[derive(Debug, Default)]
pub struct InMemoryBcryptKeyStore {
    pub keys: Mutex<VecDeque<BcryptPublicKey>>,
}

impl InMemoryBcryptKeyStore {
    pub fn latest(&self) -> Option<BcryptPublicKey> {
        let guard = self.keys.lock().ok()?;
        guard.back().cloned()
    }
}

impl BcryptPublicKeyHandler for InMemoryBcryptKeyStore {
    fn on_key(&self, key: BcryptPublicKey) -> CoreResult<()> {
        let mut guard = self.keys.lock().map_err(|_| CoreError::Message("keys poisoned".to_string()))?;
        guard.push_back(key);
        Ok(())
    }
}

pub struct BcryptPublicKeyServer {
    listener: TcpListener,
    config: BcryptPublicKeyServerConfig,
    handler: Arc<dyn BcryptPublicKeyHandler>,
}

impl BcryptPublicKeyServer {
    pub fn bind(
        addr: SocketAddr,
        config: BcryptPublicKeyServerConfig,
        handler: Arc<dyn BcryptPublicKeyHandler>,
    ) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
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
            let timeouts = self.config.timeouts;
            thread::spawn(move || {
                let mut transport = match TcpTransport::from_stream(stream, timeouts) {
                    Ok(transport) => transport,
                    Err(_) => return,
                };
                loop {
                    let msg = match read_message(&mut transport) {
                        Ok(msg) => msg,
                        Err(_) => return,
                    };
                    if let BcryptPublicKeyMessage::Put(key) = msg {
                        let response = match handler.on_key(key) {
                            Ok(_) => BcryptPublicKeyMessage::Ok,
                            Err(err) => BcryptPublicKeyMessage::Error(format!("{err:?}")),
                        };
                        let _ = write_message(&mut transport, &response);
                    }
                }
            });
        }
        Ok(())
    }
}

pub struct AsyncBcryptPublicKeyServer {
    listener: tokio::net::TcpListener,
    handler: Arc<dyn BcryptPublicKeyHandler>,
}

impl AsyncBcryptPublicKeyServer {
    pub async fn bind(
        addr: SocketAddr,
        _config: BcryptPublicKeyServerConfig,
        handler: Arc<dyn BcryptPublicKeyHandler>,
    ) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            handler,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                let mut transport = AsyncTcpTransport::from_stream(stream);
                loop {
                    let msg = match read_message_async(&mut transport).await {
                        Ok(msg) => msg,
                        Err(_) => return,
                    };
                    if let BcryptPublicKeyMessage::Put(key) = msg {
                        let response = match handler.on_key(key) {
                            Ok(_) => BcryptPublicKeyMessage::Ok,
                            Err(err) => BcryptPublicKeyMessage::Error(format!("{err:?}")),
                        };
                        let _ = write_message_async(&mut transport, &response).await;
                    }
                }
            });
        }
    }
}

#[derive(Debug, Clone)]
enum BcryptPublicKeyMessage {
    Put(BcryptPublicKey),
    Ok,
    Error(String),
}

fn write_message(transport: &mut TcpTransport, msg: &BcryptPublicKeyMessage) -> CoreResult<()> {
    let payload = encode_message(msg)?;
    write_len_prefixed(transport, &payload)
}

async fn write_message_async(transport: &mut AsyncTcpTransport, msg: &BcryptPublicKeyMessage) -> CoreResult<()> {
    let payload = encode_message(msg)?;
    write_len_prefixed_async(transport, &payload).await
}

fn read_message(transport: &mut TcpTransport) -> CoreResult<BcryptPublicKeyMessage> {
    let payload = read_len_prefixed(transport)?;
    decode_message(&payload)
}

async fn read_message_async(transport: &mut AsyncTcpTransport) -> CoreResult<BcryptPublicKeyMessage> {
    let payload = read_len_prefixed_async(transport).await?;
    decode_message(&payload)
}

fn encode_message(msg: &BcryptPublicKeyMessage) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    match msg {
        BcryptPublicKeyMessage::Put(key) => {
            out.push(1);
            let blob = key.encode()?;
            out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&blob);
        }
        BcryptPublicKeyMessage::Ok => {
            out.push(2);
        }
        BcryptPublicKeyMessage::Error(message) => {
            out.push(3);
            out.extend_from_slice(&(message.len() as u32).to_be_bytes());
            out.extend_from_slice(message.as_bytes());
        }
    }
    Ok(out)
}

fn decode_message(data: &[u8]) -> CoreResult<BcryptPublicKeyMessage> {
    if data.is_empty() {
        return Err(CoreError::Parse("empty message".to_string()));
    }
    match data[0] {
        1 => {
            if data.len() < 5 {
                return Err(CoreError::Parse("invalid key message".to_string()));
            }
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + len {
                return Err(CoreError::Parse("invalid key length".to_string()));
            }
            let key = BcryptPublicKey::decode(&data[5..5 + len])?;
            Ok(BcryptPublicKeyMessage::Put(key))
        }
        2 => Ok(BcryptPublicKeyMessage::Ok),
        3 => {
            if data.len() < 5 {
                return Err(CoreError::Parse("invalid error message".to_string()));
            }
            let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            if data.len() < 5 + len {
                return Err(CoreError::Parse("invalid error length".to_string()));
            }
            let msg = String::from_utf8_lossy(&data[5..5 + len]).to_string();
            Ok(BcryptPublicKeyMessage::Error(msg))
        }
        _ => Err(CoreError::Parse("unknown message type".to_string())),
    }
}

fn write_len_prefixed(transport: &mut TcpTransport, payload: &[u8]) -> CoreResult<()> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    transport.write_all(&out)
}

fn read_len_prefixed(transport: &mut TcpTransport) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload)?;
    Ok(payload)
}

async fn write_len_prefixed_async(transport: &mut AsyncTcpTransport, payload: &[u8]) -> CoreResult<()> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    transport.write_all(&out).await
}

async fn read_len_prefixed_async(transport: &mut AsyncTcpTransport) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let key = BcryptPublicKey::new(vec![1, 0, 1], vec![0xAA, 0xBB]);
        let encoded = key.encode().unwrap();
        let decoded = BcryptPublicKey::decode(&encoded).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn client_server() {
        let handler = Arc::new(InMemoryBcryptKeyStore::default());
        let server = BcryptPublicKeyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            BcryptPublicKeyServerConfig::default(),
            handler.clone(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        let mut client =
            BcryptPublicKeyClient::connect(&NetAddr::from_socket(addr), BcryptPublicKeyClientConfig::default()).unwrap();
        let key = BcryptPublicKey::new(vec![1, 0, 1], vec![0x01, 0x02, 0x03]);
        client.send_key(&key).unwrap();
        let stored = handler.latest().unwrap();
        assert_eq!(stored, key);
    }
}
