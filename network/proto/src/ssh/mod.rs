use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use aes::Aes128;
use corelib::error::{CoreError, CoreResult};
use ctr::cipher::{KeyIvInit, StreamCipher};
use net::NetAddr;
use ring::agreement;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use ring::signature::KeyPair;

use crate::transport::{
    AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport,
};
use crate::util::Timeouts;

const VERSION: &str = "SSH-2.0-moonlight_ssh";
const MAX_PACKET: usize = 256 * 1024;

const MSG_DISCONNECT: u8 = 1;
#[allow(dead_code)]
const MSG_IGNORE: u8 = 2;
#[allow(dead_code)]
const MSG_UNIMPLEMENTED: u8 = 3;
#[allow(dead_code)]
const MSG_DEBUG: u8 = 4;
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const MSG_CHANNEL_DATA: u8 = 94;
#[allow(dead_code)]
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
#[allow(dead_code)]
const MSG_CHANNEL_REQUEST: u8 = 98;

const KEX_ALG: &str = "curve25519-sha256";
const HOSTKEY_ALG: &str = "ssh-ed25519";
const CIPHER_ALG: &str = "aes128-ctr";
const MAC_ALG: &str = "hmac-sha2-256";
const COMP_ALG: &str = "none";

const CHANNEL_WINDOW: u32 = 1_048_576;
const CHANNEL_MAX_PACKET: u32 = 32 * 1024;

#[derive(Debug, Clone)]
pub struct HostKey {
    seed: [u8; 32],
}

impl HostKey {
    pub fn from_seed(seed: &[u8; 32]) -> CoreResult<Self> {
        let _ = signature::Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|_| CoreError::Parse("invalid ed25519 seed".to_string()))?;
        Ok(Self { seed: *seed })
    }

    pub fn public_key_blob(&self) -> Vec<u8> {
        let keypair = self.keypair().expect("keypair");
        let mut out = Vec::new();
        encode_string(&mut out, HOSTKEY_ALG.as_bytes());
        encode_string(&mut out, keypair.public_key().as_ref());
        out
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let keypair = self.keypair().expect("keypair");
        let sig = keypair.sign(data);
        let mut out = Vec::new();
        encode_string(&mut out, HOSTKEY_ALG.as_bytes());
        encode_string(&mut out, sig.as_ref());
        out
    }

    fn keypair(&self) -> CoreResult<signature::Ed25519KeyPair> {
        signature::Ed25519KeyPair::from_seed_unchecked(&self.seed)
            .map_err(|_| CoreError::Parse("invalid ed25519 seed".to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct KexInit {
    cookie: [u8; 16],
    kex_algs: Vec<String>,
    host_key_algs: Vec<String>,
    ciphers_c2s: Vec<String>,
    ciphers_s2c: Vec<String>,
    macs_c2s: Vec<String>,
    macs_s2c: Vec<String>,
    comp_c2s: Vec<String>,
    comp_s2c: Vec<String>,
    first_kex_packet_follows: bool,
}

impl KexInit {
    fn new() -> Self {
        let mut cookie = [0u8; 16];
        let _ = SystemRandom::new().fill(&mut cookie);
        Self {
            cookie,
            kex_algs: vec![KEX_ALG.to_string()],
            host_key_algs: vec![HOSTKEY_ALG.to_string()],
            ciphers_c2s: vec![CIPHER_ALG.to_string()],
            ciphers_s2c: vec![CIPHER_ALG.to_string()],
            macs_c2s: vec![MAC_ALG.to_string()],
            macs_s2c: vec![MAC_ALG.to_string()],
            comp_c2s: vec![COMP_ALG.to_string()],
            comp_s2c: vec![COMP_ALG.to_string()],
            first_kex_packet_follows: false,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(MSG_KEXINIT);
        out.extend_from_slice(&self.cookie);
        encode_namelist(&mut out, &self.kex_algs);
        encode_namelist(&mut out, &self.host_key_algs);
        encode_namelist(&mut out, &self.ciphers_c2s);
        encode_namelist(&mut out, &self.ciphers_s2c);
        encode_namelist(&mut out, &self.macs_c2s);
        encode_namelist(&mut out, &self.macs_s2c);
        encode_namelist(&mut out, &self.comp_c2s);
        encode_namelist(&mut out, &self.comp_s2c);
        encode_namelist(&mut out, &[]);
        encode_namelist(&mut out, &[]);
        out.push(self.first_kex_packet_follows as u8);
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }

    fn decode(payload: &[u8]) -> CoreResult<Self> {
        if payload.is_empty() || payload[0] != MSG_KEXINIT {
            return Err(CoreError::Parse("invalid kexinit".to_string()));
        }
        let mut cursor = 1usize;
        if cursor + 16 > payload.len() {
            return Err(CoreError::Parse("invalid kexinit".to_string()));
        }
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(&payload[cursor..cursor + 16]);
        cursor += 16;
        let kex_algs = decode_namelist(payload, &mut cursor)?;
        let host_key_algs = decode_namelist(payload, &mut cursor)?;
        let ciphers_c2s = decode_namelist(payload, &mut cursor)?;
        let ciphers_s2c = decode_namelist(payload, &mut cursor)?;
        let macs_c2s = decode_namelist(payload, &mut cursor)?;
        let macs_s2c = decode_namelist(payload, &mut cursor)?;
        let comp_c2s = decode_namelist(payload, &mut cursor)?;
        let comp_s2c = decode_namelist(payload, &mut cursor)?;
        let _ = decode_namelist(payload, &mut cursor)?;
        let _ = decode_namelist(payload, &mut cursor)?;
        if cursor >= payload.len() {
            return Err(CoreError::Parse("invalid kexinit".to_string()));
        }
        let first_kex_packet_follows = payload[cursor] != 0;
        cursor += 1;
        if cursor + 4 > payload.len() {
            return Err(CoreError::Parse("invalid kexinit".to_string()));
        }
        Ok(Self {
            cookie,
            kex_algs,
            host_key_algs,
            ciphers_c2s,
            ciphers_s2c,
            macs_c2s,
            macs_s2c,
            comp_c2s,
            comp_s2c,
            first_kex_packet_follows,
        })
    }
}

struct CipherState {
    cipher: Ctr128BE,
    block_size: usize,
}

type Ctr128BE = ctr::Ctr128BE<Aes128>;

impl CipherState {
    fn new(key: &[u8], iv: &[u8]) -> CoreResult<Self> {
        if key.len() != 16 || iv.len() != 16 {
            return Err(CoreError::Parse("invalid aes128-ctr key/iv".to_string()));
        }
        let cipher = Ctr128BE::new(key.into(), iv.into());
        Ok(Self {
            cipher,
            block_size: 16,
        })
    }

    fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

struct SshTransport<T> {
    io: T,
    seq_in: u32,
    seq_out: u32,
    enc: Option<CipherState>,
    dec: Option<CipherState>,
    mac_out: Option<Vec<u8>>,
    mac_in: Option<Vec<u8>>,
    block_size: usize,
}

impl<T> SshTransport<T> {
    fn new(io: T) -> Self {
        Self {
            io,
            seq_in: 0,
            seq_out: 0,
            enc: None,
            dec: None,
            mac_out: None,
            mac_in: None,
            block_size: 8,
        }
    }

    fn set_crypto(&mut self, enc: CipherState, dec: CipherState, mac_out: Vec<u8>, mac_in: Vec<u8>) {
        self.block_size = enc.block_size;
        self.enc = Some(enc);
        self.dec = Some(dec);
        self.mac_out = Some(mac_out);
        self.mac_in = Some(mac_in);
    }
}

impl<T: StreamTransport> SshTransport<T> {

    fn write_packet(&mut self, payload: &[u8]) -> CoreResult<()> {
        if payload.len() > MAX_PACKET {
            return Err(CoreError::Parse("packet too large".to_string()));
        }
        let mut padding_len = 4usize;
        let mut packet_len = payload.len() + 1 + padding_len;
        while (packet_len + 4) % self.block_size != 0 {
            padding_len += 1;
            packet_len = payload.len() + 1 + padding_len;
        }
        let mut packet = Vec::with_capacity(4 + packet_len);
        packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend_from_slice(payload);
        let mut padding = vec![0u8; padding_len];
        let _ = SystemRandom::new().fill(&mut padding);
        packet.extend_from_slice(&padding);

        if let Some(enc) = self.enc.as_mut() {
            enc.apply(&mut packet);
        }
        if let Some(mac_key) = &self.mac_out {
            let mac = hmac_sha256(mac_key, &packet, self.seq_out);
            self.io.write_all(&packet)?;
            self.io.write_all(&mac)?;
        } else {
            self.io.write_all(&packet)?;
        }
        self.seq_out = self.seq_out.wrapping_add(1);
        Ok(())
    }

    fn read_packet(&mut self) -> CoreResult<Vec<u8>> {
        let mut first = vec![0u8; self.block_size];
        self.io.read_exact(&mut first)?;
        let packet_len = if let Some(dec) = self.dec.as_ref() {
            let mut tmp = first.clone();
            let mut dec = CipherState {
                cipher: dec.cipher.clone(),
                block_size: dec.block_size,
            };
            dec.apply(&mut tmp);
            u32::from_be_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]) as usize
        } else {
            u32::from_be_bytes([first[0], first[1], first[2], first[3]]) as usize
        };
        if packet_len > MAX_PACKET {
            return Err(CoreError::Parse("packet too large".to_string()));
        }
        let mut rest = vec![0u8; 4 + packet_len - self.block_size];
        self.io.read_exact(&mut rest)?;
        let mut packet_enc = Vec::with_capacity(4 + packet_len);
        packet_enc.extend_from_slice(&first);
        packet_enc.extend_from_slice(&rest);
        if let Some(mac_key) = &self.mac_in {
            let mut mac = vec![0u8; 32];
            self.io.read_exact(&mut mac)?;
            let expected = hmac_sha256(mac_key, &packet_enc, self.seq_in);
            if mac != expected {
                return Err(CoreError::Parse("invalid mac".to_string()));
            }
        }
        let mut packet = packet_enc;
        if let Some(dec) = self.dec.as_mut() {
            dec.apply(&mut packet);
        }
        self.seq_in = self.seq_in.wrapping_add(1);
        let padding_len = packet[4] as usize;
        if 5 + padding_len > packet.len() {
            return Err(CoreError::Parse("invalid padding".to_string()));
        }
        let payload_len = packet_len - padding_len - 1;
        Ok(packet[5..5 + payload_len].to_vec())
    }
}

impl<T: AsyncStreamTransport> SshTransport<T> {
    async fn write_packet_async(&mut self, payload: &[u8]) -> CoreResult<()> {
        if payload.len() > MAX_PACKET {
            return Err(CoreError::Parse("packet too large".to_string()));
        }
        let mut padding_len = 4usize;
        let mut packet_len = payload.len() + 1 + padding_len;
        while (packet_len + 4) % self.block_size != 0 {
            padding_len += 1;
            packet_len = payload.len() + 1 + padding_len;
        }
        let mut packet = Vec::with_capacity(4 + packet_len);
        packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend_from_slice(payload);
        let mut padding = vec![0u8; padding_len];
        let _ = SystemRandom::new().fill(&mut padding);
        packet.extend_from_slice(&padding);

        if let Some(enc) = self.enc.as_mut() {
            enc.apply(&mut packet);
        }
        if let Some(mac_key) = &self.mac_out {
            let mac = hmac_sha256(mac_key, &packet, self.seq_out);
            self.io.write_all(&packet).await?;
            self.io.write_all(&mac).await?;
        } else {
            self.io.write_all(&packet).await?;
        }
        self.seq_out = self.seq_out.wrapping_add(1);
        Ok(())
    }

    async fn read_packet_async(&mut self) -> CoreResult<Vec<u8>> {
        let mut first = vec![0u8; self.block_size];
        self.io.read_exact(&mut first).await?;
        let packet_len = if let Some(dec) = self.dec.as_ref() {
            let mut tmp = first.clone();
            let mut dec = CipherState {
                cipher: dec.cipher.clone(),
                block_size: dec.block_size,
            };
            dec.apply(&mut tmp);
            u32::from_be_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]) as usize
        } else {
            u32::from_be_bytes([first[0], first[1], first[2], first[3]]) as usize
        };
        if packet_len > MAX_PACKET {
            return Err(CoreError::Parse("packet too large".to_string()));
        }
        let mut rest = vec![0u8; 4 + packet_len - self.block_size];
        self.io.read_exact(&mut rest).await?;
        let mut packet_enc = Vec::with_capacity(4 + packet_len);
        packet_enc.extend_from_slice(&first);
        packet_enc.extend_from_slice(&rest);
        if let Some(mac_key) = &self.mac_in {
            let mut mac = vec![0u8; 32];
            self.io.read_exact(&mut mac).await?;
            let expected = hmac_sha256(mac_key, &packet_enc, self.seq_in);
            if mac != expected {
                return Err(CoreError::Parse("invalid mac".to_string()));
            }
        }
        let mut packet = packet_enc;
        if let Some(dec) = self.dec.as_mut() {
            dec.apply(&mut packet);
        }
        self.seq_in = self.seq_in.wrapping_add(1);
        let padding_len = packet[4] as usize;
        if 5 + padding_len > packet.len() {
            return Err(CoreError::Parse("invalid padding".to_string()));
        }
        let payload_len = packet_len - padding_len - 1;
        Ok(packet[5..5 + payload_len].to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub server_id: String,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            server_id: VERSION.to_string(),
        }
    }
}

pub struct SshClient {
    transport: SshTransport<TcpTransport>,
    #[allow(dead_code)]
    session_id: Vec<u8>,
    #[allow(dead_code)]
    server_host_key: Vec<u8>,
}

pub struct SshServer {
    listener: TcpListener,
    host_key: HostKey,
    config: SshConfig,
    timeouts: Timeouts,
}

pub struct AsyncSshClient {
    transport: SshTransport<AsyncTcpTransport>,
    #[allow(dead_code)]
    session_id: Vec<u8>,
    #[allow(dead_code)]
    server_host_key: Vec<u8>,
}

pub struct AsyncSshServer {
    listener: tokio::net::TcpListener,
    host_key: HostKey,
    config: SshConfig,
    timeouts: Timeouts,
}

#[derive(Debug, Clone)]
pub struct Channel {
    local_id: u32,
    remote_id: u32,
    window: u32,
    max_packet: u32,
}

#[derive(Debug, Clone)]
pub struct AsyncChannel {
    local_id: u32,
    remote_id: u32,
    window: u32,
    max_packet: u32,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub allow_password: bool,
    pub allow_publickey: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_password: true,
            allow_publickey: true,
        }
    }
}

pub trait AuthHandler: Send + Sync {
    fn check_password(&self, username: &str, password: &str) -> bool;
    fn check_publickey(&self, username: &str, key_blob: &[u8], signature: Option<&[u8]>) -> bool;
}

pub struct AllowAllAuth;

impl AuthHandler for AllowAllAuth {
    fn check_password(&self, _username: &str, _password: &str) -> bool {
        true
    }

    fn check_publickey(&self, _username: &str, _key_blob: &[u8], _signature: Option<&[u8]>) -> bool {
        true
    }
}

impl SshClient {
    pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, timeouts)?;
        let mut transport = SshTransport::new(transport);
        let server_version = exchange_versions(&mut transport.io, VERSION)?;
        let (session_id, server_host_key) = client_kex(&mut transport, VERSION.as_bytes(), server_version.as_bytes())?;
        Ok(Self {
            transport,
            session_id,
            server_host_key,
        })
    }

    pub fn userauth_password(&mut self, username: &str, password: &str) -> CoreResult<()> {
        service_request(&mut self.transport, "ssh-userauth")?;
        let mut payload = Vec::new();
        payload.push(MSG_USERAUTH_REQUEST);
        encode_string(&mut payload, username.as_bytes());
        encode_string(&mut payload, b"ssh-connection");
        encode_string(&mut payload, b"password");
        payload.push(0);
        encode_string(&mut payload, password.as_bytes());
        self.transport.write_packet(&payload)?;
        loop {
            let resp = self.transport.read_packet()?;
            match resp.get(0).copied() {
                Some(MSG_USERAUTH_SUCCESS) => return Ok(()),
                Some(MSG_USERAUTH_FAILURE) => {
                    return Err(CoreError::Parse("auth failed".to_string()));
                }
                _ => continue,
            }
        }
    }

    pub fn open_session(&mut self) -> CoreResult<Channel> {
        let local_id = 0u32;
        let mut payload = Vec::new();
        payload.push(MSG_CHANNEL_OPEN);
        encode_string(&mut payload, b"session");
        payload.extend_from_slice(&local_id.to_be_bytes());
        payload.extend_from_slice(&CHANNEL_WINDOW.to_be_bytes());
        payload.extend_from_slice(&CHANNEL_MAX_PACKET.to_be_bytes());
        self.transport.write_packet(&payload)?;
        loop {
            let resp = self.transport.read_packet()?;
            match resp.get(0).copied() {
                Some(MSG_CHANNEL_OPEN_CONFIRMATION) => {
                    let mut cursor = 1usize;
                    let remote_id = read_u32(&resp, &mut cursor)?;
                    let local_id = read_u32(&resp, &mut cursor)?;
                    let window = read_u32(&resp, &mut cursor)?;
                    let max_packet = read_u32(&resp, &mut cursor)?;
                    return Ok(Channel {
                        local_id,
                        remote_id,
                        window,
                        max_packet,
                    });
                }
                Some(MSG_CHANNEL_OPEN_FAILURE) => {
                    return Err(CoreError::Parse("channel open failed".to_string()));
                }
                _ => continue,
            }
        }
    }

    pub fn send_channel_data(&mut self, channel: &mut Channel, data: &[u8]) -> CoreResult<()> {
        if data.len() as u32 > channel.max_packet {
            return Err(CoreError::Parse("channel data too large".to_string()));
        }
        if channel.window < data.len() as u32 {
            return Err(CoreError::Parse("channel window exceeded".to_string()));
        }
        let mut payload = Vec::new();
        payload.push(MSG_CHANNEL_DATA);
        payload.extend_from_slice(&channel.remote_id.to_be_bytes());
        encode_string(&mut payload, data);
        self.transport.write_packet(&payload)?;
        channel.window -= data.len() as u32;
        Ok(())
    }

    pub fn recv_channel_data(&mut self, channel: &mut Channel) -> CoreResult<Vec<u8>> {
        loop {
            let resp = self.transport.read_packet()?;
            match resp.get(0).copied() {
                Some(MSG_CHANNEL_DATA) => {
                    let mut cursor = 1usize;
                    let channel_id = read_u32(&resp, &mut cursor)?;
                    let data = read_string(&resp, &mut cursor)?;
                    if channel_id == channel.local_id {
                        return Ok(data);
                    }
                }
                Some(MSG_CHANNEL_WINDOW_ADJUST) => {
                    let mut cursor = 1usize;
                    let channel_id = read_u32(&resp, &mut cursor)?;
                    let amount = read_u32(&resp, &mut cursor)?;
                    if channel_id == channel.local_id {
                        channel.window = channel.window.saturating_add(amount);
                    }
                }
                Some(MSG_CHANNEL_CLOSE) => return Ok(Vec::new()),
                _ => continue,
            }
        }
    }
}

impl AsyncSshClient {
    pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, timeouts).await?;
        let mut transport = SshTransport::new(transport);
        let server_version = exchange_versions_async(&mut transport.io, VERSION).await?;
        let (session_id, server_host_key) =
            client_kex_async(&mut transport, VERSION.as_bytes(), server_version.as_bytes()).await?;
        Ok(Self {
            transport,
            session_id,
            server_host_key,
        })
    }

    pub async fn userauth_password(&mut self, username: &str, password: &str) -> CoreResult<()> {
        service_request_async(&mut self.transport, "ssh-userauth").await?;
        let mut payload = Vec::new();
        payload.push(MSG_USERAUTH_REQUEST);
        encode_string(&mut payload, username.as_bytes());
        encode_string(&mut payload, b"ssh-connection");
        encode_string(&mut payload, b"password");
        payload.push(0);
        encode_string(&mut payload, password.as_bytes());
        self.transport.write_packet_async(&payload).await?;
        loop {
            let resp = self.transport.read_packet_async().await?;
            match resp.get(0).copied() {
                Some(MSG_USERAUTH_SUCCESS) => return Ok(()),
                Some(MSG_USERAUTH_FAILURE) => {
                    return Err(CoreError::Parse("auth failed".to_string()));
                }
                _ => continue,
            }
        }
    }

    pub async fn open_session(&mut self) -> CoreResult<AsyncChannel> {
        let local_id = 0u32;
        let mut payload = Vec::new();
        payload.push(MSG_CHANNEL_OPEN);
        encode_string(&mut payload, b"session");
        payload.extend_from_slice(&local_id.to_be_bytes());
        payload.extend_from_slice(&CHANNEL_WINDOW.to_be_bytes());
        payload.extend_from_slice(&CHANNEL_MAX_PACKET.to_be_bytes());
        self.transport.write_packet_async(&payload).await?;
        loop {
            let resp = self.transport.read_packet_async().await?;
            match resp.get(0).copied() {
                Some(MSG_CHANNEL_OPEN_CONFIRMATION) => {
                    let mut cursor = 1usize;
                    let remote_id = read_u32(&resp, &mut cursor)?;
                    let local_id = read_u32(&resp, &mut cursor)?;
                    let window = read_u32(&resp, &mut cursor)?;
                    let max_packet = read_u32(&resp, &mut cursor)?;
                    return Ok(AsyncChannel {
                        local_id,
                        remote_id,
                        window,
                        max_packet,
                    });
                }
                Some(MSG_CHANNEL_OPEN_FAILURE) => {
                    return Err(CoreError::Parse("channel open failed".to_string()));
                }
                _ => continue,
            }
        }
    }

    pub async fn send_channel_data(&mut self, channel: &mut AsyncChannel, data: &[u8]) -> CoreResult<()> {
        if data.len() as u32 > channel.max_packet {
            return Err(CoreError::Parse("channel data too large".to_string()));
        }
        if channel.window < data.len() as u32 {
            return Err(CoreError::Parse("channel window exceeded".to_string()));
        }
        let mut payload = Vec::new();
        payload.push(MSG_CHANNEL_DATA);
        payload.extend_from_slice(&channel.remote_id.to_be_bytes());
        encode_string(&mut payload, data);
        self.transport.write_packet_async(&payload).await?;
        channel.window -= data.len() as u32;
        Ok(())
    }

    pub async fn recv_channel_data(&mut self, channel: &mut AsyncChannel) -> CoreResult<Vec<u8>> {
        loop {
            let resp = self.transport.read_packet_async().await?;
            match resp.get(0).copied() {
                Some(MSG_CHANNEL_DATA) => {
                    let mut cursor = 1usize;
                    let channel_id = read_u32(&resp, &mut cursor)?;
                    let data = read_string(&resp, &mut cursor)?;
                    if channel_id == channel.local_id {
                        return Ok(data);
                    }
                }
                Some(MSG_CHANNEL_WINDOW_ADJUST) => {
                    let mut cursor = 1usize;
                    let channel_id = read_u32(&resp, &mut cursor)?;
                    let amount = read_u32(&resp, &mut cursor)?;
                    if channel_id == channel.local_id {
                        channel.window = channel.window.saturating_add(amount);
                    }
                }
                Some(MSG_CHANNEL_CLOSE) => return Ok(Vec::new()),
                _ => continue,
            }
        }
    }
}

impl SshServer {
    pub fn bind(addr: SocketAddr, host_key: HostKey, config: SshConfig, timeouts: Timeouts) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            host_key,
            config,
            timeouts,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: AuthHandler + 'static,
    {
        let handler = Arc::new(handler);
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let host_key = self.host_key.clone();
            let config = self.config.clone();
            let handler = Arc::clone(&handler);
            let timeouts = self.timeouts;
            thread::spawn(move || {
                let _ = handle_server(stream, host_key, config, handler, timeouts);
            });
        }
        Ok(())
    }
}

impl AsyncSshServer {
    pub async fn bind(addr: SocketAddr, host_key: HostKey, config: SshConfig, timeouts: Timeouts) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            host_key,
            config,
            timeouts,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: AuthHandler + 'static,
    {
        let handler = Arc::new(handler);
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let host_key = self.host_key.clone();
            let config = self.config.clone();
            let handler = Arc::clone(&handler);
            let timeouts = self.timeouts;
            tokio::spawn(async move {
                let _ = handle_server_async(stream, host_key, config, handler, timeouts).await;
            });
        }
    }
}

fn handle_server(
    stream: TcpStream,
    host_key: HostKey,
    config: SshConfig,
    handler: Arc<dyn AuthHandler>,
    timeouts: Timeouts,
) -> CoreResult<()> {
    let transport = TcpTransport::from_stream(stream, timeouts)?;
    let mut transport = SshTransport::new(transport);
    let client_version = exchange_versions(&mut transport.io, &config.server_id)?;
    server_kex(&mut transport, &host_key, client_version.as_bytes(), config.server_id.as_bytes())?;
    server_auth(&mut transport, handler)?;
    server_session(&mut transport)
}

async fn handle_server_async(
    stream: tokio::net::TcpStream,
    host_key: HostKey,
    config: SshConfig,
    handler: Arc<dyn AuthHandler>,
    _timeouts: Timeouts,
) -> CoreResult<()> {
    let transport = AsyncTcpTransport::from_stream(stream);
    let mut transport = SshTransport::new(transport);
    let client_version = exchange_versions_async(&mut transport.io, &config.server_id).await?;
    server_kex_async(
        &mut transport,
        &host_key,
        client_version.as_bytes(),
        config.server_id.as_bytes(),
    )
    .await?;
    server_auth_async(&mut transport, handler).await?;
    server_session_async(&mut transport).await
}

fn server_auth(transport: &mut SshTransport<TcpTransport>, handler: Arc<dyn AuthHandler>) -> CoreResult<()> {
    loop {
        let payload = transport.read_packet()?;
        match payload.get(0).copied() {
            Some(MSG_SERVICE_REQUEST) => {
                let mut cursor = 1usize;
                let service = read_string(&payload, &mut cursor)?;
                if service != b"ssh-userauth" {
                    return Err(CoreError::Parse("unsupported service".to_string()));
                }
                let mut resp = Vec::new();
                resp.push(MSG_SERVICE_ACCEPT);
                encode_string(&mut resp, b"ssh-userauth");
                transport.write_packet(&resp)?;
            }
            Some(MSG_USERAUTH_REQUEST) => {
                let mut cursor = 1usize;
                let username = read_string(&payload, &mut cursor)?;
                let _service = read_string(&payload, &mut cursor)?;
                let method = read_string(&payload, &mut cursor)?;
                let success = if method == b"password" {
                    let _ = read_u8(&payload, &mut cursor)?;
                    let password = read_string(&payload, &mut cursor)?;
                    handler.check_password(&String::from_utf8_lossy(&username), &String::from_utf8_lossy(&password))
                } else if method == b"publickey" {
                    let has_sig = read_u8(&payload, &mut cursor)? != 0;
                    let alg = read_string(&payload, &mut cursor)?;
                    let key_blob = read_string(&payload, &mut cursor)?;
                    let signature = if has_sig {
                        Some(read_string(&payload, &mut cursor)?)
                    } else {
                        None
                    };
                    handler.check_publickey(&String::from_utf8_lossy(&username), &key_blob, signature.as_deref())
                        && alg == HOSTKEY_ALG.as_bytes()
                } else {
                    false
                };
                if success {
                    let resp = vec![MSG_USERAUTH_SUCCESS];
                    transport.write_packet(&resp)?;
                    return Ok(());
                } else {
                    let mut resp = Vec::new();
                    resp.push(MSG_USERAUTH_FAILURE);
                    encode_string(&mut resp, b"password,publickey");
                    resp.push(0);
                    transport.write_packet(&resp)?;
                }
            }
            _ => continue,
        }
    }
}

async fn server_auth_async(
    transport: &mut SshTransport<AsyncTcpTransport>,
    handler: Arc<dyn AuthHandler>,
) -> CoreResult<()> {
    loop {
        let payload = transport.read_packet_async().await?;
        match payload.get(0).copied() {
            Some(MSG_SERVICE_REQUEST) => {
                let mut cursor = 1usize;
                let service = read_string(&payload, &mut cursor)?;
                if service != b"ssh-userauth" {
                    return Err(CoreError::Parse("unsupported service".to_string()));
                }
                let mut resp = Vec::new();
                resp.push(MSG_SERVICE_ACCEPT);
                encode_string(&mut resp, b"ssh-userauth");
                transport.write_packet_async(&resp).await?;
            }
            Some(MSG_USERAUTH_REQUEST) => {
                let mut cursor = 1usize;
                let username = read_string(&payload, &mut cursor)?;
                let _service = read_string(&payload, &mut cursor)?;
                let method = read_string(&payload, &mut cursor)?;
                let success = if method == b"password" {
                    let _ = read_u8(&payload, &mut cursor)?;
                    let password = read_string(&payload, &mut cursor)?;
                    handler.check_password(&String::from_utf8_lossy(&username), &String::from_utf8_lossy(&password))
                } else if method == b"publickey" {
                    let has_sig = read_u8(&payload, &mut cursor)? != 0;
                    let alg = read_string(&payload, &mut cursor)?;
                    let key_blob = read_string(&payload, &mut cursor)?;
                    let signature = if has_sig {
                        Some(read_string(&payload, &mut cursor)?)
                    } else {
                        None
                    };
                    handler.check_publickey(&String::from_utf8_lossy(&username), &key_blob, signature.as_deref())
                        && alg == HOSTKEY_ALG.as_bytes()
                } else {
                    false
                };
                if success {
                    let resp = vec![MSG_USERAUTH_SUCCESS];
                    transport.write_packet_async(&resp).await?;
                    return Ok(());
                } else {
                    let mut resp = Vec::new();
                    resp.push(MSG_USERAUTH_FAILURE);
                    encode_string(&mut resp, b"password,publickey");
                    resp.push(0);
                    transport.write_packet_async(&resp).await?;
                }
            }
            _ => continue,
        }
    }
}

fn server_session(transport: &mut SshTransport<TcpTransport>) -> CoreResult<()> {
    let mut channels: HashMap<u32, Channel> = HashMap::new();
    loop {
        let payload = transport.read_packet()?;
        match payload.get(0).copied() {
            Some(MSG_CHANNEL_OPEN) => {
                let mut cursor = 1usize;
                let channel_type = read_string(&payload, &mut cursor)?;
                if channel_type != b"session" {
                    send_channel_open_failure(transport, &payload, 3, "unsupported")?;
                    continue;
                }
                let remote_id = read_u32(&payload, &mut cursor)?;
                let window = read_u32(&payload, &mut cursor)?;
                let max_packet = read_u32(&payload, &mut cursor)?;
                let local_id = channels.len() as u32;
                channels.insert(
                    local_id,
                    Channel {
                        local_id,
                        remote_id,
                        window,
                        max_packet,
                    },
                );
                let mut resp = Vec::new();
                resp.push(MSG_CHANNEL_OPEN_CONFIRMATION);
                resp.extend_from_slice(&remote_id.to_be_bytes());
                resp.extend_from_slice(&local_id.to_be_bytes());
                resp.extend_from_slice(&CHANNEL_WINDOW.to_be_bytes());
                resp.extend_from_slice(&CHANNEL_MAX_PACKET.to_be_bytes());
                transport.write_packet(&resp)?;
            }
            Some(MSG_CHANNEL_DATA) => {
                let mut cursor = 1usize;
                let channel_id = read_u32(&payload, &mut cursor)?;
                let data = read_string(&payload, &mut cursor)?;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    if channel.window >= data.len() as u32 {
                        channel.window -= data.len() as u32;
                        let mut resp = Vec::new();
                        resp.push(MSG_CHANNEL_DATA);
                        resp.extend_from_slice(&channel.remote_id.to_be_bytes());
                        encode_string(&mut resp, &data);
                        transport.write_packet(&resp)?;
                        let adjust = data.len() as u32;
                        let mut adjust_msg = Vec::new();
                        adjust_msg.push(MSG_CHANNEL_WINDOW_ADJUST);
                        adjust_msg.extend_from_slice(&channel.remote_id.to_be_bytes());
                        adjust_msg.extend_from_slice(&adjust.to_be_bytes());
                        transport.write_packet(&adjust_msg)?;
                    }
                }
            }
            Some(MSG_CHANNEL_CLOSE) => return Ok(()),
            Some(MSG_DISCONNECT) => return Ok(()),
            _ => continue,
        }
    }
}

async fn server_session_async(transport: &mut SshTransport<AsyncTcpTransport>) -> CoreResult<()> {
    let mut channels: HashMap<u32, AsyncChannel> = HashMap::new();
    loop {
        let payload = transport.read_packet_async().await?;
        match payload.get(0).copied() {
            Some(MSG_CHANNEL_OPEN) => {
                let mut cursor = 1usize;
                let channel_type = read_string(&payload, &mut cursor)?;
                if channel_type != b"session" {
                    send_channel_open_failure_async(transport, &payload, 3, "unsupported").await?;
                    continue;
                }
                let remote_id = read_u32(&payload, &mut cursor)?;
                let window = read_u32(&payload, &mut cursor)?;
                let max_packet = read_u32(&payload, &mut cursor)?;
                let local_id = channels.len() as u32;
                channels.insert(
                    local_id,
                    AsyncChannel {
                        local_id,
                        remote_id,
                        window,
                        max_packet,
                    },
                );
                let mut resp = Vec::new();
                resp.push(MSG_CHANNEL_OPEN_CONFIRMATION);
                resp.extend_from_slice(&remote_id.to_be_bytes());
                resp.extend_from_slice(&local_id.to_be_bytes());
                resp.extend_from_slice(&CHANNEL_WINDOW.to_be_bytes());
                resp.extend_from_slice(&CHANNEL_MAX_PACKET.to_be_bytes());
                transport.write_packet_async(&resp).await?;
            }
            Some(MSG_CHANNEL_DATA) => {
                let mut cursor = 1usize;
                let channel_id = read_u32(&payload, &mut cursor)?;
                let data = read_string(&payload, &mut cursor)?;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    if channel.window >= data.len() as u32 {
                        channel.window -= data.len() as u32;
                        let mut resp = Vec::new();
                        resp.push(MSG_CHANNEL_DATA);
                        resp.extend_from_slice(&channel.remote_id.to_be_bytes());
                        encode_string(&mut resp, &data);
                        transport.write_packet_async(&resp).await?;
                        let adjust = data.len() as u32;
                        let mut adjust_msg = Vec::new();
                        adjust_msg.push(MSG_CHANNEL_WINDOW_ADJUST);
                        adjust_msg.extend_from_slice(&channel.remote_id.to_be_bytes());
                        adjust_msg.extend_from_slice(&adjust.to_be_bytes());
                        transport.write_packet_async(&adjust_msg).await?;
                    }
                }
            }
            Some(MSG_CHANNEL_CLOSE) => return Ok(()),
            Some(MSG_DISCONNECT) => return Ok(()),
            _ => continue,
        }
    }
}

fn send_channel_open_failure(transport: &mut SshTransport<TcpTransport>, payload: &[u8], reason: u32, msg: &str) -> CoreResult<()> {
    let mut cursor = 1usize;
    let _ = read_string(payload, &mut cursor)?;
    let remote_id = read_u32(payload, &mut cursor)?;
    let mut resp = Vec::new();
    resp.push(MSG_CHANNEL_OPEN_FAILURE);
    resp.extend_from_slice(&remote_id.to_be_bytes());
    resp.extend_from_slice(&reason.to_be_bytes());
    encode_string(&mut resp, msg.as_bytes());
    encode_string(&mut resp, b"");
    transport.write_packet(&resp)
}

async fn send_channel_open_failure_async(transport: &mut SshTransport<AsyncTcpTransport>, payload: &[u8], reason: u32, msg: &str) -> CoreResult<()> {
    let mut cursor = 1usize;
    let _ = read_string(payload, &mut cursor)?;
    let remote_id = read_u32(payload, &mut cursor)?;
    let mut resp = Vec::new();
    resp.push(MSG_CHANNEL_OPEN_FAILURE);
    resp.extend_from_slice(&remote_id.to_be_bytes());
    resp.extend_from_slice(&reason.to_be_bytes());
    encode_string(&mut resp, msg.as_bytes());
    encode_string(&mut resp, b"");
    transport.write_packet_async(&resp).await
}

fn exchange_versions<T: StreamTransport>(io: &mut T, version: &str) -> CoreResult<String> {
    io.write_all(format!("{}\r\n", version).as_bytes())?;
    read_version(io)
}

fn read_version<T: StreamTransport>(io: &mut T) -> CoreResult<String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.len() > 1024 {
            return Err(CoreError::Parse("version too long".to_string()));
        }
        if byte[0] == b'\n' {
            let s = String::from_utf8_lossy(&line).trim().to_string();
            if s.starts_with("SSH-") {
                return Ok(s);
            }
            line.clear();
        }
    }
}

async fn exchange_versions_async<T: AsyncStreamTransport>(
    io: &mut T,
    version: &str,
) -> CoreResult<String> {
    io.write_all(format!("{}\r\n", version).as_bytes()).await?;
    read_version_async(io).await
}

async fn read_version_async<T: AsyncStreamTransport>(io: &mut T) -> CoreResult<String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.len() > 1024 {
            return Err(CoreError::Parse("version too long".to_string()));
        }
        if byte[0] == b'\n' {
            let s = String::from_utf8_lossy(&line).trim().to_string();
            if s.starts_with("SSH-") {
                return Ok(s);
            }
            line.clear();
        }
    }
}

fn client_kex(
    transport: &mut SshTransport<TcpTransport>,
    v_c: &[u8],
    v_s: &[u8],
) -> CoreResult<(Vec<u8>, Vec<u8>)> {
    let kex_init = KexInit::new();
    let kex_payload = kex_init.encode();
    transport.write_packet(&kex_payload)?;
    let server_kex_payload = transport.read_packet()?;
    let server_kex = KexInit::decode(&server_kex_payload)?;

    let (kex_alg, host_alg, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c) =
        negotiate(&kex_init, &server_kex)?;
    if kex_alg != KEX_ALG || host_alg != HOSTKEY_ALG || cipher_c2s != CIPHER_ALG || cipher_s2c != CIPHER_ALG || mac_c2s != MAC_ALG || mac_s2c != MAC_ALG {
        return Err(CoreError::Parse("unsupported algorithm".to_string()));
    }

    let (my_kex, my_pub) = x25519_keypair()?;

    let mut init = Vec::new();
    init.push(MSG_KEX_ECDH_INIT);
    encode_string(&mut init, &my_pub);
    transport.write_packet(&init)?;

    let reply = transport.read_packet()?;
    if reply.get(0).copied() != Some(MSG_KEX_ECDH_REPLY) {
        return Err(CoreError::Parse("invalid kex reply".to_string()));
    }
    let mut cursor = 1usize;
    let host_key_blob = read_string(&reply, &mut cursor)?;
    let server_pub = read_string(&reply, &mut cursor)?;
    let signature_blob = read_string(&reply, &mut cursor)?;

    let shared = x25519_agree(my_kex, &server_pub)?;

    let h = kex_hash(
        v_c,
        v_s,
        &kex_payload,
        &server_kex_payload,
        &host_key_blob,
        &my_pub,
        &server_pub,
        &shared,
    );

    verify_hostkey_signature(&host_key_blob, &signature_blob, &h)?;

    transport.write_packet(&[MSG_NEWKEYS])?;
    let newkeys = transport.read_packet()?;
    if newkeys.get(0).copied() != Some(MSG_NEWKEYS) {
        return Err(CoreError::Parse("missing newkeys".to_string()));
    }

    let session_id = h.clone();
    let keys = derive_keys(&shared, &h, &session_id);
    transport.set_crypto(
        CipherState::new(&keys.c2s_enc_key, &keys.c2s_iv)?,
        CipherState::new(&keys.s2c_enc_key, &keys.s2c_iv)?,
        keys.c2s_mac_key,
        keys.s2c_mac_key,
    );

    Ok((session_id, host_key_blob))
}

async fn client_kex_async(
    transport: &mut SshTransport<AsyncTcpTransport>,
    v_c: &[u8],
    v_s: &[u8],
) -> CoreResult<(Vec<u8>, Vec<u8>)> {
    let kex_init = KexInit::new();
    let kex_payload = kex_init.encode();
    transport.write_packet_async(&kex_payload).await?;
    let server_kex_payload = transport.read_packet_async().await?;
    let server_kex = KexInit::decode(&server_kex_payload)?;

    let (kex_alg, host_alg, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c) =
        negotiate(&kex_init, &server_kex)?;
    if kex_alg != KEX_ALG || host_alg != HOSTKEY_ALG || cipher_c2s != CIPHER_ALG || cipher_s2c != CIPHER_ALG || mac_c2s != MAC_ALG || mac_s2c != MAC_ALG {
        return Err(CoreError::Parse("unsupported algorithm".to_string()));
    }

    let (my_kex, my_pub) = x25519_keypair()?;

    let mut init = Vec::new();
    init.push(MSG_KEX_ECDH_INIT);
    encode_string(&mut init, &my_pub);
    transport.write_packet_async(&init).await?;

    let reply = transport.read_packet_async().await?;
    if reply.get(0).copied() != Some(MSG_KEX_ECDH_REPLY) {
        return Err(CoreError::Parse("invalid kex reply".to_string()));
    }
    let mut cursor = 1usize;
    let host_key_blob = read_string(&reply, &mut cursor)?;
    let server_pub = read_string(&reply, &mut cursor)?;
    let signature_blob = read_string(&reply, &mut cursor)?;

    let shared = x25519_agree(my_kex, &server_pub)?;

    let h = kex_hash(
        v_c,
        v_s,
        &kex_payload,
        &server_kex_payload,
        &host_key_blob,
        &my_pub,
        &server_pub,
        &shared,
    );

    verify_hostkey_signature(&host_key_blob, &signature_blob, &h)?;

    transport.write_packet_async(&[MSG_NEWKEYS]).await?;
    let newkeys = transport.read_packet_async().await?;
    if newkeys.get(0).copied() != Some(MSG_NEWKEYS) {
        return Err(CoreError::Parse("missing newkeys".to_string()));
    }

    let session_id = h.clone();
    let keys = derive_keys(&shared, &h, &session_id);
    transport.set_crypto(
        CipherState::new(&keys.c2s_enc_key, &keys.c2s_iv)?,
        CipherState::new(&keys.s2c_enc_key, &keys.s2c_iv)?,
        keys.c2s_mac_key,
        keys.s2c_mac_key,
    );

    Ok((session_id, host_key_blob))
}

fn server_kex(
    transport: &mut SshTransport<TcpTransport>,
    host_key: &HostKey,
    v_c: &[u8],
    v_s: &[u8],
) -> CoreResult<()> {
    let server_kex = KexInit::new();
    let server_payload = server_kex.encode();
    transport.write_packet(&server_payload)?;
    let client_payload = transport.read_packet()?;
    let client_kex = KexInit::decode(&client_payload)?;

    let (kex_alg, host_alg, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c) =
        negotiate(&client_kex, &server_kex)?;
    if kex_alg != KEX_ALG || host_alg != HOSTKEY_ALG || cipher_c2s != CIPHER_ALG || cipher_s2c != CIPHER_ALG || mac_c2s != MAC_ALG || mac_s2c != MAC_ALG {
        return Err(CoreError::Parse("unsupported algorithm".to_string()));
    }

    let init = transport.read_packet()?;
    if init.get(0).copied() != Some(MSG_KEX_ECDH_INIT) {
        return Err(CoreError::Parse("invalid kex init".to_string()));
    }
    let mut cursor = 1usize;
    let client_pub = read_string(&init, &mut cursor)?;

    let (server_kex_key, server_pub) = x25519_keypair()?;

    let shared = x25519_agree(server_kex_key, &client_pub)?;

    let host_key_blob = host_key.public_key_blob();
    let h = kex_hash(
        v_c,
        v_s,
        &client_payload,
        &server_payload,
        &host_key_blob,
        &client_pub,
        &server_pub,
        &shared,
    );
    let signature = host_key.sign(&h);

    let mut reply = Vec::new();
    reply.push(MSG_KEX_ECDH_REPLY);
    encode_string(&mut reply, &host_key_blob);
    encode_string(&mut reply, &server_pub);
    encode_string(&mut reply, &signature);
    transport.write_packet(&reply)?;

    let newkeys = transport.read_packet()?;
    if newkeys.get(0).copied() != Some(MSG_NEWKEYS) {
        return Err(CoreError::Parse("missing newkeys".to_string()));
    }
    transport.write_packet(&[MSG_NEWKEYS])?;

    let session_id = h.clone();
    let keys = derive_keys(&shared, &h, &session_id);
    transport.set_crypto(
        CipherState::new(&keys.s2c_enc_key, &keys.s2c_iv)?,
        CipherState::new(&keys.c2s_enc_key, &keys.c2s_iv)?,
        keys.s2c_mac_key,
        keys.c2s_mac_key,
    );
    Ok(())
}

async fn server_kex_async(
    transport: &mut SshTransport<AsyncTcpTransport>,
    host_key: &HostKey,
    v_c: &[u8],
    v_s: &[u8],
) -> CoreResult<()> {
    let server_kex = KexInit::new();
    let server_payload = server_kex.encode();
    transport.write_packet_async(&server_payload).await?;
    let client_payload = transport.read_packet_async().await?;
    let client_kex = KexInit::decode(&client_payload)?;

    let (kex_alg, host_alg, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c) =
        negotiate(&client_kex, &server_kex)?;
    if kex_alg != KEX_ALG || host_alg != HOSTKEY_ALG || cipher_c2s != CIPHER_ALG || cipher_s2c != CIPHER_ALG || mac_c2s != MAC_ALG || mac_s2c != MAC_ALG {
        return Err(CoreError::Parse("unsupported algorithm".to_string()));
    }

    let init = transport.read_packet_async().await?;
    if init.get(0).copied() != Some(MSG_KEX_ECDH_INIT) {
        return Err(CoreError::Parse("invalid kex init".to_string()));
    }
    let mut cursor = 1usize;
    let client_pub = read_string(&init, &mut cursor)?;

    let (server_kex_key, server_pub) = x25519_keypair()?;

    let shared = x25519_agree(server_kex_key, &client_pub)?;

    let host_key_blob = host_key.public_key_blob();
    let h = kex_hash(
        v_c,
        v_s,
        &client_payload,
        &server_payload,
        &host_key_blob,
        &client_pub,
        &server_pub,
        &shared,
    );
    let signature = host_key.sign(&h);

    let mut reply = Vec::new();
    reply.push(MSG_KEX_ECDH_REPLY);
    encode_string(&mut reply, &host_key_blob);
    encode_string(&mut reply, &server_pub);
    encode_string(&mut reply, &signature);
    transport.write_packet_async(&reply).await?;

    let newkeys = transport.read_packet_async().await?;
    if newkeys.get(0).copied() != Some(MSG_NEWKEYS) {
        return Err(CoreError::Parse("missing newkeys".to_string()));
    }
    transport.write_packet_async(&[MSG_NEWKEYS]).await?;

    let session_id = h.clone();
    let keys = derive_keys(&shared, &h, &session_id);
    transport.set_crypto(
        CipherState::new(&keys.s2c_enc_key, &keys.s2c_iv)?,
        CipherState::new(&keys.c2s_enc_key, &keys.c2s_iv)?,
        keys.s2c_mac_key,
        keys.c2s_mac_key,
    );
    Ok(())
}

fn service_request(transport: &mut SshTransport<TcpTransport>, name: &str) -> CoreResult<()> {
    let mut payload = Vec::new();
    payload.push(MSG_SERVICE_REQUEST);
    encode_string(&mut payload, name.as_bytes());
    transport.write_packet(&payload)?;
    let response = transport.read_packet()?;
    if response.get(0).copied() != Some(MSG_SERVICE_ACCEPT) {
        return Err(CoreError::Parse("service not accepted".to_string()));
    }
    Ok(())
}

async fn service_request_async(transport: &mut SshTransport<AsyncTcpTransport>, name: &str) -> CoreResult<()> {
    let mut payload = Vec::new();
    payload.push(MSG_SERVICE_REQUEST);
    encode_string(&mut payload, name.as_bytes());
    transport.write_packet_async(&payload).await?;
    let response = transport.read_packet_async().await?;
    if response.get(0).copied() != Some(MSG_SERVICE_ACCEPT) {
        return Err(CoreError::Parse("service not accepted".to_string()));
    }
    Ok(())
}

fn verify_hostkey_signature(host_key_blob: &[u8], signature_blob: &[u8], data: &[u8]) -> CoreResult<()> {
    let mut cursor = 0usize;
    let alg = read_string(host_key_blob, &mut cursor)?;
    let key = read_string(host_key_blob, &mut cursor)?;
    if alg != HOSTKEY_ALG.as_bytes() {
        return Err(CoreError::Parse("unsupported host key".to_string()));
    }
    let mut sig_cursor = 0usize;
    let sig_alg = read_string(signature_blob, &mut sig_cursor)?;
    let sig = read_string(signature_blob, &mut sig_cursor)?;
    if sig_alg != HOSTKEY_ALG.as_bytes() {
        return Err(CoreError::Parse("unsupported signature".to_string()));
    }
    let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, key);
    verifier
        .verify(data, &sig)
        .map_err(|_| CoreError::Parse("invalid hostkey signature".to_string()))
}

fn x25519_keypair() -> CoreResult<(agreement::EphemeralPrivateKey, Vec<u8>)> {
    let key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
        .map_err(|_| CoreError::Parse("kex failed".to_string()))?;
    let pubkey = key
        .compute_public_key()
        .map_err(|_| CoreError::Parse("kex failed".to_string()))?;
    Ok((key, pubkey.as_ref().to_vec()))
}

fn x25519_agree(key: agreement::EphemeralPrivateKey, peer_pub: &[u8]) -> CoreResult<Vec<u8>> {
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_pub);
    agreement::agree_ephemeral(key, &peer, |shared| shared.to_vec())
        .map_err(|_| CoreError::Parse("kex failed".to_string()))
}

fn negotiate(client: &KexInit, server: &KexInit) -> CoreResult<(String, String, String, String, String, String)> {
    let kex_alg = first_match(&client.kex_algs, &server.kex_algs)?;
    let host_alg = first_match(&client.host_key_algs, &server.host_key_algs)?;
    let cipher_c2s = first_match(&client.ciphers_c2s, &server.ciphers_c2s)?;
    let cipher_s2c = first_match(&client.ciphers_s2c, &server.ciphers_s2c)?;
    let mac_c2s = first_match(&client.macs_c2s, &server.macs_c2s)?;
    let mac_s2c = first_match(&client.macs_s2c, &server.macs_s2c)?;
    Ok((kex_alg, host_alg, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c))
}

fn first_match(client: &[String], server: &[String]) -> CoreResult<String> {
    for c in client {
        if server.iter().any(|s| s == c) {
            return Ok(c.clone());
        }
    }
    Err(CoreError::Parse("no matching algorithm".to_string()))
}

struct SessionKeys {
    c2s_iv: Vec<u8>,
    s2c_iv: Vec<u8>,
    c2s_enc_key: Vec<u8>,
    s2c_enc_key: Vec<u8>,
    c2s_mac_key: Vec<u8>,
    s2c_mac_key: Vec<u8>,
}

fn derive_keys(k: &[u8], h: &[u8], session_id: &[u8]) -> SessionKeys {
    SessionKeys {
        c2s_iv: derive_key(k, h, session_id, b'A', 16),
        s2c_iv: derive_key(k, h, session_id, b'B', 16),
        c2s_enc_key: derive_key(k, h, session_id, b'C', 16),
        s2c_enc_key: derive_key(k, h, session_id, b'D', 16),
        c2s_mac_key: derive_key(k, h, session_id, b'E', 32),
        s2c_mac_key: derive_key(k, h, session_id, b'F', 32),
    }
}

fn derive_key(k: &[u8], h: &[u8], session_id: &[u8], letter: u8, len: usize) -> Vec<u8> {
    let mut key = Vec::new();
    let mut data = Vec::new();
    data.extend_from_slice(&mpint(k));
    data.extend_from_slice(h);
    data.push(letter);
    data.extend_from_slice(session_id);
    key.extend_from_slice(&sha256::digest(&data));
    while key.len() < len {
        let mut next = Vec::new();
        next.extend_from_slice(&mpint(k));
        next.extend_from_slice(h);
        next.extend_from_slice(&key);
        key.extend_from_slice(&sha256::digest(&next));
    }
    key.truncate(len);
    key
}

fn kex_hash(
    v_c: &[u8],
    v_s: &[u8],
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8],
    q_s: &[u8],
    k: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    encode_string(&mut data, v_c);
    encode_string(&mut data, v_s);
    encode_string(&mut data, i_c);
    encode_string(&mut data, i_s);
    encode_string(&mut data, k_s);
    encode_string(&mut data, q_c);
    encode_string(&mut data, q_s);
    data.extend_from_slice(&mpint(k));
    sha256::digest(&data).to_vec()
}

fn mpint(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0, 0, 0, 0];
    }
    let mut out = Vec::new();
    let mut value = data.to_vec();
    while value.len() > 1 && value[0] == 0 {
        value.remove(0);
    }
    if value[0] & 0x80 != 0 {
        out.extend_from_slice(&((value.len() + 1) as u32).to_be_bytes());
        out.push(0);
        out.extend_from_slice(&value);
    } else {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(&value);
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8], seq: u32) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&seq.to_be_bytes());
    inner.extend_from_slice(data);
    hmac_sha256_raw(key, &inner)
}

fn hmac_sha256_raw(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut o_key = [0u8; 64];
    let mut i_key = [0u8; 64];
    for i in 0..64 {
        o_key[i] = key_block[i] ^ 0x5c;
        i_key[i] = key_block[i] ^ 0x36;
    }
    let mut i_data = Vec::with_capacity(64 + data.len());
    i_data.extend_from_slice(&i_key);
    i_data.extend_from_slice(data);
    let i_hash = sha256::digest(&i_data);

    let mut o_data = Vec::with_capacity(64 + i_hash.len());
    o_data.extend_from_slice(&o_key);
    o_data.extend_from_slice(&i_hash);
    sha256::digest(&o_data).to_vec()
}

fn encode_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn encode_namelist(buf: &mut Vec<u8>, list: &[String]) {
    if list.is_empty() {
        buf.extend_from_slice(&0u32.to_be_bytes());
        return;
    }
    let joined = list.join(",");
    encode_string(buf, joined.as_bytes());
}

fn decode_namelist(data: &[u8], cursor: &mut usize) -> CoreResult<Vec<String>> {
    let raw = read_string(data, cursor)?;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let list = String::from_utf8(raw)
        .map_err(|_| CoreError::Parse("invalid namelist".to_string()))?;
    Ok(list.split(',').map(|s| s.to_string()).collect())
}

fn read_u32(data: &[u8], cursor: &mut usize) -> CoreResult<u32> {
    if *cursor + 4 > data.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let value = u32::from_be_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn read_u8(data: &[u8], cursor: &mut usize) -> CoreResult<u8> {
    if *cursor >= data.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let value = data[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_string(data: &[u8], cursor: &mut usize) -> CoreResult<Vec<u8>> {
    let len = read_u32(data, cursor)? as usize;
    if *cursor + len > data.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let out = data[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAuth;

    impl AuthHandler for TestAuth {
        fn check_password(&self, username: &str, password: &str) -> bool {
            username == "user" && password == "pass"
        }

        fn check_publickey(&self, _username: &str, _key_blob: &[u8], _signature: Option<&[u8]>) -> bool {
            false
        }
    }

    #[test]
    fn kex_init_roundtrip() {
        let kex = KexInit::new();
        let encoded = kex.encode();
        let decoded = KexInit::decode(&encoded).unwrap();
        assert_eq!(decoded.kex_algs[0], KEX_ALG);
        assert_eq!(decoded.host_key_algs[0], HOSTKEY_ALG);
    }

    #[test]
    fn mpint_encoding() {
        let data = [0x80u8];
        let encoded = mpint(&data);
        assert_eq!(encoded.len(), 6);
    }

    #[test]
    fn server_client_roundtrip() {
        let host_key = HostKey::from_seed(&[7u8; 32]).unwrap();
        let server = match SshServer::bind("127.0.0.1:0".parse().unwrap(), host_key, SshConfig::default(), Timeouts::default()) {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {:?}", err),
        };
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve(TestAuth);
        });

        let mut client = SshClient::connect(&NetAddr::from_socket(addr), Timeouts::default()).unwrap();
        client.userauth_password("user", "pass").unwrap();
        let mut channel = client.open_session().unwrap();
        client.send_channel_data(&mut channel, b"ping").unwrap();
        let data = client.recv_channel_data(&mut channel).unwrap();
        assert_eq!(data, b"ping");
    }
}
