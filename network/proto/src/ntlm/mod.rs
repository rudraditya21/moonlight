use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};
use md5::digest as md5_digest;
use ring::rand::{SecureRandom, SystemRandom};

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const NEGOTIATE_OEM: u32 = 0x0000_0002;
pub const REQUEST_TARGET: u32 = 0x0000_0004;
pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub const NEGOTIATE_SEAL: u32 = 0x0000_0020;
pub const NEGOTIATE_DATAGRAM: u32 = 0x0000_0040;
pub const NEGOTIATE_LM_KEY: u32 = 0x0000_0080;
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
pub const NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub const NEGOTIATE_128: u32 = 0x2000_0000;
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub const NEGOTIATE_56: u32 = 0x8000_0000;

const TYPE_NEGOTIATE: u32 = 1;
const TYPE_CHALLENGE: u32 = 2;
const TYPE_AUTHENTICATE: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub ntlm_rev: u8,
}

impl Version {
    pub fn windows_10() -> Self {
        Self {
            major: 10,
            minor: 0,
            build: 19041,
            ntlm_rev: 15,
        }
    }

    fn encode(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.major;
        out[1] = self.minor;
        out[2..4].copy_from_slice(&self.build.to_le_bytes());
        out[4] = 0;
        out[5] = 0;
        out[6] = 0;
        out[7] = self.ntlm_rev;
        out
    }

    fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 8 {
            return Err(CoreError::Parse("invalid version".to_string()));
        }
        Ok(Self {
            major: data[0],
            minor: data[1],
            build: u16::from_le_bytes([data[2], data[3]]),
            ntlm_rev: data[7],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateMessage {
    pub flags: u32,
    pub domain: String,
    pub workstation: String,
    pub version: Option<Version>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeMessage {
    pub target_name: String,
    pub flags: u32,
    pub server_challenge: [u8; 8],
    pub target_info: Vec<AvPair>,
    pub version: Option<Version>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateMessage {
    pub lm_response: Vec<u8>,
    pub nt_response: Vec<u8>,
    pub domain: String,
    pub user: String,
    pub workstation: String,
    pub encrypted_session_key: Vec<u8>,
    pub flags: u32,
    pub version: Option<Version>,
    pub mic: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtlmMessage {
    Negotiate(NegotiateMessage),
    Challenge(ChallengeMessage),
    Authenticate(AuthenticateMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvPair {
    Eol,
    NbComputerName(String),
    NbDomainName(String),
    DnsComputerName(String),
    DnsDomainName(String),
    DnsTreeName(String),
    Flags(u32),
    Timestamp(u64),
    SingleHost(Vec<u8>),
    TargetName(String),
    ChannelBindings([u8; 16]),
    Unknown(u16, Vec<u8>),
}

impl AvPair {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            AvPair::Eol => {
                out.extend_from_slice(&0u16.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes());
            }
            AvPair::NbComputerName(value) => encode_av_string(out, 1, value),
            AvPair::NbDomainName(value) => encode_av_string(out, 2, value),
            AvPair::DnsComputerName(value) => encode_av_string(out, 3, value),
            AvPair::DnsDomainName(value) => encode_av_string(out, 4, value),
            AvPair::DnsTreeName(value) => encode_av_string(out, 5, value),
            AvPair::Flags(value) => {
                out.extend_from_slice(&6u16.to_le_bytes());
                out.extend_from_slice(&4u16.to_le_bytes());
                out.extend_from_slice(&value.to_le_bytes());
            }
            AvPair::Timestamp(value) => {
                out.extend_from_slice(&7u16.to_le_bytes());
                out.extend_from_slice(&8u16.to_le_bytes());
                out.extend_from_slice(&value.to_le_bytes());
            }
            AvPair::SingleHost(value) => {
                out.extend_from_slice(&8u16.to_le_bytes());
                out.extend_from_slice(&(value.len() as u16).to_le_bytes());
                out.extend_from_slice(value);
            }
            AvPair::TargetName(value) => encode_av_string(out, 9, value),
            AvPair::ChannelBindings(value) => {
                out.extend_from_slice(&10u16.to_le_bytes());
                out.extend_from_slice(&16u16.to_le_bytes());
                out.extend_from_slice(value);
            }
            AvPair::Unknown(id, value) => {
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&(value.len() as u16).to_le_bytes());
                out.extend_from_slice(value);
            }
        }
    }

    fn decode(mut data: &[u8]) -> CoreResult<Vec<AvPair>> {
        let mut out = Vec::new();
        while data.len() >= 4 {
            let id = u16::from_le_bytes([data[0], data[1]]);
            let len = u16::from_le_bytes([data[2], data[3]]) as usize;
            data = &data[4..];
            if data.len() < len {
                return Err(CoreError::Parse("invalid AV pair".to_string()));
            }
            let value = &data[..len];
            data = &data[len..];
            let pair = match id {
                0 => AvPair::Eol,
                1 => AvPair::NbComputerName(decode_av_string(value)?),
                2 => AvPair::NbDomainName(decode_av_string(value)?),
                3 => AvPair::DnsComputerName(decode_av_string(value)?),
                4 => AvPair::DnsDomainName(decode_av_string(value)?),
                5 => AvPair::DnsTreeName(decode_av_string(value)?),
                6 => {
                    if value.len() != 4 {
                        return Err(CoreError::Parse("invalid AV flags".to_string()));
                    }
                    AvPair::Flags(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
                }
                7 => {
                    if value.len() != 8 {
                        return Err(CoreError::Parse("invalid AV timestamp".to_string()));
                    }
                    AvPair::Timestamp(u64::from_le_bytes([
                        value[0], value[1], value[2], value[3], value[4], value[5], value[6],
                        value[7],
                    ]))
                }
                8 => AvPair::SingleHost(value.to_vec()),
                9 => AvPair::TargetName(decode_av_string(value)?),
                10 => {
                    if value.len() != 16 {
                        return Err(CoreError::Parse("invalid AV channel bindings".to_string()));
                    }
                    let mut out_bytes = [0u8; 16];
                    out_bytes.copy_from_slice(value);
                    AvPair::ChannelBindings(out_bytes)
                }
                _ => AvPair::Unknown(id, value.to_vec()),
            };
            out.push(pair);
            if matches!(out.last(), Some(AvPair::Eol)) {
                break;
            }
        }
        Ok(out)
    }
}

fn encode_av_string(out: &mut Vec<u8>, id: u16, value: &str) {
    let encoded = utf16le_bytes(value);
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(encoded.len() as u16).to_le_bytes());
    out.extend_from_slice(&encoded);
}

fn decode_av_string(value: &[u8]) -> CoreResult<String> {
    decode_utf16le(value)
}

impl NegotiateMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = self.flags;
        if !self.domain.is_empty() {
            flags |= NEGOTIATE_OEM_DOMAIN_SUPPLIED;
        }
        if !self.workstation.is_empty() {
            flags |= NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
        }
        let domain_bytes = encode_string(&self.domain, flags);
        let workstation_bytes = encode_string(&self.workstation, flags);
        let mut payload = Vec::new();
        let base_len = 32 + if self.version.is_some() { 8 } else { 0 };
        let domain_offset = base_len + payload.len();
        payload.extend_from_slice(&domain_bytes);
        let workstation_offset = base_len + payload.len();
        payload.extend_from_slice(&workstation_bytes);

        let mut out = Vec::with_capacity(base_len + payload.len());
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&TYPE_NEGOTIATE.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&security_buffer(domain_bytes.len(), domain_offset));
        out.extend_from_slice(&security_buffer(
            workstation_bytes.len(),
            workstation_offset,
        ));
        if let Some(version) = self.version {
            out.extend_from_slice(&version.encode());
        }
        out.extend_from_slice(&payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 32 || &data[..8] != SIGNATURE {
            return Err(CoreError::Parse("invalid NTLM negotiate".to_string()));
        }
        let message_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if message_type != TYPE_NEGOTIATE {
            return Err(CoreError::Parse("invalid NTLM negotiate type".to_string()));
        }
        let flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let (domain_len, domain_offset) = read_security_buffer(&data[16..24])?;
        let (workstation_len, workstation_offset) = read_security_buffer(&data[24..32])?;
        let mut cursor = 32;
        let version = if data.len() >= 40 && (flags & NEGOTIATE_VERSION) != 0 {
            let ver = Version::decode(&data[32..40])?;
            cursor = 40;
            Some(ver)
        } else {
            None
        };
        let domain = read_string(data, domain_offset, domain_len, flags)?;
        let workstation = read_string(data, workstation_offset, workstation_len, flags)?;
        let _ = cursor;
        Ok(Self {
            flags,
            domain,
            workstation,
            version,
        })
    }
}

impl ChallengeMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = self.flags;
        if !self.target_info.is_empty() {
            flags |= NEGOTIATE_TARGET_INFO;
        }
        let target_name_bytes = encode_string(&self.target_name, flags);
        let mut target_info_bytes = Vec::new();
        for pair in &self.target_info {
            pair.encode(&mut target_info_bytes);
        }
        if !self.target_info.iter().any(|p| matches!(p, AvPair::Eol)) {
            AvPair::Eol.encode(&mut target_info_bytes);
        }
        let base_len = 48 + if self.version.is_some() { 8 } else { 0 };
        let target_name_offset = base_len;
        let target_info_offset = base_len + target_name_bytes.len();
        let mut out =
            Vec::with_capacity(base_len + target_name_bytes.len() + target_info_bytes.len());
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&TYPE_CHALLENGE.to_le_bytes());
        out.extend_from_slice(&security_buffer(
            target_name_bytes.len(),
            target_name_offset,
        ));
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&self.server_challenge);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&security_buffer(
            target_info_bytes.len(),
            target_info_offset,
        ));
        if let Some(version) = self.version {
            out.extend_from_slice(&version.encode());
        }
        out.extend_from_slice(&target_name_bytes);
        out.extend_from_slice(&target_info_bytes);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 48 || &data[..8] != SIGNATURE {
            return Err(CoreError::Parse("invalid NTLM challenge".to_string()));
        }
        let message_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if message_type != TYPE_CHALLENGE {
            return Err(CoreError::Parse("invalid NTLM challenge type".to_string()));
        }
        let (target_len, target_offset) = read_security_buffer(&data[12..20])?;
        let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(&data[24..32]);
        let (target_info_len, target_info_offset) = read_security_buffer(&data[40..48])?;
        let version = if data.len() >= 56 && (flags & NEGOTIATE_VERSION) != 0 {
            Some(Version::decode(&data[48..56])?)
        } else {
            None
        };
        let target_name = read_string(data, target_offset, target_len, flags)?;
        let target_info = if target_info_len > 0 {
            let start = target_info_offset;
            let end = target_info_offset + target_info_len;
            if end > data.len() {
                return Err(CoreError::Parse("invalid target info offset".to_string()));
            }
            AvPair::decode(&data[start..end])?
        } else {
            Vec::new()
        };
        Ok(Self {
            target_name,
            flags,
            server_challenge,
            target_info,
            version,
        })
    }
}

impl AuthenticateMessage {
    pub fn encode(&self) -> Vec<u8> {
        let flags = self.flags;
        let lm_bytes = self.lm_response.clone();
        let nt_bytes = self.nt_response.clone();
        let domain_bytes = encode_string(&self.domain, flags);
        let user_bytes = encode_string(&self.user, flags);
        let workstation_bytes = encode_string(&self.workstation, flags);
        let session_bytes = self.encrypted_session_key.clone();
        let base_len = 64
            + if self.version.is_some() { 8 } else { 0 }
            + if self.mic.is_some() { 16 } else { 0 };
        let mut payload = Vec::new();
        let lm_offset = base_len + payload.len();
        payload.extend_from_slice(&lm_bytes);
        let nt_offset = base_len + payload.len();
        payload.extend_from_slice(&nt_bytes);
        let domain_offset = base_len + payload.len();
        payload.extend_from_slice(&domain_bytes);
        let user_offset = base_len + payload.len();
        payload.extend_from_slice(&user_bytes);
        let workstation_offset = base_len + payload.len();
        payload.extend_from_slice(&workstation_bytes);
        let session_offset = base_len + payload.len();
        payload.extend_from_slice(&session_bytes);

        let mut out = Vec::with_capacity(base_len + payload.len());
        out.extend_from_slice(SIGNATURE);
        out.extend_from_slice(&TYPE_AUTHENTICATE.to_le_bytes());
        out.extend_from_slice(&security_buffer(lm_bytes.len(), lm_offset));
        out.extend_from_slice(&security_buffer(nt_bytes.len(), nt_offset));
        out.extend_from_slice(&security_buffer(domain_bytes.len(), domain_offset));
        out.extend_from_slice(&security_buffer(user_bytes.len(), user_offset));
        out.extend_from_slice(&security_buffer(
            workstation_bytes.len(),
            workstation_offset,
        ));
        out.extend_from_slice(&security_buffer(session_bytes.len(), session_offset));
        out.extend_from_slice(&flags.to_le_bytes());
        if let Some(version) = self.version {
            out.extend_from_slice(&version.encode());
        }
        if let Some(mic) = self.mic {
            out.extend_from_slice(&mic);
        }
        out.extend_from_slice(&payload);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 64 || &data[..8] != SIGNATURE {
            return Err(CoreError::Parse("invalid NTLM authenticate".to_string()));
        }
        let message_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if message_type != TYPE_AUTHENTICATE {
            return Err(CoreError::Parse(
                "invalid NTLM authenticate type".to_string(),
            ));
        }
        let (lm_len, lm_offset) = read_security_buffer(&data[12..20])?;
        let (nt_len, nt_offset) = read_security_buffer(&data[20..28])?;
        let (domain_len, domain_offset) = read_security_buffer(&data[28..36])?;
        let (user_len, user_offset) = read_security_buffer(&data[36..44])?;
        let (workstation_len, workstation_offset) = read_security_buffer(&data[44..52])?;
        let (session_len, session_offset) = read_security_buffer(&data[52..60])?;
        let flags = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
        let mut cursor = 64;
        let version = if data.len() >= cursor + 8 && (flags & NEGOTIATE_VERSION) != 0 {
            let ver = Version::decode(&data[cursor..cursor + 8])?;
            cursor += 8;
            Some(ver)
        } else {
            None
        };
        let mut payload_start = usize::MAX;
        let buffers = [
            (lm_len, lm_offset),
            (nt_len, nt_offset),
            (domain_len, domain_offset),
            (user_len, user_offset),
            (workstation_len, workstation_offset),
            (session_len, session_offset),
        ];
        for (len, offset) in buffers {
            if len > 0 && offset < payload_start {
                payload_start = offset;
            }
        }
        if payload_start == usize::MAX {
            payload_start = data.len();
        }
        let mic = if cursor + 16 <= payload_start {
            let mut mic = [0u8; 16];
            mic.copy_from_slice(&data[cursor..cursor + 16]);
            Some(mic)
        } else {
            None
        };
        let lm_response = read_bytes(data, lm_offset, lm_len)?;
        let nt_response = read_bytes(data, nt_offset, nt_len)?;
        let domain = read_string(data, domain_offset, domain_len, flags)?;
        let user = read_string(data, user_offset, user_len, flags)?;
        let workstation = read_string(data, workstation_offset, workstation_len, flags)?;
        let encrypted_session_key = read_bytes(data, session_offset, session_len)?;
        Ok(Self {
            lm_response,
            nt_response,
            domain,
            user,
            workstation,
            encrypted_session_key,
            flags,
            version,
            mic,
        })
    }
}

impl NtlmMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            NtlmMessage::Negotiate(msg) => msg.encode(),
            NtlmMessage::Challenge(msg) => msg.encode(),
            NtlmMessage::Authenticate(msg) => msg.encode(),
        }
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 12 || &data[..8] != SIGNATURE {
            return Err(CoreError::Parse("invalid NTLM message".to_string()));
        }
        let message_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        match message_type {
            TYPE_NEGOTIATE => Ok(NtlmMessage::Negotiate(NegotiateMessage::decode(data)?)),
            TYPE_CHALLENGE => Ok(NtlmMessage::Challenge(ChallengeMessage::decode(data)?)),
            TYPE_AUTHENTICATE => Ok(NtlmMessage::Authenticate(AuthenticateMessage::decode(
                data,
            )?)),
            _ => Err(CoreError::Parse("invalid NTLM message type".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub enum NtlmSecret {
    Plaintext(String),
    NtHash([u8; 16]),
    LmHash([u8; 16]),
}

impl NtlmSecret {
    fn nt_hash(&self) -> Option<[u8; 16]> {
        match self {
            NtlmSecret::Plaintext(value) => Some(nt_hash(value)),
            NtlmSecret::NtHash(value) => Some(*value),
            NtlmSecret::LmHash(_) => None,
        }
    }

    fn lm_hash(&self) -> Option<[u8; 16]> {
        match self {
            NtlmSecret::Plaintext(value) => Some(lm_hash(value)),
            NtlmSecret::NtHash(_) => None,
            NtlmSecret::LmHash(value) => Some(*value),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NtlmClientConfig {
    pub username: String,
    pub password: NtlmSecret,
    pub domain: String,
    pub workstation: String,
    pub flags: u32,
    pub client_challenge: Option<[u8; 8]>,
    pub timestamp: Option<u64>,
    pub version: Option<Version>,
}

impl Default for NtlmClientConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: NtlmSecret::Plaintext(String::new()),
            domain: String::new(),
            workstation: String::from("MOONLIGHT"),
            flags: default_flags(),
            client_challenge: None,
            timestamp: None,
            version: Some(Version::windows_10()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NtlmServerConfig {
    pub target_name: String,
    pub flags: u32,
    pub server_challenge: Option<[u8; 8]>,
    pub target_info: Vec<AvPair>,
    pub credentials: HashMap<String, NtlmSecret>,
    pub version: Option<Version>,
}

impl Default for NtlmServerConfig {
    fn default() -> Self {
        Self {
            target_name: String::from("MOONLIGHT"),
            flags: default_flags(),
            server_challenge: None,
            target_info: Vec::new(),
            credentials: HashMap::new(),
            version: Some(Version::windows_10()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NtlmClient {
    config: NtlmClientConfig,
}

#[derive(Debug, Clone)]
pub struct NtlmServer {
    config: NtlmServerConfig,
}

#[derive(Debug, Clone)]
pub struct NtlmSession {
    pub exported_session_key: [u8; 16],
    pub signing_key_client: [u8; 16],
    pub signing_key_server: [u8; 16],
    pub sealing_key_client: [u8; 16],
    pub sealing_key_server: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct NtlmSigner {
    key: [u8; 16],
    seq: u32,
}

#[derive(Debug, Clone)]
pub struct NtlmSealer {
    rc4: Rc4,
    signer: NtlmSigner,
}

impl NtlmSigner {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key, seq: 0 }
    }

    pub fn sign(&mut self, message: &[u8]) -> [u8; 16] {
        let mut payload = Vec::with_capacity(4 + message.len());
        payload.extend_from_slice(&self.seq.to_le_bytes());
        payload.extend_from_slice(message);
        let checksum = hmac_md5(&self.key, &payload);
        let mut signature = [0u8; 16];
        signature[..4].copy_from_slice(&1u32.to_le_bytes());
        signature[4..12].copy_from_slice(&checksum[..8]);
        signature[12..16].copy_from_slice(&self.seq.to_le_bytes());
        self.seq = self.seq.wrapping_add(1);
        signature
    }
}

impl NtlmSealer {
    pub fn new(sealing_key: [u8; 16], signing_key: [u8; 16]) -> Self {
        Self {
            rc4: Rc4::new(&sealing_key),
            signer: NtlmSigner::new(signing_key),
        }
    }

    pub fn seal(&mut self, message: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut data = message.to_vec();
        let mut signature = self.signer.sign(message);
        self.rc4.process(&mut data);
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&signature[4..12]);
        self.rc4.process(&mut checksum);
        signature[4..12].copy_from_slice(&checksum);
        (data, signature)
    }
}

impl NtlmClient {
    pub fn new(config: NtlmClientConfig) -> Self {
        Self { config }
    }

    pub fn negotiate(&self) -> NegotiateMessage {
        NegotiateMessage {
            flags: self.config.flags,
            domain: self.config.domain.clone(),
            workstation: self.config.workstation.clone(),
            version: self.config.version,
        }
    }

    pub fn respond(
        &self,
        challenge: &ChallengeMessage,
    ) -> CoreResult<(AuthenticateMessage, NtlmSession)> {
        let flags = merge_flags(self.config.flags, challenge.flags);
        let nt_hash = self
            .config
            .password
            .nt_hash()
            .ok_or_else(|| CoreError::Message("NTLM client requires NT hash".to_string()))?;
        let lm_hash_opt = self.config.password.lm_hash();
        let client_challenge = self
            .config
            .client_challenge
            .unwrap_or_else(|| random_bytes_8());
        let timestamp = self.config.timestamp.unwrap_or_else(filetime_now);

        let (lm_response, nt_response, session_base_key) =
            if (flags & NEGOTIATE_EXTENDED_SESSIONSECURITY) != 0
                || challenge
                    .target_info
                    .iter()
                    .any(|p| matches!(p, AvPair::Eol))
                || challenge.target_info.len() > 0
            {
                let ntlmv2_hash = ntlmv2_hash(&nt_hash, &self.config.username, &self.config.domain);
                let mut target_info = challenge.target_info.clone();
                if !target_info.iter().any(|p| matches!(p, AvPair::Eol)) {
                    target_info.push(AvPair::Eol);
                }
                let blob = build_ntlmv2_blob(timestamp, client_challenge, &target_info);
                let mut data = Vec::with_capacity(8 + blob.len());
                data.extend_from_slice(&challenge.server_challenge);
                data.extend_from_slice(&blob);
                let nt_proof = hmac_md5(&ntlmv2_hash, &data);
                let mut nt_response = Vec::with_capacity(16 + blob.len());
                nt_response.extend_from_slice(&nt_proof);
                nt_response.extend_from_slice(&blob);
                let mut lm_data = Vec::with_capacity(16);
                lm_data.extend_from_slice(&challenge.server_challenge);
                lm_data.extend_from_slice(&client_challenge);
                let lm_hash = hmac_md5(&ntlmv2_hash, &lm_data);
                let mut lm_response = Vec::with_capacity(24);
                lm_response.extend_from_slice(&lm_hash);
                lm_response.extend_from_slice(&client_challenge);
                let session_base_key = hmac_md5(&ntlmv2_hash, &nt_proof);
                (lm_response, nt_response, session_base_key)
            } else {
                let nt_response = ntlm_v1_response(&nt_hash, &challenge.server_challenge);
                let lm_hash = lm_hash_opt
                    .ok_or_else(|| CoreError::Message("NTLMv1 requires LM hash".to_string()))?;
                let lm_response = lm_v1_response(&lm_hash, &challenge.server_challenge);
                let session_base_key = md4_digest(&nt_hash);
                (lm_response.to_vec(), nt_response.to_vec(), session_base_key)
            };

        let (exported_session_key, encrypted_session_key) = if (flags & NEGOTIATE_KEY_EXCH) != 0 {
            let mut random = [0u8; 16];
            let _ = SystemRandom::new().fill(&mut random);
            let mut rc4 = Rc4::new(&session_base_key);
            let encrypted = rc4.apply(&random);
            (random, encrypted)
        } else {
            (session_base_key, Vec::new())
        };

        let session = derive_session_keys(exported_session_key);

        let authenticate = AuthenticateMessage {
            lm_response,
            nt_response,
            domain: self.config.domain.clone(),
            user: self.config.username.clone(),
            workstation: self.config.workstation.clone(),
            encrypted_session_key,
            flags,
            version: self.config.version,
            mic: None,
        };

        Ok((authenticate, session))
    }
}

impl NtlmServer {
    pub fn new(config: NtlmServerConfig) -> Self {
        Self { config }
    }

    pub fn challenge(&self, negotiate: &NegotiateMessage) -> ChallengeMessage {
        let flags = merge_flags(self.config.flags, negotiate.flags);
        let mut server_challenge = [0u8; 8];
        if let Some(challenge) = self.config.server_challenge {
            server_challenge = challenge;
        } else {
            let _ = SystemRandom::new().fill(&mut server_challenge);
        }
        ChallengeMessage {
            target_name: self.config.target_name.clone(),
            flags,
            server_challenge,
            target_info: self.config.target_info.clone(),
            version: self.config.version,
        }
    }

    pub fn authenticate(
        &self,
        challenge: &ChallengeMessage,
        authenticate: &AuthenticateMessage,
    ) -> CoreResult<NtlmSession> {
        let username_key = authenticate.user.to_ascii_uppercase();
        let secret = self
            .config
            .credentials
            .get(&username_key)
            .or_else(|| self.config.credentials.get(&authenticate.user))
            .ok_or_else(|| CoreError::Message("unknown NTLM user".to_string()))?;
        let flags = authenticate.flags;
        let nt_hash = secret
            .nt_hash()
            .ok_or_else(|| CoreError::Message("NTLM server requires NT hash".to_string()))?;
        let lm_hash = secret.lm_hash();
        let session_base_key = if (flags & NEGOTIATE_EXTENDED_SESSIONSECURITY) != 0
            || authenticate.nt_response.len() > 24
        {
            let ntlmv2_hash = ntlmv2_hash(&nt_hash, &authenticate.user, &authenticate.domain);
            let nt_response = &authenticate.nt_response;
            if nt_response.len() < 16 {
                return Err(CoreError::Parse("invalid NTLMv2 response".to_string()));
            }
            let nt_proof = &nt_response[..16];
            let blob = &nt_response[16..];
            let mut data = Vec::with_capacity(8 + blob.len());
            data.extend_from_slice(&challenge.server_challenge);
            data.extend_from_slice(blob);
            let expected = hmac_md5(&ntlmv2_hash, &data);
            if !constant_time_eq(&expected, nt_proof) {
                return Err(CoreError::Message("invalid NTLMv2 proof".to_string()));
            }
            if authenticate.lm_response.len() == 24 {
                let mut data = Vec::with_capacity(16);
                data.extend_from_slice(&challenge.server_challenge);
                data.extend_from_slice(&authenticate.lm_response[16..]);
                let expected_lm = hmac_md5(&ntlmv2_hash, &data);
                if !constant_time_eq(&expected_lm, &authenticate.lm_response[..16]) {
                    return Err(CoreError::Message("invalid LMv2 response".to_string()));
                }
            }
            hmac_md5(&ntlmv2_hash, nt_proof)
        } else {
            let expected_nt = ntlm_v1_response(&nt_hash, &challenge.server_challenge);
            if !constant_time_eq(&expected_nt, &authenticate.nt_response) {
                return Err(CoreError::Message("invalid NTLMv1 response".to_string()));
            }
            if !authenticate.lm_response.is_empty() {
                if let Some(lm_hash) = lm_hash {
                    let expected_lm = lm_v1_response(&lm_hash, &challenge.server_challenge);
                    if !constant_time_eq(&expected_lm, &authenticate.lm_response) {
                        return Err(CoreError::Message("invalid LM response".to_string()));
                    }
                } else {
                    return Err(CoreError::Message("LM hash unavailable".to_string()));
                }
            }
            md4_digest(&nt_hash)
        };

        let exported_session_key = if (flags & NEGOTIATE_KEY_EXCH) != 0
            && authenticate.encrypted_session_key.len() == 16
        {
            let mut rc4 = Rc4::new(&session_base_key);
            let mut decrypted = authenticate.encrypted_session_key.clone();
            rc4.process(&mut decrypted);
            let mut out = [0u8; 16];
            out.copy_from_slice(&decrypted);
            out
        } else {
            session_base_key
        };

        Ok(derive_session_keys(exported_session_key))
    }
}

pub fn default_flags() -> u32 {
    NEGOTIATE_UNICODE
        | NEGOTIATE_OEM
        | REQUEST_TARGET
        | NEGOTIATE_SIGN
        | NEGOTIATE_SEAL
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN
        | NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NEGOTIATE_TARGET_INFO
        | NEGOTIATE_VERSION
        | NEGOTIATE_128
        | NEGOTIATE_56
}

pub fn encode_http_token(message: &NtlmMessage) -> String {
    format!("NTLM {}", base64_encode(&message.encode()))
}

pub fn decode_http_token(header_value: &str) -> CoreResult<NtlmMessage> {
    let token = header_value.trim();
    let token = token.strip_prefix("NTLM").unwrap_or(token).trim();
    let data =
        base64_decode(token).ok_or_else(|| CoreError::Parse("invalid base64".to_string()))?;
    NtlmMessage::decode(&data)
}

fn merge_flags(client: u32, server: u32) -> u32 {
    let mut flags = client & server;
    if (flags & NEGOTIATE_UNICODE) == 0 {
        flags |= NEGOTIATE_OEM;
    }
    flags
}

fn security_buffer(len: usize, offset: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    let len_u16 = len as u16;
    out[0..2].copy_from_slice(&len_u16.to_le_bytes());
    out[2..4].copy_from_slice(&len_u16.to_le_bytes());
    out[4..8].copy_from_slice(&(offset as u32).to_le_bytes());
    out
}

fn read_security_buffer(data: &[u8]) -> CoreResult<(usize, usize)> {
    if data.len() < 8 {
        return Err(CoreError::Parse("invalid security buffer".to_string()));
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    Ok((len, offset))
}

fn read_bytes(data: &[u8], offset: usize, len: usize) -> CoreResult<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let end = offset + len;
    if end > data.len() {
        return Err(CoreError::Parse("invalid buffer offset".to_string()));
    }
    Ok(data[offset..end].to_vec())
}

fn read_string(data: &[u8], offset: usize, len: usize, flags: u32) -> CoreResult<String> {
    let bytes = read_bytes(data, offset, len)?;
    if bytes.is_empty() {
        return Ok(String::new());
    }
    if (flags & NEGOTIATE_UNICODE) != 0 {
        decode_utf16le(&bytes)
    } else {
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

fn encode_string(value: &str, flags: u32) -> Vec<u8> {
    if value.is_empty() {
        return Vec::new();
    }
    if (flags & NEGOTIATE_UNICODE) != 0 {
        utf16le_bytes(value)
    } else {
        value.as_bytes().to_vec()
    }
}

fn decode_utf16le(bytes: &[u8]) -> CoreResult<String> {
    if bytes.len() % 2 != 0 {
        return Err(CoreError::Parse("invalid utf16 length".to_string()));
    }
    let mut words = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        words.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&words).map_err(|_| CoreError::Parse("invalid utf16".to_string()))
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn nt_hash(password: &str) -> [u8; 16] {
    let bytes = utf16le_bytes(password);
    md4_digest(&bytes)
}

fn lm_hash(password: &str) -> [u8; 16] {
    let mut oem = Vec::with_capacity(14);
    for c in password.chars() {
        if oem.len() >= 14 {
            break;
        }
        if c.is_ascii() {
            oem.push(c.to_ascii_uppercase() as u8);
        } else {
            oem.push(b'?');
        }
    }
    while oem.len() < 14 {
        oem.push(0);
    }
    let mut out = [0u8; 16];
    let key1 = des_key_from_7bytes(&oem[0..7]);
    let key2 = des_key_from_7bytes(&oem[7..14]);
    let block = *b"KGS!@#$%";
    out[..8].copy_from_slice(&des_encrypt_block(key1, block));
    out[8..].copy_from_slice(&des_encrypt_block(key2, block));
    out
}

fn ntlm_v1_response(nt_hash: &[u8; 16], challenge: &[u8; 8]) -> [u8; 24] {
    let mut key_bytes = [0u8; 21];
    key_bytes[..16].copy_from_slice(nt_hash);
    let key1 = des_key_from_7bytes(&key_bytes[0..7]);
    let key2 = des_key_from_7bytes(&key_bytes[7..14]);
    let key3 = des_key_from_7bytes(&key_bytes[14..21]);
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(&des_encrypt_block(key1, *challenge));
    out[8..16].copy_from_slice(&des_encrypt_block(key2, *challenge));
    out[16..].copy_from_slice(&des_encrypt_block(key3, *challenge));
    out
}

fn lm_v1_response(lm_hash: &[u8; 16], challenge: &[u8; 8]) -> [u8; 24] {
    let mut key_bytes = [0u8; 21];
    key_bytes[..16].copy_from_slice(lm_hash);
    let key1 = des_key_from_7bytes(&key_bytes[0..7]);
    let key2 = des_key_from_7bytes(&key_bytes[7..14]);
    let key3 = des_key_from_7bytes(&key_bytes[14..21]);
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(&des_encrypt_block(key1, *challenge));
    out[8..16].copy_from_slice(&des_encrypt_block(key2, *challenge));
    out[16..].copy_from_slice(&des_encrypt_block(key3, *challenge));
    out
}

fn ntlmv2_hash(nt_hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let mut id = String::new();
    id.push_str(&user.to_ascii_uppercase());
    id.push_str(domain);
    let id_bytes = utf16le_bytes(&id);
    hmac_md5(nt_hash, &id_bytes)
}

fn build_ntlmv2_blob(timestamp: u64, client_challenge: [u8; 8], target_info: &[AvPair]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&0x01010000u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&0u32.to_le_bytes());
    let mut info_bytes = Vec::new();
    for pair in target_info {
        pair.encode(&mut info_bytes);
    }
    if !target_info.iter().any(|p| matches!(p, AvPair::Eol)) {
        AvPair::Eol.encode(&mut info_bytes);
    }
    blob.extend_from_slice(&info_bytes);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob
}

fn derive_session_keys(exported_session_key: [u8; 16]) -> NtlmSession {
    let signing_key_client = md5_magic(
        &exported_session_key,
        b"session key to client-to-server signing key magic constant",
    );
    let signing_key_server = md5_magic(
        &exported_session_key,
        b"session key to server-to-client signing key magic constant",
    );
    let sealing_key_client = md5_magic(
        &exported_session_key,
        b"session key to client-to-server sealing key magic constant",
    );
    let sealing_key_server = md5_magic(
        &exported_session_key,
        b"session key to server-to-client sealing key magic constant",
    );
    NtlmSession {
        exported_session_key,
        signing_key_client,
        signing_key_server,
        sealing_key_client,
        sealing_key_server,
    }
}

fn md5_magic(key: &[u8; 16], magic: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(16 + magic.len());
    data.extend_from_slice(key);
    data.extend_from_slice(magic);
    md5_digest(&data)
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let digest = md5_digest(key);
        key_block[..16].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut o_key_pad = [0u8; 64];
    let mut i_key_pad = [0u8; 64];
    for i in 0..64 {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&i_key_pad);
    inner.extend_from_slice(data);
    let inner_digest = md5_digest(&inner);
    let mut outer = Vec::with_capacity(64 + 16);
    outer.extend_from_slice(&o_key_pad);
    outer.extend_from_slice(&inner_digest);
    md5_digest(&outer)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn random_bytes_8() -> [u8; 8] {
    let mut out = [0u8; 8];
    let _ = SystemRandom::new().fill(&mut out);
    out
}

fn filetime_now() -> u64 {
    const UNIX_TO_FILETIME: u64 = 11644473600;
    const HUNDRED_NANOSECONDS: u64 = 10_000_000;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs() + UNIX_TO_FILETIME) * HUNDRED_NANOSECONDS + (now.subsec_nanos() as u64 / 100)
}

#[derive(Debug, Clone)]
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256u16 {
            let idx = i as u8;
            j = j
                .wrapping_add(s[idx as usize])
                .wrapping_add(key[i as usize % key.len()]);
            s.swap(idx as usize, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            let k = self.s[idx as usize];
            *byte ^= k;
        }
    }

    fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.process(&mut out);
        out
    }
}

fn md4_digest(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize()
}

struct Md4 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    length_bits: u64,
}

impl Md4 {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buffer: [0u8; 64],
            buffer_len: 0,
            length_bits: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.length_bits = self.length_bits.wrapping_add((data.len() as u64) * 8);
        let mut offset = 0;
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..self.buffer_len + needed]
                    .copy_from_slice(&data[..needed]);
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
                offset = needed;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }
        while offset + 64 <= data.len() {
            self.process_block(&data[offset..offset + 64]);
            offset += 64;
        }
        if offset < data.len() {
            let remaining = &data[offset..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.length_bits;
        let mut padding = [0u8; 64];
        padding[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            64 + 56 - self.buffer_len
        };
        self.update(&padding[..pad_len]);
        self.update(&bit_len.to_le_bytes());
        let mut out = [0u8; 16];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            let start = i * 4;
            x[i] = u32::from_le_bytes([
                block[start],
                block[start + 1],
                block[start + 2],
                block[start + 3],
            ]);
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        macro_rules! round1 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
                $a = $a.wrapping_add(f($b, $c, $d)).wrapping_add(x[$k]);
                $a = $a.rotate_left($s);
            };
        }
        macro_rules! round2 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(g($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x5a827999);
                $a = $a.rotate_left($s);
            };
        }
        macro_rules! round3 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(h($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x6ed9eba1);
                $a = $a.rotate_left($s);
            };
        }
        round1!(a, b, c, d, 0, 3);
        round1!(d, a, b, c, 1, 7);
        round1!(c, d, a, b, 2, 11);
        round1!(b, c, d, a, 3, 19);
        round1!(a, b, c, d, 4, 3);
        round1!(d, a, b, c, 5, 7);
        round1!(c, d, a, b, 6, 11);
        round1!(b, c, d, a, 7, 19);
        round1!(a, b, c, d, 8, 3);
        round1!(d, a, b, c, 9, 7);
        round1!(c, d, a, b, 10, 11);
        round1!(b, c, d, a, 11, 19);
        round1!(a, b, c, d, 12, 3);
        round1!(d, a, b, c, 13, 7);
        round1!(c, d, a, b, 14, 11);
        round1!(b, c, d, a, 15, 19);

        round2!(a, b, c, d, 0, 3);
        round2!(d, a, b, c, 4, 5);
        round2!(c, d, a, b, 8, 9);
        round2!(b, c, d, a, 12, 13);
        round2!(a, b, c, d, 1, 3);
        round2!(d, a, b, c, 5, 5);
        round2!(c, d, a, b, 9, 9);
        round2!(b, c, d, a, 13, 13);
        round2!(a, b, c, d, 2, 3);
        round2!(d, a, b, c, 6, 5);
        round2!(c, d, a, b, 10, 9);
        round2!(b, c, d, a, 14, 13);
        round2!(a, b, c, d, 3, 3);
        round2!(d, a, b, c, 7, 5);
        round2!(c, d, a, b, 11, 9);
        round2!(b, c, d, a, 15, 13);

        round3!(a, b, c, d, 0, 3);
        round3!(d, a, b, c, 8, 9);
        round3!(c, d, a, b, 4, 11);
        round3!(b, c, d, a, 12, 15);
        round3!(a, b, c, d, 2, 3);
        round3!(d, a, b, c, 10, 9);
        round3!(c, d, a, b, 6, 11);
        round3!(b, c, d, a, 14, 15);
        round3!(a, b, c, d, 1, 3);
        round3!(d, a, b, c, 9, 9);
        round3!(c, d, a, b, 5, 11);
        round3!(b, c, d, a, 13, 15);
        round3!(a, b, c, d, 3, 3);
        round3!(d, a, b, c, 11, 9);
        round3!(c, d, a, b, 7, 11);
        round3!(b, c, d, a, 15, 15);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

#[inline]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn des_key_from_7bytes(bytes: &[u8]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = bytes[0] & 0xfe;
    key[1] = ((bytes[0] << 7) | (bytes[1] >> 1)) & 0xfe;
    key[2] = ((bytes[1] << 6) | (bytes[2] >> 2)) & 0xfe;
    key[3] = ((bytes[2] << 5) | (bytes[3] >> 3)) & 0xfe;
    key[4] = ((bytes[3] << 4) | (bytes[4] >> 4)) & 0xfe;
    key[5] = ((bytes[4] << 3) | (bytes[5] >> 5)) & 0xfe;
    key[6] = ((bytes[5] << 2) | (bytes[6] >> 6)) & 0xfe;
    key[7] = (bytes[6] << 1) & 0xfe;
    for byte in key.iter_mut() {
        let mut parity = 0u8;
        let mut v = *byte;
        for _ in 0..7 {
            parity ^= v & 1;
            v >>= 1;
        }
        if parity == 0 {
            *byte |= 1;
        }
    }
    key
}

fn des_encrypt_block(key: [u8; 8], block: [u8; 8]) -> [u8; 8] {
    let key_u64 = u64::from_be_bytes(key);
    let block_u64 = u64::from_be_bytes(block);
    let mut permuted_block = permute(block_u64, &IP_TABLE, 64);
    let mut left = (permuted_block >> 32) as u32;
    let mut right = (permuted_block & 0xffff_ffff) as u32;
    let subkeys = des_key_schedule(key_u64);
    for subkey in subkeys {
        let next_left = right;
        let f_out = des_f(right, subkey);
        let next_right = left ^ f_out;
        left = next_left;
        right = next_right;
    }
    permuted_block = ((right as u64) << 32) | left as u64;
    let final_block = permute(permuted_block, &FP_TABLE, 64);
    final_block.to_be_bytes()
}

fn des_key_schedule(key: u64) -> [u64; 16] {
    let permuted = permute(key, &PC1_TABLE, 64);
    let mut c = ((permuted >> 28) & 0x0fff_ffff) as u32;
    let mut d = (permuted & 0x0fff_ffff) as u32;
    let mut subkeys = [0u64; 16];
    for (i, shift) in SHIFTS.iter().enumerate() {
        c = ((c << shift) | (c >> (28 - shift))) & 0x0fff_ffff;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0fff_ffff;
        let combined = ((c as u64) << 28) | d as u64;
        subkeys[i] = permute(combined, &PC2_TABLE, 56);
    }
    subkeys
}

fn des_f(r: u32, subkey: u64) -> u32 {
    let expanded = permute(r as u64, &E_TABLE, 32);
    let xored = expanded ^ subkey;
    let mut out = 0u32;
    for i in 0..8 {
        let shift = 42 - (i * 6);
        let chunk = ((xored >> shift) & 0x3f) as u8;
        let row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
        let col = (chunk >> 1) & 0x0f;
        let s = S_BOXES[i][row as usize][col as usize] as u32;
        out = (out << 4) | s;
    }
    permute(out as u64, &P_TABLE, 32) as u32
}

fn permute(input: u64, table: &[u8], input_bits: u8) -> u64 {
    let shift = 64u32.saturating_sub(input_bits as u32);
    let aligned = if shift == 64 { 0 } else { input << shift };
    let mut out = 0u64;
    for (i, &pos) in table.iter().enumerate() {
        let bit = (aligned >> (64 - pos)) & 1;
        out |= bit << (table.len() - 1 - i);
    }
    out
}

const IP_TABLE: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP_TABLE: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const PC1_TABLE: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC2_TABLE: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const E_TABLE: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const P_TABLE: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const S_BOXES: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if i + 1 < data.len() {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

fn base64_decode(data: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = data.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c0 = bytes[i];
        let c1 = if i + 1 < bytes.len() {
            bytes[i + 1]
        } else {
            b'='
        };
        let c2 = if i + 2 < bytes.len() {
            bytes[i + 2]
        } else {
            b'='
        };
        let c3 = if i + 3 < bytes.len() {
            bytes[i + 3]
        } else {
            b'='
        };
        let v0 = val(c0)?;
        let v1 = val(c1)?;
        let v2 = if c2 == b'=' { 0 } else { val(c2)? };
        let v3 = if c3 == b'=' { 0 } else { val(c3)? };
        let triple = ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6) | v3 as u32;
        out.push(((triple >> 16) & 0xff) as u8);
        if c2 != b'=' {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if c3 != b'=' {
            out.push((triple & 0xff) as u8);
        }
        i += 4;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod hex {
        pub fn encode(data: impl AsRef<[u8]>) -> String {
            data.as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        }
    }

    #[test]
    fn md4_vectors() {
        let cases = [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        for (input, expected) in cases {
            let digest = md4_digest(input.as_bytes());
            let hex = digest
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            assert_eq!(hex, expected);
        }
    }

    #[test]
    fn rc4_vector() {
        let mut rc4 = Rc4::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        rc4.process(&mut data);
        assert_eq!(hex::encode(data), "bbf316e8d940af0ad3");
    }

    #[test]
    fn des_vector() {
        let key = 0x133457799bbcdff1u64.to_be_bytes();
        let block = 0x0123456789abcdefu64.to_be_bytes();
        let out = des_encrypt_block(key, block);
        assert_eq!(hex::encode(out), "85e813540f0ab405");
    }

    #[test]
    fn lm_nt_hash_vectors() {
        let lm = lm_hash("password");
        let nt = nt_hash("password");
        assert_eq!(hex::encode(lm), "e52cac67419a9a224a3b108f3fa6cb6d");
        assert_eq!(hex::encode(nt), "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn negotiate_roundtrip() {
        let msg = NegotiateMessage {
            flags: default_flags()
                | NEGOTIATE_OEM_DOMAIN_SUPPLIED
                | NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
            domain: "DOMAIN".to_string(),
            workstation: "HOST".to_string(),
            version: Some(Version::windows_10()),
        };
        let encoded = msg.encode();
        let decoded = NegotiateMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn challenge_roundtrip() {
        let msg = ChallengeMessage {
            target_name: "TARGET".to_string(),
            flags: default_flags(),
            server_challenge: [1u8; 8],
            target_info: vec![
                AvPair::DnsDomainName("example.com".to_string()),
                AvPair::Eol,
            ],
            version: Some(Version::windows_10()),
        };
        let encoded = msg.encode();
        let decoded = ChallengeMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn authenticate_roundtrip() {
        let msg = AuthenticateMessage {
            lm_response: vec![1, 2, 3],
            nt_response: vec![4, 5, 6],
            domain: "DOMAIN".to_string(),
            user: "User".to_string(),
            workstation: "HOST".to_string(),
            encrypted_session_key: vec![7, 8, 9],
            flags: default_flags(),
            version: Some(Version::windows_10()),
            mic: Some([9u8; 16]),
        };
        let encoded = msg.encode();
        let decoded = AuthenticateMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn ntlmv2_handshake() {
        let mut server_config = NtlmServerConfig::default();
        server_config.credentials.insert(
            "USER".to_string(),
            NtlmSecret::Plaintext("Password".to_string()),
        );
        server_config.server_challenge = Some([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        server_config.target_info = vec![AvPair::DnsDomainName("domain".to_string()), AvPair::Eol];
        let server = NtlmServer::new(server_config);

        let mut client_config = NtlmClientConfig::default();
        client_config.username = "User".to_string();
        client_config.password = NtlmSecret::Plaintext("Password".to_string());
        client_config.domain = "Domain".to_string();
        client_config.client_challenge = Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);
        client_config.timestamp = Some(0x01_23_45_67_89_ab_cd_ef);
        let client = NtlmClient::new(client_config);

        let negotiate = client.negotiate();
        let challenge = server.challenge(&negotiate);
        let (auth, _) = client.respond(&challenge).unwrap();
        let session = server.authenticate(&challenge, &auth).unwrap();
        assert_ne!(session.exported_session_key, [0u8; 16]);
    }
}
