use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use corelib::error::{CoreError, CoreResult};
use http_body_util::{BodyExt, Full};
use hickory_proto::op::Message as HickoryMessage;
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use net::NetAddr;
use tokio::net::UdpSocket as TokioUdpSocket;

use crate::framing::{Framer, LengthPrefixedFramer};
use crate::http::{HttpMethod, HttpRequest, HttpResponse};
use crate::http2::{Http2Request, Http2Response, Http2Server, Http2TlsServer};
use crate::http3::{Http3Request, Http3Response, Http3Server};
use crate::transport::{
    AsyncStreamTransport, AsyncTcpTransport, AsyncTlsClientTransport, AsyncTlsServer,
    AsyncTlsServerTransport, AsyncUdpTransport, StreamTransport, TcpTransport, TlsClientConfig,
    TlsServerConfig, TlsStreamTransport, UdpTransport,
};
use crate::util::Timeouts;

const DNS_MAX_PACKET: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsFlags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFlags {
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: u8,
}

impl DnsFlags {
    pub fn to_bits(self) -> u16 {
        let mut bits = 0u16;
        if self.qr {
            bits |= 1 << 15;
        }
        bits |= ((self.opcode as u16) & 0x0f) << 11;
        if self.aa {
            bits |= 1 << 10;
        }
        if self.tc {
            bits |= 1 << 9;
        }
        if self.rd {
            bits |= 1 << 8;
        }
        if self.ra {
            bits |= 1 << 7;
        }
        bits |= (self.rcode as u16) & 0x0f;
        bits
    }

    pub fn from_bits(bits: u16) -> Self {
        Self {
            qr: (bits & (1 << 15)) != 0,
            opcode: ((bits >> 11) & 0x0f) as u8,
            aa: (bits & (1 << 10)) != 0,
            tc: (bits & (1 << 9)) != 0,
            rd: (bits & (1 << 8)) != 0,
            ra: (bits & (1 << 7)) != 0,
            rcode: (bits & 0x0f) as u8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: DnsRecordData,
}

impl DnsRecord {
    pub fn mdns_cache_flush(&self) -> bool {
        (self.class & 0x8000) != 0
    }

    pub fn mdns_class(&self) -> u16 {
        self.class & 0x7fff
    }

    pub fn set_mdns_cache_flush(&mut self, enabled: bool) {
        if enabled {
            self.class |= 0x8000;
        } else {
            self.class &= 0x7fff;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsClientSubnet {
    pub family: u16,
    pub source_prefix: u8,
    pub scope_prefix: u8,
    pub address: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOptionValue {
    ClientSubnet(DnsClientSubnet),
    Cookie { client: Vec<u8>, server: Vec<u8> },
    TcpKeepalive(Option<u16>),
    Padding(usize),
    Nsid(Vec<u8>),
    Dau(Vec<u8>),
    Dhu(Vec<u8>),
    N3u(Vec<u8>),
    Expire(u32),
    Chain(Vec<u8>),
    KeyTag(Vec<u16>),
    ExtendedError { code: u16, text: String },
    Unknown(u16, Vec<u8>),
}

impl DnsOption {
    pub fn ecs(family: u16, source_prefix: u8, scope_prefix: u8, address: Vec<u8>) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&family.to_be_bytes());
        data.push(source_prefix);
        data.push(scope_prefix);
        data.extend_from_slice(&address);
        Self { code: 8, data }
    }

    pub fn cookie(client: &[u8], server: Option<&[u8]>) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(client);
        if let Some(server) = server {
            data.extend_from_slice(server);
        }
        Self { code: 10, data }
    }

    pub fn padding(len: usize) -> Self {
        Self {
            code: 12,
            data: vec![0u8; len],
        }
    }

    pub fn tcp_keepalive(timeout: Option<u16>) -> Self {
        let mut data = Vec::new();
        if let Some(timeout) = timeout {
            data.extend_from_slice(&timeout.to_be_bytes());
        }
        Self { code: 11, data }
    }

    pub fn nsid() -> Self {
        Self {
            code: 3,
            data: Vec::new(),
        }
    }

    pub fn dau(algs: &[u8]) -> Self {
        Self {
            code: 5,
            data: algs.to_vec(),
        }
    }

    pub fn dhu(algs: &[u8]) -> Self {
        Self {
            code: 6,
            data: algs.to_vec(),
        }
    }

    pub fn n3u(algs: &[u8]) -> Self {
        Self {
            code: 7,
            data: algs.to_vec(),
        }
    }

    pub fn expire(seconds: u32) -> Self {
        Self {
            code: 9,
            data: seconds.to_be_bytes().to_vec(),
        }
    }

    pub fn chain(data: Vec<u8>) -> Self {
        Self { code: 13, data }
    }

    pub fn key_tag(tags: &[u16]) -> Self {
        let mut data = Vec::with_capacity(tags.len() * 2);
        for tag in tags {
            data.extend_from_slice(&tag.to_be_bytes());
        }
        Self { code: 14, data }
    }

    pub fn ede(code: u16, text: Option<&str>) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&code.to_be_bytes());
        if let Some(text) = text {
            data.extend_from_slice(text.as_bytes());
        }
        Self { code: 15, data }
    }

    pub fn parse_ecs(&self) -> Option<DnsClientSubnet> {
        if self.code != 8 || self.data.len() < 4 {
            return None;
        }
        let family = u16::from_be_bytes([self.data[0], self.data[1]]);
        let source_prefix = self.data[2];
        let scope_prefix = self.data[3];
        let address = self.data[4..].to_vec();
        Some(DnsClientSubnet {
            family,
            source_prefix,
            scope_prefix,
            address,
        })
    }

    pub fn parse(&self) -> CoreResult<DnsOptionValue> {
        match self.code {
            3 => Ok(DnsOptionValue::Nsid(self.data.clone())),
            5 => Ok(DnsOptionValue::Dau(self.data.clone())),
            6 => Ok(DnsOptionValue::Dhu(self.data.clone())),
            7 => Ok(DnsOptionValue::N3u(self.data.clone())),
            8 => self
                .parse_ecs()
                .map(DnsOptionValue::ClientSubnet)
                .ok_or_else(|| CoreError::Parse("invalid ecs option".to_string())),
            9 => {
                if self.data.len() != 4 {
                    return Err(CoreError::Parse("invalid expire option".to_string()));
                }
                let seconds =
                    u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]);
                Ok(DnsOptionValue::Expire(seconds))
            }
            10 => {
                if self.data.len() < 8 {
                    return Err(CoreError::Parse("invalid cookie option".to_string()));
                }
                let client = self.data[..8].to_vec();
                let server = self.data[8..].to_vec();
                Ok(DnsOptionValue::Cookie { client, server })
            }
            11 => {
                if self.data.is_empty() {
                    return Ok(DnsOptionValue::TcpKeepalive(None));
                }
                if self.data.len() != 2 {
                    return Err(CoreError::Parse("invalid keepalive option".to_string()));
                }
                let timeout = u16::from_be_bytes([self.data[0], self.data[1]]);
                Ok(DnsOptionValue::TcpKeepalive(Some(timeout)))
            }
            12 => Ok(DnsOptionValue::Padding(self.data.len())),
            13 => Ok(DnsOptionValue::Chain(self.data.clone())),
            14 => {
                if self.data.len() % 2 != 0 {
                    return Err(CoreError::Parse("invalid key tag option".to_string()));
                }
                let mut tags = Vec::new();
                let mut i = 0usize;
                while i < self.data.len() {
                    tags.push(u16::from_be_bytes([self.data[i], self.data[i + 1]]));
                    i += 2;
                }
                Ok(DnsOptionValue::KeyTag(tags))
            }
            15 => {
                if self.data.len() < 2 {
                    return Err(CoreError::Parse("invalid ede option".to_string()));
                }
                let code = u16::from_be_bytes([self.data[0], self.data[1]]);
                let text = if self.data.len() > 2 {
                    std::str::from_utf8(&self.data[2..])
                        .map_err(|_| CoreError::Parse("invalid ede text".to_string()))?
                        .to_string()
                } else {
                    String::new()
                };
                Ok(DnsOptionValue::ExtendedError { code, text })
            }
            _ => Ok(DnsOptionValue::Unknown(self.code, self.data.clone())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDnskey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDs {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRrsig {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub signature_expiration: u32,
    pub signature_inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNsec {
    pub next_domain: String,
    pub type_bitmaps: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNsec3 {
    pub hash_alg: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed_owner: Vec<u8>,
    pub type_bitmaps: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    PTR(String),
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(String),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    DNSKEY(DnsDnskey),
    DS(DnsDs),
    RRSIG(DnsRrsig),
    NSEC(DnsNsec),
    NSEC3(DnsNsec3),
    OPT {
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        flags: u16,
        options: Vec<DnsOption>,
    },
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn new_query(id: u16, name: impl Into<String>, qtype: u16) -> Self {
        Self {
            header: DnsHeader {
                id,
                flags: DnsFlags {
                    qr: false,
                    opcode: 0,
                    aa: false,
                    tc: false,
                    rd: true,
                    ra: false,
                    rcode: 0,
                },
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: name.into(),
                qtype,
                qclass: 1,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        let mut compression = HashMap::new();
        buf.extend_from_slice(&self.header.id.to_be_bytes());
        buf.extend_from_slice(&self.header.flags.to_bits().to_be_bytes());
        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        for question in &self.questions {
            encode_name(&question.name, &mut buf, &mut compression)?;
            buf.extend_from_slice(&question.qtype.to_be_bytes());
            buf.extend_from_slice(&question.qclass.to_be_bytes());
        }

        for record in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
        {
            encode_name(&record.name, &mut buf, &mut compression)?;
            buf.extend_from_slice(&record.rtype.to_be_bytes());
            let (class, ttl) = match &record.data {
                DnsRecordData::OPT {
                    udp_payload_size,
                    extended_rcode,
                    version,
                    flags,
                    ..
                } => {
                    let ttl = ((*extended_rcode as u32) << 24)
                        | ((*version as u32) << 16)
                        | (*flags as u32);
                    (*udp_payload_size, ttl)
                }
                _ => (record.class, record.ttl),
            };
            buf.extend_from_slice(&class.to_be_bytes());
            buf.extend_from_slice(&ttl.to_be_bytes());
            let rdlen_pos = buf.len();
            buf.extend_from_slice(&0u16.to_be_bytes());
            let start = buf.len();
            let _rdata_len = encode_rdata(&record.data, &mut compression, &mut buf)?;
            let rdlen = (buf.len() - start) as u16;
            let rdlen_bytes = rdlen.to_be_bytes();
            buf[rdlen_pos] = rdlen_bytes[0];
            buf[rdlen_pos + 1] = rdlen_bytes[1];
            let _ = _rdata_len;
        }

        Ok(buf)
    }

    pub fn decode(bytes: &[u8]) -> CoreResult<Self> {
        if bytes.len() < 12 {
            return Err(CoreError::Parse("dns message too short".to_string()));
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = DnsFlags::from_bits(u16::from_be_bytes([bytes[2], bytes[3]]));
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);
        let mut offset = 12usize;
        let mut questions = Vec::with_capacity(qdcount as usize);
        for _ in 0..qdcount {
            let (name, next) = decode_name(bytes, offset)?;
            offset = next;
            let qtype = read_u16(bytes, &mut offset)?;
            let qclass = read_u16(bytes, &mut offset)?;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }
        let mut answers = Vec::with_capacity(ancount as usize);
        for _ in 0..ancount {
            answers.push(decode_record(bytes, &mut offset)?);
        }
        let mut authorities = Vec::with_capacity(nscount as usize);
        for _ in 0..nscount {
            authorities.push(decode_record(bytes, &mut offset)?);
        }
        let mut additionals = Vec::with_capacity(arcount as usize);
        for _ in 0..arcount {
            additionals.push(decode_record(bytes, &mut offset)?);
        }
        Ok(Self {
            header: DnsHeader {
                id,
                flags,
                qdcount,
                ancount,
                nscount,
                arcount,
            },
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

fn encode_name(
    name: &str,
    buf: &mut Vec<u8>,
    compression: &mut HashMap<String, u16>,
) -> CoreResult<()> {
    if name.is_empty() {
        buf.push(0);
        return Ok(());
    }
    if let Some(offset) = compression.get(name) {
        let pointer = 0xC000u16 | offset;
        buf.extend_from_slice(&pointer.to_be_bytes());
        return Ok(());
    }
    let labels: Vec<&str> = name.split('.').collect();
    for i in 0..labels.len() {
        let suffix = labels[i..].join(".");
        if let Some(offset) = compression.get(&suffix) {
            let pointer = 0xC000u16 | offset;
            buf.extend_from_slice(&pointer.to_be_bytes());
            return Ok(());
        }
        compression.insert(suffix.clone(), buf.len() as u16);
        let label = labels[i];
        if label.len() > 63 {
            return Err(CoreError::Parse("label too long".to_string()));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(())
}

fn decode_name(msg: &[u8], offset: usize) -> CoreResult<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut consumed = 0usize;
    let mut jumps = 0usize;
    loop {
        if pos >= msg.len() {
            return Err(CoreError::Parse("name out of bounds".to_string()));
        }
        let len = msg[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                return Err(CoreError::Parse("truncated pointer".to_string()));
            }
            let pointer = (((len & 0x3F) as u16) << 8) | msg[pos + 1] as u16;
            if !jumped {
                consumed += 2;
            }
            pos = pointer as usize;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return Err(CoreError::Parse("too many compression jumps".to_string()));
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                consumed += 1;
            }
            break;
        }
        pos += 1;
        if pos + len as usize > msg.len() {
            return Err(CoreError::Parse("label out of bounds".to_string()));
        }
        let label = std::str::from_utf8(&msg[pos..pos + len as usize])
            .map_err(|_| CoreError::Parse("invalid label".to_string()))?;
        labels.push(label.to_string());
        pos += len as usize;
        if !jumped {
            consumed += 1 + len as usize;
        }
    }
    Ok((labels.join("."), offset + consumed))
}

fn encode_rdata(
    data: &DnsRecordData,
    compression: &mut HashMap<String, u16>,
    buf: &mut Vec<u8>,
) -> CoreResult<usize> {
    let start = buf.len();
    match data {
        DnsRecordData::A(addr) => buf.extend_from_slice(&addr.octets()),
        DnsRecordData::AAAA(addr) => buf.extend_from_slice(&addr.octets()),
        DnsRecordData::CNAME(name) | DnsRecordData::NS(name) | DnsRecordData::PTR(name) => {
            encode_name(name, buf, compression)?
        }
        DnsRecordData::MX {
            preference,
            exchange,
        } => {
            buf.extend_from_slice(&preference.to_be_bytes());
            encode_name(exchange, buf, compression)?;
        }
        DnsRecordData::TXT(text) => {
            if text.len() > 255 {
                return Err(CoreError::Parse("txt too long".to_string()));
            }
            buf.push(text.len() as u8);
            buf.extend_from_slice(text.as_bytes());
        }
        DnsRecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            buf.extend_from_slice(&priority.to_be_bytes());
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
            encode_name(target, buf, compression)?;
        }
        DnsRecordData::DNSKEY(key) => {
            buf.extend_from_slice(&key.flags.to_be_bytes());
            buf.push(key.protocol);
            buf.push(key.algorithm);
            buf.extend_from_slice(&key.public_key);
        }
        DnsRecordData::DS(ds) => {
            buf.extend_from_slice(&ds.key_tag.to_be_bytes());
            buf.push(ds.algorithm);
            buf.push(ds.digest_type);
            buf.extend_from_slice(&ds.digest);
        }
        DnsRecordData::RRSIG(sig) => {
            buf.extend_from_slice(&sig.type_covered.to_be_bytes());
            buf.push(sig.algorithm);
            buf.push(sig.labels);
            buf.extend_from_slice(&sig.original_ttl.to_be_bytes());
            buf.extend_from_slice(&sig.signature_expiration.to_be_bytes());
            buf.extend_from_slice(&sig.signature_inception.to_be_bytes());
            buf.extend_from_slice(&sig.key_tag.to_be_bytes());
            encode_name(&sig.signer_name, buf, compression)?;
            buf.extend_from_slice(&sig.signature);
        }
        DnsRecordData::NSEC(nsec) => {
            encode_name(&nsec.next_domain, buf, compression)?;
            buf.extend_from_slice(&nsec.type_bitmaps);
        }
        DnsRecordData::NSEC3(nsec3) => {
            buf.push(nsec3.hash_alg);
            buf.push(nsec3.flags);
            buf.extend_from_slice(&nsec3.iterations.to_be_bytes());
            buf.push(nsec3.salt.len() as u8);
            buf.extend_from_slice(&nsec3.salt);
            buf.push(nsec3.next_hashed_owner.len() as u8);
            buf.extend_from_slice(&nsec3.next_hashed_owner);
            buf.extend_from_slice(&nsec3.type_bitmaps);
        }
        DnsRecordData::OPT { options, .. } => {
            for opt in options {
                buf.extend_from_slice(&opt.code.to_be_bytes());
                buf.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
                buf.extend_from_slice(&opt.data);
            }
        }
        DnsRecordData::Unknown(raw) => buf.extend_from_slice(raw),
    }
    Ok(buf.len() - start)
}

fn decode_rdata(
    msg: &[u8],
    offset: &mut usize,
    rtype: u16,
    rdlen: usize,
    class: u16,
    ttl: u32,
) -> CoreResult<DnsRecordData> {
    let start = *offset;
    let end = start + rdlen;
    if end > msg.len() {
        return Err(CoreError::Parse("rdata out of bounds".to_string()));
    }
    let data = match rtype {
        1 => {
            if rdlen != 4 {
                return Err(CoreError::Parse("invalid A record".to_string()));
            }
            let addr = Ipv4Addr::new(msg[start], msg[start + 1], msg[start + 2], msg[start + 3]);
            *offset = end;
            DnsRecordData::A(addr)
        }
        28 => {
            if rdlen != 16 {
                return Err(CoreError::Parse("invalid AAAA record".to_string()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&msg[start..end]);
            *offset = end;
            DnsRecordData::AAAA(Ipv6Addr::from(octets))
        }
        5 => {
            let (name, next) = decode_name(msg, *offset)?;
            *offset = next;
            DnsRecordData::CNAME(name)
        }
        2 => {
            let (name, next) = decode_name(msg, *offset)?;
            *offset = next;
            DnsRecordData::NS(name)
        }
        12 => {
            let (name, next) = decode_name(msg, *offset)?;
            *offset = next;
            DnsRecordData::PTR(name)
        }
        15 => {
            let preference = read_u16(msg, offset)?;
            let (exchange, next) = decode_name(msg, *offset)?;
            *offset = next;
            DnsRecordData::MX {
                preference,
                exchange,
            }
        }
        16 => {
            if rdlen < 1 {
                return Err(CoreError::Parse("invalid TXT record".to_string()));
            }
            let len = msg[*offset] as usize;
            *offset += 1;
            if *offset + len > msg.len() {
                return Err(CoreError::Parse("invalid TXT record".to_string()));
            }
            let text = std::str::from_utf8(&msg[*offset..*offset + len])
                .map_err(|_| CoreError::Parse("invalid TXT record".to_string()))?
                .to_string();
            *offset += len;
            DnsRecordData::TXT(text)
        }
        33 => {
            let priority = read_u16(msg, offset)?;
            let weight = read_u16(msg, offset)?;
            let port = read_u16(msg, offset)?;
            let (target, next) = decode_name(msg, *offset)?;
            *offset = next;
            DnsRecordData::SRV {
                priority,
                weight,
                port,
                target,
            }
        }
        48 => {
            let flags = read_u16(msg, offset)?;
            let protocol = read_u8(msg, offset)?;
            let algorithm = read_u8(msg, offset)?;
            if *offset > end {
                return Err(CoreError::Parse("invalid dnskey".to_string()));
            }
            let public_key = msg[*offset..end].to_vec();
            *offset = end;
            DnsRecordData::DNSKEY(DnsDnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            })
        }
        43 => {
            let key_tag = read_u16(msg, offset)?;
            let algorithm = read_u8(msg, offset)?;
            let digest_type = read_u8(msg, offset)?;
            if *offset > end {
                return Err(CoreError::Parse("invalid ds record".to_string()));
            }
            let digest = msg[*offset..end].to_vec();
            *offset = end;
            DnsRecordData::DS(DnsDs {
                key_tag,
                algorithm,
                digest_type,
                digest,
            })
        }
        46 => {
            let type_covered = read_u16(msg, offset)?;
            let algorithm = read_u8(msg, offset)?;
            let labels = read_u8(msg, offset)?;
            let original_ttl = read_u32(msg, offset)?;
            let signature_expiration = read_u32(msg, offset)?;
            let signature_inception = read_u32(msg, offset)?;
            let key_tag = read_u16(msg, offset)?;
            let (signer_name, next) = decode_name(msg, *offset)?;
            *offset = next;
            if *offset > end {
                return Err(CoreError::Parse("invalid rrsig".to_string()));
            }
            let signature = msg[*offset..end].to_vec();
            *offset = end;
            DnsRecordData::RRSIG(DnsRrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
            })
        }
        47 => {
            let (next_domain, next) = decode_name(msg, *offset)?;
            *offset = next;
            if *offset > end {
                return Err(CoreError::Parse("invalid nsec".to_string()));
            }
            let type_bitmaps = msg[*offset..end].to_vec();
            *offset = end;
            DnsRecordData::NSEC(DnsNsec {
                next_domain,
                type_bitmaps,
            })
        }
        50 => {
            let hash_alg = read_u8(msg, offset)?;
            let flags = read_u8(msg, offset)?;
            let iterations = read_u16(msg, offset)?;
            let salt_len = read_u8(msg, offset)? as usize;
            if *offset + salt_len > end {
                return Err(CoreError::Parse("invalid nsec3".to_string()));
            }
            let salt = msg[*offset..*offset + salt_len].to_vec();
            *offset += salt_len;
            let next_len = read_u8(msg, offset)? as usize;
            if *offset + next_len > end {
                return Err(CoreError::Parse("invalid nsec3".to_string()));
            }
            let next_hashed_owner = msg[*offset..*offset + next_len].to_vec();
            *offset += next_len;
            let type_bitmaps = msg[*offset..end].to_vec();
            *offset = end;
            DnsRecordData::NSEC3(DnsNsec3 {
                hash_alg,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmaps,
            })
        }
        41 => {
            let mut options = Vec::new();
            while *offset + 4 <= end {
                let code = read_u16(msg, offset)?;
                let len = read_u16(msg, offset)? as usize;
                if *offset + len > end {
                    return Err(CoreError::Parse("invalid opt record".to_string()));
                }
                let data = msg[*offset..*offset + len].to_vec();
                *offset += len;
                options.push(DnsOption { code, data });
            }
            let extended_rcode = ((ttl >> 24) & 0xff) as u8;
            let version = ((ttl >> 16) & 0xff) as u8;
            let flags = (ttl & 0xffff) as u16;
            DnsRecordData::OPT {
                udp_payload_size: class,
                extended_rcode,
                version,
                flags,
                options,
            }
        }
        _ => {
            let raw = msg[start..end].to_vec();
            *offset = end;
            DnsRecordData::Unknown(raw)
        }
    };
    Ok(data)
}

fn decode_record(msg: &[u8], offset: &mut usize) -> CoreResult<DnsRecord> {
    let (name, next) = decode_name(msg, *offset)?;
    *offset = next;
    let rtype = read_u16(msg, offset)?;
    let class = read_u16(msg, offset)?;
    let ttl = read_u32(msg, offset)?;
    let rdlen = read_u16(msg, offset)? as usize;
    let data = decode_rdata(msg, offset, rtype, rdlen, class, ttl)?;
    Ok(DnsRecord {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

fn read_u16(msg: &[u8], offset: &mut usize) -> CoreResult<u16> {
    if *offset + 2 > msg.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let value = u16::from_be_bytes([msg[*offset], msg[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

fn read_u8(msg: &[u8], offset: &mut usize) -> CoreResult<u8> {
    if *offset + 1 > msg.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let value = msg[*offset];
    *offset += 1;
    Ok(value)
}

fn read_u32(msg: &[u8], offset: &mut usize) -> CoreResult<u32> {
    if *offset + 4 > msg.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let value = u32::from_be_bytes([
        msg[*offset],
        msg[*offset + 1],
        msg[*offset + 2],
        msg[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}

pub fn dnskey_tag(key: &DnsDnskey) -> u16 {
    let mut data = Vec::new();
    data.extend_from_slice(&key.flags.to_be_bytes());
    data.push(key.protocol);
    data.push(key.algorithm);
    data.extend_from_slice(&key.public_key);
    let mut sum: u32 = 0;
    for (i, b) in data.iter().enumerate() {
        if i % 2 == 0 {
            sum += (*b as u32) << 8;
        } else {
            sum += *b as u32;
        }
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    (sum & 0xFFFF) as u16
}

pub fn compute_ds(owner: &str, key: &DnsDnskey, digest_type: u8) -> CoreResult<Vec<u8>> {
    let mut data = Vec::new();
    encode_name_canonical(owner, &mut data)?;
    data.extend_from_slice(&key.flags.to_be_bytes());
    data.push(key.protocol);
    data.push(key.algorithm);
    data.extend_from_slice(&key.public_key);
    match digest_type {
        1 => Ok(sha1::digest(&data).to_vec()),
        2 => Ok(sha256::digest(&data).to_vec()),
        4 => Ok(sha384::digest(&data).to_vec()),
        _ => Err(CoreError::Parse("unsupported ds digest".to_string())),
    }
}

pub fn verify_ds(owner: &str, ds: &DnsDs, key: &DnsDnskey) -> CoreResult<bool> {
    if ds.key_tag != dnskey_tag(key) || ds.algorithm != key.algorithm {
        return Ok(false);
    }
    let digest = compute_ds(owner, key, ds.digest_type)?;
    Ok(digest == ds.digest)
}

pub fn verify_rrsig_at(
    owner: &str,
    rrset: &[DnsRecord],
    rrsig: &DnsRrsig,
    dnskey: &DnsDnskey,
    now: u32,
) -> CoreResult<()> {
    if rrsig.algorithm != dnskey.algorithm {
        return Err(CoreError::Parse("algorithm mismatch".to_string()));
    }
    if rrsig.key_tag != dnskey_tag(dnskey) {
        return Err(CoreError::Parse("key tag mismatch".to_string()));
    }
    if now < rrsig.signature_inception || now > rrsig.signature_expiration {
        return Err(CoreError::Parse("signature expired".to_string()));
    }
    for rr in rrset {
        if rr.rtype != rrsig.type_covered {
            return Err(CoreError::Parse("rrset type mismatch".to_string()));
        }
    }

    let signed = build_rrsig_signed_data(owner, rrset, rrsig)?;
    verify_signature(rrsig, dnskey, &signed)
}

pub fn verify_rrsig(
    owner: &str,
    rrset: &[DnsRecord],
    rrsig: &DnsRrsig,
    dnskey: &DnsDnskey,
) -> CoreResult<()> {
    let now = corelib::time::now_secs() as u32;
    verify_rrsig_at(owner, rrset, rrsig, dnskey, now)
}

fn build_rrsig_signed_data(
    owner: &str,
    rrset: &[DnsRecord],
    rrsig: &DnsRrsig,
) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    out.push(rrsig.algorithm);
    out.push(rrsig.labels);
    out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    out.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
    out.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
    out.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    encode_name_canonical(&rrsig.signer_name, &mut out)?;

    let owner_name = wildcard_owner(owner, rrsig.labels);
    let mut rr_bytes = Vec::new();
    for rr in rrset {
        rr_bytes.push(encode_canonical_rr(&owner_name, rr, rrsig.original_ttl)?);
    }
    rr_bytes.sort();
    for rr in rr_bytes {
        out.extend_from_slice(&rr);
    }
    Ok(out)
}

fn encode_canonical_rr(owner: &str, rr: &DnsRecord, ttl: u32) -> CoreResult<Vec<u8>> {
    let mut buf = Vec::new();
    encode_name_canonical(owner, &mut buf)?;
    buf.extend_from_slice(&rr.rtype.to_be_bytes());
    buf.extend_from_slice(&rr.class.to_be_bytes());
    buf.extend_from_slice(&ttl.to_be_bytes());
    let mut rdata = Vec::new();
    encode_rdata_canonical(&rr.data, &mut rdata)?;
    buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rdata);
    Ok(buf)
}

fn encode_rdata_canonical(data: &DnsRecordData, buf: &mut Vec<u8>) -> CoreResult<()> {
    match data {
        DnsRecordData::A(addr) => buf.extend_from_slice(&addr.octets()),
        DnsRecordData::AAAA(addr) => buf.extend_from_slice(&addr.octets()),
        DnsRecordData::CNAME(name) | DnsRecordData::NS(name) | DnsRecordData::PTR(name) => {
            encode_name_canonical(name, buf)?;
        }
        DnsRecordData::MX {
            preference,
            exchange,
        } => {
            buf.extend_from_slice(&preference.to_be_bytes());
            encode_name_canonical(exchange, buf)?;
        }
        DnsRecordData::TXT(text) => {
            buf.push(text.len() as u8);
            buf.extend_from_slice(text.as_bytes());
        }
        DnsRecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            buf.extend_from_slice(&priority.to_be_bytes());
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
            encode_name_canonical(target, buf)?;
        }
        DnsRecordData::DNSKEY(key) => {
            buf.extend_from_slice(&key.flags.to_be_bytes());
            buf.push(key.protocol);
            buf.push(key.algorithm);
            buf.extend_from_slice(&key.public_key);
        }
        DnsRecordData::DS(ds) => {
            buf.extend_from_slice(&ds.key_tag.to_be_bytes());
            buf.push(ds.algorithm);
            buf.push(ds.digest_type);
            buf.extend_from_slice(&ds.digest);
        }
        DnsRecordData::RRSIG(sig) => {
            buf.extend_from_slice(&sig.type_covered.to_be_bytes());
            buf.push(sig.algorithm);
            buf.push(sig.labels);
            buf.extend_from_slice(&sig.original_ttl.to_be_bytes());
            buf.extend_from_slice(&sig.signature_expiration.to_be_bytes());
            buf.extend_from_slice(&sig.signature_inception.to_be_bytes());
            buf.extend_from_slice(&sig.key_tag.to_be_bytes());
            encode_name_canonical(&sig.signer_name, buf)?;
            buf.extend_from_slice(&sig.signature);
        }
        DnsRecordData::NSEC(nsec) => {
            encode_name_canonical(&nsec.next_domain, buf)?;
            buf.extend_from_slice(&nsec.type_bitmaps);
        }
        DnsRecordData::NSEC3(nsec3) => {
            buf.push(nsec3.hash_alg);
            buf.push(nsec3.flags);
            buf.extend_from_slice(&nsec3.iterations.to_be_bytes());
            buf.push(nsec3.salt.len() as u8);
            buf.extend_from_slice(&nsec3.salt);
            buf.push(nsec3.next_hashed_owner.len() as u8);
            buf.extend_from_slice(&nsec3.next_hashed_owner);
            buf.extend_from_slice(&nsec3.type_bitmaps);
        }
        DnsRecordData::OPT { options, .. } => {
            for opt in options {
                buf.extend_from_slice(&opt.code.to_be_bytes());
                buf.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
                buf.extend_from_slice(&opt.data);
            }
        }
        DnsRecordData::Unknown(raw) => buf.extend_from_slice(raw),
    }
    Ok(())
}

fn encode_name_canonical(name: &str, buf: &mut Vec<u8>) -> CoreResult<()> {
    if name.is_empty() {
        buf.push(0);
        return Ok(());
    }
    for label in name.split('.') {
        let label = label.to_ascii_lowercase();
        if label.len() > 63 {
            return Err(CoreError::Parse("label too long".to_string()));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(())
}

fn wildcard_owner(owner: &str, labels: u8) -> String {
    let parts: Vec<&str> = owner.trim_end_matches('.').split('.').collect();
    if labels as usize >= parts.len() {
        return owner.to_string();
    }
    let suffix = parts[parts.len() - labels as usize..].join(".");
    format!("*.{}", suffix)
}

fn verify_signature(rrsig: &DnsRrsig, key: &DnsDnskey, data: &[u8]) -> CoreResult<()> {
    match key.algorithm {
        5 | 7 => verify_rsa(
            &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            key,
            &rrsig.signature,
            data,
        ),
        8 => verify_rsa(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key,
            &rrsig.signature,
            data,
        ),
        10 => verify_rsa(
            &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            key,
            &rrsig.signature,
            data,
        ),
        13 => verify_ecdsa(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            key,
            &rrsig.signature,
            data,
        ),
        14 => verify_ecdsa(
            &ring::signature::ECDSA_P384_SHA384_FIXED,
            key,
            &rrsig.signature,
            data,
        ),
        15 => verify_ed25519(key, &rrsig.signature, data),
        _ => Err(CoreError::Parse("unsupported dnssec algorithm".to_string())),
    }
}

fn verify_ed25519(key: &DnsDnskey, signature: &[u8], data: &[u8]) -> CoreResult<()> {
    let verifier =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key.public_key);
    verifier
        .verify(data, signature)
        .map_err(|_| CoreError::Parse("ed25519 verify failed".to_string()))
}

fn verify_ecdsa(
    alg: &'static ring::signature::EcdsaVerificationAlgorithm,
    key: &DnsDnskey,
    signature: &[u8],
    data: &[u8],
) -> CoreResult<()> {
    let mut pubkey = Vec::with_capacity(1 + key.public_key.len());
    pubkey.push(0x04);
    pubkey.extend_from_slice(&key.public_key);
    let verifier = ring::signature::UnparsedPublicKey::new(alg, pubkey);
    verifier
        .verify(data, signature)
        .map_err(|_| CoreError::Parse("ecdsa verify failed".to_string()))
}

fn verify_rsa(
    alg: &'static ring::signature::RsaParameters,
    key: &DnsDnskey,
    signature: &[u8],
    data: &[u8],
) -> CoreResult<()> {
    let (e, n) = parse_rsa_key(&key.public_key)?;
    let components = ring::signature::RsaPublicKeyComponents { n: &n, e: &e };
    components
        .verify(alg, data, signature)
        .map_err(|_| CoreError::Parse("rsa verify failed".to_string()))
}

fn parse_rsa_key(data: &[u8]) -> CoreResult<(Vec<u8>, Vec<u8>)> {
    if data.is_empty() {
        return Err(CoreError::Parse("invalid rsa key".to_string()));
    }
    let (exp_len, offset) = if data[0] == 0 {
        if data.len() < 3 {
            return Err(CoreError::Parse("invalid rsa key".to_string()));
        }
        let len = u16::from_be_bytes([data[1], data[2]]) as usize;
        (len, 3)
    } else {
        (data[0] as usize, 1)
    };
    if data.len() < offset + exp_len {
        return Err(CoreError::Parse("invalid rsa key".to_string()));
    }
    let e = data[offset..offset + exp_len].to_vec();
    let n = data[offset + exp_len..].to_vec();
    Ok((e, n))
}

pub fn nsec_type_bitmap_contains(type_bitmaps: &[u8], rr_type: u16) -> CoreResult<bool> {
    let window = (rr_type / 256) as u8;
    let bit_index = (rr_type % 256) as usize;
    let byte_index = bit_index / 8;
    let bit = 0x80u8 >> (bit_index % 8);
    let mut i = 0usize;
    while i < type_bitmaps.len() {
        if i + 2 > type_bitmaps.len() {
            return Err(CoreError::Parse("invalid type bitmap".to_string()));
        }
        let win = type_bitmaps[i];
        let len = type_bitmaps[i + 1] as usize;
        i += 2;
        if len == 0 || len > 32 || i + len > type_bitmaps.len() {
            return Err(CoreError::Parse("invalid type bitmap".to_string()));
        }
        if win == window {
            if byte_index >= len {
                return Ok(false);
            }
            return Ok((type_bitmaps[i + byte_index] & bit) != 0);
        }
        i += len;
    }
    Ok(false)
}

pub fn nsec_type_bitmap_list(type_bitmaps: &[u8]) -> CoreResult<Vec<u16>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < type_bitmaps.len() {
        if i + 2 > type_bitmaps.len() {
            return Err(CoreError::Parse("invalid type bitmap".to_string()));
        }
        let window = type_bitmaps[i] as u16;
        let len = type_bitmaps[i + 1] as usize;
        i += 2;
        if len == 0 || len > 32 || i + len > type_bitmaps.len() {
            return Err(CoreError::Parse("invalid type bitmap".to_string()));
        }
        for (byte_index, byte) in type_bitmaps[i..i + len].iter().enumerate() {
            if *byte == 0 {
                continue;
            }
            for bit in 0..8 {
                if (byte & (0x80 >> bit)) != 0 {
                    let rr_type = window * 256 + (byte_index as u16 * 8 + bit as u16);
                    out.push(rr_type);
                }
            }
        }
        i += len;
    }
    Ok(out)
}

pub fn nsec_type_bitmap_build(types: &[u16]) -> Vec<u8> {
    let mut windows: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    for rr_type in types {
        let window = (rr_type / 256) as u8;
        let bit_index = (rr_type % 256) as usize;
        let byte_index = bit_index / 8;
        let bit = 0x80u8 >> (bit_index % 8);
        let entry = windows.entry(window).or_insert_with(Vec::new);
        if entry.len() <= byte_index {
            entry.resize(byte_index + 1, 0u8);
        }
        entry[byte_index] |= bit;
    }
    let mut out = Vec::new();
    for (window, bitmap) in windows {
        out.push(window);
        out.push(bitmap.len() as u8);
        out.extend_from_slice(&bitmap);
    }
    out
}

pub fn nsec_covers(name: &str, owner: &str, next: &str) -> bool {
    let name = canonical_name(name);
    let owner = canonical_name(owner);
    let next = canonical_name(next);
    if owner < next {
        name > owner && name < next
    } else {
        name > owner || name < next
    }
}

pub fn nsec3_hash(name: &str, iterations: u16, salt: &[u8]) -> Vec<u8> {
    let mut data = canonical_wire_name(name);
    data.extend_from_slice(salt);
    let mut digest = sha1::digest(&data).to_vec();
    for _ in 0..iterations {
        let mut next = digest.clone();
        next.extend_from_slice(salt);
        digest = sha1::digest(&next).to_vec();
    }
    digest
}

pub fn nsec3_hash_base32(name: &str, iterations: u16, salt: &[u8]) -> String {
    let hash = nsec3_hash(name, iterations, salt);
    base32hex_encode(&hash)
}

pub fn nsec3_covers(name_hash: &[u8], owner_hash: &[u8], next_hash: &[u8]) -> bool {
    if owner_hash < next_hash {
        name_hash > owner_hash && name_hash < next_hash
    } else {
        name_hash > owner_hash || name_hash < next_hash
    }
}

fn canonical_wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = encode_name_canonical(name, &mut out);
    out
}

fn canonical_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = encode_name_canonical(name, &mut out);
    out
}

fn base32hex_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u8;
    for &b in data {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

pub struct DnsClient {
    server: SocketAddr,
    timeouts: Timeouts,
    max_packet: usize,
}

impl DnsClient {
    pub fn new(server: SocketAddr, timeouts: Timeouts) -> Self {
        Self {
            server,
            timeouts,
            max_packet: DNS_MAX_PACKET,
        }
    }

    pub fn max_packet(mut self, max_packet: usize) -> Self {
        self.max_packet = max_packet;
        self
    }

    pub fn query_udp(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(self.timeouts.read))?;
        let bytes = message.encode()?;
        socket.send_to(&bytes, self.server)?;
        let (resp, _) = socket.recv_from(self.max_packet)?;
        DnsMessage::decode(&resp)
    }

    pub fn query_tcp(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let addr = NetAddr::from_socket(self.server);
        let mut transport = TcpTransport::connect(&addr, self.timeouts)?;
        let framer = LengthPrefixedFramer::new(2, self.max_packet)?;
        let bytes = message.encode()?;
        let framed = framer.frame(&bytes)?;
        transport.write_all(&framed)?;
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 2048];
            let read = transport.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if let Some(frame) = framer.deframe(&mut buf)? {
                return DnsMessage::decode(&frame.payload);
            }
        }
        Err(CoreError::Parse("unexpected eof".to_string()))
    }

    pub fn query_tls(
        &self,
        message: &DnsMessage,
        server_name: &str,
        tls: &TlsClientConfig,
    ) -> CoreResult<DnsMessage> {
        let addr = NetAddr::from_socket(self.server);
        let mut transport = TlsStreamTransport::connect(&addr, server_name, tls, self.timeouts)?;
        let framer = LengthPrefixedFramer::new(2, self.max_packet)?;
        let bytes = message.encode()?;
        let framed = framer.frame(&bytes)?;
        transport.write_all(&framed)?;
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 2048];
            let read = transport.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if let Some(frame) = framer.deframe(&mut buf)? {
                return DnsMessage::decode(&frame.payload);
            }
        }
        Err(CoreError::Parse("unexpected eof".to_string()))
    }
}

const MDNS_PORT: u16 = 5353;
const MDNS_IPV4: &str = "224.0.0.251";
const MDNS_IPV6: &str = "ff02::fb";

pub struct MdnsClient {
    socket: UdpSocket,
}

impl MdnsClient {
    pub fn bind_v4() -> CoreResult<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", MDNS_PORT)).map_err(CoreError::Io)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(CoreError::Io)?;
        let mcast: Ipv4Addr = MDNS_IPV4
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket
            .join_multicast_v4(&mcast, &Ipv4Addr::UNSPECIFIED)
            .map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub fn bind_v6() -> CoreResult<Self> {
        let socket = UdpSocket::bind(("::", MDNS_PORT)).map_err(CoreError::Io)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(CoreError::Io)?;
        let mcast: Ipv6Addr = MDNS_IPV6
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket.join_multicast_v6(&mcast, 0).map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub fn send_query(&self, message: &DnsMessage) -> CoreResult<()> {
        let bytes = message.encode()?;
        let target: SocketAddr = format!("{}:{}", MDNS_IPV4, MDNS_PORT).parse().unwrap();
        self.socket.send_to(&bytes, target).map_err(CoreError::Io)?;
        Ok(())
    }

    pub fn send_query_v6(&self, message: &DnsMessage) -> CoreResult<()> {
        let bytes = message.encode()?;
        let target: SocketAddr = format!("[{}]:{}", MDNS_IPV6, MDNS_PORT).parse().unwrap();
        self.socket.send_to(&bytes, target).map_err(CoreError::Io)?;
        Ok(())
    }

    pub fn recv(&self, max_bytes: usize) -> CoreResult<(DnsMessage, SocketAddr)> {
        let mut buf = vec![0u8; max_bytes];
        let (len, addr) = self.socket.recv_from(&mut buf).map_err(CoreError::Io)?;
        buf.truncate(len);
        let msg = DnsMessage::decode(&buf)?;
        Ok((msg, addr))
    }
}

pub struct MdnsServer {
    socket: UdpSocket,
}

impl MdnsServer {
    pub fn bind_v4() -> CoreResult<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", MDNS_PORT)).map_err(CoreError::Io)?;
        let mcast: Ipv4Addr = MDNS_IPV4
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket
            .join_multicast_v4(&mcast, &Ipv4Addr::UNSPECIFIED)
            .map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub fn bind_v6() -> CoreResult<Self> {
        let socket = UdpSocket::bind(("::", MDNS_PORT)).map_err(CoreError::Io)?;
        let mcast: Ipv6Addr = MDNS_IPV6
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket.join_multicast_v6(&mcast, 0).map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        loop {
            let mut buf = vec![0u8; DNS_MAX_PACKET];
            let (len, peer) = self.socket.recv_from(&mut buf).map_err(CoreError::Io)?;
            buf.truncate(len);
            let handler = Arc::clone(&handler);
            let socket = self.socket.try_clone().map_err(CoreError::Io)?;
            thread::spawn(move || {
                if let Ok(req) = DnsMessage::decode(&buf) {
                    if let Ok(resp) = handler(req).encode() {
                        let _ = socket.send_to(&resp, peer);
                    }
                }
            });
        }
    }
}

pub struct AsyncMdnsClient {
    socket: TokioUdpSocket,
}

impl AsyncMdnsClient {
    pub async fn bind_v4() -> CoreResult<Self> {
        let socket = TokioUdpSocket::bind(("0.0.0.0", MDNS_PORT))
            .await
            .map_err(CoreError::Io)?;
        let mcast: Ipv4Addr = MDNS_IPV4
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket
            .join_multicast_v4(mcast, Ipv4Addr::UNSPECIFIED)
            .map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub async fn bind_v6() -> CoreResult<Self> {
        let socket = TokioUdpSocket::bind(("::", MDNS_PORT))
            .await
            .map_err(CoreError::Io)?;
        let mcast: Ipv6Addr = MDNS_IPV6
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket.join_multicast_v6(&mcast, 0).map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub async fn send_query(&self, message: &DnsMessage) -> CoreResult<()> {
        let bytes = message.encode()?;
        let target: SocketAddr = format!("{}:{}", MDNS_IPV4, MDNS_PORT).parse().unwrap();
        self.socket
            .send_to(&bytes, target)
            .await
            .map_err(CoreError::Io)?;
        Ok(())
    }

    pub async fn send_query_v6(&self, message: &DnsMessage) -> CoreResult<()> {
        let bytes = message.encode()?;
        let target: SocketAddr = format!("[{}]:{}", MDNS_IPV6, MDNS_PORT).parse().unwrap();
        self.socket
            .send_to(&bytes, target)
            .await
            .map_err(CoreError::Io)?;
        Ok(())
    }

    pub async fn recv(&self, max_bytes: usize) -> CoreResult<(DnsMessage, SocketAddr)> {
        let mut buf = vec![0u8; max_bytes];
        let (len, addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(CoreError::Io)?;
        buf.truncate(len);
        let msg = DnsMessage::decode(&buf)?;
        Ok((msg, addr))
    }
}

pub struct AsyncMdnsServer {
    socket: Arc<TokioUdpSocket>,
}

impl AsyncMdnsServer {
    pub async fn bind_v4() -> CoreResult<Self> {
        let socket = TokioUdpSocket::bind(("0.0.0.0", MDNS_PORT))
            .await
            .map_err(CoreError::Io)?;
        let mcast: Ipv4Addr = MDNS_IPV4
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket
            .join_multicast_v4(mcast, Ipv4Addr::UNSPECIFIED)
            .map_err(CoreError::Io)?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub async fn bind_v6() -> CoreResult<Self> {
        let socket = TokioUdpSocket::bind(("::", MDNS_PORT))
            .await
            .map_err(CoreError::Io)?;
        let mcast: Ipv6Addr = MDNS_IPV6
            .parse()
            .map_err(|_| CoreError::Parse("invalid mdns addr".to_string()))?;
        socket.join_multicast_v6(&mcast, 0).map_err(CoreError::Io)?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub async fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let mut buf = vec![0u8; DNS_MAX_PACKET];
        loop {
            let (len, peer) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(CoreError::Io)?;
            let data = buf[..len].to_vec();
            let handler = Arc::clone(&handler);
            let socket = Arc::clone(&self.socket);
            tokio::spawn(async move {
                if let Ok(req) = DnsMessage::decode(&data) {
                    if let Ok(resp) = handler(req).encode() {
                        let _ = socket.send_to(&resp, peer).await;
                    }
                }
            });
        }
    }
}

pub struct AsyncDnsClient {
    server: SocketAddr,
    timeouts: Timeouts,
    max_packet: usize,
}

impl AsyncDnsClient {
    pub fn new(server: SocketAddr, timeouts: Timeouts) -> Self {
        Self {
            server,
            timeouts,
            max_packet: DNS_MAX_PACKET,
        }
    }

    pub async fn query_udp(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let socket = AsyncUdpTransport::bind_any().await?;
        let bytes = message.encode()?;
        socket.send_to(&bytes, self.server).await?;
        let (resp, _) = tokio::time::timeout(self.timeouts.read, socket.recv_from(self.max_packet))
            .await
            .map_err(|_| CoreError::Parse("dns udp timeout".to_string()))??;
        DnsMessage::decode(&resp)
    }

    pub async fn query_tcp(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let addr = NetAddr::from_socket(self.server);
        let mut transport = AsyncTcpTransport::connect(&addr, self.timeouts).await?;
        let framer = LengthPrefixedFramer::new(2, self.max_packet)?;
        let bytes = message.encode()?;
        let framed = framer.frame(&bytes)?;
        transport.write_all(&framed).await?;
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 2048];
            let read = tokio::time::timeout(self.timeouts.read, transport.read(&mut chunk))
                .await
                .map_err(|_| CoreError::Parse("dns tcp timeout".to_string()))??;
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if let Some(frame) = framer.deframe(&mut buf)? {
                return DnsMessage::decode(&frame.payload);
            }
        }
        Err(CoreError::Parse("unexpected eof".to_string()))
    }

    pub async fn query_tls(
        &self,
        message: &DnsMessage,
        server_name: &str,
        tls: &TlsClientConfig,
    ) -> CoreResult<DnsMessage> {
        let addr = NetAddr::from_socket(self.server);
        let mut transport =
            AsyncTlsClientTransport::connect(&addr, server_name, tls, self.timeouts).await?;
        let framer = LengthPrefixedFramer::new(2, self.max_packet)?;
        let bytes = message.encode()?;
        let framed = framer.frame(&bytes)?;
        transport.write_all(&framed).await?;
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 2048];
            let read = tokio::time::timeout(self.timeouts.read, transport.read(&mut chunk))
                .await
                .map_err(|_| CoreError::Parse("dns tls timeout".to_string()))??;
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if let Some(frame) = framer.deframe(&mut buf)? {
                return DnsMessage::decode(&frame.payload);
            }
        }
        Err(CoreError::Parse("unexpected eof".to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct DohClient {
    url: DohUrl,
    timeouts: Timeouts,
    max_packet: usize,
}

#[derive(Debug, Clone)]
pub struct AsyncDohClient {
    url: DohUrl,
    timeouts: Timeouts,
    max_packet: usize,
}

#[derive(Debug, Clone)]
pub struct AsyncDoh2Client {
    url: DohUrl,
    timeouts: Timeouts,
    max_packet: usize,
}

#[derive(Debug, Clone)]
pub struct AsyncDoh3Client {
    url: DohUrl,
    max_packet: usize,
}

#[derive(Debug, Clone)]
struct DohUrl {
    scheme: String,
    host: String,
    host_header: String,
    port: u16,
    path: String,
}

impl DohUrl {
    fn parse(url: &str) -> CoreResult<Self> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| CoreError::Parse("invalid doh url".to_string()))?;
        let scheme = scheme.to_lowercase();
        let default_port = if scheme == "https" { 443 } else { 80 };
        let (host_port, path) = if let Some((host, path)) = rest.split_once('/') {
            (host, format!("/{}", path))
        } else {
            (rest, "/dns-query".to_string())
        };
        let (host, host_header, port) = if host_port.starts_with('[') {
            let end = host_port
                .find(']')
                .ok_or_else(|| CoreError::Parse("invalid ipv6 host".to_string()))?;
            let host = host_port[1..end].to_string();
            let port = host_port
                .get(end + 1..)
                .and_then(|s| s.strip_prefix(':'))
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(default_port);
            (host.clone(), format!("[{}]", host), port)
        } else if let Some((host, port)) = host_port.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                (host.to_string(), host.to_string(), port)
            } else {
                (host_port.to_string(), host_port.to_string(), default_port)
            }
        } else {
            (host_port.to_string(), host_port.to_string(), default_port)
        };
        Ok(Self {
            scheme,
            host,
            host_header,
            port,
            path,
        })
    }
}

async fn doh_send_http11_request<S>(
    io: S,
    url: &DohUrl,
    payload: Vec<u8>,
    timeouts: Timeouts,
    max_packet: usize,
) -> CoreResult<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(|err| CoreError::Message(err.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri(url.path.as_str())
        .header("host", &url.host_header)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(Full::new(bytes::Bytes::from(payload)))
        .map_err(|_| CoreError::Parse("invalid doh request".to_string()))?;

    let response = tokio::time::timeout(timeouts.read, sender.send_request(request))
        .await
        .map_err(|_| CoreError::Parse("doh request timeout".to_string()))?
        .map_err(|err| CoreError::Message(err.to_string()))?;

    if response.status().as_u16() != 200 {
        return Err(CoreError::Parse("doh non-200 response".to_string()));
    }

    let body = tokio::time::timeout(timeouts.read, response.into_body().collect())
        .await
        .map_err(|_| CoreError::Parse("doh response timeout".to_string()))?
        .map_err(|err| CoreError::Message(err.to_string()))?
        .to_bytes();
    if body.len() > max_packet {
        return Err(CoreError::Parse("doh response too large".to_string()));
    }
    Ok(body.to_vec())
}

async fn doh_query_http11_async(
    url: &DohUrl,
    payload: Vec<u8>,
    timeouts: Timeouts,
    max_packet: usize,
) -> CoreResult<Vec<u8>> {
    let target = NetAddr::new(&url.host, url.port)
        .resolve()?
        .into_iter()
        .next()
        .ok_or_else(|| CoreError::Parse("unable to resolve".to_string()))?;
    let tcp = tokio::time::timeout(timeouts.connect, tokio::net::TcpStream::connect(target))
        .await
        .map_err(|_| CoreError::Parse("connect timeout".to_string()))?
        .map_err(CoreError::Io)?;
    tcp.set_nodelay(true).map_err(CoreError::Io)?;

    if url.scheme == "https" {
        let tls = TlsClientConfig::with_webpki_roots()?.with_alpn(&[b"http/1.1"]);
        let server_name = rustls::pki_types::ServerName::try_from(url.host.as_str())
            .map_err(|_| CoreError::Parse("invalid server name".to_string()))?
            .to_owned();
        let connector = tokio_rustls::TlsConnector::from(tls.inner());
        let stream = tokio::time::timeout(timeouts.connect, connector.connect(server_name, tcp))
            .await
            .map_err(|_| CoreError::Parse("tls handshake timeout".to_string()))?
            .map_err(|err| CoreError::Message(err.to_string()))?;
        return doh_send_http11_request(stream, url, payload, timeouts, max_packet).await;
    }

    doh_send_http11_request(tcp, url, payload, timeouts, max_packet).await
}

impl DohClient {
    pub fn new(url: &str, timeouts: Timeouts) -> CoreResult<Self> {
        Ok(Self {
            url: DohUrl::parse(url)?,
            timeouts,
            max_packet: DNS_MAX_PACKET,
        })
    }

    pub fn max_packet(mut self, max_packet: usize) -> Self {
        self.max_packet = max_packet;
        self
    }

    pub fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let payload = message.encode()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| CoreError::Message(err.to_string()))?;
        let bytes = runtime.block_on(doh_query_http11_async(
            &self.url,
            payload,
            self.timeouts,
            self.max_packet,
        ))?;
        DnsMessage::decode(&bytes)
    }
}

impl AsyncDohClient {
    pub fn new(url: &str, timeouts: Timeouts) -> CoreResult<Self> {
        Ok(Self {
            url: DohUrl::parse(url)?,
            timeouts,
            max_packet: DNS_MAX_PACKET,
        })
    }

    pub fn max_packet(mut self, max_packet: usize) -> Self {
        self.max_packet = max_packet;
        self
    }

    pub async fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let payload = message.encode()?;
        let bytes =
            doh_query_http11_async(&self.url, payload, self.timeouts, self.max_packet).await?;
        DnsMessage::decode(&bytes)
    }
}

impl AsyncDoh2Client {
    pub fn new(url: &str, timeouts: Timeouts) -> CoreResult<Self> {
        Ok(Self {
            url: DohUrl::parse(url)?,
            timeouts,
            max_packet: DNS_MAX_PACKET,
        })
    }

    pub fn max_packet(mut self, max_packet: usize) -> Self {
        self.max_packet = max_packet;
        self
    }

    pub async fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let uri = if (self.url.scheme == "https" && self.url.port == 443)
            || (self.url.scheme == "http" && self.url.port == 80)
        {
            format!("{}://{}{}", self.url.scheme, self.url.host, self.url.path)
        } else {
            format!(
                "{}://{}:{}{}",
                self.url.scheme, self.url.host, self.url.port, self.url.path
            )
        };
        let mut req = crate::http2::Http2Request::new("POST", uri);
        req.set_header("content-type", "application/dns-message");
        req.set_header("accept", "application/dns-message");
        req.body = message.encode()?;
        let addr = NetAddr::new(&self.url.host, self.url.port);
        let tls = TlsClientConfig::with_webpki_roots()?.with_alpn(&[b"h2"]);
        let mut client =
            crate::http2::Http2Client::connect_tls(&addr, &self.url.host, &tls, self.timeouts)
                .await?;
        let response = client.send(&req).await?;
        if response.status != 200 {
            return Err(CoreError::Parse("doh2 non-200 response".to_string()));
        }
        if response.body.len() > self.max_packet {
            return Err(CoreError::Parse("doh2 response too large".to_string()));
        }
        DnsMessage::decode(&response.body)
    }
}

impl AsyncDoh3Client {
    pub fn new(url: &str) -> CoreResult<Self> {
        Ok(Self {
            url: DohUrl::parse(url)?,
            max_packet: DNS_MAX_PACKET,
        })
    }

    pub fn max_packet(mut self, max_packet: usize) -> Self {
        self.max_packet = max_packet;
        self
    }

    pub async fn query(&self, message: &DnsMessage) -> CoreResult<DnsMessage> {
        let mut req = crate::http3::Http3Request::new("POST", self.url.path.clone());
        req.scheme = self.url.scheme.clone();
        req.authority = if (self.url.scheme == "https" && self.url.port == 443)
            || (self.url.scheme == "http" && self.url.port == 80)
        {
            self.url.host.clone()
        } else {
            format!("{}:{}", self.url.host, self.url.port)
        };
        req.set_header("content-type", "application/dns-message");
        req.set_header("accept", "application/dns-message");
        req.body = message.encode()?;
        let addr = NetAddr::new(&self.url.host, self.url.port);
        let mut client = crate::http3::Http3Client::connect(&addr, &self.url.host).await?;
        let response = client.request(&req).await?;
        if response.status != 200 {
            return Err(CoreError::Parse("doh3 non-200 response".to_string()));
        }
        if response.body.len() > self.max_packet {
            return Err(CoreError::Parse("doh3 response too large".to_string()));
        }
        DnsMessage::decode(&response.body)
    }
}

#[derive(Debug, Clone)]
pub struct DohServer {
    config: DohServerConfig,
}

#[derive(Debug, Clone)]
struct DohServerConfig {
    path: String,
    max_packet: usize,
}

#[derive(Debug)]
enum DohError {
    NotFound,
    BadRequest(String),
    Internal(String),
}

impl DohServer {
    pub fn new() -> Self {
        Self {
            config: DohServerConfig {
                path: "/dns-query".to_string(),
                max_packet: DNS_MAX_PACKET,
            },
        }
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.config.path = path.into();
        self
    }

    pub fn max_packet(mut self, max_packet: usize) -> Self {
        self.config.max_packet = max_packet;
        self
    }

    pub fn serve_http<F>(&self, addr: SocketAddr, timeouts: Timeouts, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let server = crate::http::HttpServer::bind(addr, timeouts)?;
        let handler = Arc::new(handler);
        let config = self.config.clone();
        server.serve(move |req| doh_http_response(&config, &handler, req))
    }

    pub async fn serve_http2<F>(&self, addr: SocketAddr, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let server = Http2Server::bind(addr).await?;
        let handler = Arc::new(handler);
        let config = self.config.clone();
        server
            .serve(move |req| doh_http2_response(&config, &handler, req))
            .await
    }

    pub async fn serve_http2_tls<F>(
        &self,
        addr: SocketAddr,
        tls: &TlsServerConfig,
        handler: F,
    ) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let server = Http2TlsServer::bind(addr, tls).await?;
        let handler = Arc::new(handler);
        let config = self.config.clone();
        server
            .serve(move |req| doh_http2_response(&config, &handler, req))
            .await
    }

    pub async fn serve_http3<F>(
        &self,
        addr: SocketAddr,
        cert_path: &str,
        key_path: &str,
        handler: F,
    ) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let server = Http3Server::bind(addr, cert_path, key_path).await?;
        let handler = Arc::new(handler);
        let config = self.config.clone();
        server
            .serve(move |req| doh_http3_response(&config, &handler, req))
            .await
    }
}

fn doh_http_response<F>(
    config: &DohServerConfig,
    handler: &Arc<F>,
    request: HttpRequest,
) -> HttpResponse
where
    F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
{
    let method = http_method_str(&request.method);
    match doh_handle_request(
        config,
        method,
        &request.path,
        &request.headers,
        &request.body,
    ) {
        Ok(msg) => doh_success_http(config, handler, msg),
        Err(err) => doh_error_http(err),
    }
}

fn doh_http2_response<F>(
    config: &DohServerConfig,
    handler: &Arc<F>,
    request: Http2Request,
) -> Http2Response
where
    F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
{
    match doh_handle_request(
        config,
        &request.method,
        &request.path,
        &request.headers,
        &request.body,
    ) {
        Ok(msg) => doh_success_http2(config, handler, msg),
        Err(err) => doh_error_http2(err),
    }
}

fn doh_http3_response<F>(
    config: &DohServerConfig,
    handler: &Arc<F>,
    request: Http3Request,
) -> Http3Response
where
    F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
{
    match doh_handle_request(
        config,
        &request.method,
        &request.path,
        &request.headers,
        &request.body,
    ) {
        Ok(msg) => doh_success_http3(config, handler, msg),
        Err(err) => doh_error_http3(err),
    }
}

fn doh_handle_request(
    config: &DohServerConfig,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<DnsMessage, DohError> {
    let (base_path, query) = split_path_query(path);
    if base_path != config.path {
        return Err(DohError::NotFound);
    }
    if method.eq_ignore_ascii_case("GET") {
        let query = query.ok_or_else(|| DohError::BadRequest("missing query".to_string()))?;
        let value = query_param(query, "dns")
            .ok_or_else(|| DohError::BadRequest("missing dns param".to_string()))?;
        let decoded = percent_decode(&value)?;
        let data = base64url_decode(&decoded)?;
        if data.len() > config.max_packet {
            return Err(DohError::BadRequest("dns message too large".to_string()));
        }
        return DnsMessage::decode(&data).map_err(|err| DohError::BadRequest(err.to_string()));
    }
    if method.eq_ignore_ascii_case("POST") {
        if body.is_empty() {
            return Err(DohError::BadRequest("empty body".to_string()));
        }
        if body.len() > config.max_packet {
            return Err(DohError::BadRequest("dns message too large".to_string()));
        }
        if let Some(ct) = header_value(headers, "content-type") {
            if !ct
                .to_ascii_lowercase()
                .starts_with("application/dns-message")
            {
                return Err(DohError::BadRequest("invalid content-type".to_string()));
            }
        }
        return DnsMessage::decode(body).map_err(|err| DohError::BadRequest(err.to_string()));
    }
    Err(DohError::BadRequest("unsupported method".to_string()))
}

fn doh_success_http<F>(
    config: &DohServerConfig,
    handler: &Arc<F>,
    request: DnsMessage,
) -> HttpResponse
where
    F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
{
    let response = (handler)(request);
    match response.encode() {
        Ok(body) => {
            if body.len() > config.max_packet {
                return doh_error_http(DohError::Internal("response too large".to_string()));
            }
            let mut resp = HttpResponse::new(200);
            resp.set_header("Content-Type", "application/dns-message");
            resp.body = body;
            resp
        }
        Err(err) => doh_error_http(DohError::Internal(err.to_string())),
    }
}

fn doh_success_http2<F>(
    config: &DohServerConfig,
    handler: &Arc<F>,
    request: DnsMessage,
) -> Http2Response
where
    F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
{
    let response = (handler)(request);
    match response.encode() {
        Ok(body) => {
            if body.len() > config.max_packet {
                return doh_error_http2(DohError::Internal("response too large".to_string()));
            }
            let mut resp = Http2Response::new(200);
            resp.set_header("content-type", "application/dns-message");
            resp.body = body;
            resp
        }
        Err(err) => doh_error_http2(DohError::Internal(err.to_string())),
    }
}

fn doh_success_http3<F>(
    config: &DohServerConfig,
    handler: &Arc<F>,
    request: DnsMessage,
) -> Http3Response
where
    F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
{
    let response = (handler)(request);
    match response.encode() {
        Ok(body) => {
            if body.len() > config.max_packet {
                return doh_error_http3(DohError::Internal("response too large".to_string()));
            }
            let mut resp = Http3Response::new(200);
            resp.set_header("content-type", "application/dns-message");
            resp.body = body;
            resp
        }
        Err(err) => doh_error_http3(DohError::Internal(err.to_string())),
    }
}

fn doh_error_http(err: DohError) -> HttpResponse {
    let (status, reason) = doh_error_status(err);
    let mut resp = HttpResponse::new(status);
    resp.reason = reason;
    resp
}

fn doh_error_http2(err: DohError) -> Http2Response {
    let (status, _) = doh_error_status(err);
    Http2Response::new(status)
}

fn doh_error_http3(err: DohError) -> Http3Response {
    let (status, _) = doh_error_status(err);
    Http3Response::new(status)
}

fn doh_error_status(err: DohError) -> (u16, String) {
    match err {
        DohError::NotFound => (404, "Not Found".to_string()),
        DohError::BadRequest(reason) => (400, reason),
        DohError::Internal(reason) => (500, reason),
    }
}

fn http_method_str(method: &HttpMethod) -> &str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Trace => "TRACE",
        HttpMethod::Connect => "CONNECT",
        HttpMethod::Other(value) => value.as_str(),
    }
}

fn split_path_query(path: &str) -> (&str, Option<&str>) {
    if let Some((base, query)) = path.split_once('?') {
        (base, Some(query))
    } else {
        (path, None)
    }
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let name = parts.next()?.trim();
        let value = parts.next().unwrap_or("").trim();
        if name == key {
            return Some(value.to_string());
        }
    }
    None
}

fn percent_decode(value: &str) -> Result<String, DohError> {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(DohError::BadRequest("invalid percent encoding".to_string()));
                }
                let hi = from_hex(bytes[i + 1])?;
                let lo = from_hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b'+');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| DohError::BadRequest("invalid utf8".to_string()))
}

fn from_hex(value: u8) -> Result<u8, DohError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(DohError::BadRequest("invalid percent encoding".to_string())),
    }
}

fn base64url_decode(value: &str) -> Result<Vec<u8>, DohError> {
    let mut input = value.replace('-', "+").replace('_', "/");
    match input.len() % 4 {
        0 => {}
        2 => input.push_str("=="),
        3 => input.push('='),
        _ => return Err(DohError::BadRequest("invalid base64".to_string())),
    }
    base64_decode(&input).map_err(|_| DohError::BadRequest("invalid base64".to_string()))
}

fn base64_decode(value: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for &b in value.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                break;
            }
            _ => return Err(()),
        } as u32;
        buffer = (buffer << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub struct DnsServer {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
}

impl DnsServer {
    pub fn new(udp_addr: SocketAddr, tcp_addr: SocketAddr) -> Self {
        Self { udp_addr, tcp_addr }
    }

    pub fn serve_udp<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let socket = UdpTransport::bind(self.udp_addr)?;
        let handler = Arc::new(handler);
        loop {
            let (data, peer) = socket.recv_from(DNS_MAX_PACKET)?;
            let handler = Arc::clone(&handler);
            let socket = socket.try_clone()?;
            thread::spawn(move || {
                if let Ok(req) = DnsMessage::decode(&data) {
                    let resp = handler(req).encode();
                    if let Ok(resp) = resp {
                        let _ = socket.send_to(&resp, peer);
                    }
                }
            });
        }
    }

    pub fn serve_tcp<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(self.tcp_addr).map_err(CoreError::Io)?;
        let handler = Arc::new(handler);
        for stream in listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            thread::spawn(move || {
                let _ = handle_tcp_client(stream, handler);
            });
        }
        Ok(())
    }

    pub fn serve_tls<F>(&self, config: &TlsServerConfig, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(self.tcp_addr).map_err(CoreError::Io)?;
        let handler = Arc::new(handler);
        loop {
            let handler = Arc::clone(&handler);
            let transport = TlsStreamTransport::accept(&listener, config, Timeouts::default())?;
            thread::spawn(move || {
                let _ = handle_framed_stream(transport, handler);
            });
        }
    }
}

pub struct AsyncDnsServer {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
}

impl AsyncDnsServer {
    pub fn new(udp_addr: SocketAddr, tcp_addr: SocketAddr) -> Self {
        Self { udp_addr, tcp_addr }
    }

    pub async fn serve_udp<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(self.udp_addr)
                .await
                .map_err(CoreError::Io)?,
        );
        let handler = Arc::new(handler);
        let mut buf = vec![0u8; DNS_MAX_PACKET];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.map_err(CoreError::Io)?;
            let data = buf[..len].to_vec();
            let handler = Arc::clone(&handler);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                if let Ok(req) = DnsMessage::decode(&data) {
                    if let Ok(resp) = handler(req).encode() {
                        let _ = socket.send_to(&resp, peer).await;
                    }
                }
            });
        }
    }

    pub async fn serve_tcp<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind(self.tcp_addr)
            .await
            .map_err(CoreError::Io)?;
        let handler = Arc::new(handler);
        loop {
            let (stream, _) = listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _ = handle_tcp_client_async(stream, handler).await;
            });
        }
    }

    pub async fn serve_tls<F>(&self, config: &TlsServerConfig, handler: F) -> CoreResult<()>
    where
        F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind(self.tcp_addr)
            .await
            .map_err(CoreError::Io)?;
        let acceptor = AsyncTlsServer::new(config);
        let handler = Arc::new(handler);
        loop {
            let (stream, _) = listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let transport = AsyncTlsServerTransport::from_stream(tls);
                    let _ = handle_framed_stream_async(transport, handler).await;
                }
            });
        }
    }
}

async fn handle_tcp_client_async(
    stream: tokio::net::TcpStream,
    handler: Arc<dyn Fn(DnsMessage) -> DnsMessage + Send + Sync>,
) -> CoreResult<()> {
    let transport = AsyncTcpTransport::from_stream(stream);
    handle_framed_stream_async(transport, handler).await
}

async fn handle_framed_stream_async<T: AsyncStreamTransport>(
    mut transport: T,
    handler: Arc<dyn Fn(DnsMessage) -> DnsMessage + Send + Sync>,
) -> CoreResult<()> {
    let framer = LengthPrefixedFramer::new(2, DNS_MAX_PACKET)?;
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 2048];
        let read = transport.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        while let Some(frame) = framer.deframe(&mut buf)? {
            let req = DnsMessage::decode(&frame.payload)?;
            let resp = (handler)(req).encode()?;
            let framed = framer.frame(&resp)?;
            transport.write_all(&framed).await?;
        }
    }
    Ok(())
}

fn handle_tcp_client(
    stream: std::net::TcpStream,
    handler: Arc<dyn Fn(DnsMessage) -> DnsMessage + Send + Sync>,
) -> CoreResult<()> {
    let transport = TcpTransport::from_stream(stream, Timeouts::default())?;
    handle_framed_stream(transport, handler)
}

fn handle_framed_stream<T: StreamTransport>(
    mut transport: T,
    handler: Arc<dyn Fn(DnsMessage) -> DnsMessage + Send + Sync>,
) -> CoreResult<()> {
    let framer = LengthPrefixedFramer::new(2, DNS_MAX_PACKET)?;
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 2048];
        let read = transport.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        while let Some(frame) = framer.deframe(&mut buf)? {
            let req = DnsMessage::decode(&frame.payload)?;
            let resp = (handler)(req).encode()?;
            let framed = framer.frame(&resp)?;
            transport.write_all(&framed)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;
    use ring::signature::{
        EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
    };

    #[test]
    fn dns_roundtrip_query() {
        let msg = DnsMessage::new_query(0x1234, "example.com", 1);
        let bytes = msg.encode().expect("encode");
        let decoded = DnsMessage::decode(&bytes).expect("decode");
        assert_eq!(decoded.questions.len(), 1);
        assert_eq!(decoded.questions[0].name, "example.com");
    }

    #[test]
    fn decode_a_record() {
        let response = DnsMessage {
            header: DnsHeader {
                id: 0x2222,
                flags: DnsFlags {
                    qr: true,
                    opcode: 0,
                    aa: true,
                    tc: false,
                    rd: true,
                    ra: true,
                    rcode: 0,
                },
                qdcount: 1,
                ancount: 1,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: "example.com".to_string(),
                qtype: 1,
                qclass: 1,
            }],
            answers: vec![DnsRecord {
                name: "example.com".to_string(),
                rtype: 1,
                class: 1,
                ttl: 60,
                data: DnsRecordData::A(Ipv4Addr::new(127, 0, 0, 1)),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let bytes = response.encode().expect("encode");
        let decoded = DnsMessage::decode(&bytes).expect("decode");
        assert_eq!(decoded.answers.len(), 1);
        match decoded.answers[0].data {
            DnsRecordData::A(addr) => assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1)),
            _ => panic!("expected A record"),
        }
    }

    #[test]
    fn dnssec_rrsig_ed25519() {
        let seed = [7u8; 32];
        let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let dnskey = DnsDnskey {
            flags: 256,
            protocol: 3,
            algorithm: 15,
            public_key: keypair.public_key().as_ref().to_vec(),
        };
        let rrset = vec![DnsRecord {
            name: "example.com".to_string(),
            rtype: 1,
            class: 1,
            ttl: 3600,
            data: DnsRecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
        }];
        let mut rrsig = DnsRrsig {
            type_covered: 1,
            algorithm: 15,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 2_000_000_000,
            signature_inception: 1_600_000_000,
            key_tag: dnskey_tag(&dnskey),
            signer_name: "example.com".to_string(),
            signature: Vec::new(),
        };
        let signed = build_rrsig_signed_data("example.com", &rrset, &rrsig).unwrap();
        let sig = keypair.sign(&signed);
        rrsig.signature = sig.as_ref().to_vec();
        verify_rrsig_at("example.com", &rrset, &rrsig, &dnskey, 1_700_000_000).unwrap();
        assert!(verify_rrsig_at("example.com", &rrset, &rrsig, &dnskey, 2_100_000_000).is_err());
    }

    #[test]
    fn nsec3_hash_vector() {
        let hash = nsec3_hash_base32("example.com", 0, b"");
        assert_eq!(hash, "ONIB9MGUB9H0RML3CDF5BGRJ59DKJHVK");
    }

    #[test]
    fn nsec_type_bitmap_roundtrip() {
        let types = vec![1u16, 2u16, 15u16, 28u16, 46u16, 257u16];
        let bitmap = nsec_type_bitmap_build(&types);
        for t in &types {
            assert!(nsec_type_bitmap_contains(&bitmap, *t).unwrap());
        }
        let mut listed = nsec_type_bitmap_list(&bitmap).unwrap();
        listed.sort_unstable();
        let mut expected = types.clone();
        expected.sort_unstable();
        assert_eq!(listed, expected);
    }

    #[test]
    fn dnssec_rrsig_rsa_sha1() {
        const RSA_PKCS8_BASE64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdfdZkSLmP7jc8fb/4XVr+zqOUTO4SrWPfmscY0yPK9C/GHAh4Opw0kJaPHVeyQeLwSjtCt5BYm/fTKS36E6rrc9dhiRU7J8hf1bEqOYzVVsZS6pm1yT9cy4tIQ+yiIH6q6kP294cvBJ22bA0G1JrVB0AgOCQ4HfGJ0/BnVQzaGC4W0psBO6k0pdRZ/lKdFItETeZetFMCw16b/HCwfPJQSWw1HgqPPgAVUIyrFSfXuOWtoK8y95wpSFZS22zFjnBNyechDyJaJVFuJRpv85D3zlgqpeYP8zU1NTAje21qlIjc0FlqaS+K3JCmgH8pADxM6zq90AGueaB8EZ6pq5MvAgMBAAECggEANGZC57jerIm4rRK1xX/iH7dG67ew2lwAR8xqg9L0LLmUD5kSJFZz1HVq8pDztaaASCyajPcgOqsiCIrB9luG2bIALj565uS0oVYrDP564hxt/fZ6T+Z2g3xhihi3abXgDyPEmy3+N2GUy7Ylm2kvXsN7zXyAaH9l9tKiQO8mSIWPQBZRa1dCn2EhtacbIA1Nc02ublO1kKDFC1JkSzsCsuWDBDERjbp+UFuHb0fNbdNeyjHqy8wfYnThlMlmoe1GsV1lL7hRG2YQdFAeQeq5j3D4A1FUofi7gIu7ZIW4uoNPDAbZfEbQxSXWBOetCQAcTxGNPwk/fGOiYcsqDpt3WQKBgQDTEiSyIp8BTPoZrwBZXy0frJECtAe72SoPyr5Xo/FYWkuzTt/gcribIvlyk21RnuUhP6FuBWET49kZ5vI6s08y7ABn16g3/OIKQf/9Cq9/dxLD68TRlSVEgBy2AOxKuotfuDAbgxQ0R5zTFM4GWYCGjXOgLYEHrNWxsoHFdy48ywKBgQC/BADikag+fe18ez71n7he2OVKj0g5DBpczJOVm41H94PPidU7Rz5ySReTsLN2lr3CLjz/Y1kvutjvRHCXz1nlHyW8OtyIedlGgrNO5I5JJolcJYEOPfMU11b12kWgMKbW/coyMmuRzILMw6gACmMbTO3iho7ipbAcOsG2NqO6rQKBgE+OYSJ7hi85UnNn0Nve0eVEaAv6y4d0XTRCmOfztT42Gp5lNmElHIvs7NTQ2L2RBJA5qaEMigCzOttWfyq89zccWTLKyG8B9Dklk1VPN8L1oK8UKMVOUBO3rhqz0lyAX5QempNkHrNt4qB1EQq3pYgRvOk8/YtlC87El8FUIKttAoGALCjRx49i9OeJ8sBPYtuE9TBxedY8HSwmIBQPfoPSmrOnHmDAEg87aZJqR/OO2bipr+2ennAqWzV4F4CcAwylvKmBwM1e1JJO39UxfOir2E93a/0jo9ZAjy3lZbsLY6g7ufI8P3SWl8NO7eXBvhioptQXHsp61/z0BOK0i9p/6ZUCgYEAmnfDjzW4pZnGj9W2fmQHTVqxa1M1rSuhKaynL/6i/3Fk3kp0u0tzkglAfiEThEufk+TfrNhR6RtBj5viAeI1kJoGxDS8AEnJscRmlEunRgmcHbDNZeaO7X3BrVXOtWMZmaDAUFxoFQHtu8iGRUoPyGj2fVvwyMfxyRmUSm2NrPk=";
        const RSA_DNSKEY_BASE64: &str = "AwEAAZ191mRIuY/uNzx9v/hdWv7Oo5RM7hKtY9+axxjTI8r0L8YcCHg6nDSQlo8dV7JB4vBKO0K3kFib99MpLfoTqutz12GJFTsnyF/VsSo5jNVWxlLqmbXJP1zLi0hD7KIgfqrqQ/b3hy8EnbZsDQbUmtUHQCA4JDgd8YnT8GdVDNoYLhbSmwE7qTSl1Fn+Up0Ui0RN5l60UwLDXpv8cLB88lBJbDUeCo8+ABVQjKsVJ9e45a2grzL3nClIVlLbbMWOcE3J5yEPIlolUW4lGm/zkPfOWCql5g/zNTU1MCN7bWqUiNzQWWppL4rckKaAfykAPEzrOr3QAa55oHwRnqmrky8=";
        let pkcs8 = base64_decode(RSA_PKCS8_BASE64).unwrap();
        let dnskey = DnsDnskey {
            flags: 256,
            protocol: 3,
            algorithm: 5,
            public_key: base64_decode(RSA_DNSKEY_BASE64).unwrap(),
        };
        let rrset = vec![DnsRecord {
            name: "example.com".to_string(),
            rtype: 1,
            class: 1,
            ttl: 3600,
            data: DnsRecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
        }];
        let mut rrsig = DnsRrsig {
            type_covered: 1,
            algorithm: 5,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 2_000_000_000,
            signature_inception: 1_600_000_000,
            key_tag: dnskey_tag(&dnskey),
            signer_name: "example.com".to_string(),
            signature: Vec::new(),
        };
        let signed = build_rrsig_signed_data("example.com", &rrset, &rrsig).unwrap();
        let dir = std::env::temp_dir();
        let key_path = dir.join("moonlight_dnssec_rsa_sha1.pk8");
        let data_path = dir.join("moonlight_dnssec_rsa_sha1.data");
        let sig_path = dir.join("moonlight_dnssec_rsa_sha1.sig");
        std::fs::write(&key_path, &pkcs8).unwrap();
        std::fs::write(&data_path, &signed).unwrap();
        let status = std::process::Command::new("openssl")
            .args([
                "dgst",
                "-sha1",
                "-sign",
                key_path.to_str().unwrap(),
                "-keyform",
                "DER",
                "-out",
                sig_path.to_str().unwrap(),
                data_path.to_str().unwrap(),
            ])
            .status();
        if status.is_err() || !status.unwrap().success() {
            return;
        }
        rrsig.signature = std::fs::read(sig_path).unwrap();
        verify_rrsig_at("example.com", &rrset, &rrsig, &dnskey, 1_700_000_000).unwrap();
    }

    #[test]
    fn dnssec_rrsig_ecdsa() {
        const P256_PKCS8_BASE64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmWhrQkXmTWwGp209xylPQFAsad8VJ1ljqfPKMrVPjt2hRANCAATUgufRF1DUnWRp+T02iNwrTvZ4QrCjh4hKE3y2M/NgqYDLJFNAMX6BTnAPAn1mfF28fTtZvTqqhtnhXHwAkOZm";
        const P384_PKCS8_BASE64: &str = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC9yr5vPfIiqHkO8matLqZUbKLNkEuPQfMWRdkqeKaX4KoPuJ3otHrtKjZ13rchBxShZANiAAS3x/ceuzNMq2xf4HQFQEg0+aq+yvUt6wciIfsusu6OoY2wR456wWdTC6pDX/vi2ifZRb+TzfjOv0jOi5jHDSEMc2WGGDIxRaJ1e7ATN1INJqLTZYeXSUXbs5O5Qu9Ln7g=";
        let rng = SystemRandom::new();

        let key_p256 = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &base64_decode(P256_PKCS8_BASE64).unwrap(),
            &rng,
        )
        .unwrap();
        let pub_p256 = key_p256.public_key().as_ref();
        let dnskey_p256 = DnsDnskey {
            flags: 256,
            protocol: 3,
            algorithm: 13,
            public_key: pub_p256[1..].to_vec(),
        };
        let rrset = vec![DnsRecord {
            name: "example.com".to_string(),
            rtype: 1,
            class: 1,
            ttl: 3600,
            data: DnsRecordData::A(Ipv4Addr::new(5, 6, 7, 8)),
        }];
        let mut rrsig = DnsRrsig {
            type_covered: 1,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 2_000_000_000,
            signature_inception: 1_600_000_000,
            key_tag: dnskey_tag(&dnskey_p256),
            signer_name: "example.com".to_string(),
            signature: Vec::new(),
        };
        let signed = build_rrsig_signed_data("example.com", &rrset, &rrsig).unwrap();
        rrsig.signature = key_p256.sign(&rng, &signed).unwrap().as_ref().to_vec();
        verify_rrsig_at("example.com", &rrset, &rrsig, &dnskey_p256, 1_700_000_000).unwrap();

        let key_p384 = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            &base64_decode(P384_PKCS8_BASE64).unwrap(),
            &rng,
        )
        .unwrap();
        let pub_p384 = key_p384.public_key().as_ref();
        let dnskey_p384 = DnsDnskey {
            flags: 256,
            protocol: 3,
            algorithm: 14,
            public_key: pub_p384[1..].to_vec(),
        };
        let mut rrsig384 = DnsRrsig {
            type_covered: 1,
            algorithm: 14,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 2_000_000_000,
            signature_inception: 1_600_000_000,
            key_tag: dnskey_tag(&dnskey_p384),
            signer_name: "example.com".to_string(),
            signature: Vec::new(),
        };
        let signed = build_rrsig_signed_data("example.com", &rrset, &rrsig384).unwrap();
        rrsig384.signature = key_p384.sign(&rng, &signed).unwrap().as_ref().to_vec();
        verify_rrsig_at(
            "example.com",
            &rrset,
            &rrsig384,
            &dnskey_p384,
            1_700_000_000,
        )
        .unwrap();
    }

    #[test]
    fn fuzz_dns_roundtrip() {
        let mut rng = XorShift64::new(0xabcdef);
        for _ in 0..128 {
            let name = format!(
                "{}.{}.{}",
                rng.next_label(),
                rng.next_label(),
                rng.next_label()
            );
            let mut msg = DnsMessage::new_query(rng.next_u16(), name.clone(), 1);
            msg.answers.push(DnsRecord {
                name: name.clone(),
                rtype: 1,
                class: 1,
                ttl: 60,
                data: DnsRecordData::A(Ipv4Addr::new(192, 168, rng.next_u8(), rng.next_u8())),
            });
            let bytes = msg.encode().expect("encode");
            let decoded = DnsMessage::decode(&bytes).expect("decode");
            assert_eq!(decoded.questions[0].name, name);
            assert_eq!(decoded.answers.len(), 1);
        }
    }

    struct XorShift64 {
        state: u64,
    }

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            x
        }

        fn next_u16(&mut self) -> u16 {
            (self.next_u64() & 0xffff) as u16
        }

        fn next_u8(&mut self) -> u8 {
            (self.next_u64() & 0xff) as u8
        }

        fn next_label(&mut self) -> String {
            let len = 3 + (self.next_u8() % 6) as usize;
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                let c = (b'a' + (self.next_u8() % 26)) as char;
                s.push(c);
            }
            s
        }
    }
}
