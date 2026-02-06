use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::framing::{Framer, LengthPrefixedFramer};
use crate::http::{AsyncHttpClient, HttpClient, HttpMethod, HttpRequest, HttpVersion};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    PTR(String),
    MX { preference: u16, exchange: String },
    TXT(String),
    SRV { priority: u16, weight: u16, port: u16, target: String },
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
            questions.push(DnsQuestion { name, qtype, qclass });
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

fn encode_name(name: &str, buf: &mut Vec<u8>, compression: &mut HashMap<String, u16>) -> CoreResult<()> {
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
        DnsRecordData::CNAME(name)
        | DnsRecordData::NS(name)
        | DnsRecordData::PTR(name) => encode_name(name, buf, compression)?,
        DnsRecordData::MX { preference, exchange } => {
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
        DnsRecordData::SRV { priority, weight, port, target } => {
            buf.extend_from_slice(&priority.to_be_bytes());
            buf.extend_from_slice(&weight.to_be_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
            encode_name(target, buf, compression)?;
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
            DnsRecordData::MX { preference, exchange }
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
            DnsRecordData::SRV { priority, weight, port, target }
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
    Ok(DnsRecord { name, rtype, class, ttl, data })
}

fn read_u16(msg: &[u8], offset: &mut usize) -> CoreResult<u16> {
    if *offset + 2 > msg.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let value = u16::from_be_bytes([msg[*offset], msg[*offset + 1]]);
    *offset += 2;
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
        let mut transport = AsyncTlsClientTransport::connect(&addr, server_name, tls, self.timeouts)
            .await?;
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
        let mut req = HttpRequest::new(HttpMethod::Post, self.url.path.clone());
        req.version = HttpVersion::Http11;
        req.set_header("Host", &self.url.host_header);
        req.set_header("Content-Type", "application/dns-message");
        req.set_header("Accept", "application/dns-message");
        req.body = message.encode()?;
        let addr = NetAddr::new(&self.url.host, self.url.port);
        let response = if self.url.scheme == "https" {
            let tls = TlsClientConfig::with_webpki_roots()?;
            let mut client = HttpClient::connect_tls(&addr, &self.url.host, &tls, self.timeouts)?;
            client.send(&req)?
        } else {
            let mut client = HttpClient::connect(&addr, self.timeouts)?;
            client.send(&req)?
        };
        if response.status_code != 200 {
            return Err(CoreError::Parse("doh non-200 response".to_string()));
        }
        if response.body.len() > self.max_packet {
            return Err(CoreError::Parse("doh response too large".to_string()));
        }
        DnsMessage::decode(&response.body)
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
        let mut req = HttpRequest::new(HttpMethod::Post, self.url.path.clone());
        req.version = HttpVersion::Http11;
        req.set_header("Host", &self.url.host_header);
        req.set_header("Content-Type", "application/dns-message");
        req.set_header("Accept", "application/dns-message");
        req.body = message.encode()?;
        let addr = NetAddr::new(&self.url.host, self.url.port);
        let response = if self.url.scheme == "https" {
            let tls = TlsClientConfig::with_webpki_roots()?;
            let mut client =
                AsyncHttpClient::connect_tls(&addr, &self.url.host, &tls, self.timeouts).await?;
            client.send(&req).await?
        } else {
            let mut client = AsyncHttpClient::connect(&addr, self.timeouts).await?;
            client.send(&req).await?
        };
        if response.status_code != 200 {
            return Err(CoreError::Parse("doh non-200 response".to_string()));
        }
        if response.body.len() > self.max_packet {
            return Err(CoreError::Parse("doh response too large".to_string()));
        }
        DnsMessage::decode(&response.body)
    }
}

pub struct DnsServer {
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
}

impl DnsServer {
    pub fn new(udp_addr: SocketAddr, tcp_addr: SocketAddr) -> Self {
        Self { udp_addr, tcp_addr }
    }

    pub fn serve_udp<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static {
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

    pub fn serve_tcp<F>(&self, handler: F) -> CoreResult<()> where F: Fn(DnsMessage) -> DnsMessage + Send + Sync + 'static {
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
        let socket = Arc::new(tokio::net::UdpSocket::bind(self.udp_addr).await.map_err(CoreError::Io)?);
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
        let listener = tokio::net::TcpListener::bind(self.tcp_addr).await.map_err(CoreError::Io)?;
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
        let listener = tokio::net::TcpListener::bind(self.tcp_addr).await.map_err(CoreError::Io)?;
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
                flags: DnsFlags { qr: true, opcode: 0, aa: true, tc: false, rd: true, ra: true, rcode: 0 },
                qdcount: 1,
                ancount: 1,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![DnsQuestion { name: "example.com".to_string(), qtype: 1, qclass: 1 }],
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
