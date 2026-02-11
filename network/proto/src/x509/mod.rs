use std::net::{SocketAddr, TcpListener};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const OPCODE_GET: u8 = 1;
const OPCODE_PARSE: u8 = 2;

#[derive(Debug, Clone)]
pub struct X509Name {
    pub rdns: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct X509Validity {
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone)]
pub struct X509Certificate {
    pub version: u8,
    pub serial: Vec<u8>,
    pub signature_algorithm: String,
    pub issuer: X509Name,
    pub subject: X509Name,
    pub validity: X509Validity,
    pub subject_public_key_algorithm: String,
    pub subject_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn parse_certificate(der: &[u8]) -> CoreResult<X509Certificate> {
    let mut reader = DerReader::new(der);
    let cert = reader.read_tag(0x30)?;
    let mut cert_reader = DerReader::new(&cert);
    let tbs = cert_reader.read_tag(0x30)?;
    let sig_alg = cert_reader.read_tag(0x30)?;
    let signature = cert_reader.read_tag(0x03)?;
    let signature = if signature.is_empty() { Vec::new() } else { signature[1..].to_vec() };
    let mut tbs_reader = DerReader::new(&tbs);
    let version = if tbs_reader.peek_tag() == Some(0xA0) {
        let version_bytes = tbs_reader.read_tag(0xA0)?;
        let mut vreader = DerReader::new(&version_bytes);
        let int = vreader.read_tag(0x02)?;
        int.last().copied().unwrap_or(0) as u8 + 1
    } else {
        1
    };
    let serial = tbs_reader.read_tag(0x02)?;
    let _sig = tbs_reader.read_tag(0x30)?;
    let issuer = parse_name(&tbs_reader.read_tag(0x30)?)?;
    let validity = parse_validity(&tbs_reader.read_tag(0x30)?)?;
    let subject = parse_name(&tbs_reader.read_tag(0x30)?)?;
    let spki = tbs_reader.read_tag(0x30)?;
    let (spki_alg, spki_key) = parse_spki(&spki)?;
    while tbs_reader.remaining() > 0 {
        let tag = tbs_reader.peek_tag().unwrap_or(0);
        let _ = tbs_reader.read_tag(tag)?;
    }
    let sig_oid = parse_algorithm_oid(&sig_alg)?;
    Ok(X509Certificate {
        version,
        serial,
        signature_algorithm: sig_oid,
        issuer,
        subject,
        validity,
        subject_public_key_algorithm: spki_alg,
        subject_public_key: spki_key,
        signature,
    })
}

fn parse_algorithm_oid(bytes: &[u8]) -> CoreResult<String> {
    let mut reader = DerReader::new(bytes);
    let oid = reader.read_tag(0x06)?;
    Ok(decode_oid(&oid))
}

fn parse_name(bytes: &[u8]) -> CoreResult<X509Name> {
    let mut reader = DerReader::new(bytes);
    let mut rdns = Vec::new();
    while reader.remaining() > 0 {
        let set = reader.read_tag(0x31)?;
        let mut set_reader = DerReader::new(&set);
        while set_reader.remaining() > 0 {
            let seq = set_reader.read_tag(0x30)?;
            let mut seq_reader = DerReader::new(&seq);
            let oid = seq_reader.read_tag(0x06)?;
            let value = seq_reader.read_any_string()?;
            rdns.push((decode_oid(&oid), value));
        }
    }
    Ok(X509Name { rdns })
}

fn parse_validity(bytes: &[u8]) -> CoreResult<X509Validity> {
    let mut reader = DerReader::new(bytes);
    let not_before = reader.read_time()?;
    let not_after = reader.read_time()?;
    Ok(X509Validity {
        not_before,
        not_after,
    })
}

fn parse_spki(bytes: &[u8]) -> CoreResult<(String, Vec<u8>)> {
    let mut reader = DerReader::new(bytes);
    let alg = reader.read_tag(0x30)?;
    let alg_oid = parse_algorithm_oid(&alg)?;
    let bitstring = reader.read_tag(0x03)?;
    let key = if bitstring.is_empty() { Vec::new() } else { bitstring[1..].to_vec() };
    Ok((alg_oid, key))
}

fn decode_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let first = bytes[0] / 40;
    let second = bytes[0] % 40;
    let mut parts = vec![first.to_string(), second.to_string()];
    let mut value = 0u32;
    for &b in &bytes[1..] {
        value = (value << 7) | (b & 0x7F) as u32;
        if b & 0x80 == 0 {
            parts.push(value.to_string());
            value = 0;
        }
    }
    parts.join(".")
}

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn read_tag(&mut self, expected: u8) -> CoreResult<Vec<u8>> {
        let tag = self.read_u8()?;
        if tag != expected {
            return Err(CoreError::Parse("unexpected der tag".to_string()));
        }
        let len = self.read_len()?;
        self.read_bytes(len)
    }

    fn read_any_string(&mut self) -> CoreResult<String> {
        let tag = self.read_u8()?;
        let len = self.read_len()?;
        let bytes = self.read_bytes(len)?;
        match tag {
            0x0C | 0x13 | 0x16 => Ok(String::from_utf8_lossy(&bytes).to_string()),
            _ => Err(CoreError::Parse("unsupported string type".to_string())),
        }
    }

    fn read_time(&mut self) -> CoreResult<String> {
        let tag = self.read_u8()?;
        let len = self.read_len()?;
        let bytes = self.read_bytes(len)?;
        match tag {
            0x17 | 0x18 => Ok(String::from_utf8_lossy(&bytes).to_string()),
            _ => Err(CoreError::Parse("invalid time type".to_string())),
        }
    }

    fn read_u8(&mut self) -> CoreResult<u8> {
        if self.pos >= self.data.len() {
            return Err(CoreError::Parse("der eof".to_string()));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_len(&mut self) -> CoreResult<usize> {
        let first = self.read_u8()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 {
            return Err(CoreError::Parse("invalid der length".to_string()));
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | (self.read_u8()? as usize);
        }
        Ok(len)
    }

    fn read_bytes(&mut self, len: usize) -> CoreResult<Vec<u8>> {
        if self.pos + len > self.data.len() {
            return Err(CoreError::Parse("der out of bounds".to_string()));
        }
        let out = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct X509ClientConfig {
    pub timeouts: Timeouts,
}

impl Default for X509ClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct X509Client {
    transport: TcpTransport,
}

impl X509Client {
    pub fn connect(addr: &NetAddr, config: X509ClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self { transport })
    }

    pub fn get_certificate(&mut self) -> CoreResult<Vec<u8>> {
        let request = encode_request(OPCODE_GET, &[]);
        self.transport.write_all(&request)?;
        decode_response(&read_response(&mut self.transport)?)
    }

    pub fn parse_remote(&mut self, der: &[u8]) -> CoreResult<String> {
        let request = encode_request(OPCODE_PARSE, der);
        self.transport.write_all(&request)?;
        let response = decode_response(&read_response(&mut self.transport)?)?;
        Ok(String::from_utf8_lossy(&response).to_string())
    }
}

pub struct AsyncX509Client {
    transport: AsyncTcpTransport,
}

impl AsyncX509Client {
    pub async fn connect(addr: &NetAddr, config: X509ClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self { transport })
    }

    pub async fn get_certificate(&mut self) -> CoreResult<Vec<u8>> {
        let request = encode_request(OPCODE_GET, &[]);
        self.transport.write_all(&request).await?;
        decode_response(&read_response_async(&mut self.transport).await?)
    }

    pub async fn parse_remote(&mut self, der: &[u8]) -> CoreResult<String> {
        let request = encode_request(OPCODE_PARSE, der);
        self.transport.write_all(&request).await?;
        let response = decode_response(&read_response_async(&mut self.transport).await?)?;
        Ok(String::from_utf8_lossy(&response).to_string())
    }
}

#[derive(Debug, Clone)]
pub struct X509ServerConfig {
    pub timeouts: Timeouts,
    pub certificate: Vec<u8>,
}

impl Default for X509ServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            certificate: Vec::new(),
        }
    }
}

pub struct X509Server {
    listener: TcpListener,
    config: X509ServerConfig,
}

impl X509Server {
    pub fn bind(addr: SocketAddr, config: X509ServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let cert = self.config.certificate.clone();
            let timeouts = self.config.timeouts;
            thread::spawn(move || {
                let mut transport = match TcpTransport::from_stream(stream, timeouts) {
                    Ok(transport) => transport,
                    Err(_) => return,
                };
                let _ = handle_connection(&mut transport, cert);
            });
        }
        Ok(())
    }
}

pub struct AsyncX509Server {
    listener: tokio::net::TcpListener,
    config: X509ServerConfig,
}

impl AsyncX509Server {
    pub async fn bind(addr: SocketAddr, config: X509ServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let cert = self.config.certificate.clone();
            tokio::spawn(async move {
                let mut transport = AsyncTcpTransport::from_stream(stream);
                let _ = handle_connection_async(&mut transport, cert).await;
            });
        }
    }
}

fn handle_connection(transport: &mut TcpTransport, cert: Vec<u8>) -> CoreResult<()> {
    loop {
        let payload = match read_response(transport) {
            Ok(payload) => payload,
            Err(_) => return Ok(()),
        };
        let (opcode, data) = decode_request(&payload)?;
        let reply = match opcode {
            OPCODE_GET => encode_response(0, &cert),
            OPCODE_PARSE => match parse_certificate(&data) {
                Ok(parsed) => {
                    let summary = format!(
                        "subject={} issuer={} serial={}",
                        format_name(&parsed.subject),
                        format_name(&parsed.issuer),
                        hex(&parsed.serial)
                    );
                    encode_response(0, summary.as_bytes())
                }
                Err(err) => encode_response(1, format!("{err:?}").as_bytes()),
            },
            _ => encode_response(1, b"unknown opcode"),
        };
        transport.write_all(&reply)?;
    }
}

async fn handle_connection_async(transport: &mut AsyncTcpTransport, cert: Vec<u8>) -> CoreResult<()> {
    loop {
        let payload = match read_response_async(transport).await {
            Ok(payload) => payload,
            Err(_) => return Ok(()),
        };
        let (opcode, data) = decode_request(&payload)?;
        let reply = match opcode {
            OPCODE_GET => encode_response(0, &cert),
            OPCODE_PARSE => match parse_certificate(&data) {
                Ok(parsed) => {
                    let summary = format!(
                        "subject={} issuer={} serial={}",
                        format_name(&parsed.subject),
                        format_name(&parsed.issuer),
                        hex(&parsed.serial)
                    );
                    encode_response(0, summary.as_bytes())
                }
                Err(err) => encode_response(1, format!("{err:?}").as_bytes()),
            },
            _ => encode_response(1, b"unknown opcode"),
        };
        transport.write_all(&reply).await?;
    }
}

fn encode_request(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(opcode);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_request(data: &[u8]) -> CoreResult<(u8, Vec<u8>)> {
    if data.len() < 5 {
        return Err(CoreError::Parse("x509 request too short".to_string()));
    }
    let opcode = data[0];
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if data.len() < 5 + len {
        return Err(CoreError::Parse("x509 request length mismatch".to_string()));
    }
    Ok((opcode, data[5..5 + len].to_vec()))
}

fn encode_response(status: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(status);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_response(data: &[u8]) -> CoreResult<Vec<u8>> {
    if data.len() < 5 {
        return Err(CoreError::Parse("x509 response too short".to_string()));
    }
    if data[0] != 0 {
        let msg = String::from_utf8_lossy(&data[5..]).to_string();
        return Err(CoreError::Message(msg));
    }
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if data.len() < 5 + len {
        return Err(CoreError::Parse("x509 response length mismatch".to_string()));
    }
    Ok(data[5..5 + len].to_vec())
}

fn read_response(transport: &mut TcpTransport) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 5];
    transport.read_exact(&mut header)?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload)?;
    let mut out = header.to_vec();
    out.extend_from_slice(&payload);
    Ok(out)
}

async fn read_response_async(transport: &mut AsyncTcpTransport) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 5];
    transport.read_exact(&mut header).await?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload).await?;
    let mut out = header.to_vec();
    out.extend_from_slice(&payload);
    Ok(out)
}

fn format_name(name: &X509Name) -> String {
    name.rdns
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",")
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 128 {
            out.push(content.len() as u8);
        } else {
            out.push(0x81);
            out.push(content.len() as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn der_seq(content: &[u8]) -> Vec<u8> {
        der_tag(0x30, content)
    }

    fn der_set(content: &[u8]) -> Vec<u8> {
        der_tag(0x31, content)
    }

    fn der_int(value: &[u8]) -> Vec<u8> {
        der_tag(0x02, value)
    }

    fn der_oid(oid: &[u8]) -> Vec<u8> {
        der_tag(0x06, oid)
    }

    fn der_null() -> Vec<u8> {
        vec![0x05, 0x00]
    }

    fn der_utf8(value: &str) -> Vec<u8> {
        der_tag(0x0C, value.as_bytes())
    }

    fn der_utctime(value: &str) -> Vec<u8> {
        der_tag(0x17, value.as_bytes())
    }

    fn build_test_cert() -> Vec<u8> {
        let version = der_tag(0xA0, &der_int(&[0x02]));
        let serial = der_int(&[0x01]);
        let sig_alg = der_seq(&[der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]), der_null()].concat());
        let name = der_seq(&[der_set(&der_seq(&[der_oid(&[0x55, 0x04, 0x03]), der_utf8("Test")].concat()))].concat());
        let validity = der_seq(&[der_utctime("240101000000Z"), der_utctime("250101000000Z")].concat());
        let spki = der_seq(
            &[der_seq(&[der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]), der_null()].concat()),
              der_tag(0x03, &[0x00, 0x01, 0x02, 0x03])].concat(),
        );
        let tbs = der_seq(&[version, serial, sig_alg.clone(), name.clone(), validity, name, spki].concat());
        let sig_val = der_tag(0x03, &[0x00, 0xAA, 0xBB, 0xCC]);
        der_seq(&[tbs, sig_alg, sig_val].concat())
    }

    #[test]
    fn parse_basic_cert() {
        let cert = build_test_cert();
        let parsed = parse_certificate(&cert).unwrap();
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.subject.rdns[0].1, "Test");
    }

    #[test]
    fn x509_server_client() {
        let cert = build_test_cert();
        let server = crate::skip_if_perm!(X509Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            X509ServerConfig {
                timeouts: Timeouts::default(),
                certificate: cert.clone(),
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });
        let mut client = X509Client::connect(&NetAddr::from_socket(addr), X509ClientConfig::default()).unwrap();
        let received = client.get_certificate().unwrap();
        assert_eq!(received, cert);
        let summary = client.parse_remote(&cert).unwrap();
        assert!(summary.contains("subject="));
    }
}
