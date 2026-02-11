use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const AJP_MAGIC: [u8; 2] = [0x12, 0x34];
const SERVER_TO_CONTAINER: u8 = 0x02;
const CLIENT_TO_SERVER_BODY: u8 = 0x03;
const SEND_BODY_CHUNK: u8 = 0x03;
const SEND_HEADERS: u8 = 0x04;
const END_RESPONSE: u8 = 0x05;
const GET_BODY_CHUNK: u8 = 0x06;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AjpMethod {
    Options = 1,
    Get = 2,
    Head = 3,
    Post = 4,
    Put = 5,
    Delete = 6,
    Trace = 7,
}

impl AjpMethod {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            1 => Ok(AjpMethod::Options),
            2 => Ok(AjpMethod::Get),
            3 => Ok(AjpMethod::Head),
            4 => Ok(AjpMethod::Post),
            5 => Ok(AjpMethod::Put),
            6 => Ok(AjpMethod::Delete),
            7 => Ok(AjpMethod::Trace),
            _ => Err(CoreError::Parse("invalid AJP method".to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AjpRequest {
    pub method: AjpMethod,
    pub protocol: String,
    pub uri: String,
    pub remote_addr: String,
    pub remote_host: String,
    pub server_name: String,
    pub server_port: u16,
    pub is_ssl: bool,
    pub headers: Vec<(String, String)>,
    pub attributes: Vec<(String, String)>,
}

impl AjpRequest {
    pub fn new(method: AjpMethod, uri: &str) -> Self {
        Self {
            method,
            protocol: "HTTP/1.1".to_string(),
            uri: uri.to_string(),
            remote_addr: "127.0.0.1".to_string(),
            remote_host: "localhost".to_string(),
            server_name: "localhost".to_string(),
            server_port: 80,
            is_ssl: false,
            headers: Vec::new(),
            attributes: Vec::new(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct AjpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl AjpResponse {
    pub fn new(status: u16, reason: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason: reason.to_string(),
            headers: Vec::new(),
            body,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AjpClientConfig {
    pub timeouts: Timeouts,
}

impl Default for AjpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct AjpClient {
    transport: TcpTransport,
}

impl AjpClient {
    pub fn connect(addr: &NetAddr, config: AjpClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self { transport })
    }

    pub fn request(&mut self, request: &AjpRequest, body: Option<&[u8]>) -> CoreResult<AjpResponse> {
        let packet = encode_forward_request(request)?;
        write_packet(&mut self.transport, &packet)?;
        if let Some(payload) = body {
            send_body(&mut self.transport, payload)?;
        }
        read_response(&mut self.transport)
    }
}

pub struct AsyncAjpClient {
    transport: AsyncTcpTransport,
}

impl AsyncAjpClient {
    pub async fn connect(addr: &NetAddr, config: AjpClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self { transport })
    }

    pub async fn request(&mut self, request: &AjpRequest, body: Option<&[u8]>) -> CoreResult<AjpResponse> {
        let packet = encode_forward_request(request)?;
        write_packet_async(&mut self.transport, &packet).await?;
        if let Some(payload) = body {
            send_body_async(&mut self.transport, payload).await?;
        }
        read_response_async(&mut self.transport).await
    }
}

#[derive(Debug, Clone)]
pub struct AjpServerConfig {
    pub timeouts: Timeouts,
    pub max_body_size: usize,
}

impl Default for AjpServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            max_body_size: 8 * 1024 * 1024,
        }
    }
}

pub trait AjpHandler: Send + Sync {
    fn handle(&self, request: AjpRequest, body: Vec<u8>) -> CoreResult<AjpResponse>;
}

#[derive(Debug)]
pub struct StaticAjpHandler {
    response: AjpResponse,
}

impl StaticAjpHandler {
    pub fn new(response: AjpResponse) -> Self {
        Self { response }
    }
}

impl AjpHandler for StaticAjpHandler {
    fn handle(&self, _request: AjpRequest, _body: Vec<u8>) -> CoreResult<AjpResponse> {
        Ok(self.response.clone())
    }
}

pub struct AjpServer {
    listener: TcpListener,
    config: AjpServerConfig,
    handler: Arc<dyn AjpHandler>,
}

impl AjpServer {
    pub fn bind(addr: SocketAddr, config: AjpServerConfig, handler: Arc<dyn AjpHandler>) -> CoreResult<Self> {
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
            let config = self.config.clone();
            let handler = Arc::clone(&self.handler);
            thread::spawn(move || {
                let _ = handle_connection(stream, config, handler);
            });
        }
        Ok(())
    }
}

pub struct AsyncAjpServer {
    listener: tokio::net::TcpListener,
    config: AjpServerConfig,
    handler: Arc<dyn AjpHandler>,
}

impl AsyncAjpServer {
    pub async fn bind(addr: SocketAddr, config: AjpServerConfig, handler: Arc<dyn AjpHandler>) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            handler,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                let _ = handle_connection_async(stream, config, handler).await;
            });
        }
    }
}

fn handle_connection(stream: TcpStream, config: AjpServerConfig, handler: Arc<dyn AjpHandler>) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let payload = match read_packet(&mut transport) {
            Ok(payload) => payload,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let (request, mut body) = decode_forward_request(&payload)?;
        if let Some(length) = request.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            body = read_body(&mut transport, length, config.max_body_size)?;
        }
        let response = handler.handle(request, body)?;
        write_response(&mut transport, response)?;
    }
}

async fn handle_connection_async(
    stream: tokio::net::TcpStream,
    config: AjpServerConfig,
    handler: Arc<dyn AjpHandler>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let payload = match read_packet_async(&mut transport).await {
            Ok(payload) => payload,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };
        let (request, mut body) = decode_forward_request(&payload)?;
        if let Some(length) = request.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            body = read_body_async(&mut transport, length, config.max_body_size).await?;
        }
        let response = handler.handle(request, body)?;
        write_response_async(&mut transport, response).await?;
    }
}

fn encode_forward_request(request: &AjpRequest) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    out.push(SERVER_TO_CONTAINER);
    out.push(request.method as u8);
    write_string(&mut out, &request.protocol);
    write_string(&mut out, &request.uri);
    write_string(&mut out, &request.remote_addr);
    write_string(&mut out, &request.remote_host);
    write_string(&mut out, &request.server_name);
    out.extend_from_slice(&request.server_port.to_be_bytes());
    out.push(if request.is_ssl { 1 } else { 0 });
    out.extend_from_slice(&(request.headers.len() as u16).to_be_bytes());
    for (name, value) in &request.headers {
        if let Some(code) = common_header_code(name) {
            out.extend_from_slice(&code.to_be_bytes());
        } else {
            write_string(&mut out, name);
        }
        write_string(&mut out, value);
    }
    for (name, value) in &request.attributes {
        out.push(0x0A);
        write_string(&mut out, name);
        write_string(&mut out, value);
    }
    out.push(0xFF);
    Ok(out)
}

fn decode_forward_request(payload: &[u8]) -> CoreResult<(AjpRequest, Vec<u8>)> {
    let mut cursor = Cursor::new(payload);
    let prefix = cursor.read_u8()?;
    if prefix != SERVER_TO_CONTAINER {
        return Err(CoreError::Parse("not a forward request".to_string()));
    }
    let method = AjpMethod::from_u8(cursor.read_u8()?)?;
    let protocol = read_string(&mut cursor)?;
    let uri = read_string(&mut cursor)?;
    let remote_addr = read_string(&mut cursor)?;
    let remote_host = read_string(&mut cursor)?;
    let server_name = read_string(&mut cursor)?;
    let server_port = cursor.read_u16()?;
    let is_ssl = cursor.read_u8()? != 0;
    let headers_count = cursor.read_u16()? as usize;
    let mut headers = Vec::with_capacity(headers_count);
    for _ in 0..headers_count {
        let name = if cursor.peek_u16()? & 0xA000 == 0xA000 {
            let code = cursor.read_u16()?;
            header_name_from_code(code).unwrap_or_else(|| format!("x-header-{:x}", code))
        } else {
            read_string(&mut cursor)?
        };
        let value = read_string(&mut cursor)?;
        headers.push((name, value));
    }
    let mut attributes = Vec::new();
    loop {
        let code = cursor.read_u8()?;
        if code == 0xFF {
            break;
        }
        if code == 0x0A {
            let name = read_string(&mut cursor)?;
            let value = read_string(&mut cursor)?;
            attributes.push((name, value));
        } else {
            return Err(CoreError::Parse("unsupported attribute".to_string()));
        }
    }
    let request = AjpRequest {
        method,
        protocol,
        uri,
        remote_addr,
        remote_host,
        server_name,
        server_port,
        is_ssl,
        headers,
        attributes,
    };
    Ok((request, Vec::new()))
}

fn write_response(transport: &mut TcpTransport, response: AjpResponse) -> CoreResult<()> {
    let headers_packet = encode_send_headers(&response)?;
    write_packet(transport, &headers_packet)?;
    if !response.body.is_empty() {
        for chunk in response.body.chunks(8186) {
            let packet = encode_send_body_chunk(chunk)?;
            write_packet(transport, &packet)?;
        }
    }
    let end = vec![END_RESPONSE, 1];
    write_packet(transport, &end)?;
    Ok(())
}

async fn write_response_async(transport: &mut AsyncTcpTransport, response: AjpResponse) -> CoreResult<()> {
    let headers_packet = encode_send_headers(&response)?;
    write_packet_async(transport, &headers_packet).await?;
    if !response.body.is_empty() {
        for chunk in response.body.chunks(8186) {
            let packet = encode_send_body_chunk(chunk)?;
            write_packet_async(transport, &packet).await?;
        }
    }
    let end = vec![END_RESPONSE, 1];
    write_packet_async(transport, &end).await?;
    Ok(())
}

fn read_response(transport: &mut TcpTransport) -> CoreResult<AjpResponse> {
    let mut status = 200;
    let mut reason = "OK".to_string();
    let mut headers = Vec::new();
    let mut body = Vec::new();
    loop {
        let payload = read_packet(transport)?;
        match payload.first().copied().unwrap_or(0) {
            SEND_HEADERS => {
                let resp = decode_send_headers(&payload)?;
                status = resp.0;
                reason = resp.1;
                headers = resp.2;
            }
            SEND_BODY_CHUNK => {
                let chunk = decode_send_body_chunk(&payload)?;
                body.extend_from_slice(&chunk);
            }
            END_RESPONSE => break,
            GET_BODY_CHUNK => continue,
            _ => {}
        }
    }
    Ok(AjpResponse {
        status,
        reason,
        headers,
        body,
    })
}

async fn read_response_async(transport: &mut AsyncTcpTransport) -> CoreResult<AjpResponse> {
    let mut status = 200;
    let mut reason = "OK".to_string();
    let mut headers = Vec::new();
    let mut body = Vec::new();
    loop {
        let payload = read_packet_async(transport).await?;
        match payload.first().copied().unwrap_or(0) {
            SEND_HEADERS => {
                let resp = decode_send_headers(&payload)?;
                status = resp.0;
                reason = resp.1;
                headers = resp.2;
            }
            SEND_BODY_CHUNK => {
                let chunk = decode_send_body_chunk(&payload)?;
                body.extend_from_slice(&chunk);
            }
            END_RESPONSE => break,
            GET_BODY_CHUNK => continue,
            _ => {}
        }
    }
    Ok(AjpResponse {
        status,
        reason,
        headers,
        body,
    })
}

fn send_body(transport: &mut TcpTransport, body: &[u8]) -> CoreResult<()> {
    let mut offset = 0usize;
    while offset < body.len() {
        let end = (offset + 8186).min(body.len());
        let chunk = &body[offset..end];
        let mut payload = Vec::new();
        payload.push(CLIENT_TO_SERVER_BODY);
        payload.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        payload.extend_from_slice(chunk);
        payload.push(0);
        write_packet(transport, &payload)?;
        offset = end;
        let _ = read_packet(transport)?;
    }
    let mut last = Vec::new();
    last.push(CLIENT_TO_SERVER_BODY);
    last.extend_from_slice(&0u16.to_be_bytes());
    last.push(0);
    write_packet(transport, &last)?;
    Ok(())
}

async fn send_body_async(transport: &mut AsyncTcpTransport, body: &[u8]) -> CoreResult<()> {
    let mut offset = 0usize;
    while offset < body.len() {
        let end = (offset + 8186).min(body.len());
        let chunk = &body[offset..end];
        let mut payload = Vec::new();
        payload.push(CLIENT_TO_SERVER_BODY);
        payload.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        payload.extend_from_slice(chunk);
        payload.push(0);
        write_packet_async(transport, &payload).await?;
        offset = end;
        let _ = read_packet_async(transport).await?;
    }
    let mut last = Vec::new();
    last.push(CLIENT_TO_SERVER_BODY);
    last.extend_from_slice(&0u16.to_be_bytes());
    last.push(0);
    write_packet_async(transport, &last).await?;
    Ok(())
}

fn read_body(transport: &mut TcpTransport, length: usize, max: usize) -> CoreResult<Vec<u8>> {
    let mut body = Vec::with_capacity(length);
    let mut remaining = length;
    while remaining > 0 {
        let request = vec![
            GET_BODY_CHUNK,
            (remaining.min(8186) as u16).to_be_bytes()[0],
            (remaining.min(8186) as u16).to_be_bytes()[1],
        ];
        write_packet(transport, &request)?;
        let payload = read_packet(transport)?;
        if payload.first().copied().unwrap_or(0) != CLIENT_TO_SERVER_BODY {
            return Err(CoreError::Parse("expected body chunk".to_string()));
        }
        let chunk_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
        if chunk_len == 0 {
            break;
        }
        if body.len() + chunk_len > max {
            return Err(CoreError::Message("body too large".to_string()));
        }
        body.extend_from_slice(&payload[3..3 + chunk_len]);
        remaining = remaining.saturating_sub(chunk_len);
    }
    Ok(body)
}

async fn read_body_async(
    transport: &mut AsyncTcpTransport,
    length: usize,
    max: usize,
) -> CoreResult<Vec<u8>> {
    let mut body = Vec::with_capacity(length);
    let mut remaining = length;
    while remaining > 0 {
        let request_len = remaining.min(8186) as u16;
        let request = vec![GET_BODY_CHUNK, request_len.to_be_bytes()[0], request_len.to_be_bytes()[1]];
        write_packet_async(transport, &request).await?;
        let payload = read_packet_async(transport).await?;
        if payload.first().copied().unwrap_or(0) != CLIENT_TO_SERVER_BODY {
            return Err(CoreError::Parse("expected body chunk".to_string()));
        }
        let chunk_len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
        if chunk_len == 0 {
            break;
        }
        if body.len() + chunk_len > max {
            return Err(CoreError::Message("body too large".to_string()));
        }
        body.extend_from_slice(&payload[3..3 + chunk_len]);
        remaining = remaining.saturating_sub(chunk_len);
    }
    Ok(body)
}

fn encode_send_headers(response: &AjpResponse) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    out.push(SEND_HEADERS);
    out.extend_from_slice(&response.status.to_be_bytes());
    write_string(&mut out, &response.reason);
    out.extend_from_slice(&(response.headers.len() as u16).to_be_bytes());
    for (name, value) in &response.headers {
        if let Some(code) = common_header_code(name) {
            out.extend_from_slice(&code.to_be_bytes());
        } else {
            write_string(&mut out, name);
        }
        write_string(&mut out, value);
    }
    Ok(out)
}

fn decode_send_headers(payload: &[u8]) -> CoreResult<(u16, String, Vec<(String, String)>)> {
    let mut cursor = Cursor::new(payload);
    let prefix = cursor.read_u8()?;
    if prefix != SEND_HEADERS {
        return Err(CoreError::Parse("not send headers".to_string()));
    }
    let status = cursor.read_u16()?;
    let reason = read_string(&mut cursor)?;
    let count = cursor.read_u16()? as usize;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        let name = if cursor.peek_u16()? & 0xA000 == 0xA000 {
            let code = cursor.read_u16()?;
            header_name_from_code(code).unwrap_or_else(|| format!("x-header-{:x}", code))
        } else {
            read_string(&mut cursor)?
        };
        let value = read_string(&mut cursor)?;
        headers.push((name, value));
    }
    Ok((status, reason, headers))
}

fn encode_send_body_chunk(body: &[u8]) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    out.push(SEND_BODY_CHUNK);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out.push(0);
    Ok(out)
}

fn decode_send_body_chunk(payload: &[u8]) -> CoreResult<Vec<u8>> {
    if payload.len() < 4 || payload[0] != SEND_BODY_CHUNK {
        return Err(CoreError::Parse("invalid body chunk".to_string()));
    }
    let len = u16::from_be_bytes([payload[1], payload[2]]) as usize;
    if payload.len() < 3 + len {
        return Err(CoreError::Parse("body chunk too short".to_string()));
    }
    Ok(payload[3..3 + len].to_vec())
}

fn write_packet(transport: &mut TcpTransport, payload: &[u8]) -> CoreResult<()> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&AJP_MAGIC);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    transport.write_all(&out)
}

async fn write_packet_async(transport: &mut AsyncTcpTransport, payload: &[u8]) -> CoreResult<()> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&AJP_MAGIC);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    transport.write_all(&out).await
}

fn read_packet(transport: &mut TcpTransport) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header)?;
    if header[0..2] != AJP_MAGIC {
        return Err(CoreError::Parse("invalid ajp header".to_string()));
    }
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload)?;
    Ok(payload)
}

async fn read_packet_async(transport: &mut AsyncTcpTransport) -> CoreResult<Vec<u8>> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header).await?;
    if header[0..2] != AJP_MAGIC {
        return Err(CoreError::Parse("invalid ajp header".to_string()));
    }
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload).await?;
    Ok(payload)
}

fn common_header_code(name: &str) -> Option<u16> {
    match name.to_ascii_lowercase().as_str() {
        "accept" => Some(0xA001),
        "accept-charset" => Some(0xA002),
        "accept-encoding" => Some(0xA003),
        "accept-language" => Some(0xA004),
        "authorization" => Some(0xA005),
        "connection" => Some(0xA006),
        "content-type" => Some(0xA007),
        "content-length" => Some(0xA008),
        "cookie" => Some(0xA009),
        "cookie2" => Some(0xA00A),
        "host" => Some(0xA00B),
        "pragma" => Some(0xA00C),
        "referer" => Some(0xA00D),
        "user-agent" => Some(0xA00E),
        _ => None,
    }
}

fn header_name_from_code(code: u16) -> Option<String> {
    let name = match code {
        0xA001 => "accept",
        0xA002 => "accept-charset",
        0xA003 => "accept-encoding",
        0xA004 => "accept-language",
        0xA005 => "authorization",
        0xA006 => "connection",
        0xA007 => "content-type",
        0xA008 => "content-length",
        0xA009 => "cookie",
        0xA00A => "cookie2",
        0xA00B => "host",
        0xA00C => "pragma",
        0xA00D => "referer",
        0xA00E => "user-agent",
        _ => return None,
    };
    Some(name.to_string())
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    if value.is_empty() {
        out.extend_from_slice(&0xFFFFu16.to_be_bytes());
        return;
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

fn read_string(cursor: &mut Cursor) -> CoreResult<String> {
    let len = cursor.read_u16()?;
    if len == 0xFFFF {
        return Ok(String::new());
    }
    let bytes = cursor.read_bytes(len as usize)?;
    let _ = cursor.read_u8()?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> CoreResult<u8> {
        if self.pos + 1 > self.buf.len() {
            return Err(CoreError::Parse("cursor eof".to_string()));
        }
        let out = self.buf[self.pos];
        self.pos += 1;
        Ok(out)
    }

    fn read_u16(&mut self) -> CoreResult<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_bytes(&mut self, len: usize) -> CoreResult<Vec<u8>> {
        if self.pos + len > self.buf.len() {
            return Err(CoreError::Parse("cursor eof".to_string()));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    fn peek_u16(&self) -> CoreResult<u16> {
        if self.pos + 2 > self.buf.len() {
            return Err(CoreError::Parse("cursor eof".to_string()));
        }
        Ok(u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::fuzz_bytes;

    #[test]
    fn ajp_roundtrip() {
        let handler = Arc::new(StaticAjpHandler::new(AjpResponse::new(200, "OK", b"hello".to_vec())));
        let server = crate::skip_if_perm!(AjpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            AjpServerConfig::default(),
            handler,
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = AjpClient::connect(&NetAddr::from_socket(addr), AjpClientConfig::default()).unwrap();
        let request = AjpRequest::new(AjpMethod::Get, "/");
        let response = client.request(&request, None).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello".to_vec());
    }

    #[test]
    fn ajp_decode_negative() {
        assert!(decode_forward_request(&[]).is_err());
        assert!(decode_send_headers(&[]).is_err());
        assert!(decode_send_body_chunk(&[]).is_err());
    }

    #[test]
    fn ajp_decode_fuzz() {
        fuzz_bytes(128, 512, 0xA1A2, |data| {
            let _ = decode_forward_request(data);
            let _ = decode_send_headers(data);
            let _ = decode_send_body_chunk(data);
        });
    }
}
