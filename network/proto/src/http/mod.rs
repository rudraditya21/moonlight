use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{
    AsyncStreamTransport, AsyncTcpTransport, AsyncTlsClientTransport, StreamTransport, TcpTransport,
};
use crate::util::Timeouts;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }

    fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "HTTP/1.0" => Ok(Self::Http10),
            "HTTP/1.1" => Ok(Self::Http11),
            _ => Err(CoreError::Parse("unsupported http version".to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Connect,
    Other(String),
}

impl HttpMethod {
    fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Other(value) => value.as_str(),
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "PATCH" => Self::Patch,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            other => Self::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub version: HttpVersion,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            version: HttpVersion::Http11,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        set_header(&mut self.headers, name, value);
    }

    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        let mut headers = self.headers.clone();
        if !self.body.is_empty() && header_value(&headers, "content-length").is_none() {
            headers.push(("Content-Length".to_string(), self.body.len().to_string()));
        }
        if header_value(&headers, "host").is_none() {
            headers.push(("Host".to_string(), "localhost".to_string()));
        }
        let mut out = Vec::new();
        out.extend_from_slice(format!("{} {} {}\r\n", self.method.as_str(), self.path, self.version.as_str()).as_bytes());
        for (name, value) in headers {
            out.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status_code: u16) -> Self {
        Self {
            version: HttpVersion::Http11,
            status_code,
            reason: default_reason(status_code).to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        set_header(&mut self.headers, name, value);
    }

    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        let mut headers = self.headers.clone();
        if !self.body.is_empty() && header_value(&headers, "content-length").is_none() {
            headers.push(("Content-Length".to_string(), self.body.len().to_string()));
        }
        let mut out = Vec::new();
        out.extend_from_slice(format!("{} {} {}\r\n", self.version.as_str(), self.status_code, self.reason).as_bytes());
        for (name, value) in headers {
            out.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

fn default_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, v)) = headers.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
        *v = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

fn parse_headers(lines: &[&str]) -> CoreResult<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ':');
        let name = parts
            .next()
            .ok_or_else(|| CoreError::Parse("invalid header".to_string()))?
            .trim();
        let value = parts
            .next()
            .ok_or_else(|| CoreError::Parse("invalid header".to_string()))?
            .trim();
        headers.push((name.to_string(), value.to_string()));
    }
    Ok(headers)
}

fn read_until_delim<T: StreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    delim: &[u8],
    max_bytes: usize,
) -> CoreResult<Vec<u8>> {
    loop {
        if buffer.len() > max_bytes {
            return Err(CoreError::Parse("header exceeds maximum size".to_string()));
        }
        if let Some(pos) = buffer.windows(delim.len()).position(|w| w == delim) {
            let header = buffer[..pos].to_vec();
            let drain_len = pos + delim.len();
            buffer.drain(..drain_len);
            return Ok(header);
        }
        let mut chunk = [0u8; 2048];
        let read = transport.read(&mut chunk)?;
        if read == 0 {
            return Err(CoreError::Parse("unexpected eof".to_string()));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn read_exact_body<T: StreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    len: usize,
) -> CoreResult<Vec<u8>> {
    let mut body = Vec::with_capacity(len);
    let take = len.min(buffer.len());
    if take > 0 {
        body.extend_from_slice(&buffer[..take]);
        buffer.drain(..take);
    }
    while body.len() < len {
        let mut chunk = vec![0u8; (len - body.len()).min(4096)];
        let read = transport.read(&mut chunk)?;
        if read == 0 {
            return Err(CoreError::Parse("unexpected eof".to_string()));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

fn read_to_end<T: StreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    max_bytes: usize,
) -> CoreResult<Vec<u8>> {
    let mut body = Vec::new();
    if !buffer.is_empty() {
        body.extend_from_slice(buffer);
        buffer.clear();
    }
    while body.len() < max_bytes {
        let mut chunk = [0u8; 4096];
        let read = transport.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    if body.len() > max_bytes {
        return Err(CoreError::Parse("body exceeds maximum size".to_string()));
    }
    Ok(body)
}

fn read_line<T: StreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    max_bytes: usize,
) -> CoreResult<String> {
    let line = read_until_delim(transport, buffer, b"\r\n", max_bytes)?;
    String::from_utf8(line).map_err(|_| CoreError::Parse("invalid utf-8".to_string()))
}

fn read_chunked_body<T: StreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    max_bytes: usize,
) -> CoreResult<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line(transport, buffer, max_bytes)?;
        let size_str = line.split(';').next().unwrap_or(&line);
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| CoreError::Parse("invalid chunk size".to_string()))?;
        if size == 0 {
            let _ = read_line(transport, buffer, max_bytes)?;
            break;
        }
        let chunk = read_exact_body(transport, buffer, size)?;
        body.extend_from_slice(&chunk);
        let _ = read_line(transport, buffer, max_bytes)?;
        if body.len() > max_bytes {
            return Err(CoreError::Parse("body exceeds maximum size".to_string()));
        }
    }
    Ok(body)
}

fn parse_request(header_bytes: &[u8]) -> CoreResult<(HttpRequest, HashMap<String, String>)> {
    let text = String::from_utf8(header_bytes.to_vec())
        .map_err(|_| CoreError::Parse("invalid utf-8".to_string()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| CoreError::Parse("missing request line".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| CoreError::Parse("missing method".to_string()))?;
    let path = parts
        .next()
        .ok_or_else(|| CoreError::Parse("missing path".to_string()))?;
    let version = parts
        .next()
        .ok_or_else(|| CoreError::Parse("missing version".to_string()))?;
    let headers = parse_headers(&lines.collect::<Vec<_>>())?;
    let mut map = HashMap::new();
    for (name, value) in &headers {
        map.insert(name.to_ascii_lowercase(), value.clone());
    }
    Ok((
        HttpRequest {
            method: HttpMethod::parse(method),
            path: path.to_string(),
            version: HttpVersion::parse(version)?,
            headers,
            body: Vec::new(),
        },
        map,
    ))
}

fn parse_response(header_bytes: &[u8]) -> CoreResult<(HttpResponse, HashMap<String, String>)> {
    let text = String::from_utf8(header_bytes.to_vec())
        .map_err(|_| CoreError::Parse("invalid utf-8".to_string()))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| CoreError::Parse("missing status line".to_string()))?;
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| CoreError::Parse("missing version".to_string()))?;
    let code = parts
        .next()
        .ok_or_else(|| CoreError::Parse("missing status".to_string()))?;
    let reason = parts.collect::<Vec<_>>().join(" ");
    let headers = parse_headers(&lines.collect::<Vec<_>>())?;
    let mut map = HashMap::new();
    for (name, value) in &headers {
        map.insert(name.to_ascii_lowercase(), value.clone());
    }
    Ok((
        HttpResponse {
            version: HttpVersion::parse(version)?,
            status_code: code.parse().map_err(|_| CoreError::Parse("invalid status".to_string()))?,
            reason,
            headers,
            body: Vec::new(),
        },
        map,
    ))
}

fn should_have_body(status: u16) -> bool {
    !(status >= 100 && status < 200) && status != 204 && status != 304
}

pub struct HttpClient<T: StreamTransport> {
    transport: T,
    read_buf: Vec<u8>,
    max_body: usize,
}

impl HttpClient<TcpTransport> {
    pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, timeouts)?;
        Ok(Self::new(transport))
    }
}

impl HttpClient<crate::transport::TlsStreamTransport> {
    pub fn connect_tls(
        addr: &NetAddr,
        server_name: &str,
        config: &crate::transport::TlsClientConfig,
        timeouts: Timeouts,
    ) -> CoreResult<Self> {
        let transport = crate::transport::TlsStreamTransport::connect(addr, server_name, config, timeouts)?;
        Ok(Self::new(transport))
    }
}

impl<T: StreamTransport> HttpClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            read_buf: Vec::new(),
            max_body: DEFAULT_MAX_BODY,
        }
    }

    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub fn send(&mut self, request: &HttpRequest) -> CoreResult<HttpResponse> {
        let bytes = request.to_bytes()?;
        self.transport.write_all(&bytes)?;
        let header_bytes = read_until_delim(&mut self.transport, &mut self.read_buf, b"\r\n\r\n", MAX_HEADER_BYTES)?;
        let (mut response, header_map) = parse_response(&header_bytes)?;
        let mut body = Vec::new();
        if should_have_body(response.status_code) {
            if let Some(len) = header_map.get("content-length") {
                let len = len.parse::<usize>().map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
                body = read_exact_body(&mut self.transport, &mut self.read_buf, len)?;
            } else if let Some(te) = header_map.get("transfer-encoding") {
                if te.to_ascii_lowercase().contains("chunked") {
                    body = read_chunked_body(&mut self.transport, &mut self.read_buf, self.max_body)?;
                }
            } else if header_map
                .get("connection")
                .map(|v| v.eq_ignore_ascii_case("close"))
                .unwrap_or(false)
                || matches!(response.version, HttpVersion::Http10)
            {
                body = read_to_end(&mut self.transport, &mut self.read_buf, self.max_body)?;
            }
        }
        response.body = body;
        Ok(response)
    }
}

pub struct HttpServer {
    listener: TcpListener,
    timeouts: Timeouts,
    max_body: usize,
}

impl HttpServer {
    pub fn bind(addr: SocketAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            timeouts,
            max_body: DEFAULT_MAX_BODY,
        })
    }

    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static {
        let handler = Arc::new(handler);
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let timeouts = self.timeouts;
            let max_body = self.max_body;
            thread::spawn(move || {
                let _ = handle_connection(stream, timeouts, max_body, handler);
            });
        }
        Ok(())
    }
}

fn handle_connection(
    stream: TcpStream,
    timeouts: Timeouts,
    max_body: usize,
    handler: Arc<dyn Fn(HttpRequest) -> HttpResponse + Send + Sync>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, timeouts)?;
    let mut buffer = Vec::new();
    loop {
        let header_bytes = match read_until_delim(&mut transport, &mut buffer, b"\r\n\r\n", MAX_HEADER_BYTES) {
            Ok(bytes) => bytes,
            Err(err) => return Err(err),
        };
        let (mut request, header_map) = parse_request(&header_bytes)?;
        if let Some(len) = header_map.get("content-length") {
            let len = len.parse::<usize>().map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
            request.body = read_exact_body(&mut transport, &mut buffer, len)?;
        } else if let Some(te) = header_map.get("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                request.body = read_chunked_body(&mut transport, &mut buffer, max_body)?;
            }
        }
        let mut response = (handler)(request.clone());
        let connection = header_map.get("connection").map(|v| v.to_ascii_lowercase());
        let should_close = match request.version {
            HttpVersion::Http10 => connection.as_deref() != Some("keep-alive"),
            HttpVersion::Http11 => connection.as_deref() == Some("close"),
        };
        if should_close {
            response.set_header("Connection", "close");
        } else if matches!(request.version, HttpVersion::Http10) {
            response.set_header("Connection", "keep-alive");
        }
        let bytes = response.to_bytes()?;
        transport.write_all(&bytes)?;
        if should_close {
            break;
        }
    }
    Ok(())
}

pub struct AsyncHttpClient<T: AsyncStreamTransport> {
    transport: T,
    read_buf: Vec<u8>,
    max_body: usize,
}

impl AsyncHttpClient<AsyncTcpTransport> {
    pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, timeouts).await?;
        Ok(Self::new(transport))
    }
}

impl AsyncHttpClient<AsyncTlsClientTransport> {
    pub async fn connect_tls(
        addr: &NetAddr,
        server_name: &str,
        config: &crate::transport::TlsClientConfig,
        timeouts: Timeouts,
    ) -> CoreResult<Self> {
        let transport = AsyncTlsClientTransport::connect(addr, server_name, config, timeouts).await?;
        Ok(Self::new(transport))
    }
}

impl<T: AsyncStreamTransport> AsyncHttpClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            read_buf: Vec::new(),
            max_body: DEFAULT_MAX_BODY,
        }
    }

    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub async fn send(&mut self, request: &HttpRequest) -> CoreResult<HttpResponse> {
        let bytes = request.to_bytes()?;
        self.transport.write_all(&bytes).await?;
        let header_bytes = read_until_delim_async(&mut self.transport, &mut self.read_buf, b"\r\n\r\n", MAX_HEADER_BYTES).await?;
        let (mut response, header_map) = parse_response(&header_bytes)?;
        let mut body = Vec::new();
        if should_have_body(response.status_code) {
            if let Some(len) = header_map.get("content-length") {
                let len = len.parse::<usize>().map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
                body = read_exact_body_async(&mut self.transport, &mut self.read_buf, len).await?;
            } else if let Some(te) = header_map.get("transfer-encoding") {
                if te.to_ascii_lowercase().contains("chunked") {
                    body = read_chunked_body_async(&mut self.transport, &mut self.read_buf, self.max_body).await?;
                }
            } else if header_map
                .get("connection")
                .map(|v| v.eq_ignore_ascii_case("close"))
                .unwrap_or(false)
                || matches!(response.version, HttpVersion::Http10)
            {
                body = read_to_end_async(&mut self.transport, &mut self.read_buf, self.max_body).await?;
            }
        }
        response.body = body;
        Ok(response)
    }
}

pub struct AsyncHttpServer {
    listener: tokio::net::TcpListener,
    max_body: usize,
}

impl AsyncHttpServer {
    pub async fn bind(addr: SocketAddr) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            max_body: DEFAULT_MAX_BODY,
        })
    }

    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve<F>(&self, handler: F) -> CoreResult<()> where F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static {
        let handler = Arc::new(handler);
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let max_body = self.max_body;
            tokio::spawn(async move {
                let _ = handle_connection_async(stream, max_body, handler).await;
            });
        }
    }
}

async fn read_until_delim_async<T: AsyncStreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    delim: &[u8],
    max_bytes: usize,
) -> CoreResult<Vec<u8>> {
    loop {
        if buffer.len() > max_bytes {
            return Err(CoreError::Parse("header exceeds maximum size".to_string()));
        }
        if let Some(pos) = buffer.windows(delim.len()).position(|w| w == delim) {
            let header = buffer[..pos].to_vec();
            let drain_len = pos + delim.len();
            buffer.drain(..drain_len);
            return Ok(header);
        }
        let mut chunk = [0u8; 2048];
        let read = transport.read(&mut chunk).await?;
        if read == 0 {
            return Err(CoreError::Parse("unexpected eof".to_string()));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

async fn read_exact_body_async<T: AsyncStreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    len: usize,
) -> CoreResult<Vec<u8>> {
    let mut body = Vec::with_capacity(len);
    let take = len.min(buffer.len());
    if take > 0 {
        body.extend_from_slice(&buffer[..take]);
        buffer.drain(..take);
    }
    while body.len() < len {
        let mut chunk = vec![0u8; (len - body.len()).min(4096)];
        let read = transport.read(&mut chunk).await?;
        if read == 0 {
            return Err(CoreError::Parse("unexpected eof".to_string()));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

async fn read_to_end_async<T: AsyncStreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    max_bytes: usize,
) -> CoreResult<Vec<u8>> {
    let mut body = Vec::new();
    if !buffer.is_empty() {
        body.extend_from_slice(buffer);
        buffer.clear();
    }
    while body.len() < max_bytes {
        let mut chunk = [0u8; 4096];
        let read = transport.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    if body.len() > max_bytes {
        return Err(CoreError::Parse("body exceeds maximum size".to_string()));
    }
    Ok(body)
}

async fn read_line_async<T: AsyncStreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    max_bytes: usize,
) -> CoreResult<String> {
    let line = read_until_delim_async(transport, buffer, b"\r\n", max_bytes).await?;
    String::from_utf8(line).map_err(|_| CoreError::Parse("invalid utf-8".to_string()))
}

async fn read_chunked_body_async<T: AsyncStreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
    max_bytes: usize,
) -> CoreResult<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line_async(transport, buffer, max_bytes).await?;
        let size_str = line.split(';').next().unwrap_or(&line);
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| CoreError::Parse("invalid chunk size".to_string()))?;
        if size == 0 {
            let _ = read_line_async(transport, buffer, max_bytes).await?;
            break;
        }
        let chunk = read_exact_body_async(transport, buffer, size).await?;
        body.extend_from_slice(&chunk);
        let _ = read_line_async(transport, buffer, max_bytes).await?;
        if body.len() > max_bytes {
            return Err(CoreError::Parse("body exceeds maximum size".to_string()));
        }
    }
    Ok(body)
}

async fn handle_connection_async(
    stream: tokio::net::TcpStream,
    max_body: usize,
    handler: Arc<dyn Fn(HttpRequest) -> HttpResponse + Send + Sync>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut buffer = Vec::new();
    loop {
        let header_bytes = read_until_delim_async(&mut transport, &mut buffer, b"\r\n\r\n", MAX_HEADER_BYTES).await?;
        let (mut request, header_map) = parse_request(&header_bytes)?;
        if let Some(len) = header_map.get("content-length") {
            let len = len.parse::<usize>().map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
            request.body = read_exact_body_async(&mut transport, &mut buffer, len).await?;
        } else if let Some(te) = header_map.get("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                request.body = read_chunked_body_async(&mut transport, &mut buffer, max_body).await?;
            }
        }
        let mut response = (handler)(request.clone());
        let connection = header_map.get("connection").map(|v| v.to_ascii_lowercase());
        let should_close = match request.version {
            HttpVersion::Http10 => connection.as_deref() != Some("keep-alive"),
            HttpVersion::Http11 => connection.as_deref() == Some("close"),
        };
        if should_close {
            response.set_header("Connection", "close");
        } else if matches!(request.version, HttpVersion::Http10) {
            response.set_header("Connection", "keep-alive");
        }
        let bytes = response.to_bytes()?;
        transport.write_all(&bytes).await?;
        if should_close {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_roundtrip() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: moonlight\r\n\r\n";
        let (req, _) = parse_request(raw).expect("parse request");
        assert_eq!(req.path, "/index.html");
        let bytes = req.to_bytes().expect("encode");
        assert!(bytes.starts_with(b"GET /index.html HTTP/1.1"));
    }

    #[test]
    fn parse_response_roundtrip() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let (resp, _) = parse_response(raw).expect("parse response");
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn fuzz_requests_roundtrip() {
        let mut rng = XorShift64::new(0x5eed5eed);
        for _ in 0..128 {
            let method = match rng.next_u8() % 5 {
                0 => HttpMethod::Get,
                1 => HttpMethod::Post,
                2 => HttpMethod::Put,
                3 => HttpMethod::Delete,
                _ => HttpMethod::Other("CUSTOM".to_string()),
            };
            let extra = rng.next_u8() % 10;
            let path = format!("/{}", rng.next_string(5 + extra as usize));
            let mut req = HttpRequest::new(method, path);
            let body_len = (rng.next_u8() % 64) as usize;
            req.body = rng.next_bytes(body_len);
            req.set_header("Host", "example.com");
            if rng.next_u8() % 2 == 0 {
                req.set_header("User-Agent", "moonlight-test");
            }
            let bytes = req.to_bytes().expect("encode");
            let header_end = bytes
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("header end");
            let header = &bytes[..header_end];
            let (parsed, map) = parse_request(header).expect("parse");
            assert_eq!(parsed.path, req.path);
            assert_eq!(parsed.method.as_str(), req.method.as_str());
            if !req.body.is_empty() {
                let len = map.get("content-length").expect("content-length");
                assert_eq!(len.parse::<usize>().unwrap(), req.body.len());
            }
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

        fn next_u8(&mut self) -> u8 {
            (self.next_u64() & 0xff) as u8
        }

        fn next_bytes(&mut self, len: usize) -> Vec<u8> {
            let mut out = Vec::with_capacity(len);
            for _ in 0..len {
                out.push(self.next_u8());
            }
            out
        }

        fn next_string(&mut self, len: usize) -> String {
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                let c = (b'a' + (self.next_u8() % 26)) as char;
                s.push(c);
            }
            s
        }
    }
}
