pub mod auth;

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use bytes::Bytes;
use corelib::error::{CoreError, CoreResult};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::{Request as HyperRequest, Response as HyperResponse};
use hyper_util::rt::TokioIo;
use http::{HeaderName, HeaderValue, Method, StatusCode, Version};
use httparse::{Header as HttpHeader, Request as HttpParseRequest, Response as HttpParseResponse};
use net::NetAddr;

use crate::transport::{
    AsyncStreamTransport, AsyncTcpTransport, AsyncTlsClientTransport, StreamTransport,
    TcpTransport, TlsClientConfig,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpTarget {
    Origin(String),
    Absolute {
        scheme: String,
        host: String,
        port: u16,
        path: String,
    },
    Authority {
        host: String,
        port: u16,
    },
    Asterisk,
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

    pub fn target(&self) -> CoreResult<HttpTarget> {
        if self.path == "*" {
            return Ok(HttpTarget::Asterisk);
        }
        if matches!(self.method, HttpMethod::Connect) {
            let (host, port) = parse_authority(&self.path)?;
            return Ok(HttpTarget::Authority { host, port });
        }
        if let Some(rest) = self.path.strip_prefix("http://") {
            let (host, port, path) = parse_absolute(rest, 80)?;
            return Ok(HttpTarget::Absolute {
                scheme: "http".to_string(),
                host,
                port,
                path,
            });
        }
        if let Some(rest) = self.path.strip_prefix("https://") {
            let (host, port, path) = parse_absolute(rest, 443)?;
            return Ok(HttpTarget::Absolute {
                scheme: "https".to_string(),
                host,
                port,
                path,
            });
        }
        Ok(HttpTarget::Origin(self.path.clone()))
    }

    pub fn set_absolute_uri(&mut self, scheme: &str, host: &str, port: u16, path: &str) {
        let default = if scheme == "https" { 443 } else { 80 };
        if port == default {
            self.path = format!("{}://{}{}", scheme, host, path);
        } else {
            self.path = format!("{}://{}:{}{}", scheme, host, port, path);
        }
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
        out.extend_from_slice(
            format!(
                "{} {} {}\r\n",
                self.method.as_str(),
                self.path,
                self.version.as_str()
            )
            .as_bytes(),
        );
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
        out.extend_from_slice(
            format!(
                "{} {} {}\r\n",
                self.version.as_str(),
                self.status_code,
                self.reason
            )
            .as_bytes(),
        );
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
    if let Some((_, v)) = headers
        .iter_mut()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
    {
        *v = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

fn parse_headers(headers: &[HttpHeader<'_>]) -> CoreResult<Vec<(String, String)>> {
    let mut parsed_headers = Vec::with_capacity(headers.len());
    for header in headers {
        let parsed_name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| CoreError::Parse("invalid header name".to_string()))?;
        let parsed_value = HeaderValue::from_bytes(header.value)
            .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
        let normalized_value = parsed_value
            .to_str()
            .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
        parsed_headers.push((
            parsed_name.as_str().to_string(),
            normalized_value.to_string(),
        ));
    }
    Ok(parsed_headers)
}

fn parse_method(method: &str) -> CoreResult<HttpMethod> {
    let parsed = Method::from_bytes(method.as_bytes())
        .map_err(|_| CoreError::Parse("invalid method".to_string()))?;
    Ok(match parsed {
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        Method::PUT => HttpMethod::Put,
        Method::DELETE => HttpMethod::Delete,
        Method::HEAD => HttpMethod::Head,
        Method::OPTIONS => HttpMethod::Options,
        Method::PATCH => HttpMethod::Patch,
        Method::TRACE => HttpMethod::Trace,
        Method::CONNECT => HttpMethod::Connect,
        _ => HttpMethod::Other(parsed.as_str().to_string()),
    })
}

fn parse_version(version: u8) -> CoreResult<HttpVersion> {
    let parsed = match version {
        0 => Version::HTTP_10,
        1 => Version::HTTP_11,
        _ => return Err(CoreError::Parse("unsupported http version".to_string())),
    };
    Ok(match parsed {
        Version::HTTP_10 => HttpVersion::Http10,
        Version::HTTP_11 => HttpVersion::Http11,
        _ => return Err(CoreError::Parse("unsupported http version".to_string())),
    })
}

fn parse_authority(value: &str) -> CoreResult<(String, u16)> {
    if value.starts_with('[') {
        let end = value
            .find(']')
            .ok_or_else(|| CoreError::Parse("invalid ipv6 authority".to_string()))?;
        let host = value[1..end].to_string();
        let port = value
            .get(end + 1..)
            .and_then(|s| s.strip_prefix(':'))
            .ok_or_else(|| CoreError::Parse("missing port".to_string()))?
            .parse::<u16>()
            .map_err(|_| CoreError::Parse("invalid port".to_string()))?;
        return Ok((host, port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| CoreError::Parse("invalid port".to_string()))?;
        return Ok((host.to_string(), port));
    }
    Err(CoreError::Parse("missing port".to_string()))
}

fn parse_absolute(rest: &str, default_port: u16) -> CoreResult<(String, u16, String)> {
    let (host_port, path) = if let Some((host, path)) = rest.split_once('/') {
        (host, format!("/{}", path))
    } else {
        (rest, "/".to_string())
    };
    if host_port.starts_with('[') {
        let end = host_port
            .find(']')
            .ok_or_else(|| CoreError::Parse("invalid ipv6 host".to_string()))?;
        let host = host_port[1..end].to_string();
        let port = host_port
            .get(end + 1..)
            .and_then(|s| s.strip_prefix(':'))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok((host, port, path));
    }
    if let Some((host, port)) = host_port.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok((host.to_string(), port, path));
        }
    }
    Ok((host_port.to_string(), default_port, path))
}

fn parse_host_header(value: &str, default_port: u16) -> CoreResult<(String, u16)> {
    if value.starts_with('[') {
        let end = value
            .find(']')
            .ok_or_else(|| CoreError::Parse("invalid ipv6 host".to_string()))?;
        let host = value[1..end].to_string();
        let port = value
            .get(end + 1..)
            .and_then(|s| s.strip_prefix(':'))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok((host, port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok((host.to_string(), port));
        }
    }
    Ok((value.to_string(), default_port))
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
    let mut raw = header_bytes.to_vec();
    if !raw.ends_with(b"\r\n\r\n") {
        raw.extend_from_slice(b"\r\n\r\n");
    }

    let mut header_slots = [httparse::EMPTY_HEADER; 128];
    let mut req = HttpParseRequest::new(&mut header_slots);
    match req
        .parse(&raw)
        .map_err(|_| CoreError::Parse("invalid request".to_string()))?
    {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(CoreError::Parse("partial request".to_string())),
    }
    let method = req
        .method
        .ok_or_else(|| CoreError::Parse("missing method".to_string()))?;
    let path = req
        .path
        .ok_or_else(|| CoreError::Parse("missing path".to_string()))?;
    let version = req
        .version
        .ok_or_else(|| CoreError::Parse("missing version".to_string()))?;
    let headers = parse_headers(req.headers)?;
    let mut map = HashMap::new();
    for (name, value) in &headers {
        map.insert(name.to_ascii_lowercase(), value.clone());
    }
    Ok((
        HttpRequest {
            method: parse_method(method)?,
            path: path.to_string(),
            version: parse_version(version)?,
            headers,
            body: Vec::new(),
        },
        map,
    ))
}

fn parse_response(header_bytes: &[u8]) -> CoreResult<(HttpResponse, HashMap<String, String>)> {
    let mut raw = header_bytes.to_vec();
    if !raw.ends_with(b"\r\n\r\n") {
        raw.extend_from_slice(b"\r\n\r\n");
    }

    let mut header_slots = [httparse::EMPTY_HEADER; 128];
    let mut response = HttpParseResponse::new(&mut header_slots);
    match response
        .parse(&raw)
        .map_err(|_| CoreError::Parse("invalid response".to_string()))?
    {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(CoreError::Parse("partial response".to_string())),
    }
    let version = response
        .version
        .ok_or_else(|| CoreError::Parse("missing version".to_string()))?;
    let status_code = response
        .code
        .ok_or_else(|| CoreError::Parse("missing status".to_string()))?;
    let reason = response.reason.unwrap_or("").to_string();
    let headers = parse_headers(response.headers)?;
    let mut map = HashMap::new();
    for (name, value) in &headers {
        map.insert(name.to_ascii_lowercase(), value.clone());
    }
    StatusCode::from_u16(status_code)
        .map_err(|_| CoreError::Parse("invalid status".to_string()))?;
    Ok((
        HttpResponse {
            version: parse_version(version)?,
            status_code,
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
        let transport =
            crate::transport::TlsStreamTransport::connect(addr, server_name, config, timeouts)?;
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
        let header_bytes = read_until_delim(
            &mut self.transport,
            &mut self.read_buf,
            b"\r\n\r\n",
            MAX_HEADER_BYTES,
        )?;
        let (mut response, header_map) = parse_response(&header_bytes)?;
        let mut body = Vec::new();
        if should_have_body(response.status_code) {
            if let Some(len) = header_map.get("content-length") {
                let len = len
                    .parse::<usize>()
                    .map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
                body = read_exact_body(&mut self.transport, &mut self.read_buf, len)?;
            } else if let Some(te) = header_map.get("transfer-encoding") {
                if te.to_ascii_lowercase().contains("chunked") {
                    body =
                        read_chunked_body(&mut self.transport, &mut self.read_buf, self.max_body)?;
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

    pub fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
    {
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

pub struct ProxyConnect {
    pub host: String,
    pub port: u16,
    pub stream: TcpStream,
    pub buffered: Vec<u8>,
}

pub struct ProxyServer {
    listener: TcpListener,
    timeouts: Timeouts,
    max_body: usize,
}

pub struct AsyncProxyConnect {
    pub host: String,
    pub port: u16,
    pub stream: tokio::net::TcpStream,
    pub buffered: Vec<u8>,
}

pub struct AsyncProxyServer {
    listener: tokio::net::TcpListener,
    max_body: usize,
}

impl AsyncProxyServer {
    pub async fn bind(addr: SocketAddr) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
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

    pub async fn serve<F, C>(&self, handler: F, connect_handler: C) -> CoreResult<()>
    where
        F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
        C: Fn(AsyncProxyConnect) -> CoreResult<()> + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let connect_handler = Arc::new(connect_handler);
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let connect_handler = Arc::clone(&connect_handler);
            let max_body = self.max_body;
            tokio::spawn(async move {
                let _ =
                    handle_proxy_connection_async(stream, max_body, handler, connect_handler).await;
            });
        }
    }
}

impl ProxyServer {
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

    pub fn serve<F, C>(&self, handler: F, connect_handler: C) -> CoreResult<()>
    where
        F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
        C: Fn(ProxyConnect) -> CoreResult<()> + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let connect_handler = Arc::new(connect_handler);
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let connect_handler = Arc::clone(&connect_handler);
            let timeouts = self.timeouts;
            let max_body = self.max_body;
            thread::spawn(move || {
                let _ =
                    handle_proxy_connection(stream, timeouts, max_body, handler, connect_handler);
            });
        }
        Ok(())
    }

    pub fn serve_forward(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let timeouts = self.timeouts;
            let max_body = self.max_body;
            thread::spawn(move || {
                let _ = handle_proxy_forward_connection(stream, timeouts, max_body);
            });
        }
        Ok(())
    }
}

pub fn proxy_forward(request: &HttpRequest, timeouts: Timeouts) -> CoreResult<HttpResponse> {
    let target = resolve_forward_target(request)?;
    let mut outbound = request.clone();
    outbound.path = target.path.clone();
    set_header(&mut outbound.headers, "Host", &target.host_header);
    remove_header(&mut outbound.headers, "Proxy-Connection");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| CoreError::Message(err.to_string()))?;
    runtime.block_on(send_with_hyper_http11_async(
        &outbound,
        &target,
        timeouts,
        DEFAULT_MAX_BODY,
    ))
}

pub async fn proxy_forward_async(
    request: &HttpRequest,
    timeouts: Timeouts,
) -> CoreResult<HttpResponse> {
    let target = resolve_forward_target(request)?;
    let mut outbound = request.clone();
    outbound.path = target.path.clone();
    set_header(&mut outbound.headers, "Host", &target.host_header);
    remove_header(&mut outbound.headers, "Proxy-Connection");
    send_with_hyper_http11_async(&outbound, &target, timeouts, DEFAULT_MAX_BODY).await
}

struct ForwardTarget {
    scheme: String,
    host: String,
    host_header: String,
    port: u16,
    path: String,
}

fn http_request_to_hyper(request: &HttpRequest) -> CoreResult<HyperRequest<Full<Bytes>>> {
    let method = Method::from_bytes(request.method.as_str().as_bytes())
        .map_err(|_| CoreError::Parse("invalid method".to_string()))?;
    let uri: http::Uri = request
        .path
        .parse()
        .map_err(|_| CoreError::Parse("invalid uri".to_string()))?;
    let mut builder = HyperRequest::builder().method(method).uri(uri);
    for (name, value) in &request.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| CoreError::Parse("invalid header name".to_string()))?;
        let value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(request.body.clone())))
        .map_err(|_| CoreError::Parse("invalid request".to_string()))
}

fn hyper_response_to_http(mut response: HyperResponse<Bytes>) -> CoreResult<HttpResponse> {
    let version = match response.version() {
        Version::HTTP_10 => HttpVersion::Http10,
        Version::HTTP_11 => HttpVersion::Http11,
        _ => HttpVersion::Http11,
    };
    let status = response.status().as_u16();
    let mut headers = Vec::with_capacity(response.headers().len());
    for (name, value) in response.headers() {
        let value = value
            .to_str()
            .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
        headers.push((name.as_str().to_string(), value.to_string()));
    }
    Ok(HttpResponse {
        version,
        status_code: status,
        reason: default_reason(status).to_string(),
        headers,
        body: response.body_mut().split_off(0).to_vec(),
    })
}

async fn hyper_send_over_io<S>(
    io: S,
    request: &HttpRequest,
    timeouts: Timeouts,
    max_body: usize,
) -> CoreResult<HttpResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(|err| CoreError::Message(err.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http_request_to_hyper(request)?;
    let response = tokio::time::timeout(timeouts.read, sender.send_request(request))
        .await
        .map_err(|_| CoreError::Parse("http request timeout".to_string()))?
        .map_err(|err| CoreError::Message(err.to_string()))?;
    let (parts, body) = response.into_parts();
    let body = tokio::time::timeout(timeouts.read, body.collect())
        .await
        .map_err(|_| CoreError::Parse("http response timeout".to_string()))?
        .map_err(|err| CoreError::Message(err.to_string()))?
        .to_bytes();
    if body.len() > max_body {
        return Err(CoreError::Parse("body exceeds maximum size".to_string()));
    }
    hyper_response_to_http(HyperResponse::from_parts(parts, body))
}

async fn send_with_hyper_http11_async(
    request: &HttpRequest,
    target: &ForwardTarget,
    timeouts: Timeouts,
    max_body: usize,
) -> CoreResult<HttpResponse> {
    let socket = NetAddr::new(&target.host, target.port)
        .resolve()?
        .into_iter()
        .next()
        .ok_or_else(|| CoreError::Parse("unable to resolve".to_string()))?;
    let tcp = tokio::time::timeout(timeouts.connect, tokio::net::TcpStream::connect(socket))
        .await
        .map_err(|_| CoreError::Parse("connect timeout".to_string()))?
        .map_err(CoreError::Io)?;
    tcp.set_nodelay(true).map_err(CoreError::Io)?;

    if target.scheme == "https" {
        let tls = TlsClientConfig::with_webpki_roots()?.with_alpn(&[b"http/1.1"]);
        let server_name = rustls::pki_types::ServerName::try_from(target.host.as_str())
            .map_err(|_| CoreError::Parse("invalid server name".to_string()))?
            .to_owned();
        let connector = tokio_rustls::TlsConnector::from(tls.inner());
        let stream = tokio::time::timeout(timeouts.connect, connector.connect(server_name, tcp))
            .await
            .map_err(|_| CoreError::Parse("tls handshake timeout".to_string()))?
            .map_err(|err| CoreError::Message(err.to_string()))?;
        return hyper_send_over_io(stream, request, timeouts, max_body).await;
    }

    hyper_send_over_io(tcp, request, timeouts, max_body).await
}

fn resolve_forward_target(request: &HttpRequest) -> CoreResult<ForwardTarget> {
    match request.target()? {
        HttpTarget::Absolute {
            scheme,
            host,
            port,
            path,
        } => {
            let host_header =
                if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
                    host.clone()
                } else {
                    format!("{}:{}", host, port)
                };
            Ok(ForwardTarget {
                scheme,
                host,
                host_header,
                port,
                path,
            })
        }
        HttpTarget::Origin(path) => {
            let host = header_value(&request.headers, "host")
                .ok_or_else(|| CoreError::Parse("missing host header".to_string()))?;
            let (host, port) = parse_host_header(host, 80)?;
            let host_header = if port == 80 {
                host.clone()
            } else {
                format!("{}:{}", host, port)
            };
            Ok(ForwardTarget {
                scheme: "http".to_string(),
                host,
                host_header,
                port,
                path,
            })
        }
        HttpTarget::Authority { .. } | HttpTarget::Asterisk => {
            Err(CoreError::Parse("unsupported proxy target".to_string()))
        }
    }
}

fn remove_header(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
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
        let header_bytes =
            match read_until_delim(&mut transport, &mut buffer, b"\r\n\r\n", MAX_HEADER_BYTES) {
                Ok(bytes) => bytes,
                Err(err) => return Err(err),
            };
        let (mut request, header_map) = parse_request(&header_bytes)?;
        if let Some(len) = header_map.get("content-length") {
            let len = len
                .parse::<usize>()
                .map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
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

fn handle_proxy_connection(
    stream: TcpStream,
    timeouts: Timeouts,
    max_body: usize,
    handler: Arc<dyn Fn(HttpRequest) -> HttpResponse + Send + Sync>,
    connect_handler: Arc<dyn Fn(ProxyConnect) -> CoreResult<()> + Send + Sync>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, timeouts)?;
    let mut buffer = Vec::new();
    loop {
        let header_bytes =
            read_until_delim(&mut transport, &mut buffer, b"\r\n\r\n", MAX_HEADER_BYTES)?;
        let (mut request, header_map) = parse_request(&header_bytes)?;
        if let Some(len) = header_map.get("content-length") {
            let len = len
                .parse::<usize>()
                .map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
            request.body = read_exact_body(&mut transport, &mut buffer, len)?;
        } else if let Some(te) = header_map.get("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                request.body = read_chunked_body(&mut transport, &mut buffer, max_body)?;
            }
        }

        let target = request.target()?;
        if matches!(request.method, HttpMethod::Connect) {
            if let HttpTarget::Authority { host, port } = target {
                let mut response = HttpResponse::new(200);
                response.reason = "Connection Established".to_string();
                response.set_header("Connection", "keep-alive");
                let bytes = response.to_bytes()?;
                transport.write_all(&bytes)?;
                let stream = transport.into_inner();
                let buffered = buffer.split_off(0);
                (connect_handler)(ProxyConnect {
                    host,
                    port,
                    stream,
                    buffered,
                })?;
                break;
            } else {
                let mut response = HttpResponse::new(400);
                response.reason = "Bad Request".to_string();
                let bytes = response.to_bytes()?;
                transport.write_all(&bytes)?;
                break;
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

fn handle_proxy_forward_connection(
    stream: TcpStream,
    timeouts: Timeouts,
    max_body: usize,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, timeouts)?;
    let mut buffer = Vec::new();
    loop {
        let header_bytes =
            read_until_delim(&mut transport, &mut buffer, b"\r\n\r\n", MAX_HEADER_BYTES)?;
        let (mut request, header_map) = parse_request(&header_bytes)?;
        if let Some(len) = header_map.get("content-length") {
            let len = len
                .parse::<usize>()
                .map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
            request.body = read_exact_body(&mut transport, &mut buffer, len)?;
        } else if let Some(te) = header_map.get("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                request.body = read_chunked_body(&mut transport, &mut buffer, max_body)?;
            }
        }

        if matches!(request.method, HttpMethod::Connect) {
            let mut response = HttpResponse::new(405);
            response.reason = "Method Not Allowed".to_string();
            let bytes = response.to_bytes()?;
            transport.write_all(&bytes)?;
            break;
        }

        let mut response = match proxy_forward(&request, timeouts) {
            Ok(resp) => resp,
            Err(err) => {
                let mut resp = HttpResponse::new(502);
                resp.reason = err.to_string();
                resp
            }
        };
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

async fn handle_proxy_connection_async(
    stream: tokio::net::TcpStream,
    max_body: usize,
    handler: Arc<dyn Fn(HttpRequest) -> HttpResponse + Send + Sync>,
    connect_handler: Arc<dyn Fn(AsyncProxyConnect) -> CoreResult<()> + Send + Sync>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut buffer = Vec::new();
    loop {
        let header_bytes =
            read_until_delim_async(&mut transport, &mut buffer, b"\r\n\r\n", MAX_HEADER_BYTES)
                .await?;
        let (mut request, header_map) = parse_request(&header_bytes)?;
        if let Some(len) = header_map.get("content-length") {
            let len = len
                .parse::<usize>()
                .map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
            request.body = read_exact_body_async(&mut transport, &mut buffer, len).await?;
        } else if let Some(te) = header_map.get("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                request.body =
                    read_chunked_body_async(&mut transport, &mut buffer, max_body).await?;
            }
        }

        let target = request.target()?;
        if matches!(request.method, HttpMethod::Connect) {
            if let HttpTarget::Authority { host, port } = target {
                let mut response = HttpResponse::new(200);
                response.reason = "Connection Established".to_string();
                response.set_header("Connection", "keep-alive");
                let bytes = response.to_bytes()?;
                transport.write_all(&bytes).await?;
                let stream = transport.into_inner();
                let buffered = buffer.split_off(0);
                return (connect_handler)(AsyncProxyConnect {
                    host,
                    port,
                    stream,
                    buffered,
                });
            } else {
                let mut response = HttpResponse::new(400);
                response.reason = "Bad Request".to_string();
                let bytes = response.to_bytes()?;
                transport.write_all(&bytes).await?;
                break;
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
        let transport =
            AsyncTlsClientTransport::connect(addr, server_name, config, timeouts).await?;
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
        let header_bytes = read_until_delim_async(
            &mut self.transport,
            &mut self.read_buf,
            b"\r\n\r\n",
            MAX_HEADER_BYTES,
        )
        .await?;
        let (mut response, header_map) = parse_response(&header_bytes)?;
        let mut body = Vec::new();
        if should_have_body(response.status_code) {
            if let Some(len) = header_map.get("content-length") {
                let len = len
                    .parse::<usize>()
                    .map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
                body = read_exact_body_async(&mut self.transport, &mut self.read_buf, len).await?;
            } else if let Some(te) = header_map.get("transfer-encoding") {
                if te.to_ascii_lowercase().contains("chunked") {
                    body = read_chunked_body_async(
                        &mut self.transport,
                        &mut self.read_buf,
                        self.max_body,
                    )
                    .await?;
                }
            } else if header_map
                .get("connection")
                .map(|v| v.eq_ignore_ascii_case("close"))
                .unwrap_or(false)
                || matches!(response.version, HttpVersion::Http10)
            {
                body = read_to_end_async(&mut self.transport, &mut self.read_buf, self.max_body)
                    .await?;
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
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
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

    pub async fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
    {
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
        let header_bytes =
            read_until_delim_async(&mut transport, &mut buffer, b"\r\n\r\n", MAX_HEADER_BYTES)
                .await?;
        let (mut request, header_map) = parse_request(&header_bytes)?;
        if let Some(len) = header_map.get("content-length") {
            let len = len
                .parse::<usize>()
                .map_err(|_| CoreError::Parse("invalid content-length".to_string()))?;
            request.body = read_exact_body_async(&mut transport, &mut buffer, len).await?;
        } else if let Some(te) = header_map.get("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                request.body =
                    read_chunked_body_async(&mut transport, &mut buffer, max_body).await?;
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
    use crate::test_util::fuzz_bytes;

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
    fn parse_targets() {
        let mut req = HttpRequest::new(HttpMethod::Get, "http://example.com:8080/test");
        let target = req.target().expect("target");
        match target {
            HttpTarget::Absolute {
                scheme,
                host,
                port,
                path,
            } => {
                assert_eq!(scheme, "http");
                assert_eq!(host, "example.com");
                assert_eq!(port, 8080);
                assert_eq!(path, "/test");
            }
            _ => panic!("expected absolute target"),
        }
        req.method = HttpMethod::Connect;
        req.path = "example.com:443".to_string();
        let target = req.target().expect("connect target");
        match target {
            HttpTarget::Authority { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected authority target"),
        }
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

    #[test]
    fn http_parse_negative() {
        assert!(parse_request(&[]).is_err());
        assert!(parse_response(&[]).is_err());
        assert!(parse_request(b"GE T / HTTP/1.1\r\nHost: example.com\r\n\r\n").is_err());
        assert!(parse_request(b"GET / HTTP/1.1\r\nBad Header\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 9999 Weird\r\n\r\n").is_err());
    }

    #[test]
    fn http_parse_fuzz() {
        fuzz_bytes(128, 512, 0x4854, |data| {
            let _ = parse_request(data);
            let _ = parse_response(data);
        });
    }
}
