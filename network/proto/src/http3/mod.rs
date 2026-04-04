use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use corelib::error::{CoreError, CoreResult};
use http::{uri::Authority, HeaderName, HeaderValue, Method, StatusCode, Uri};
use net::NetAddr;
use quiche::h3::NameValue;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket as TokioUdpSocket;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TICK: Duration = Duration::from_millis(200);

#[derive(Debug, Clone)]
pub struct Http3Request {
    pub method: String,
    pub path: String,
    pub authority: String,
    pub scheme: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Http3Request {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            authority: "localhost".to_string(),
            scheme: "https".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Some((_, v)) = self
            .headers
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            *v = value.to_string();
        } else {
            self.headers.push((name.to_string(), value.to_string()));
        }
    }
}

#[derive(Debug, Clone)]
pub struct Http3Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Http3Response {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        if let Some((_, v)) = self
            .headers
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
        {
            *v = value.to_string();
        } else {
            self.headers.push((name.to_string(), value.to_string()));
        }
    }
}

fn parse_h3_header_utf8(header: &quiche::h3::Header) -> CoreResult<(String, String)> {
    let name = std::str::from_utf8(header.name())
        .map_err(|_| CoreError::Parse("http3 header name is not utf-8".to_string()))?;
    let value = std::str::from_utf8(header.value())
        .map_err(|_| CoreError::Parse("http3 header value is not utf-8".to_string()))?;
    Ok((name.to_string(), value.to_string()))
}

fn validate_regular_header_pair(name: &str, value: &str) -> CoreResult<(String, String)> {
    if name.starts_with(':') {
        return Err(CoreError::Parse("pseudo headers are reserved".to_string()));
    }
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| CoreError::Parse("invalid header name".to_string()))?;
    let value = HeaderValue::from_bytes(value.as_bytes())
        .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
    let value = value
        .to_str()
        .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
    Ok((name.as_str().to_string(), value.to_string()))
}

fn normalize_request_path(path: &str) -> CoreResult<String> {
    if path.is_empty() {
        return Err(CoreError::Parse("http3 path is required".to_string()));
    }
    let uri: Uri = path
        .parse()
        .map_err(|_| CoreError::Parse("invalid http3 path".to_string()))?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(CoreError::Parse(
            "http3 :path must be origin-form".to_string(),
        ));
    }
    let Some(path_and_query) = uri.path_and_query() else {
        return Err(CoreError::Parse("http3 path is required".to_string()));
    };
    let normalized = path_and_query.as_str();
    if normalized != "*" && !normalized.starts_with('/') {
        return Err(CoreError::Parse(
            "http3 path must start with '/' or '*'".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

fn build_headers(request: &Http3Request) -> CoreResult<Vec<quiche::h3::Header>> {
    let method = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| CoreError::Parse("invalid method".to_string()))?;
    let path = normalize_request_path(&request.path)?;
    let scheme = request.scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(CoreError::Parse("unsupported http3 scheme".to_string()));
    }
    let authority = request
        .authority
        .parse::<Authority>()
        .map_err(|_| CoreError::Parse("invalid authority".to_string()))?;

    let mut headers = vec![
        quiche::h3::Header::new(b":method", method.as_str().as_bytes()),
        quiche::h3::Header::new(b":scheme", scheme.as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_str().as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
    ];
    for (name, value) in &request.headers {
        let (name, value) = validate_regular_header_pair(name, value)?;
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    Ok(headers)
}

fn parse_response_headers(
    headers: &[quiche::h3::Header],
) -> CoreResult<(u16, Vec<(String, String)>)> {
    let mut status = None;
    let mut out = Vec::new();
    for header in headers {
        let (name, value) = parse_h3_header_utf8(header)?;
        if name == ":status" {
            let code = value
                .parse::<u16>()
                .map_err(|_| CoreError::Parse("invalid status".to_string()))?;
            StatusCode::from_u16(code)
                .map_err(|_| CoreError::Parse("invalid status".to_string()))?;
            status = Some(code);
        } else if name.starts_with(':') {
            return Err(CoreError::Parse(
                "unexpected pseudo header in response".to_string(),
            ));
        } else {
            out.push(validate_regular_header_pair(&name, &value)?);
        }
    }
    let status = status.ok_or_else(|| CoreError::Parse("missing :status header".to_string()))?;
    Ok((status, out))
}

fn parse_request_headers(headers: &[quiche::h3::Header]) -> CoreResult<Http3Request> {
    let mut method = None::<String>;
    let mut path = None::<String>;
    let mut authority = None::<String>;
    let mut scheme = None::<String>;
    let mut regular_headers = Vec::new();
    for header in headers {
        let (name, value) = parse_h3_header_utf8(header)?;
        match name.as_str() {
            ":method" => method = Some(value),
            ":path" => path = Some(value),
            ":authority" => authority = Some(value),
            ":scheme" => scheme = Some(value),
            _ if name.starts_with(':') => {
                return Err(CoreError::Parse(
                    "unsupported pseudo header in request".to_string(),
                ));
            }
            _ => regular_headers.push(validate_regular_header_pair(&name, &value)?),
        }
    }

    let method = method.ok_or_else(|| CoreError::Parse("missing :method header".to_string()))?;
    Method::from_bytes(method.as_bytes())
        .map_err(|_| CoreError::Parse("invalid method".to_string()))?;
    let path = normalize_request_path(
        &path.ok_or_else(|| CoreError::Parse("missing :path header".to_string()))?,
    )?;

    let authority = authority.unwrap_or_else(|| "localhost".to_string());
    authority
        .parse::<Authority>()
        .map_err(|_| CoreError::Parse("invalid authority".to_string()))?;

    let scheme = scheme
        .unwrap_or_else(|| "https".to_string())
        .to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(CoreError::Parse("unsupported http3 scheme".to_string()));
    }

    Ok(Http3Request {
        method,
        path,
        authority,
        scheme,
        headers: regular_headers,
        body: Vec::new(),
    })
}

fn build_response_headers(response: &Http3Response) -> CoreResult<Vec<quiche::h3::Header>> {
    let status = StatusCode::from_u16(response.status)
        .map_err(|_| CoreError::Parse("invalid status".to_string()))?;
    let mut headers = vec![quiche::h3::Header::new(
        b":status",
        status.as_u16().to_string().as_bytes(),
    )];
    for (name, value) in &response.headers {
        let (name, value) = validate_regular_header_pair(name, value)?;
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    Ok(headers)
}

fn build_config() -> CoreResult<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|err| CoreError::Message(err.to_string()))?;
    config.verify_peer(false);
    config
        .set_application_protos(&[b"h3", b"h3-29", b"h3-28", b"h3-27"])
        .map_err(|err| CoreError::Message(err.to_string()))?;
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    Ok(config)
}

async fn flush_conn_send(
    socket: &TokioUdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> CoreResult<()> {
    loop {
        match conn.send(out) {
            Ok((len, send_info)) => {
                socket
                    .send_to(&out[..len], send_info.to)
                    .await
                    .map_err(CoreError::Io)?;
            }
            Err(quiche::Error::Done) => break,
            Err(err) => return Err(CoreError::Message(err.to_string())),
        }
    }
    Ok(())
}

fn next_conn_wait(conn: &quiche::Connection, remaining: Duration) -> Duration {
    conn.timeout().map_or(remaining.min(IO_TICK), |timeout| {
        timeout.min(remaining).min(IO_TICK)
    })
}

fn random_cid(len: usize) -> CoreResult<Vec<u8>> {
    let mut out = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| CoreError::Parse("unable to generate random connection id".to_string()))?;
    Ok(out)
}

pub struct Http3Client {
    socket: TokioUdpSocket,
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    max_body: usize,
    local_addr: SocketAddr,
}

impl Http3Client {
    pub async fn connect(addr: &NetAddr, server_name: &str) -> CoreResult<Self> {
        let peer = addr
            .resolve()?
            .into_iter()
            .next()
            .ok_or_else(|| CoreError::Parse("unable to resolve".to_string()))?;
        let socket = TokioUdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(CoreError::Io)?;
        let local_addr = socket.local_addr().map_err(CoreError::Io)?;
        let mut config = build_config()?;
        let scid_bytes = random_cid(16)?;
        let scid = quiche::ConnectionId::from_vec(scid_bytes);
        let conn = quiche::connect(Some(server_name), &scid, local_addr, peer, &mut config)
            .map_err(|err| CoreError::Message(err.to_string()))?;
        let h3_config =
            quiche::h3::Config::new().map_err(|err| CoreError::Message(err.to_string()))?;
        let mut client = Self {
            socket,
            conn,
            h3: None,
            max_body: DEFAULT_MAX_BODY,
            local_addr,
        };
        client.handshake().await?;
        let h3 = quiche::h3::Connection::with_transport(&mut client.conn, &h3_config)
            .map_err(|err| CoreError::Message(err.to_string()))?;
        client.h3 = Some(h3);
        Ok(client)
    }

    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    async fn handshake(&mut self) -> CoreResult<()> {
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut buf = vec![0u8; 65535];
        let start = Instant::now();
        while !self.conn.is_established() {
            flush_conn_send(&self.socket, &mut self.conn, &mut out).await?;
            if self.conn.is_closed() {
                return Err(CoreError::Parse("http3 connection closed".to_string()));
            }
            if start.elapsed() > HANDSHAKE_TIMEOUT {
                return Err(CoreError::Parse("http3 handshake timeout".to_string()));
            }
            let remaining = HANDSHAKE_TIMEOUT.saturating_sub(start.elapsed());
            let wait = next_conn_wait(&self.conn, remaining);
            match tokio::time::timeout(wait, self.socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    let recv_info = quiche::RecvInfo {
                        from,
                        to: self.local_addr,
                    };
                    let _ = self.conn.recv(&mut buf[..len], recv_info);
                }
                Ok(Err(err)) => return Err(CoreError::Io(err)),
                Err(_) => self.conn.on_timeout(),
            }
        }
        Ok(())
    }

    pub async fn request(&mut self, request: &Http3Request) -> CoreResult<Http3Response> {
        let h3 = self
            .h3
            .as_mut()
            .ok_or_else(|| CoreError::Parse("http3 connection not ready".to_string()))?;
        let headers = build_headers(request)?;
        let expected_stream_id = h3
            .send_request(&mut self.conn, &headers, request.body.is_empty())
            .map_err(|err| CoreError::Message(err.to_string()))?;
        if !request.body.is_empty() {
            h3.send_body(&mut self.conn, expected_stream_id, &request.body, true)
                .map_err(|err| CoreError::Message(err.to_string()))?;
        }
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut buf = vec![0u8; 65535];
        let mut response_headers: Option<Vec<quiche::h3::Header>> = None;
        let mut response_complete = false;
        let mut response_body = Vec::new();
        let start = Instant::now();
        loop {
            flush_conn_send(&self.socket, &mut self.conn, &mut out).await?;
            if self.conn.is_closed() {
                return Err(CoreError::Parse("http3 connection closed".to_string()));
            }
            if start.elapsed() > RESPONSE_TIMEOUT {
                return Err(CoreError::Parse("http3 response timeout".to_string()));
            }
            let remaining = RESPONSE_TIMEOUT.saturating_sub(start.elapsed());
            let wait = next_conn_wait(&self.conn, remaining);
            match tokio::time::timeout(wait, self.socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    let recv_info = quiche::RecvInfo {
                        from,
                        to: self.local_addr,
                    };
                    let _ = self.conn.recv(&mut buf[..len], recv_info);
                }
                Ok(Err(err)) => return Err(CoreError::Io(err)),
                Err(_) => self.conn.on_timeout(),
            }

            loop {
                match h3.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        if stream_id != expected_stream_id {
                            continue;
                        }
                        response_headers = Some(list);
                        if self.conn.stream_finished(stream_id) {
                            response_complete = true;
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        if stream_id != expected_stream_id {
                            continue;
                        }
                        let mut data = vec![0u8; self.max_body.min(4096)];
                        while let Ok(read) = h3.recv_body(&mut self.conn, stream_id, &mut data) {
                            if read == 0 {
                                break;
                            }
                            if response_body.len() + read > self.max_body {
                                return Err(CoreError::Parse(
                                    "body exceeds maximum size".to_string(),
                                ));
                            }
                            response_body.extend_from_slice(&data[..read]);
                        }
                        if self.conn.stream_finished(stream_id) {
                            response_complete = true;
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        if stream_id == expected_stream_id {
                            response_complete = true;
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(_)))
                    | Ok((_stream_id, quiche::h3::Event::PriorityUpdate))
                    | Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => return Err(CoreError::Message(err.to_string())),
                }
            }

            if response_complete {
                let headers = response_headers
                    .as_ref()
                    .ok_or_else(|| CoreError::Parse("missing response headers".to_string()))?;
                let (status, header_pairs) = parse_response_headers(headers)?;
                return Ok(Http3Response {
                    status,
                    headers: header_pairs,
                    body: response_body,
                });
            }
        }
    }
}

pub struct Http3Server {
    socket: TokioUdpSocket,
    local_addr: SocketAddr,
    max_body: usize,
    cert_path: String,
    key_path: String,
}

struct ServerConn {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    streams: HashMap<u64, Http3Request>,
}

impl Http3Server {
    pub async fn bind(addr: SocketAddr, cert_path: &str, key_path: &str) -> CoreResult<Self> {
        let socket = TokioUdpSocket::bind(addr).await.map_err(CoreError::Io)?;
        let local_addr = socket.local_addr().map_err(CoreError::Io)?;
        Ok(Self {
            socket,
            local_addr,
            max_body: DEFAULT_MAX_BODY,
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
        })
    }

    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(Http3Request) -> Http3Response + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let mut conns: Vec<ServerConn> = Vec::new();
        let mut conn_ids: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        loop {
            let (len, from) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(CoreError::Io)?;
            let to = self.local_addr;
            let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                Ok(hdr) => hdr,
                Err(_) => continue,
            };
            let conn_id = hdr.dcid.as_ref().to_vec();
            let conn_index = if let Some(index) = conn_ids.get(&conn_id) {
                *index
            } else {
                let scid_bytes = random_cid(16)?;
                let scid = quiche::ConnectionId::from_vec(scid_bytes);
                let mut config = build_config()?;
                config
                    .load_cert_chain_from_pem_file(&self.cert_path)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                config
                    .load_priv_key_from_pem_file(&self.key_path)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                let conn = quiche::accept(&scid, None, to, from, &mut config)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                let index = conns.len();
                conns.push(ServerConn {
                    conn,
                    h3: None,
                    streams: HashMap::new(),
                });
                insert_conn_ids(&mut conn_ids, index, &conns[index].conn, conn_id.clone());
                index
            };
            let server_conn = &mut conns[conn_index];
            insert_conn_ids(&mut conn_ids, conn_index, &server_conn.conn, conn_id);
            let conn = &mut server_conn.conn;
            let streams = &mut server_conn.streams;
            let recv_info = quiche::RecvInfo { from, to };
            let _ = conn.recv(&mut buf[..len], recv_info);

            while let Ok((len, send_info)) = conn.send(&mut out) {
                self.socket
                    .send_to(&out[..len], send_info.to)
                    .await
                    .map_err(CoreError::Io)?;
            }

            if conn.is_established() && server_conn.h3.is_none() {
                let h3_config =
                    quiche::h3::Config::new().map_err(|err| CoreError::Message(err.to_string()))?;
                let h3 = quiche::h3::Connection::with_transport(conn, &h3_config)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                server_conn.h3 = Some(h3);
            }

            let Some(h3) = server_conn.h3.as_mut() else {
                continue;
            };

            loop {
                match h3.poll(conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
                        match parse_request_headers(&list) {
                            Ok(req) => {
                                if more_frames && !conn.stream_finished(stream_id) {
                                    streams.insert(stream_id, req);
                                } else {
                                    let response = (handler)(req);
                                    let headers = build_response_headers(&response)?;
                                    h3.send_response(
                                        conn,
                                        stream_id,
                                        &headers,
                                        response.body.is_empty(),
                                    )
                                    .map_err(|err| CoreError::Message(err.to_string()))?;
                                    if !response.body.is_empty() {
                                        h3.send_body(conn, stream_id, &response.body, true)
                                            .map_err(|err| CoreError::Message(err.to_string()))?;
                                    }
                                }
                            }
                            Err(_) => {
                                let response = Http3Response::new(400);
                                let headers = build_response_headers(&response)?;
                                h3.send_response(conn, stream_id, &headers, true)
                                    .map_err(|err| CoreError::Message(err.to_string()))?;
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let mut overflow = false;
                        if let Some(req) = streams.get_mut(&stream_id) {
                            let mut data = vec![0u8; self.max_body.min(4096)];
                            while let Ok(read) = h3.recv_body(conn, stream_id, &mut data) {
                                if read == 0 {
                                    break;
                                }
                                if req.body.len() + read > self.max_body {
                                    overflow = true;
                                    break;
                                }
                                req.body.extend_from_slice(&data[..read]);
                            }
                        }
                        if overflow {
                            streams.remove(&stream_id);
                            let response = Http3Response::new(413);
                            let headers = build_response_headers(&response)?;
                            h3.send_response(conn, stream_id, &headers, true)
                                .map_err(|err| CoreError::Message(err.to_string()))?;
                        } else if conn.stream_finished(stream_id) {
                            if let Some(req) = streams.remove(&stream_id) {
                                let response = (handler)(req);
                                let headers = build_response_headers(&response)?;
                                h3.send_response(
                                    conn,
                                    stream_id,
                                    &headers,
                                    response.body.is_empty(),
                                )
                                .map_err(|err| CoreError::Message(err.to_string()))?;
                                if !response.body.is_empty() {
                                    h3.send_body(conn, stream_id, &response.body, true)
                                        .map_err(|err| CoreError::Message(err.to_string()))?;
                                }
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        if let Some(req) = streams.remove(&stream_id) {
                            let response = (handler)(req);
                            let headers = build_response_headers(&response)?;
                            h3.send_response(conn, stream_id, &headers, response.body.is_empty())
                                .map_err(|err| CoreError::Message(err.to_string()))?;
                            if !response.body.is_empty() {
                                h3.send_body(conn, stream_id, &response.body, true)
                                    .map_err(|err| CoreError::Message(err.to_string()))?;
                            }
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(_)))
                    | Ok((_stream_id, quiche::h3::Event::PriorityUpdate))
                    | Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => return Err(CoreError::Message(err.to_string())),
                }
            }

            while let Ok((len, send_info)) = conn.send(&mut out) {
                self.socket
                    .send_to(&out[..len], send_info.to)
                    .await
                    .map_err(CoreError::Io)?;
            }
        }
    }
}

fn insert_conn_ids(
    conn_ids: &mut HashMap<Vec<u8>, usize>,
    index: usize,
    conn: &quiche::Connection,
    initial: Vec<u8>,
) {
    conn_ids.insert(initial, index);
    for scid in conn.source_ids() {
        conn_ids.insert(scid.as_ref().to_vec(), index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::fuzz_bytes;
    use net::NetAddr;
    use std::fs;

    #[test]
    fn header_roundtrip() {
        let mut req = Http3Request::new("GET", "/");
        req.authority = "example.com".to_string();
        req.set_header("user-agent", "moonlight");
        let headers = build_headers(&req).expect("build headers");
        let (status, parsed) = parse_response_headers(&[
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"server", b"moonlight"),
        ])
        .expect("parse headers");
        assert_eq!(status, 200);
        assert_eq!(parsed[0].0, "server");
        assert_eq!(headers[0].name(), b":method");
    }

    #[tokio::test]
    async fn http3_roundtrip() {
        if std::env::var("MOONLIGHT_HTTP3_TEST").is_err() {
            eprintln!("MOONLIGHT_HTTP3_TEST not set; skipping http3 roundtrip");
            return;
        }
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let dir = std::env::temp_dir();
        let cert_path = dir.join("moonlight_http3_test_cert.pem");
        let key_path = dir.join("moonlight_http3_test_key.pem");
        fs::write(&cert_path, cert_pem).unwrap();
        fs::write(&key_path, key_pem).unwrap();

        let server = Http3Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .await
        .expect("bind");
        let addr = server.local_addr();
        tokio::spawn(async move {
            if let Err(err) = server
                .serve(|_req| {
                    let mut resp = Http3Response::new(200);
                    resp.body = b"ok".to_vec();
                    resp
                })
                .await
            {
                eprintln!("http3 test server error: {:?}", err);
            }
        });

        let req = Http3Request::new("POST", "/dns-query");
        let mut last_err = None;
        for _ in 0..3 {
            match Http3Client::connect(&NetAddr::from_socket(addr), "localhost").await {
                Ok(mut client) => match client.request(&req).await {
                    Ok(resp) => {
                        assert_eq!(resp.status, 200);
                        assert_eq!(resp.body, b"ok".to_vec());
                        return;
                    }
                    Err(err) => last_err = Some(err),
                },
                Err(err) => last_err = Some(err),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("http3 roundtrip failed: {:?}", last_err);
    }

    #[test]
    fn http3_parse_headers_empty() {
        assert!(parse_response_headers(&[]).is_err());
    }

    #[test]
    fn http3_invalid_request_headers() {
        let req = Http3Request::new("GET /", "/");
        assert!(build_headers(&req).is_err());
        let mut req = Http3Request::new("GET", "/");
        req.set_header(":invalid", "x");
        assert!(build_headers(&req).is_err());
    }

    #[test]
    fn http3_parse_headers_fuzz() {
        fuzz_bytes(128, 128, 0x4833, |data| {
            let mut headers = Vec::new();
            if !data.is_empty() {
                let mid = data.len() / 2;
                let name = if mid == 0 { b"x" } else { &data[..mid] };
                let value = &data[mid..];
                headers.push(quiche::h3::Header::new(name, value));
            }
            let _ = parse_response_headers(&headers);
        });
    }
}
