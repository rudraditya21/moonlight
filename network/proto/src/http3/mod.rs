use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;
use tokio::net::UdpSocket as TokioUdpSocket;
use quiche::h3::NameValue;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;

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

fn build_headers(request: &Http3Request) -> Vec<quiche::h3::Header> {
    let mut headers = vec![
        quiche::h3::Header::new(b":method", request.method.as_bytes()),
        quiche::h3::Header::new(b":scheme", request.scheme.as_bytes()),
        quiche::h3::Header::new(b":authority", request.authority.as_bytes()),
        quiche::h3::Header::new(b":path", request.path.as_bytes()),
    ];
    for (name, value) in &request.headers {
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    headers
}

fn parse_headers(headers: &[quiche::h3::Header]) -> (u16, Vec<(String, String)>) {
    let mut status = 200u16;
    let mut out = Vec::new();
    for header in headers {
        let name = String::from_utf8_lossy(header.name()).to_string();
        let value = String::from_utf8_lossy(header.value()).to_string();
        if name == ":status" {
            if let Ok(code) = value.parse() {
                status = code;
            }
        } else {
            out.push((name, value));
        }
    }
    (status, out)
}

fn build_response_headers(response: &Http3Response) -> Vec<quiche::h3::Header> {
    let mut headers = vec![quiche::h3::Header::new(
        b":status",
        response.status.to_string().as_bytes(),
    )];
    for (name, value) in &response.headers {
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    headers
}

fn build_config() -> CoreResult<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|err| CoreError::Message(err.to_string()))?;
    config.verify_peer(false);
    config.set_application_protos(&[b"h3-29", b"h3-28", b"h3-27", b"h3"])
        .map_err(|err| CoreError::Message(err.to_string()))?;
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    Ok(config)
}

fn random_cid(len: usize) -> Vec<u8> {
    let mut seed = 0x1234abcd_u64;
    let mut out = vec![0u8; len];
    for byte in &mut out {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = (seed & 0xff) as u8;
    }
    out
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
        let socket = TokioUdpSocket::bind("0.0.0.0:0").await.map_err(CoreError::Io)?;
        let local_addr = socket.local_addr().map_err(CoreError::Io)?;
        let mut config = build_config()?;
        let scid_bytes = random_cid(16);
        let scid = quiche::ConnectionId::from_vec(scid_bytes);
        let conn = quiche::connect(
            Some(server_name),
            &scid,
            local_addr,
            peer,
            &mut config,
        )
        .map_err(|err| CoreError::Message(err.to_string()))?;
        let h3_config = quiche::h3::Config::new()
            .map_err(|err| CoreError::Message(err.to_string()))?;
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
            while let Ok((len, send_info)) = self.conn.send(&mut out) {
                self.socket
                    .send_to(&out[..len], send_info.to)
                    .await
                    .map_err(CoreError::Io)?;
            }
            if start.elapsed() > Duration::from_secs(5) {
                return Err(CoreError::Parse("http3 handshake timeout".to_string()));
            }
            let remaining = Duration::from_secs(5)
                .saturating_sub(start.elapsed())
                .max(Duration::from_millis(100));
            let (len, from) = tokio::time::timeout(remaining, self.socket.recv_from(&mut buf))
                .await
                .map_err(|_| CoreError::Parse("http3 handshake timeout".to_string()))?
                .map_err(CoreError::Io)?;
            let recv_info = quiche::RecvInfo {
                from,
                to: self.local_addr,
            };
            let _ = self.conn.recv(&mut buf[..len], recv_info);
        }
        Ok(())
    }

    pub async fn request(&mut self, request: &Http3Request) -> CoreResult<Http3Response> {
        let h3 = self
            .h3
            .as_mut()
            .ok_or_else(|| CoreError::Parse("http3 connection not ready".to_string()))?;
        let headers = build_headers(request);
        let stream_id = h3
            .send_request(&mut self.conn, &headers, request.body.is_empty())
            .map_err(|err| CoreError::Message(err.to_string()))?;
        if !request.body.is_empty() {
            h3
                .send_body(&mut self.conn, stream_id, &request.body, true)
                .map_err(|err| CoreError::Message(err.to_string()))?;
        }
        let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut buf = vec![0u8; 65535];
        let mut response_headers: Option<Vec<quiche::h3::Header>> = None;
        let mut response_body = Vec::new();
        let start = Instant::now();
        loop {
            while let Ok((len, send_info)) = self.conn.send(&mut out) {
                self.socket
                    .send_to(&out[..len], send_info.to)
                    .await
                    .map_err(CoreError::Io)?;
            }
            if start.elapsed() > Duration::from_secs(10) {
                return Err(CoreError::Parse("http3 response timeout".to_string()));
            }
            let remaining = Duration::from_secs(10)
                .saturating_sub(start.elapsed())
                .max(Duration::from_millis(100));
            let (len, from) = tokio::time::timeout(remaining, self.socket.recv_from(&mut buf))
                .await
                .map_err(|_| CoreError::Parse("http3 response timeout".to_string()))?
                .map_err(CoreError::Io)?;
            let recv_info = quiche::RecvInfo {
                from,
                to: self.local_addr,
            };
            let _ = self.conn.recv(&mut buf[..len], recv_info);

            loop {
                match h3.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        response_headers = Some(list);
                        if self.conn.stream_finished(stream_id) {
                            break;
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        let mut data = vec![0u8; self.max_body.min(4096)];
                        while let Ok(read) = h3.recv_body(&mut self.conn, stream_id, &mut data) {
                            if read == 0 {
                                break;
                            }
                            if response_body.len() + read > self.max_body {
                                return Err(CoreError::Parse("body exceeds maximum size".to_string()));
                            }
                            response_body.extend_from_slice(&data[..read]);
                        }
                        if self.conn.stream_finished(stream_id) {
                            break;
                        }
                    }
                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        break;
                    }
                    Ok((_stream_id, quiche::h3::Event::Reset(_)))
                    | Ok((_stream_id, quiche::h3::Event::PriorityUpdate))
                    | Ok((_stream_id, quiche::h3::Event::GoAway)) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => return Err(CoreError::Message(err.to_string())),
                }
            }

            if let Some(headers) = &response_headers {
                let (status, header_pairs) = parse_headers(headers);
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
    h3: quiche::h3::Connection,
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
            let (len, from) = self.socket.recv_from(&mut buf).await.map_err(CoreError::Io)?;
            let to = self.local_addr;
            let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                Ok(hdr) => hdr,
                Err(_) => continue,
            };
            let conn_id = hdr.dcid.as_ref().to_vec();
            let conn_index = if let Some(index) = conn_ids.get(&conn_id) {
                *index
            } else {
                let scid_bytes = random_cid(16);
                let scid = quiche::ConnectionId::from_vec(scid_bytes);
                let mut config = build_config()?;
                config
                    .load_cert_chain_from_pem_file(&self.cert_path)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                config
                    .load_priv_key_from_pem_file(&self.key_path)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                let mut conn = quiche::accept(&scid, None, to, from, &mut config)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                let h3_config = quiche::h3::Config::new()
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                let h3 = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .map_err(|err| CoreError::Message(err.to_string()))?;
                let index = conns.len();
                conns.push(ServerConn {
                    conn,
                    h3,
                    streams: HashMap::new(),
                });
                insert_conn_ids(&mut conn_ids, index, &conns[index].conn, conn_id.clone());
                index
            };
            let server_conn = &mut conns[conn_index];
            insert_conn_ids(&mut conn_ids, conn_index, &server_conn.conn, conn_id);
            let conn = &mut server_conn.conn;
            let h3 = &mut server_conn.h3;
            let streams = &mut server_conn.streams;
            let recv_info = quiche::RecvInfo { from, to };
            let _ = conn.recv(&mut buf[..len], recv_info);

            while let Ok((len, send_info)) = conn.send(&mut out) {
                self.socket
                    .send_to(&out[..len], send_info.to)
                    .await
                    .map_err(CoreError::Io)?;
            }

            loop {
                match h3.poll(conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        let mut req = Http3Request::new("GET", "/");
                        for header in list {
                            let name = String::from_utf8_lossy(header.name()).to_string();
                            let value = String::from_utf8_lossy(header.value()).to_string();
                            match name.as_str() {
                                ":method" => req.method = value,
                                ":path" => req.path = value,
                                ":authority" => req.authority = value,
                                ":scheme" => req.scheme = value,
                                _ => req.headers.push((name, value)),
                            }
                        }
                        streams.insert(stream_id, req);
                    }
                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        if let Some(req) = streams.get_mut(&stream_id) {
                            let mut data = vec![0u8; self.max_body.min(4096)];
                            while let Ok(read) = h3.recv_body(conn, stream_id, &mut data) {
                                if read == 0 {
                                    break;
                                }
                                if req.body.len() + read > self.max_body {
                                    break;
                                }
                                req.body.extend_from_slice(&data[..read]);
                            }
                        }
                    }
                    Ok((stream_id, quiche::h3::Event::Finished)) => {
                        if let Some(req) = streams.remove(&stream_id) {
                            let response = (handler)(req);
                            let headers = build_response_headers(&response);
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
    use std::fs;
    use net::NetAddr;

    #[test]
    fn header_roundtrip() {
        let mut req = Http3Request::new("GET", "/");
        req.authority = "example.com".to_string();
        req.set_header("user-agent", "moonlight");
        let headers = build_headers(&req);
        let (status, parsed) = parse_headers(&[
            quiche::h3::Header::new(b":status", b"200"),
            quiche::h3::Header::new(b"server", b"moonlight"),
        ]);
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
            let _ = server
                .serve(|_req| {
                    let mut resp = Http3Response::new(200);
                    resp.body = b"ok".to_vec();
                    resp
                })
                .await;
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
}
