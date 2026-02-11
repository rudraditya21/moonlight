use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use corelib::error::{CoreError, CoreResult};
use h2::client;
use h2::server;
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use net::NetAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::transport::TlsClientConfig;
use crate::transport::TlsServerConfig;
use crate::util::Timeouts;

const DEFAULT_MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Http2Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Http2Request {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
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
pub struct Http2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Http2Response {
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

fn to_request(req: &Http2Request) -> CoreResult<Request<()>> {
    let method = Method::from_bytes(req.method.as_bytes())
        .map_err(|_| CoreError::Parse("invalid method".to_string()))?;
    let uri: Uri = req
        .path
        .parse()
        .map_err(|_| CoreError::Parse("invalid uri".to_string()))?;
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in &req.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| CoreError::Parse("invalid header name".to_string()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|_| CoreError::Parse("invalid request".to_string()))
}

fn from_request(req: &Request<Vec<u8>>) -> Http2Request {
    let mut headers = Vec::new();
    for (name, value) in req.headers() {
        if let Ok(value) = value.to_str() {
            headers.push((name.to_string(), value.to_string()));
        }
    }
    Http2Request {
        method: req.method().as_str().to_string(),
        path: req.uri().to_string(),
        headers,
        body: req.body().clone(),
    }
}

fn to_response(resp: &Http2Response) -> CoreResult<Response<()>> {
    let status = StatusCode::from_u16(resp.status)
        .map_err(|_| CoreError::Parse("invalid status".to_string()))?;
    let mut builder = Response::builder().status(status);
    for (name, value) in &resp.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| CoreError::Parse("invalid header name".to_string()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| CoreError::Parse("invalid header value".to_string()))?;
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|_| CoreError::Parse("invalid response".to_string()))
}

fn from_response(resp: &Response<Vec<u8>>) -> Http2Response {
    let mut headers = Vec::new();
    for (name, value) in resp.headers() {
        if let Ok(value) = value.to_str() {
            headers.push((name.to_string(), value.to_string()));
        }
    }
    Http2Response {
        status: resp.status().as_u16(),
        headers,
        body: resp.body().clone(),
    }
}

async fn read_body(mut body: h2::RecvStream, max_body: usize) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|err| CoreError::Message(err.to_string()))?;
        if out.len() + chunk.len() > max_body {
            return Err(CoreError::Parse("body exceeds maximum size".to_string()));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

pub struct Http2Client {
    sender: client::SendRequest<Bytes>,
    max_body: usize,
}

impl Http2Client {
    pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let socket = addr
            .resolve()?
            .into_iter()
            .next()
            .ok_or_else(|| CoreError::Parse("unable to resolve".to_string()))?;
        let stream = tokio::time::timeout(timeouts.connect, TcpStream::connect(socket))
            .await
            .map_err(|_| CoreError::Parse("connect timeout".to_string()))??;
        let (sender, connection) = client::handshake(stream)
            .await
            .map_err(|err| CoreError::Message(err.to_string()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self {
            sender,
            max_body: DEFAULT_MAX_BODY,
        })
    }

    pub async fn connect_tls(
        addr: &NetAddr,
        server_name: &str,
        config: &TlsClientConfig,
        timeouts: Timeouts,
    ) -> CoreResult<Self> {
        let socket = addr
            .resolve()?
            .into_iter()
            .next()
            .ok_or_else(|| CoreError::Parse("unable to resolve".to_string()))?;
        let stream = tokio::time::timeout(timeouts.connect, TcpStream::connect(socket))
            .await
            .map_err(|_| CoreError::Parse("connect timeout".to_string()))??;
        let server_name = rustls::pki_types::ServerName::try_from(server_name)
            .map_err(|_| CoreError::Parse("invalid server name".to_string()))?
            .to_owned();
        let connector = tokio_rustls::TlsConnector::from(config.with_alpn(&[b"h2"]).inner());
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|err| CoreError::Message(err.to_string()))?;
        let (sender, connection) = client::handshake(tls)
            .await
            .map_err(|err| CoreError::Message(err.to_string()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self {
            sender,
            max_body: DEFAULT_MAX_BODY,
        })
    }

    pub fn max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    pub async fn send(&mut self, request: &Http2Request) -> CoreResult<Http2Response> {
        let req = to_request(request)?;
        let end_of_stream = request.body.is_empty();
        let (response_future, mut stream) = self
            .sender
            .send_request(req, end_of_stream)
            .map_err(|err| CoreError::Message(err.to_string()))?;
        if !end_of_stream {
            stream
                .send_data(Bytes::from(request.body.clone()), true)
                .map_err(|err| CoreError::Message(err.to_string()))?;
        }
        let response = response_future
            .await
            .map_err(|err| CoreError::Message(err.to_string()))?;
        let (parts, body) = response.into_parts();
        let body_bytes = read_body(body, self.max_body).await?;
        let resp = Response::from_parts(parts, body_bytes);
        Ok(from_response(&resp))
    }
}

pub struct Http2Server {
    listener: TcpListener,
    max_body: usize,
}

impl Http2Server {
    pub async fn bind(addr: SocketAddr) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).await.map_err(CoreError::Io)?;
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
        F: Fn(Http2Request) -> Http2Response + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let max_body = self.max_body;
            tokio::spawn(async move {
                let _ = handle_connection_io(stream, max_body, handler).await;
            });
        }
    }
}

pub struct Http2TlsServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    max_body: usize,
}

impl Http2TlsServer {
    pub async fn bind(addr: SocketAddr, config: &TlsServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        let config = config.with_alpn(&[b"h2"]);
        let acceptor = TlsAcceptor::from(config.inner());
        Ok(Self {
            listener,
            acceptor,
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
        F: Fn(Http2Request) -> Http2Response + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let acceptor = self.acceptor.clone();
            let max_body = self.max_body;
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls) => {
                        let _ = handle_connection_io(tls, max_body, handler).await;
                    }
                    Err(_) => {}
                }
            });
        }
    }
}

async fn handle_connection_io<T>(
    stream: T,
    max_body: usize,
    handler: Arc<dyn Fn(Http2Request) -> Http2Response + Send + Sync>,
) -> CoreResult<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = server::handshake(stream)
        .await
        .map_err(|err| CoreError::Message(err.to_string()))?;
    while let Some(result) = connection.accept().await {
        let (request, mut respond) = result.map_err(|err| CoreError::Message(err.to_string()))?;
        let (parts, body) = request.into_parts();
        let body_bytes = read_body(body, max_body).await?;
        let req = Request::from_parts(parts, body_bytes);
        let response = (handler)(from_request(&req));
        let resp = to_response(&response)?;
        let end_of_stream = response.body.is_empty();
        let mut send = respond
            .send_response(resp, end_of_stream)
            .map_err(|err| CoreError::Message(err.to_string()))?;
        if !end_of_stream {
            send.send_data(Bytes::from(response.body), true)
                .map_err(|err| CoreError::Message(err.to_string()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{fuzz_bytes, fuzz_strings};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    #[tokio::test]
    async fn http2_roundtrip() {
        let server = match Http2Server::bind("127.0.0.1:0".parse().unwrap()).await {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {:?}", err),
        };
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = server
                .serve(|req| {
                    assert_eq!(req.method, "GET");
                    let mut resp = Http2Response::new(200);
                    resp.body = b"ok".to_vec();
                    resp
                })
                .await;
        });

        let mut client = Http2Client::connect(&NetAddr::from_socket(addr), Timeouts::default())
            .await
            .expect("connect");
        let req = Http2Request::new("GET", "/");
        let resp = client.send(&req).await.expect("send");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok".to_vec());
    }

    #[tokio::test]
    async fn http2_tls_roundtrip() {
        let rcgen::CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let server_tls =
            TlsServerConfig::from_der(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_der))
                .unwrap();

        let server = match Http2TlsServer::bind("127.0.0.1:0".parse().unwrap(), &server_tls).await {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {:?}", err),
        };
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = server
                .serve(|req| {
                    assert_eq!(req.method, "GET");
                    let mut resp = Http2Response::new(200);
                    resp.body = b"ok".to_vec();
                    resp
                })
                .await;
        });

        let client_tls = TlsClientConfig::with_root_certificates(vec![cert_der])
            .unwrap()
            .with_alpn(&[b"h2"]);
        let mut client = Http2Client::connect_tls(
            &NetAddr::from_socket(addr),
            "localhost",
            &client_tls,
            Timeouts::default(),
        )
        .await
        .expect("connect");
        let req = Http2Request::new("GET", "/");
        let resp = client.send(&req).await.expect("send");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok".to_vec());
    }

    #[test]
    fn http2_to_request_negative() {
        let req = Http2Request::new("\0", "not a uri");
        assert!(to_request(&req).is_err());
    }

    #[test]
    fn http2_to_request_fuzz() {
        fuzz_strings(128, 64, 0x4852, |text| {
            let mut req = Http2Request::new(text, text);
            req.set_header("x", text);
            let _ = to_request(&req);
        });
    }

    #[test]
    fn http2_to_response_fuzz() {
        fuzz_bytes(128, 8, 0x4853, |data| {
            let status = if data.len() >= 2 {
                u16::from_be_bytes([data[0], data[1]])
            } else {
                0
            };
            let mut resp = Http2Response::new(status);
            resp.set_header("x", "y");
            let _ = to_response(&resp);
        });
    }
}
