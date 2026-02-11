use std::fs::File;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::util::Timeouts;

pub trait StreamTransport {
    fn read(&mut self, buf: &mut [u8]) -> CoreResult<usize>;
    fn read_exact(&mut self, buf: &mut [u8]) -> CoreResult<()>;
    fn write_all(&mut self, buf: &[u8]) -> CoreResult<()>;
    fn shutdown(&mut self) -> CoreResult<()>;
    fn peer_addr(&self) -> CoreResult<SocketAddr>;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> CoreResult<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> CoreResult<()>;
}

#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let mut last_err = None;
        for socket in addr.resolve()? {
            match TcpStream::connect_timeout(&socket, timeouts.connect) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(timeouts.read))
                        .map_err(CoreError::Io)?;
                    stream
                        .set_write_timeout(Some(timeouts.write))
                        .map_err(CoreError::Io)?;
                    return Ok(Self { stream });
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err
            .map(CoreError::Io)
            .unwrap_or_else(|| CoreError::Parse("unable to connect".to_string())))
    }

    pub fn from_stream(stream: TcpStream, timeouts: Timeouts) -> CoreResult<Self> {
        stream
            .set_read_timeout(Some(timeouts.read))
            .map_err(CoreError::Io)?;
        stream
            .set_write_timeout(Some(timeouts.write))
            .map_err(CoreError::Io)?;
        Ok(Self { stream })
    }

    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl StreamTransport for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> CoreResult<usize> {
        self.stream.read(buf).map_err(CoreError::Io)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> CoreResult<()> {
        self.stream.read_exact(buf).map_err(CoreError::Io)
    }

    fn write_all(&mut self, buf: &[u8]) -> CoreResult<()> {
        self.stream.write_all(buf).map_err(CoreError::Io)
    }

    fn shutdown(&mut self) -> CoreResult<()> {
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(CoreError::Io)
    }

    fn peer_addr(&self) -> CoreResult<SocketAddr> {
        self.stream.peer_addr().map_err(CoreError::Io)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> CoreResult<()> {
        self.stream.set_read_timeout(timeout).map_err(CoreError::Io)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> CoreResult<()> {
        self.stream
            .set_write_timeout(timeout)
            .map_err(CoreError::Io)
    }
}

#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
}

impl Clone for UdpTransport {
    fn clone(&self) -> Self {
        let socket = self.socket.try_clone().expect("clone udp");
        Self { socket }
    }
}

impl UdpTransport {
    pub fn bind(addr: SocketAddr) -> CoreResult<Self> {
        let socket = UdpSocket::bind(addr).map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub fn bind_any() -> CoreResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> CoreResult<()> {
        self.socket.set_read_timeout(timeout).map_err(CoreError::Io)
    }

    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> CoreResult<usize> {
        self.socket.send_to(data, addr).map_err(CoreError::Io)
    }

    pub fn recv_from(&self, max_bytes: usize) -> CoreResult<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; max_bytes];
        let (len, addr) = self.socket.recv_from(&mut buf).map_err(CoreError::Io)?;
        buf.truncate(len);
        Ok((buf, addr))
    }

    pub fn try_clone(&self) -> CoreResult<UdpSocket> {
        self.socket.try_clone().map_err(CoreError::Io)
    }
}

#[derive(Clone)]
pub struct TlsClientConfig {
    inner: Arc<ClientConfig>,
}

impl TlsClientConfig {
    pub fn with_webpki_roots() -> CoreResult<Self> {
        let mut root_store = RootCertStore::empty();
        root_store
            .roots
            .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Self {
            inner: Arc::new(config),
        })
    }

    pub fn with_root_certificates(certs: Vec<CertificateDer<'static>>) -> CoreResult<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(certs.into_iter());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Self {
            inner: Arc::new(config),
        })
    }

    pub fn inner(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.inner)
    }

    pub fn with_alpn(&self, protos: &[&[u8]]) -> Self {
        let mut cfg = (*self.inner).clone();
        cfg.alpn_protocols = protos.iter().map(|p| p.to_vec()).collect();
        Self {
            inner: Arc::new(cfg),
        }
    }
}

#[derive(Clone)]
pub struct TlsServerConfig {
    inner: Arc<ServerConfig>,
}

impl TlsServerConfig {
    pub fn from_der(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> CoreResult<Self> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| CoreError::Message(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(config),
        })
    }

    pub fn inner(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.inner)
    }

    pub fn with_alpn(&self, protos: &[&[u8]]) -> Self {
        let mut cfg = (*self.inner).clone();
        cfg.alpn_protocols = protos.iter().map(|p| p.to_vec()).collect();
        Self {
            inner: Arc::new(cfg),
        }
    }
}

pub fn load_certs_from_pem(path: &str) -> CoreResult<Vec<CertificateDer<'static>>> {
    let mut file = File::open(path).map_err(CoreError::Io)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(CoreError::Io)?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(buf));
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| CoreError::Message(err.to_string()))?;
    if certs.is_empty() {
        return Err(CoreError::Parse("no certificates found".to_string()));
    }
    Ok(certs)
}

pub fn load_private_key_from_pem(path: &str) -> CoreResult<PrivateKeyDer<'static>> {
    let mut file = File::open(path).map_err(CoreError::Io)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(CoreError::Io)?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(&buf));
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .transpose()
        .map_err(|err| CoreError::Message(err.to_string()))?
    {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(buf));
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .next()
        .transpose()
        .map_err(|err| CoreError::Message(err.to_string()))?
    {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }
    Err(CoreError::Parse("no private key found".to_string()))
}

pub enum TlsStreamTransport {
    Client(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    Server(rustls::StreamOwned<rustls::ServerConnection, TcpStream>),
}

impl TlsStreamTransport {
    pub fn connect(
        addr: &NetAddr,
        server_name: &str,
        config: &TlsClientConfig,
        timeouts: Timeouts,
    ) -> CoreResult<Self> {
        let mut last_err = None;
        for socket in addr.resolve()? {
            match TcpStream::connect_timeout(&socket, timeouts.connect) {
                Ok(stream) => {
                    stream
                        .set_read_timeout(Some(timeouts.read))
                        .map_err(CoreError::Io)?;
                    stream
                        .set_write_timeout(Some(timeouts.write))
                        .map_err(CoreError::Io)?;
                    let server_name = ServerName::try_from(server_name)
                        .map_err(|_| CoreError::Parse("invalid server name".to_string()))?;
                    let conn =
                        rustls::ClientConnection::new(config.inner(), server_name.to_owned())
                            .map_err(|err| CoreError::Message(err.to_string()))?;
                    return Ok(Self::Client(rustls::StreamOwned::new(conn, stream)));
                }
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err
            .map(CoreError::Io)
            .unwrap_or_else(|| CoreError::Parse("unable to connect".to_string())))
    }

    pub fn accept(
        listener: &TcpListener,
        config: &TlsServerConfig,
        timeouts: Timeouts,
    ) -> CoreResult<Self> {
        let (stream, _) = listener.accept().map_err(CoreError::Io)?;
        stream
            .set_read_timeout(Some(timeouts.read))
            .map_err(CoreError::Io)?;
        stream
            .set_write_timeout(Some(timeouts.write))
            .map_err(CoreError::Io)?;
        let conn = rustls::ServerConnection::new(config.inner())
            .map_err(|err| CoreError::Message(err.to_string()))?;
        Ok(Self::Server(rustls::StreamOwned::new(conn, stream)))
    }
}

impl StreamTransport for TlsStreamTransport {
    fn read(&mut self, buf: &mut [u8]) -> CoreResult<usize> {
        match self {
            Self::Client(stream) => stream.read(buf).map_err(CoreError::Io),
            Self::Server(stream) => stream.read(buf).map_err(CoreError::Io),
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> CoreResult<()> {
        match self {
            Self::Client(stream) => stream.read_exact(buf).map_err(CoreError::Io),
            Self::Server(stream) => stream.read_exact(buf).map_err(CoreError::Io),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> CoreResult<()> {
        match self {
            Self::Client(stream) => stream.write_all(buf).map_err(CoreError::Io),
            Self::Server(stream) => stream.write_all(buf).map_err(CoreError::Io),
        }
    }

    fn shutdown(&mut self) -> CoreResult<()> {
        match self {
            Self::Client(stream) => stream
                .get_ref()
                .shutdown(std::net::Shutdown::Both)
                .map_err(CoreError::Io),
            Self::Server(stream) => stream
                .get_ref()
                .shutdown(std::net::Shutdown::Both)
                .map_err(CoreError::Io),
        }
    }

    fn peer_addr(&self) -> CoreResult<SocketAddr> {
        match self {
            Self::Client(stream) => stream.get_ref().peer_addr().map_err(CoreError::Io),
            Self::Server(stream) => stream.get_ref().peer_addr().map_err(CoreError::Io),
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> CoreResult<()> {
        match self {
            Self::Client(stream) => stream
                .get_ref()
                .set_read_timeout(timeout)
                .map_err(CoreError::Io),
            Self::Server(stream) => stream
                .get_ref()
                .set_read_timeout(timeout)
                .map_err(CoreError::Io),
        }
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> CoreResult<()> {
        match self {
            Self::Client(stream) => stream
                .get_ref()
                .set_write_timeout(timeout)
                .map_err(CoreError::Io),
            Self::Server(stream) => stream
                .get_ref()
                .set_write_timeout(timeout)
                .map_err(CoreError::Io),
        }
    }
}

pub trait AsyncStreamTransport {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<usize>> + Send + 'a>>;
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>>;
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>>;
    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>>;
}

pub struct AsyncTcpTransport {
    stream: tokio::net::TcpStream,
}

impl AsyncTcpTransport {
    pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let mut last_err = None;
        for socket in addr.resolve()? {
            match tokio::time::timeout(timeouts.connect, tokio::net::TcpStream::connect(socket))
                .await
            {
                Ok(Ok(stream)) => {
                    stream.set_nodelay(true).map_err(CoreError::Io)?;
                    return Ok(Self { stream });
                }
                Ok(Err(err)) => last_err = Some(err),
                Err(_) => {
                    last_err = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "connect timeout",
                    ))
                }
            }
        }
        Err(last_err
            .map(CoreError::Io)
            .unwrap_or_else(|| CoreError::Parse("unable to connect".to_string())))
    }

    pub fn from_stream(stream: tokio::net::TcpStream) -> Self {
        Self { stream }
    }

    pub fn into_inner(self) -> tokio::net::TcpStream {
        self.stream
    }
}

impl AsyncStreamTransport for AsyncTcpTransport {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<usize>> + Send + 'a>> {
        Box::pin(async move { self.stream.read(buf).await.map_err(CoreError::Io) })
    }

    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move {
            self.stream
                .read_exact(buf)
                .await
                .map(|_| ())
                .map_err(CoreError::Io)
        })
    }

    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move { self.stream.write_all(buf).await.map_err(CoreError::Io) })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move { self.stream.shutdown().await.map_err(CoreError::Io) })
    }
}

pub struct AsyncUdpTransport {
    socket: tokio::net::UdpSocket,
}

impl AsyncUdpTransport {
    pub async fn bind(addr: SocketAddr) -> CoreResult<Self> {
        let socket = tokio::net::UdpSocket::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub async fn bind_any() -> CoreResult<Self> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(CoreError::Io)?;
        Ok(Self { socket })
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> CoreResult<usize> {
        self.socket.send_to(data, addr).await.map_err(CoreError::Io)
    }

    pub async fn recv_from(&self, max_bytes: usize) -> CoreResult<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; max_bytes];
        let (len, addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(CoreError::Io)?;
        buf.truncate(len);
        Ok((buf, addr))
    }
}

pub struct AsyncTlsClientTransport {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl AsyncTlsClientTransport {
    pub async fn connect(
        addr: &NetAddr,
        server_name: &str,
        config: &TlsClientConfig,
        timeouts: Timeouts,
    ) -> CoreResult<Self> {
        let tcp = AsyncTcpTransport::connect(addr, timeouts).await?;
        let server_name = ServerName::try_from(server_name)
            .map_err(|_| CoreError::Parse("invalid server name".to_string()))?
            .to_owned();
        let connector = TlsConnector::from(config.inner());
        let stream = connector
            .connect(server_name, tcp.stream)
            .await
            .map_err(|err| CoreError::Message(err.to_string()))?;
        Ok(Self { stream })
    }
}

impl AsyncStreamTransport for AsyncTlsClientTransport {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<usize>> + Send + 'a>> {
        Box::pin(async move { self.stream.read(buf).await.map_err(CoreError::Io) })
    }

    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move {
            self.stream
                .read_exact(buf)
                .await
                .map(|_| ())
                .map_err(CoreError::Io)
        })
    }

    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move { self.stream.write_all(buf).await.map_err(CoreError::Io) })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move { self.stream.shutdown().await.map_err(CoreError::Io) })
    }
}

pub struct AsyncTlsServerTransport {
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
}

impl AsyncTlsServerTransport {
    pub fn from_stream(stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Self {
        Self { stream }
    }
}

impl AsyncStreamTransport for AsyncTlsServerTransport {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<usize>> + Send + 'a>> {
        Box::pin(async move { self.stream.read(buf).await.map_err(CoreError::Io) })
    }

    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move {
            self.stream
                .read_exact(buf)
                .await
                .map(|_| ())
                .map_err(CoreError::Io)
        })
    }

    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move { self.stream.write_all(buf).await.map_err(CoreError::Io) })
    }

    fn shutdown<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = CoreResult<()>> + Send + 'a>> {
        Box::pin(async move { self.stream.shutdown().await.map_err(CoreError::Io) })
    }
}

#[derive(Clone)]
pub struct AsyncTlsServer {
    acceptor: TlsAcceptor,
}

impl AsyncTlsServer {
    pub fn new(config: &TlsServerConfig) -> Self {
        Self {
            acceptor: TlsAcceptor::from(config.inner()),
        }
    }

    pub async fn accept(
        &self,
        stream: tokio::net::TcpStream,
    ) -> CoreResult<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        self.acceptor
            .accept(stream)
            .await
            .map_err(|err| CoreError::Message(err.to_string()))
    }
}
