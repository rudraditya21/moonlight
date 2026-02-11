use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

pub const SOCKS5_DEFAULT_PORT: u16 = 1080;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5AuthMethod {
    NoAuth = 0x00,
    UserPass = 0x02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5Address {
    IpV4(Ipv4Addr),
    IpV6(Ipv6Addr),
    Domain(String),
}

impl Socks5Address {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Socks5Address::IpV4(addr) => {
                out.push(0x01);
                out.extend_from_slice(&addr.octets());
            }
            Socks5Address::Domain(name) => {
                out.push(0x03);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
            }
            Socks5Address::IpV6(addr) => {
                out.push(0x04);
                out.extend_from_slice(&addr.octets());
            }
        }
    }

    fn decode(data: &[u8], idx: &mut usize) -> CoreResult<Self> {
        if *idx >= data.len() {
            return Err(CoreError::Parse("socks5 address eof".to_string()));
        }
        let atyp = data[*idx];
        *idx += 1;
        match atyp {
            0x01 => {
                if *idx + 4 > data.len() {
                    return Err(CoreError::Parse("socks5 ipv4".to_string()));
                }
                let addr =
                    Ipv4Addr::new(data[*idx], data[*idx + 1], data[*idx + 2], data[*idx + 3]);
                *idx += 4;
                Ok(Socks5Address::IpV4(addr))
            }
            0x03 => {
                if *idx >= data.len() {
                    return Err(CoreError::Parse("socks5 domain len".to_string()));
                }
                let len = data[*idx] as usize;
                *idx += 1;
                if *idx + len > data.len() {
                    return Err(CoreError::Parse("socks5 domain".to_string()));
                }
                let name = String::from_utf8_lossy(&data[*idx..*idx + len]).to_string();
                *idx += len;
                Ok(Socks5Address::Domain(name))
            }
            0x04 => {
                if *idx + 16 > data.len() {
                    return Err(CoreError::Parse("socks5 ipv6".to_string()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[*idx..*idx + 16]);
                *idx += 16;
                Ok(Socks5Address::IpV6(Ipv6Addr::from(octets)))
            }
            _ => Err(CoreError::Parse("socks5 unknown address".to_string())),
        }
    }

    fn to_socket_addrs(&self, port: u16) -> CoreResult<Vec<SocketAddr>> {
        match self {
            Socks5Address::IpV4(addr) => Ok(vec![SocketAddr::new(IpAddr::V4(*addr), port)]),
            Socks5Address::IpV6(addr) => Ok(vec![SocketAddr::new(IpAddr::V6(*addr), port)]),
            Socks5Address::Domain(name) => {
                let addrs = (name.as_str(), port)
                    .to_socket_addrs()
                    .map_err(CoreError::Io)?
                    .collect::<Vec<_>>();
                if addrs.is_empty() {
                    return Err(CoreError::Parse("socks5 resolve failed".to_string()));
                }
                Ok(addrs)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Socks5ClientConfig {
    pub timeouts: Timeouts,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for Socks5ClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: None,
            password: None,
        }
    }
}

pub struct Socks5Client {
    transport: TcpTransport,
}

impl Socks5Client {
    pub fn connect(
        proxy: &net::NetAddr,
        target: Socks5Address,
        port: u16,
        config: Socks5ClientConfig,
    ) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(proxy, config.timeouts)?;
        let methods = if config.username.is_some() {
            vec![0x00, 0x02]
        } else {
            vec![0x00]
        };
        let mut hello = Vec::with_capacity(2 + methods.len());
        hello.push(0x05);
        hello.push(methods.len() as u8);
        hello.extend_from_slice(&methods);
        transport.write_all(&hello)?;
        let mut resp = [0u8; 2];
        transport.read_exact(&mut resp)?;
        if resp[0] != 0x05 || resp[1] == 0xFF {
            return Err(CoreError::Message("socks5 no acceptable auth".to_string()));
        }
        if resp[1] == Socks5AuthMethod::UserPass as u8 {
            let username = config.username.unwrap_or_default();
            let password = config.password.unwrap_or_default();
            let mut auth = Vec::new();
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            transport.write_all(&auth)?;
            let mut auth_resp = [0u8; 2];
            transport.read_exact(&mut auth_resp)?;
            if auth_resp[1] != 0x00 {
                return Err(CoreError::Message("socks5 auth failed".to_string()));
            }
        }

        let mut req = Vec::new();
        req.push(0x05);
        req.push(Socks5Command::Connect as u8);
        req.push(0x00);
        target.encode(&mut req);
        req.extend_from_slice(&port.to_be_bytes());
        transport.write_all(&req)?;
        let mut header = [0u8; 4];
        transport.read_exact(&mut header)?;
        if header[0] != 0x05 {
            return Err(CoreError::Parse("socks5 response".to_string()));
        }
        if header[1] != 0x00 {
            return Err(CoreError::Message(format!(
                "socks5 connect failed: {}",
                header[1]
            )));
        }
        let _ = read_address(&mut transport, header[3])?;
        let mut port_buf = [0u8; 2];
        transport.read_exact(&mut port_buf)?;
        Ok(Self { transport })
    }

    pub fn into_stream(self) -> TcpStream {
        self.transport.into_inner()
    }
}

pub struct AsyncSocks5Client {
    transport: AsyncTcpTransport,
}

impl AsyncSocks5Client {
    pub async fn connect(
        proxy: &net::NetAddr,
        target: Socks5Address,
        port: u16,
        config: Socks5ClientConfig,
    ) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(proxy, config.timeouts).await?;
        let methods = if config.username.is_some() {
            vec![0x00, 0x02]
        } else {
            vec![0x00]
        };
        let mut hello = Vec::with_capacity(2 + methods.len());
        hello.push(0x05);
        hello.push(methods.len() as u8);
        hello.extend_from_slice(&methods);
        transport.write_all(&hello).await?;
        let mut resp = [0u8; 2];
        transport.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] == 0xFF {
            return Err(CoreError::Message("socks5 no acceptable auth".to_string()));
        }
        if resp[1] == Socks5AuthMethod::UserPass as u8 {
            let username = config.username.unwrap_or_default();
            let password = config.password.unwrap_or_default();
            let mut auth = Vec::new();
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            transport.write_all(&auth).await?;
            let mut auth_resp = [0u8; 2];
            transport.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err(CoreError::Message("socks5 auth failed".to_string()));
            }
        }

        let mut req = Vec::new();
        req.push(0x05);
        req.push(Socks5Command::Connect as u8);
        req.push(0x00);
        target.encode(&mut req);
        req.extend_from_slice(&port.to_be_bytes());
        transport.write_all(&req).await?;
        let mut header = [0u8; 4];
        transport.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            return Err(CoreError::Parse("socks5 response".to_string()));
        }
        if header[1] != 0x00 {
            return Err(CoreError::Message(format!(
                "socks5 connect failed: {}",
                header[1]
            )));
        }
        let _ = read_address_async(&mut transport, header[3]).await?;
        let mut port_buf = [0u8; 2];
        transport.read_exact(&mut port_buf).await?;
        Ok(Self { transport })
    }

    pub fn into_stream(self) -> tokio::net::TcpStream {
        self.transport.into_inner()
    }
}

#[derive(Debug, Clone)]
pub struct Socks5ServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
}

impl Default for Socks5ServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: HashMap::new(),
        }
    }
}

pub struct Socks5Server {
    listener: TcpListener,
    config: Socks5ServerConfig,
}

impl Socks5Server {
    pub fn bind(addr: SocketAddr, config: Socks5ServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_socks5_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncSocks5Server {
    listener: tokio::net::TcpListener,
    config: Socks5ServerConfig,
}

impl AsyncSocks5Server {
    pub async fn bind(addr: SocketAddr, config: Socks5ServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_socks5_stream_async(stream, config).await;
            });
        }
    }
}

fn handle_socks5_stream(stream: TcpStream, config: Socks5ServerConfig) -> CoreResult<()> {
    let timeouts = config.timeouts;
    let mut transport = TcpTransport::from_stream(stream, timeouts)?;

    let mut hello = [0u8; 2];
    transport.read_exact(&mut hello)?;
    if hello[0] != 0x05 {
        return Err(CoreError::Parse("socks5 bad version".to_string()));
    }
    let nmethods = hello[1] as usize;
    let mut methods = vec![0u8; nmethods];
    transport.read_exact(&mut methods)?;
    let reply = if config.users.is_empty() {
        if methods.contains(&(Socks5AuthMethod::NoAuth as u8)) {
            Socks5AuthMethod::NoAuth as u8
        } else {
            0xFF
        }
    } else if methods.contains(&(Socks5AuthMethod::UserPass as u8)) {
        Socks5AuthMethod::UserPass as u8
    } else {
        0xFF
    };
    transport.write_all(&[0x05, reply])?;
    if reply == 0xFF {
        return Ok(());
    }
    if reply == Socks5AuthMethod::UserPass as u8 {
        if !handle_userpass(&mut transport, &config.users)? {
            return Ok(());
        }
    }

    let mut header = [0u8; 4];
    transport.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(CoreError::Parse("socks5 request".to_string()));
    }
    let command = header[1];
    let address = read_address(&mut transport, header[3])?;
    let mut port_buf = [0u8; 2];
    transport.read_exact(&mut port_buf)?;
    let port = u16::from_be_bytes(port_buf);

    if command != Socks5Command::Connect as u8 {
        send_reply(
            &mut transport,
            0x07,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )?;
        return Ok(());
    }

    let remote = match connect_target(&address, port, timeouts.connect) {
        Ok(stream) => stream,
        Err(_) => {
            send_reply(
                &mut transport,
                0x05,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )?;
            return Ok(());
        }
    };
    let bound = remote.local_addr().map_err(CoreError::Io)?;
    send_reply(&mut transport, 0x00, bound)?;

    relay_streams(transport.into_inner(), remote);
    Ok(())
}

async fn handle_socks5_stream_async(
    stream: tokio::net::TcpStream,
    config: Socks5ServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut hello = [0u8; 2];
    transport.read_exact(&mut hello).await?;
    if hello[0] != 0x05 {
        return Err(CoreError::Parse("socks5 bad version".to_string()));
    }
    let nmethods = hello[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        transport.read_exact(&mut methods).await?;
    }
    let reply = if config.users.is_empty() {
        if methods.contains(&(Socks5AuthMethod::NoAuth as u8)) {
            Socks5AuthMethod::NoAuth as u8
        } else {
            0xFF
        }
    } else if methods.contains(&(Socks5AuthMethod::UserPass as u8)) {
        Socks5AuthMethod::UserPass as u8
    } else {
        0xFF
    };
    transport.write_all(&[0x05, reply]).await?;
    if reply == 0xFF {
        return Ok(());
    }
    if reply == Socks5AuthMethod::UserPass as u8 {
        if !handle_userpass_async(&mut transport, &config.users).await? {
            return Ok(());
        }
    }

    let mut header = [0u8; 4];
    transport.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(CoreError::Parse("socks5 request".to_string()));
    }
    let command = header[1];
    let address = read_address_async(&mut transport, header[3]).await?;
    let mut port_buf = [0u8; 2];
    transport.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    if command != Socks5Command::Connect as u8 {
        send_reply_async(
            &mut transport,
            0x07,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await?;
        return Ok(());
    }

    let remote = match connect_target_async(&address, port).await {
        Ok(stream) => stream,
        Err(_) => {
            send_reply_async(
                &mut transport,
                0x05,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await?;
            return Ok(());
        }
    };
    let bound = remote.local_addr().map_err(CoreError::Io)?;
    send_reply_async(&mut transport, 0x00, bound).await?;

    let client = transport.into_inner();
    relay_streams_async(client, remote).await?;
    Ok(())
}

fn handle_userpass<T: StreamTransport>(
    transport: &mut T,
    users: &HashMap<String, String>,
) -> CoreResult<bool> {
    let mut header = [0u8; 2];
    transport.read_exact(&mut header)?;
    if header[0] != 0x01 {
        transport.write_all(&[0x01, 0x01])?;
        return Ok(false);
    }
    let ulen = header[1] as usize;
    let mut uname = vec![0u8; ulen];
    transport.read_exact(&mut uname)?;
    let mut plen = [0u8; 1];
    transport.read_exact(&mut plen)?;
    let plen = plen[0] as usize;
    let mut pass = vec![0u8; plen];
    transport.read_exact(&mut pass)?;
    let username = String::from_utf8_lossy(&uname).to_string();
    let password = String::from_utf8_lossy(&pass).to_string();
    let ok = users
        .get(&username)
        .map(|p| p == &password)
        .unwrap_or(false);
    let status = if ok { 0x00 } else { 0x01 };
    transport.write_all(&[0x01, status])?;
    Ok(ok)
}

async fn handle_userpass_async<T: AsyncStreamTransport>(
    transport: &mut T,
    users: &HashMap<String, String>,
) -> CoreResult<bool> {
    let mut header = [0u8; 2];
    transport.read_exact(&mut header).await?;
    if header[0] != 0x01 {
        transport.write_all(&[0x01, 0x01]).await?;
        return Ok(false);
    }
    let ulen = header[1] as usize;
    let mut uname = vec![0u8; ulen];
    transport.read_exact(&mut uname).await?;
    let mut plen = [0u8; 1];
    transport.read_exact(&mut plen).await?;
    let plen = plen[0] as usize;
    let mut pass = vec![0u8; plen];
    transport.read_exact(&mut pass).await?;
    let username = String::from_utf8_lossy(&uname).to_string();
    let password = String::from_utf8_lossy(&pass).to_string();
    let ok = users
        .get(&username)
        .map(|p| p == &password)
        .unwrap_or(false);
    let status = if ok { 0x00 } else { 0x01 };
    transport.write_all(&[0x01, status]).await?;
    Ok(ok)
}

fn send_reply<T: StreamTransport>(transport: &mut T, code: u8, bind: SocketAddr) -> CoreResult<()> {
    let mut resp = Vec::new();
    resp.push(0x05);
    resp.push(code);
    resp.push(0x00);
    match bind {
        SocketAddr::V4(addr) => {
            resp.push(0x01);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            resp.push(0x04);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    transport.write_all(&resp)
}

async fn send_reply_async<T: AsyncStreamTransport>(
    transport: &mut T,
    code: u8,
    bind: SocketAddr,
) -> CoreResult<()> {
    let mut resp = Vec::new();
    resp.push(0x05);
    resp.push(code);
    resp.push(0x00);
    match bind {
        SocketAddr::V4(addr) => {
            resp.push(0x01);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            resp.push(0x04);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    transport.write_all(&resp).await
}

fn connect_target(address: &Socks5Address, port: u16, timeout: Duration) -> CoreResult<TcpStream> {
    for addr in address.to_socket_addrs(port)? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                stream.set_nodelay(true).map_err(CoreError::Io)?;
                return Ok(stream);
            }
            Err(_) => continue,
        }
    }
    Err(CoreError::Message("socks5 connect failed".to_string()))
}

async fn connect_target_async(
    address: &Socks5Address,
    port: u16,
) -> CoreResult<tokio::net::TcpStream> {
    let addrs = address.to_socket_addrs(port)?;
    for addr in addrs {
        if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
            stream.set_nodelay(true).map_err(CoreError::Io)?;
            return Ok(stream);
        }
    }
    Err(CoreError::Message("socks5 connect failed".to_string()))
}

fn read_address<T: StreamTransport>(transport: &mut T, atyp: u8) -> CoreResult<Socks5Address> {
    let mut buf = vec![atyp];
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            transport.read_exact(&mut addr)?;
            buf.extend_from_slice(&addr);
        }
        0x03 => {
            let mut len = [0u8; 1];
            transport.read_exact(&mut len)?;
            let len = len[0] as usize;
            buf.push(len as u8);
            let mut name = vec![0u8; len];
            transport.read_exact(&mut name)?;
            buf.extend_from_slice(&name);
        }
        0x04 => {
            let mut addr = [0u8; 16];
            transport.read_exact(&mut addr)?;
            buf.extend_from_slice(&addr);
        }
        _ => return Err(CoreError::Parse("socks5 address type".to_string())),
    }
    let mut idx = 0usize;
    Socks5Address::decode(&buf, &mut idx)
}

async fn read_address_async<T: AsyncStreamTransport>(
    transport: &mut T,
    atyp: u8,
) -> CoreResult<Socks5Address> {
    let mut buf = vec![atyp];
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            transport.read_exact(&mut addr).await?;
            buf.extend_from_slice(&addr);
        }
        0x03 => {
            let mut len = [0u8; 1];
            transport.read_exact(&mut len).await?;
            let len = len[0] as usize;
            buf.push(len as u8);
            let mut name = vec![0u8; len];
            transport.read_exact(&mut name).await?;
            buf.extend_from_slice(&name);
        }
        0x04 => {
            let mut addr = [0u8; 16];
            transport.read_exact(&mut addr).await?;
            buf.extend_from_slice(&addr);
        }
        _ => return Err(CoreError::Parse("socks5 address type".to_string())),
    }
    let mut idx = 0usize;
    Socks5Address::decode(&buf, &mut idx)
}

fn relay_streams(mut client: TcpStream, mut remote: TcpStream) {
    let mut client_clone = client.try_clone().ok();
    let mut remote_clone = remote.try_clone().ok();
    let handle = thread::spawn(move || {
        if let (Some(mut c), Some(mut r)) = (client_clone.take(), remote_clone.take()) {
            let _ = std::io::copy(&mut c, &mut r);
            let _ = r.shutdown(std::net::Shutdown::Write);
        }
    });
    let _ = std::io::copy(&mut remote, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = handle.join();
}

async fn relay_streams_async(
    mut client: tokio::net::TcpStream,
    mut remote: tokio::net::TcpStream,
) -> CoreResult<()> {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut remote)
        .await
        .map_err(CoreError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::fuzz_bytes;

    #[test]
    fn socks5_no_auth_handshake() {
        let server = crate::skip_if_perm!(Socks5Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            Socks5ServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let proxy = net::NetAddr::from_socket(addr);
        let client = Socks5Client::connect(
            &proxy,
            Socks5Address::IpV4(Ipv4Addr::new(127, 0, 0, 1)),
            7,
            Socks5ClientConfig::default(),
        );
        assert!(client.is_err());
    }

    #[test]
    fn socks5_decode_negative() {
        let mut idx = 0usize;
        assert!(Socks5Address::decode(&[], &mut idx).is_err());
    }

    #[test]
    fn socks5_decode_fuzz() {
        fuzz_bytes(128, 256, 0x50A5, |data| {
            let mut idx = 0usize;
            let _ = Socks5Address::decode(data, &mut idx);
        });
    }
}
