use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use corelib::error::{CoreError, CoreResult};

use crate::address::NetAddr;

#[derive(Debug)]
pub struct TcpClient {
    stream: TcpStream,
}

impl TcpClient {
    pub fn connect(addr: &NetAddr) -> CoreResult<Self> {
        let mut last_err = None;
        for socket in addr.resolve()? {
            match TcpStream::connect(socket) {
                Ok(stream) => return Ok(TcpClient { stream }),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err
            .map(CoreError::Io)
            .unwrap_or_else(|| CoreError::Parse("unable to connect".to_string())))
    }

    pub fn connect_timeout(addr: &NetAddr, timeout: Duration) -> CoreResult<Self> {
        let mut last_err = None;
        for socket in addr.resolve()? {
            match TcpStream::connect_timeout(&socket, timeout) {
                Ok(stream) => return Ok(TcpClient { stream }),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err
            .map(CoreError::Io)
            .unwrap_or_else(|| CoreError::Parse("unable to connect".to_string())))
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> CoreResult<()> {
        self.stream.set_read_timeout(timeout).map_err(CoreError::Io)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> CoreResult<()> {
        self.stream
            .set_write_timeout(timeout)
            .map_err(CoreError::Io)
    }

    pub fn peer_addr(&self) -> CoreResult<SocketAddr> {
        self.stream.peer_addr().map_err(CoreError::Io)
    }

    pub fn send_all(&mut self, data: &[u8]) -> CoreResult<()> {
        self.stream.write_all(data).map_err(CoreError::Io)
    }

    pub fn recv_exact(&mut self, len: usize) -> CoreResult<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).map_err(CoreError::Io)?;
        Ok(buf)
    }

    pub fn recv_to_end(&mut self, max_bytes: usize) -> CoreResult<Vec<u8>> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = self.stream.read(&mut chunk).map_err(CoreError::Io)?;
            if read == 0 {
                break;
            }
            if buf.len() + read > max_bytes {
                return Err(CoreError::Parse(
                    "response exceeds maximum size".to_string(),
                ));
            }
            buf.extend_from_slice(&chunk[..read]);
        }
        Ok(buf)
    }
}

#[derive(Debug)]
pub struct UdpClient {
    socket: UdpSocket,
}

impl UdpClient {
    pub fn bind_any() -> CoreResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(CoreError::Io)?;
        Ok(UdpClient { socket })
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
}
