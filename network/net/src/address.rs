use std::net::{SocketAddr, ToSocketAddrs};

use corelib::error::{CoreError, CoreResult};

#[derive(Debug, Clone)]
pub struct NetAddr {
    pub host: String,
    pub port: u16,
}

impl NetAddr {
    pub fn new(host: &str, port: u16) -> Self {
        NetAddr {
            host: host.to_string(),
            port,
        }
    }

    pub fn parse(input: &str) -> CoreResult<Self> {
        if input.starts_with('[') {
            let end = input
                .find(']')
                .ok_or_else(|| CoreError::Parse("invalid IPv6 bracket".to_string()))?;
            let host = &input[1..end];
            let port_part = input.get(end + 1..).unwrap_or("");
            let port = port_part
                .strip_prefix(':')
                .ok_or_else(|| CoreError::Parse("missing port".to_string()))?
                .parse()
                .map_err(|_| CoreError::Parse("invalid port".to_string()))?;
            return Ok(NetAddr::new(host, port));
        }

        let mut parts = input.rsplitn(2, ':');
        let port = parts
            .next()
            .ok_or_else(|| CoreError::Parse("missing port".to_string()))?
            .parse()
            .map_err(|_| CoreError::Parse("invalid port".to_string()))?;
        let host = parts
            .next()
            .ok_or_else(|| CoreError::Parse("missing host".to_string()))?;
        Ok(NetAddr::new(host, port))
    }

    pub fn resolve(&self) -> CoreResult<Vec<SocketAddr>> {
        let addr = format!("{}:{}", self.host, self.port);
        let resolved: Vec<SocketAddr> = addr.to_socket_addrs().map_err(CoreError::Io)?.collect();
        if resolved.is_empty() {
            return Err(CoreError::Parse("unable to resolve address".to_string()));
        }
        Ok(resolved)
    }
}
