use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const UEL: &str = "\x1b%-12345X";
const READ_BUF: usize = 1024;

#[derive(Debug, Clone)]
pub struct PjlCommand {
    pub verb: String,
    pub args: Vec<String>,
    pub raw: String,
}

impl PjlCommand {
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        if !line.to_ascii_uppercase().starts_with("@PJL") {
            return None;
        }
        let mut parts = line.split_whitespace();
        let _ = parts.next();
        let verb = parts.next()?.to_string();
        let args = parts.map(|s| s.to_string()).collect::<Vec<_>>();
        Some(Self {
            verb,
            args,
            raw: line.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PjlResponse {
    pub lines: Vec<String>,
}

impl PjlResponse {
    pub fn ok() -> Self {
        Self {
            lines: vec!["@PJL OK".to_string()],
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            lines: vec![format!("@PJL ERROR {message}")],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for line in &self.lines {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct PjlServerConfig {
    pub timeouts: Timeouts,
    pub device_id: String,
    pub status: String,
    pub variables: HashMap<String, String>,
}

impl Default for PjlServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            device_id: "Moonlight Printer".to_string(),
            status: "READY".to_string(),
            variables: HashMap::new(),
        }
    }
}

pub struct PjlServer {
    listener: TcpListener,
    config: PjlServerConfig,
}

impl PjlServer {
    pub fn bind(addr: SocketAddr, config: PjlServerConfig) -> CoreResult<Self> {
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
                let _ = handle_pjl_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncPjlServer {
    listener: tokio::net::TcpListener,
    config: PjlServerConfig,
}

impl AsyncPjlServer {
    pub async fn bind(addr: SocketAddr, config: PjlServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_pjl_stream_async(stream, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct PjlClientConfig {
    pub timeouts: Timeouts,
}

impl Default for PjlClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct PjlClient {
    transport: TcpTransport,
    buffer: Vec<u8>,
}

impl PjlClient {
    pub fn connect(addr: &net::NetAddr, config: PjlClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self {
            transport,
            buffer: Vec::new(),
        })
    }

    pub fn send_command(&mut self, command: &str) -> CoreResult<PjlResponse> {
        let line = format!("@PJL {command}\r\n");
        self.transport.write_all(line.as_bytes())?;
        self.read_response()
    }

    pub fn info_id(&mut self) -> CoreResult<String> {
        let response = self.send_command("INFO ID")?;
        for line in response.lines {
            if let Some(value) = line.strip_prefix("@PJL INFO ID ") {
                return Ok(value.trim_matches('"').to_string());
            }
        }
        Err(CoreError::Parse("pjl missing id".to_string()))
    }

    fn read_response(&mut self) -> CoreResult<PjlResponse> {
        let mut lines = Vec::new();
        loop {
            match read_line(&mut self.transport, &mut self.buffer)? {
                Some(line) => {
                    if line.is_empty() {
                        break;
                    }
                    lines.push(line);
                    if lines.len() > 8 {
                        break;
                    }
                }
                None => break,
            }
        }
        Ok(PjlResponse { lines })
    }
}

pub struct AsyncPjlClient {
    transport: AsyncTcpTransport,
    buffer: Vec<u8>,
}

impl AsyncPjlClient {
    pub async fn connect(addr: &net::NetAddr, config: PjlClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self {
            transport,
            buffer: Vec::new(),
        })
    }

    pub async fn send_command(&mut self, command: &str) -> CoreResult<PjlResponse> {
        let line = format!("@PJL {command}\r\n");
        self.transport.write_all(line.as_bytes()).await?;
        self.read_response().await
    }

    pub async fn info_id(&mut self) -> CoreResult<String> {
        let response = self.send_command("INFO ID").await?;
        for line in response.lines {
            if let Some(value) = line.strip_prefix("@PJL INFO ID ") {
                return Ok(value.trim_matches('"').to_string());
            }
        }
        Err(CoreError::Parse("pjl missing id".to_string()))
    }

    async fn read_response(&mut self) -> CoreResult<PjlResponse> {
        let mut lines = Vec::new();
        loop {
            match read_line_async(&mut self.transport, &mut self.buffer).await? {
                Some(line) => {
                    if line.is_empty() {
                        break;
                    }
                    lines.push(line);
                    if lines.len() > 8 {
                        break;
                    }
                }
                None => break,
            }
        }
        Ok(PjlResponse { lines })
    }
}

fn handle_pjl_stream(stream: TcpStream, mut config: PjlServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let mut buffer = Vec::new();
    loop {
        let line = match read_line(&mut transport, &mut buffer)? {
            Some(line) => line,
            None => return Ok(()),
        };
        if line.contains(UEL) {
            config.variables.clear();
            continue;
        }
        let Some(command) = PjlCommand::parse(&line) else {
            continue;
        };
        let response = handle_command(&mut config, &command);
        transport.write_all(&response.to_bytes())?;
    }
}

async fn handle_pjl_stream_async(stream: tokio::net::TcpStream, mut config: PjlServerConfig) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut buffer = Vec::new();
    loop {
        let line = match read_line_async(&mut transport, &mut buffer).await? {
            Some(line) => line,
            None => return Ok(()),
        };
        if line.contains(UEL) {
            config.variables.clear();
            continue;
        }
        let Some(command) = PjlCommand::parse(&line) else {
            continue;
        };
        let response = handle_command(&mut config, &command);
        transport.write_all(&response.to_bytes()).await?;
    }
}

fn handle_command(config: &mut PjlServerConfig, command: &PjlCommand) -> PjlResponse {
    let verb = command.verb.to_ascii_uppercase();
    match verb.as_str() {
        "INFO" => {
            if let Some(arg) = command.args.get(0) {
                match arg.to_ascii_uppercase().as_str() {
                    "ID" => PjlResponse {
                        lines: vec![format!("@PJL INFO ID \"{}\"", config.device_id)],
                    },
                    "STATUS" => PjlResponse {
                        lines: vec![format!("@PJL INFO STATUS \"{}\"", config.status)],
                    },
                    _ => PjlResponse::error("unsupported info"),
                }
            } else {
                PjlResponse::error("missing info arg")
            }
        }
        "SET" => {
            let rest = command.args.join(" ");
            if let Some((key, value)) = rest.split_once('=') {
                config.variables.insert(key.to_string(), value.to_string());
                PjlResponse::ok()
            } else {
                PjlResponse::error("invalid set")
            }
        }
        "RESET" => {
            config.variables.clear();
            PjlResponse::ok()
        }
        "ECHO" => {
            let msg = command.args.join(" ");
            PjlResponse {
                lines: vec![format!("@PJL {msg}")],
            }
        }
        "JOB" => PjlResponse::ok(),
        "EOJ" => PjlResponse::ok(),
        _ => PjlResponse::error("unsupported command"),
    }
}

fn read_line<T: StreamTransport>(transport: &mut T, buffer: &mut Vec<u8>) -> CoreResult<Option<String>> {
    loop {
        if let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
            let line = buffer.drain(..=pos).collect::<Vec<_>>();
            let text = String::from_utf8_lossy(&line);
            return Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()));
        }
        let mut temp = [0u8; READ_BUF];
        let read = match transport.read(&mut temp) {
            Ok(read) => read,
            Err(CoreError::Io(err))
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&temp[..read]);
    }
}

async fn read_line_async<T: AsyncStreamTransport>(
    transport: &mut T,
    buffer: &mut Vec<u8>,
) -> CoreResult<Option<String>> {
    loop {
        if let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
            let line = buffer.drain(..=pos).collect::<Vec<_>>();
            let text = String::from_utf8_lossy(&line);
            return Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()));
        }
        let mut temp = [0u8; READ_BUF];
        let read = transport.read(&mut temp).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&temp[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pjl_info_id() {
        let server = crate::skip_if_perm!(PjlServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            PjlServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = PjlClient::connect(&net::NetAddr::from_socket(addr), PjlClientConfig::default()).unwrap();
        let device = client.info_id().unwrap();
        assert_eq!(device, "Moonlight Printer");
    }
}
