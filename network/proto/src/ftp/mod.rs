use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const READ_BUFFER: usize = 8 * 1024;
const DEFAULT_GREETING: &str = "220 moonlight ftp ready";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpResponse {
    pub code: u16,
    pub message: String,
}

impl FtpResponse {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn to_line(&self) -> String {
        format!("{} {}\r\n", self.code, self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpCommand {
    pub name: String,
    pub argument: Option<String>,
}

impl FtpCommand {
    pub fn parse(line: &str) -> CoreResult<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        let mut parts = line.splitn(2, ' ');
        let name = parts
            .next()
            .ok_or_else(|| CoreError::Parse("empty command".to_string()))?
            .to_ascii_uppercase();
        let argument = parts.next().map(|s| s.to_string());
        Ok(Self { name, argument })
    }

    pub fn format(&self) -> String {
        if let Some(arg) = &self.argument {
            format!("{} {}\r\n", self.name, arg)
        } else {
            format!("{}\r\n", self.name)
        }
    }
}

#[derive(Debug, Clone)]
pub struct FtpClientConfig {
    pub timeouts: Timeouts,
}

impl Default for FtpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct FtpClient {
    transport: TcpTransport,
    buffer: LineBuffer,
}

impl FtpClient {
    pub fn connect(addr: &NetAddr, config: FtpClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self {
            transport,
            buffer: LineBuffer::new(),
        })
    }

    pub fn read_response(&mut self) -> CoreResult<FtpResponse> {
        let line = self.buffer.read_line(&mut self.transport)?;
        parse_response(&line)
    }

    pub fn send_command(&mut self, cmd: &FtpCommand) -> CoreResult<()> {
        let line = cmd.format();
        self.transport.write_all(line.as_bytes())
    }

    pub fn command(&mut self, name: &str, argument: Option<&str>) -> CoreResult<FtpResponse> {
        let cmd = FtpCommand {
            name: name.to_ascii_uppercase(),
            argument: argument.map(|s| s.to_string()),
        };
        self.send_command(&cmd)?;
        self.read_response()
    }

    pub fn login(&mut self, user: &str, pass: &str) -> CoreResult<()> {
        let resp = self.command("USER", Some(user))?;
        if resp.code == 230 {
            return Ok(());
        }
        if resp.code != 331 {
            return Err(CoreError::Message(resp.message));
        }
        let resp = self.command("PASS", Some(pass))?;
        if resp.code != 230 {
            return Err(CoreError::Message(resp.message));
        }
        Ok(())
    }

    pub fn list(&mut self, path: Option<&str>) -> CoreResult<Vec<String>> {
        let data = self.enter_pasv()?;
        let resp = self.command("LIST", path)?;
        if resp.code >= 400 {
            return Err(CoreError::Message(resp.message));
        }
        let lines = read_data_lines(data)?;
        if resp.code == 125 || resp.code == 150 {
            let final_resp = self.read_response()?;
            if final_resp.code >= 400 {
                return Err(CoreError::Message(final_resp.message));
            }
        }
        Ok(lines)
    }

    pub fn retr(&mut self, path: &str) -> CoreResult<Vec<u8>> {
        let data = self.enter_pasv()?;
        let resp = self.command("RETR", Some(path))?;
        if resp.code >= 400 {
            return Err(CoreError::Message(resp.message));
        }
        let bytes = read_data_bytes(data)?;
        if resp.code == 125 || resp.code == 150 {
            let final_resp = self.read_response()?;
            if final_resp.code >= 400 {
                return Err(CoreError::Message(final_resp.message));
            }
        }
        Ok(bytes)
    }

    pub fn stor(&mut self, path: &str, data: &[u8]) -> CoreResult<()> {
        let mut stream = self.enter_pasv()?;
        let resp = self.command("STOR", Some(path))?;
        if resp.code >= 400 {
            return Err(CoreError::Message(resp.message));
        }
        stream.write_all(data)?;
        drop(stream);
        if resp.code == 125 || resp.code == 150 {
            let final_resp = self.read_response()?;
            if final_resp.code >= 400 {
                return Err(CoreError::Message(final_resp.message));
            }
        }
        Ok(())
    }

    pub fn enter_pasv(&mut self) -> CoreResult<TcpTransport> {
        let resp = self.command("PASV", None)?;
        if resp.code != 227 {
            return Err(CoreError::Message(resp.message));
        }
        let addr = parse_pasv_response(&resp.message)?;
        TcpTransport::connect(&NetAddr::from_socket(addr), Timeouts::default())
    }
}

#[derive(Debug, Clone)]
pub struct AsyncFtpClientConfig {
    pub timeouts: Timeouts,
}

impl Default for AsyncFtpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct AsyncFtpClient {
    transport: AsyncTcpTransport,
    buffer: AsyncLineBuffer,
}

impl AsyncFtpClient {
    pub async fn connect(addr: &NetAddr, config: AsyncFtpClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self {
            transport,
            buffer: AsyncLineBuffer::new(),
        })
    }

    pub async fn read_response(&mut self) -> CoreResult<FtpResponse> {
        let line = self.buffer.read_line(&mut self.transport).await?;
        parse_response(&line)
    }

    pub async fn send_command(&mut self, cmd: &FtpCommand) -> CoreResult<()> {
        let line = cmd.format();
        self.transport.write_all(line.as_bytes()).await
    }

    pub async fn command(&mut self, name: &str, argument: Option<&str>) -> CoreResult<FtpResponse> {
        let cmd = FtpCommand {
            name: name.to_ascii_uppercase(),
            argument: argument.map(|s| s.to_string()),
        };
        self.send_command(&cmd).await?;
        self.read_response().await
    }

    pub async fn login(&mut self, user: &str, pass: &str) -> CoreResult<()> {
        let resp = self.command("USER", Some(user)).await?;
        if resp.code == 230 {
            return Ok(());
        }
        if resp.code != 331 {
            return Err(CoreError::Message(resp.message));
        }
        let resp = self.command("PASS", Some(pass)).await?;
        if resp.code != 230 {
            return Err(CoreError::Message(resp.message));
        }
        Ok(())
    }

    pub async fn list(&mut self, path: Option<&str>) -> CoreResult<Vec<String>> {
        let data = self.enter_pasv().await?;
        let resp = self.command("LIST", path).await?;
        if resp.code >= 400 {
            return Err(CoreError::Message(resp.message));
        }
        let lines = read_data_lines_async(data).await?;
        if resp.code == 125 || resp.code == 150 {
            let final_resp = self.read_response().await?;
            if final_resp.code >= 400 {
                return Err(CoreError::Message(final_resp.message));
            }
        }
        Ok(lines)
    }

    pub async fn retr(&mut self, path: &str) -> CoreResult<Vec<u8>> {
        let data = self.enter_pasv().await?;
        let resp = self.command("RETR", Some(path)).await?;
        if resp.code >= 400 {
            return Err(CoreError::Message(resp.message));
        }
        let bytes = read_data_bytes_async(data).await?;
        if resp.code == 125 || resp.code == 150 {
            let final_resp = self.read_response().await?;
            if final_resp.code >= 400 {
                return Err(CoreError::Message(final_resp.message));
            }
        }
        Ok(bytes)
    }

    pub async fn stor(&mut self, path: &str, data: &[u8]) -> CoreResult<()> {
        let mut stream = self.enter_pasv().await?;
        let resp = self.command("STOR", Some(path)).await?;
        if resp.code >= 400 {
            return Err(CoreError::Message(resp.message));
        }
        stream.write_all(data).await?;
        drop(stream);
        if resp.code == 125 || resp.code == 150 {
            let final_resp = self.read_response().await?;
            if final_resp.code >= 400 {
                return Err(CoreError::Message(final_resp.message));
            }
        }
        Ok(())
    }

    pub async fn enter_pasv(&mut self) -> CoreResult<AsyncTcpTransport> {
        let resp = self.command("PASV", None).await?;
        if resp.code != 227 {
            return Err(CoreError::Message(resp.message));
        }
        let addr = parse_pasv_response(&resp.message)?;
        AsyncTcpTransport::connect(&NetAddr::from_socket(addr), Timeouts::default()).await
    }
}

#[derive(Debug, Clone)]
pub struct FtpServerConfig {
    pub timeouts: Timeouts,
    pub greeting: String,
    pub passive_range: (u16, u16),
    pub allow_anonymous: bool,
}

impl Default for FtpServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            greeting: DEFAULT_GREETING.to_string(),
            passive_range: (40000, 40100),
            allow_anonymous: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FtpSession {
    pub user: Option<String>,
    pub authed: bool,
    pub cwd: String,
}

impl Default for FtpSession {
    fn default() -> Self {
        Self {
            user: None,
            authed: false,
            cwd: "/".to_string(),
        }
    }
}

pub trait FtpBackend: Send + Sync {
    fn validate_user(&self, user: &str, pass: &str) -> CoreResult<bool>;
    fn list(&self, cwd: &str, path: Option<&str>) -> CoreResult<Vec<String>>;
    fn retrieve(&self, cwd: &str, path: &str) -> CoreResult<Vec<u8>>;
    fn store(&self, cwd: &str, path: &str, data: &[u8]) -> CoreResult<()>;
}

#[derive(Debug, Default)]
pub struct InMemoryFtpBackend {
    files: Mutex<HashMap<String, Vec<u8>>>,
    users: HashMap<String, String>,
}

impl InMemoryFtpBackend {
    pub fn with_user(mut self, user: &str, pass: &str) -> Self {
        self.users.insert(user.to_string(), pass.to_string());
        self
    }

    pub fn with_file(self, path: &str, data: Vec<u8>) -> Self {
        let mut guard = self.files.lock().expect("files");
        guard.insert(normalize_path(path), data);
        drop(guard);
        self
    }
}

impl FtpBackend for InMemoryFtpBackend {
    fn validate_user(&self, user: &str, pass: &str) -> CoreResult<bool> {
        if self.users.is_empty() {
            return Ok(true);
        }
        Ok(self.users.get(user).map(|p| p == pass).unwrap_or(false))
    }

    fn list(&self, cwd: &str, path: Option<&str>) -> CoreResult<Vec<String>> {
        let path = resolve_path(cwd, path.unwrap_or(""));
        let guard = self.files.lock().map_err(|_| CoreError::Message("files poisoned".to_string()))?;
        let mut out = Vec::new();
        for key in guard.keys() {
            if key.starts_with(&path) {
                out.push(key.clone());
            }
        }
        if out.is_empty() {
            out.push(path);
        }
        Ok(out)
    }

    fn retrieve(&self, cwd: &str, path: &str) -> CoreResult<Vec<u8>> {
        let path = resolve_path(cwd, path);
        let guard = self.files.lock().map_err(|_| CoreError::Message("files poisoned".to_string()))?;
        guard
            .get(&path)
            .cloned()
            .ok_or_else(|| CoreError::Message("file not found".to_string()))
    }

    fn store(&self, cwd: &str, path: &str, data: &[u8]) -> CoreResult<()> {
        let path = resolve_path(cwd, path);
        let mut guard = self.files.lock().map_err(|_| CoreError::Message("files poisoned".to_string()))?;
        guard.insert(path, data.to_vec());
        Ok(())
    }
}

pub struct FtpServer {
    listener: TcpListener,
    backend: Arc<dyn FtpBackend>,
    config: FtpServerConfig,
}

impl FtpServer {
    pub fn bind(addr: SocketAddr, config: FtpServerConfig, backend: Arc<dyn FtpBackend>) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            backend,
            config,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let backend = Arc::clone(&self.backend);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_control_session(stream, backend, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncFtpServer {
    listener: tokio::net::TcpListener,
    backend: Arc<dyn FtpBackend>,
    config: FtpServerConfig,
}

impl AsyncFtpServer {
    pub async fn bind(addr: SocketAddr, config: FtpServerConfig, backend: Arc<dyn FtpBackend>) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            backend,
            config,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let backend = Arc::clone(&self.backend);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_control_session_async(stream, backend, config).await;
            });
        }
    }
}

fn handle_control_session(
    stream: TcpStream,
    backend: Arc<dyn FtpBackend>,
    config: FtpServerConfig,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let mut buffer = LineBuffer::new();
    transport.write_all(format!("{}\r\n", config.greeting).as_bytes())?;

    let mut session = FtpSession::default();
    let mut pending_data: Option<DataListener> = None;

    loop {
        let line = match buffer.read_line(&mut transport) {
            Ok(line) => line,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => return Ok(()),
            Err(err) => return Err(err),
        };
        let cmd = FtpCommand::parse(&line)?;
        if is_data_command(&cmd) {
            handle_data_command(&cmd, &mut session, &backend, &mut pending_data, &mut transport)?;
            continue;
        }
        let response = handle_command(&cmd, &mut session, &backend, &config, &mut pending_data)?;
        if let Some(resp) = response {
            transport.write_all(resp.to_line().as_bytes())?;
            if resp.code == 221 {
                break;
            }
        }
    }
    Ok(())
}

async fn handle_control_session_async(
    stream: tokio::net::TcpStream,
    backend: Arc<dyn FtpBackend>,
    config: FtpServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut buffer = AsyncLineBuffer::new();
    transport.write_all(format!("{}\r\n", config.greeting).as_bytes()).await?;

    let mut session = FtpSession::default();
    let mut pending_data: Option<AsyncDataListener> = None;

    loop {
        let line = match buffer.read_line(&mut transport).await {
            Ok(line) => line,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => return Ok(()),
            Err(err) => return Err(err),
        };
        let cmd = FtpCommand::parse(&line)?;
        if is_data_command(&cmd) {
            handle_data_command_async(&cmd, &mut session, &backend, &mut pending_data, &mut transport).await?;
            continue;
        }
        let response = handle_command_async(&cmd, &mut session, &backend, &config, &mut pending_data).await?;
        if let Some(resp) = response {
            transport.write_all(resp.to_line().as_bytes()).await?;
            if resp.code == 221 {
                break;
            }
        }
    }
    Ok(())
}

fn is_data_command(cmd: &FtpCommand) -> bool {
    matches!(cmd.name.as_str(), "LIST" | "RETR" | "STOR")
}

fn handle_data_command(
    cmd: &FtpCommand,
    session: &mut FtpSession,
    backend: &Arc<dyn FtpBackend>,
    pending_data: &mut Option<DataListener>,
    transport: &mut TcpTransport,
) -> CoreResult<()> {
    if !session.authed {
        let resp = FtpResponse::new(530, "Not logged in");
        transport.write_all(resp.to_line().as_bytes())?;
        return Ok(());
    }
    let listener = match pending_data.take() {
        Some(listener) => listener,
        None => {
            let resp = FtpResponse::new(425, "Use PASV first");
            transport.write_all(resp.to_line().as_bytes())?;
            return Ok(());
        }
    };
    match cmd.name.as_str() {
        "LIST" => {
            let listing = backend.list(&session.cwd, cmd.argument.as_deref())?;
            transport.write_all(FtpResponse::new(150, "Opening data connection").to_line().as_bytes())?;
            let mut data_stream = listener.accept()?;
            for line in listing {
                data_stream.write_all(format!("{}\r\n", line).as_bytes())?;
            }
            transport.write_all(FtpResponse::new(226, "Transfer complete").to_line().as_bytes())?;
        }
        "RETR" => {
            let path = cmd.argument.clone().unwrap_or_default();
            let data = backend.retrieve(&session.cwd, &path)?;
            transport.write_all(FtpResponse::new(150, "Opening data connection").to_line().as_bytes())?;
            let mut data_stream = listener.accept()?;
            data_stream.write_all(&data)?;
            transport.write_all(FtpResponse::new(226, "Transfer complete").to_line().as_bytes())?;
        }
        "STOR" => {
            let path = cmd.argument.clone().unwrap_or_default();
            transport.write_all(FtpResponse::new(150, "Opening data connection").to_line().as_bytes())?;
            let data = read_data_bytes(listener.accept()?)?;
            match backend.store(&session.cwd, &path, &data) {
                Ok(()) => {
                    transport.write_all(FtpResponse::new(226, "Transfer complete").to_line().as_bytes())?;
                }
                Err(err) => {
                    transport.write_all(FtpResponse::new(550, err.to_string()).to_line().as_bytes())?;
                }
            }
        }
        _ => {
            transport.write_all(FtpResponse::new(502, "Command not implemented").to_line().as_bytes())?;
        }
    }
    Ok(())
}

async fn handle_data_command_async(
    cmd: &FtpCommand,
    session: &mut FtpSession,
    backend: &Arc<dyn FtpBackend>,
    pending_data: &mut Option<AsyncDataListener>,
    transport: &mut AsyncTcpTransport,
) -> CoreResult<()> {
    if !session.authed {
        let resp = FtpResponse::new(530, "Not logged in");
        transport.write_all(resp.to_line().as_bytes()).await?;
        return Ok(());
    }
    let listener = match pending_data.take() {
        Some(listener) => listener,
        None => {
            let resp = FtpResponse::new(425, "Use PASV first");
            transport.write_all(resp.to_line().as_bytes()).await?;
            return Ok(());
        }
    };
    match cmd.name.as_str() {
        "LIST" => {
            let listing = backend.list(&session.cwd, cmd.argument.as_deref())?;
            transport.write_all(FtpResponse::new(150, "Opening data connection").to_line().as_bytes()).await?;
            let mut data_stream = listener.accept().await?;
            for line in listing {
                data_stream.write_all(format!("{}\r\n", line).as_bytes()).await?;
            }
            transport.write_all(FtpResponse::new(226, "Transfer complete").to_line().as_bytes()).await?;
        }
        "RETR" => {
            let path = cmd.argument.clone().unwrap_or_default();
            let data = backend.retrieve(&session.cwd, &path)?;
            transport.write_all(FtpResponse::new(150, "Opening data connection").to_line().as_bytes()).await?;
            let mut data_stream = listener.accept().await?;
            data_stream.write_all(&data).await?;
            transport.write_all(FtpResponse::new(226, "Transfer complete").to_line().as_bytes()).await?;
        }
        "STOR" => {
            let path = cmd.argument.clone().unwrap_or_default();
            transport.write_all(FtpResponse::new(150, "Opening data connection").to_line().as_bytes()).await?;
            let data = read_data_bytes_async(listener.accept().await?).await?;
            match backend.store(&session.cwd, &path, &data) {
                Ok(()) => {
                    transport.write_all(FtpResponse::new(226, "Transfer complete").to_line().as_bytes()).await?;
                }
                Err(err) => {
                    transport.write_all(FtpResponse::new(550, err.to_string()).to_line().as_bytes()).await?;
                }
            }
        }
        _ => {
            transport.write_all(FtpResponse::new(502, "Command not implemented").to_line().as_bytes()).await?;
        }
    }
    Ok(())
}

fn handle_command(
    cmd: &FtpCommand,
    session: &mut FtpSession,
    backend: &Arc<dyn FtpBackend>,
    config: &FtpServerConfig,
    pending_data: &mut Option<DataListener>,
) -> CoreResult<Option<FtpResponse>> {
    let name = cmd.name.as_str();
    match name {
        "USER" => {
            session.user = cmd.argument.clone();
            session.authed = false;
            Ok(Some(FtpResponse::new(331, "User name okay, need password")))
        }
        "PASS" => {
            let user = session.user.clone().unwrap_or_default();
            let pass = cmd.argument.clone().unwrap_or_default();
            if config.allow_anonymous && user.eq_ignore_ascii_case("anonymous") {
                session.authed = true;
                return Ok(Some(FtpResponse::new(230, "Login successful")));
            }
            if backend.validate_user(&user, &pass)? {
                session.authed = true;
                Ok(Some(FtpResponse::new(230, "Login successful")))
            } else {
                Ok(Some(FtpResponse::new(530, "Login incorrect")))
            }
        }
        "SYST" => Ok(Some(FtpResponse::new(215, "UNIX Type: L8"))),
        "FEAT" => Ok(Some(FtpResponse::new(211, "no-features"))),
        "PWD" => Ok(Some(FtpResponse::new(257, format!("\"{}\"", session.cwd)))),
        "CWD" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            if let Some(path) = cmd.argument.as_deref() {
                session.cwd = resolve_path(&session.cwd, path);
                Ok(Some(FtpResponse::new(250, "Directory changed")))
            } else {
                Ok(Some(FtpResponse::new(501, "Missing path")))
            }
        }
        "TYPE" => Ok(Some(FtpResponse::new(200, "Type set"))),
        "PASV" => {
            let listener = DataListener::bind(config.passive_range)?;
            let addr = listener.addr();
            let response = format!("Entering Passive Mode ({})", format_pasv(addr));
            *pending_data = Some(listener);
            Ok(Some(FtpResponse::new(227, response)))
        }
        "LIST" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            let listener = pending_data.take().ok_or_else(|| CoreError::Message("PASV required".to_string()))?;
            let path = cmd.argument.as_deref();
            let listing = backend.list(&session.cwd, path)?;
            let mut data_stream = listener.accept()?;
            for line in listing {
                data_stream.write_all(format!("{}\r\n", line).as_bytes())?;
            }
            Ok(Some(FtpResponse::new(226, "Transfer complete")))
        }
        "RETR" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            let listener = pending_data.take().ok_or_else(|| CoreError::Message("PASV required".to_string()))?;
            let path = cmd.argument.clone().ok_or_else(|| CoreError::Message("Missing path".to_string()))?;
            let data = backend.retrieve(&session.cwd, &path)?;
            let mut data_stream = listener.accept()?;
            data_stream.write_all(&data)?;
            Ok(Some(FtpResponse::new(226, "Transfer complete")))
        }
        "STOR" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            let listener = pending_data.take().ok_or_else(|| CoreError::Message("PASV required".to_string()))?;
            let path = cmd.argument.clone().ok_or_else(|| CoreError::Message("Missing path".to_string()))?;
            let data = read_data_bytes(listener.accept()?)?;
            backend.store(&session.cwd, &path, &data)?;
            Ok(Some(FtpResponse::new(226, "Transfer complete")))
        }
        "QUIT" => Ok(Some(FtpResponse::new(221, "Goodbye"))),
        _ => Ok(Some(FtpResponse::new(502, "Command not implemented"))),
    }
}

async fn handle_command_async(
    cmd: &FtpCommand,
    session: &mut FtpSession,
    backend: &Arc<dyn FtpBackend>,
    config: &FtpServerConfig,
    pending_data: &mut Option<AsyncDataListener>,
) -> CoreResult<Option<FtpResponse>> {
    let name = cmd.name.as_str();
    match name {
        "USER" => {
            session.user = cmd.argument.clone();
            session.authed = false;
            Ok(Some(FtpResponse::new(331, "User name okay, need password")))
        }
        "PASS" => {
            let user = session.user.clone().unwrap_or_default();
            let pass = cmd.argument.clone().unwrap_or_default();
            if config.allow_anonymous && user.eq_ignore_ascii_case("anonymous") {
                session.authed = true;
                return Ok(Some(FtpResponse::new(230, "Login successful")));
            }
            if backend.validate_user(&user, &pass)? {
                session.authed = true;
                Ok(Some(FtpResponse::new(230, "Login successful")))
            } else {
                Ok(Some(FtpResponse::new(530, "Login incorrect")))
            }
        }
        "SYST" => Ok(Some(FtpResponse::new(215, "UNIX Type: L8"))),
        "FEAT" => Ok(Some(FtpResponse::new(211, "no-features"))),
        "PWD" => Ok(Some(FtpResponse::new(257, format!("\"{}\"", session.cwd)))),
        "CWD" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            if let Some(path) = cmd.argument.as_deref() {
                session.cwd = resolve_path(&session.cwd, path);
                Ok(Some(FtpResponse::new(250, "Directory changed")))
            } else {
                Ok(Some(FtpResponse::new(501, "Missing path")))
            }
        }
        "TYPE" => Ok(Some(FtpResponse::new(200, "Type set"))),
        "PASV" => {
            let listener = AsyncDataListener::bind(config.passive_range).await?;
            let addr = listener.addr();
            let response = format!("Entering Passive Mode ({})", format_pasv(addr));
            *pending_data = Some(listener);
            Ok(Some(FtpResponse::new(227, response)))
        }
        "LIST" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            let listener = pending_data.take().ok_or_else(|| CoreError::Message("PASV required".to_string()))?;
            let path = cmd.argument.as_deref();
            let listing = backend.list(&session.cwd, path)?;
            let mut data_stream = listener.accept().await?;
            for line in listing {
                data_stream.write_all(format!("{}\r\n", line).as_bytes()).await?;
            }
            Ok(Some(FtpResponse::new(226, "Transfer complete")))
        }
        "RETR" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            let listener = pending_data.take().ok_or_else(|| CoreError::Message("PASV required".to_string()))?;
            let path = cmd.argument.clone().ok_or_else(|| CoreError::Message("Missing path".to_string()))?;
            let data = backend.retrieve(&session.cwd, &path)?;
            let mut data_stream = listener.accept().await?;
            data_stream.write_all(&data).await?;
            Ok(Some(FtpResponse::new(226, "Transfer complete")))
        }
        "STOR" => {
            if !session.authed {
                return Ok(Some(FtpResponse::new(530, "Not logged in")));
            }
            let listener = pending_data.take().ok_or_else(|| CoreError::Message("PASV required".to_string()))?;
            let path = cmd.argument.clone().ok_or_else(|| CoreError::Message("Missing path".to_string()))?;
            let data = read_data_bytes_async(listener.accept().await?).await?;
            backend.store(&session.cwd, &path, &data)?;
            Ok(Some(FtpResponse::new(226, "Transfer complete")))
        }
        "QUIT" => Ok(Some(FtpResponse::new(221, "Goodbye"))),
        _ => Ok(Some(FtpResponse::new(502, "Command not implemented"))),
    }
}

struct DataListener {
    listener: TcpListener,
}

impl DataListener {
    fn bind(range: (u16, u16)) -> CoreResult<Self> {
        let (start, end) = range;
        for port in start..=end {
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
            if let Ok(listener) = TcpListener::bind(addr) {
                return Ok(Self { listener });
            }
        }
        Err(CoreError::Message("no available data port".to_string()))
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap_or_else(|_| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
    }

    fn accept(self) -> CoreResult<TcpTransport> {
        let (stream, _) = self.listener.accept().map_err(CoreError::Io)?;
        TcpTransport::from_stream(stream, Timeouts::default())
    }
}

struct AsyncDataListener {
    listener: tokio::net::TcpListener,
}

impl AsyncDataListener {
    async fn bind(range: (u16, u16)) -> CoreResult<Self> {
        let (start, end) = range;
        for port in start..=end {
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
            if let Ok(listener) = tokio::net::TcpListener::bind(addr).await {
                return Ok(Self { listener });
            }
        }
        Err(CoreError::Message("no available data port".to_string()))
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap_or_else(|_| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
    }

    async fn accept(self) -> CoreResult<AsyncTcpTransport> {
        let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
        Ok(AsyncTcpTransport::from_stream(stream))
    }
}

struct LineBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl LineBuffer {
    fn new() -> Self {
        Self {
            buf: vec![0u8; READ_BUFFER],
            start: 0,
            end: 0,
        }
    }

    fn read_line<T: StreamTransport>(&mut self, transport: &mut T) -> CoreResult<String> {
        loop {
            if let Some(pos) = find_crlf(&self.buf[self.start..self.end]) {
                let end = self.start + pos;
                let line = self.buf[self.start..end].to_vec();
                self.start = end + 2;
                return Ok(String::from_utf8_lossy(&line).to_string());
            }
            if self.fill(transport)? == 0 {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
        }
    }

    fn fill<T: StreamTransport>(&mut self, transport: &mut T) -> CoreResult<usize> {
        if self.start > 0 {
            let len = self.end - self.start;
            self.buf.copy_within(self.start..self.end, 0);
            self.start = 0;
            self.end = len;
        }
        if self.end == self.buf.len() {
            self.buf.resize(self.buf.len() * 2, 0);
        }
        let read = transport.read(&mut self.buf[self.end..])?;
        self.end += read;
        Ok(read)
    }
}

struct AsyncLineBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl AsyncLineBuffer {
    fn new() -> Self {
        Self {
            buf: vec![0u8; READ_BUFFER],
            start: 0,
            end: 0,
        }
    }

    async fn read_line<T: AsyncStreamTransport>(&mut self, transport: &mut T) -> CoreResult<String> {
        loop {
            if let Some(pos) = find_crlf(&self.buf[self.start..self.end]) {
                let end = self.start + pos;
                let line = self.buf[self.start..end].to_vec();
                self.start = end + 2;
                return Ok(String::from_utf8_lossy(&line).to_string());
            }
            if self.fill(transport).await? == 0 {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
        }
    }

    async fn fill<T: AsyncStreamTransport>(&mut self, transport: &mut T) -> CoreResult<usize> {
        if self.start > 0 {
            let len = self.end - self.start;
            self.buf.copy_within(self.start..self.end, 0);
            self.start = 0;
            self.end = len;
        }
        if self.end == self.buf.len() {
            self.buf.resize(self.buf.len() * 2, 0);
        }
        let read = transport.read(&mut self.buf[self.end..]).await?;
        self.end += read;
        Ok(read)
    }
}

fn parse_response(line: &str) -> CoreResult<FtpResponse> {
    if line.len() < 3 {
        return Err(CoreError::Parse("invalid response".to_string()));
    }
    let code = line[..3]
        .parse::<u16>()
        .map_err(|_| CoreError::Parse("invalid response code".to_string()))?;
    let message = line[3..].trim().to_string();
    Ok(FtpResponse { code, message })
}

fn parse_pasv_response(message: &str) -> CoreResult<SocketAddr> {
    let start = message.find('(').ok_or_else(|| CoreError::Parse("invalid PASV response".to_string()))? + 1;
    let end = message[start..].find(')').ok_or_else(|| CoreError::Parse("invalid PASV response".to_string()))? + start;
    let parts: Vec<u16> = message[start..end]
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();
    if parts.len() != 6 {
        return Err(CoreError::Parse("invalid PASV response".to_string()));
    }
    let ip = Ipv4Addr::new(parts[0] as u8, parts[1] as u8, parts[2] as u8, parts[3] as u8);
    let port = (parts[4] << 8) | parts[5];
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

fn format_pasv(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => {
            let ip = v4.ip().octets();
            let port = v4.port();
            format!("{},{},{},{},{},{}", ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xff)
        }
        SocketAddr::V6(_) => "127,0,0,1,0,0".to_string(),
    }
}

fn read_data_lines(mut stream: TcpTransport) -> CoreResult<Vec<String>> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        };
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buf);
    Ok(text.lines().map(|l| l.to_string()).collect())
}

fn read_data_bytes(mut stream: TcpTransport) -> CoreResult<Vec<u8>> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        };
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(buf)
}

async fn read_data_lines_async(mut stream: AsyncTcpTransport) -> CoreResult<Vec<String>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let text = String::from_utf8_lossy(&buf);
    Ok(text.lines().map(|l| l.to_string()).collect())
}

async fn read_data_bytes_async(mut stream: AsyncTcpTransport) -> CoreResult<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(buf)
}

fn resolve_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        normalize_path(path)
    } else {
        normalize_path(&format!("{}/{}", cwd.trim_end_matches('/'), path))
    }
}

fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    for i in 0..(data.len() - 1) {
        if data[i] == b'\r' && data[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pasv() {
        let msg = "Entering Passive Mode (127,0,0,1,195,80)";
        let addr = parse_pasv_response(msg).unwrap();
        assert_eq!(addr, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 50000)));
    }

    #[test]
    fn command_roundtrip() {
        let cmd = FtpCommand::parse("USER test\r\n").unwrap();
        assert_eq!(cmd.name, "USER");
        assert_eq!(cmd.argument.as_deref(), Some("test"));
        let line = cmd.format();
        assert_eq!(line, "USER test\r\n");
    }

    #[test]
    fn server_client_roundtrip() {
        let mut client_config = FtpClientConfig::default();
        client_config.timeouts.read = std::time::Duration::from_secs(20);
        let backend = Arc::new(InMemoryFtpBackend::default().with_user("user", "pass").with_file(
            "/file.txt",
            b"data".to_vec(),
        ));
        let server_config = FtpServerConfig::default();
        let server = match FtpServer::bind("127.0.0.1:0".parse().unwrap(), server_config, backend) {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {err:?}"),
        };
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = FtpClient::connect(&NetAddr::from_socket(addr), client_config).unwrap();
        let _ = client.read_response().unwrap();
        client.login("user", "pass").unwrap();
        let list = client.list(None).unwrap();
        assert!(list.iter().any(|l| l.contains("/file.txt")));
        let data = client.retr("/file.txt").unwrap();
        assert_eq!(data, b"data".to_vec());
        client.stor("/new.txt", b"hello").unwrap();
    }
}
