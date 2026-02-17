use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

pub const TELNET_DEFAULT_PORT: u16 = 23;

pub const SE: u8 = 240;
pub const NOP: u8 = 241;
pub const DM: u8 = 242;
pub const BRK: u8 = 243;
pub const IP: u8 = 244;
pub const AO: u8 = 245;
pub const AYT: u8 = 246;
pub const EC: u8 = 247;
pub const EL: u8 = 248;
pub const GA: u8 = 249;
pub const SB: u8 = 250;
pub const WILL: u8 = 251;
pub const WONT: u8 = 252;
pub const DO: u8 = 253;
pub const DONT: u8 = 254;
pub const IAC: u8 = 255;

pub const OPT_BINARY: u8 = 0;
pub const OPT_ECHO: u8 = 1;
pub const OPT_SUPPRESS_GO_AHEAD: u8 = 3;
pub const OPT_STATUS: u8 = 5;
pub const OPT_TERM_TYPE: u8 = 24;
pub const OPT_NAWS: u8 = 31;
pub const NEW_ENVIRON: u8 = 39;

pub const NEW_ENVIRON_IS: u8 = 0;
pub const NEW_ENVIRON_SEND: u8 = 1;
pub const NEW_ENVIRON_INFO: u8 = 2;

pub const NEW_ENVIRON_VAR: u8 = 0;
pub const NEW_ENVIRON_VALUE: u8 = 1;
pub const NEW_ENVIRON_ESC: u8 = 2;
pub const NEW_ENVIRON_USERVAR: u8 = 3;

const READ_BUF: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelnetNegotiationCommand {
    Do,
    Dont,
    Will,
    Wont,
}

impl TelnetNegotiationCommand {
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            DO => Some(Self::Do),
            DONT => Some(Self::Dont),
            WILL => Some(Self::Will),
            WONT => Some(Self::Wont),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            Self::Do => DO,
            Self::Dont => DONT,
            Self::Will => WILL,
            Self::Wont => WONT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelnetEvent {
    Data(Vec<u8>),
    Negotiation {
        command: TelnetNegotiationCommand,
        option: u8,
    },
    Subnegotiation {
        option: u8,
        data: Vec<u8>,
    },
    Command(u8),
}

#[derive(Debug, Clone)]
enum ParseState {
    Data,
    Iac,
    NegotiationCommand(u8),
    SubnegotiationOption,
    SubnegotiationData {
        option: u8,
        data: Vec<u8>,
        saw_iac: bool,
    },
}

#[derive(Debug, Clone)]
pub struct TelnetParser {
    state: ParseState,
    data_buf: Vec<u8>,
}

impl TelnetParser {
    pub fn new() -> Self {
        Self {
            state: ParseState::Data,
            data_buf: Vec::new(),
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Vec<TelnetEvent> {
        let mut events = Vec::new();
        for &byte in input {
            match &mut self.state {
                ParseState::Data => {
                    if byte == IAC {
                        flush_data(&mut self.data_buf, &mut events);
                        self.state = ParseState::Iac;
                    } else {
                        self.data_buf.push(byte);
                    }
                }
                ParseState::Iac => {
                    if byte == IAC {
                        self.data_buf.push(IAC);
                        self.state = ParseState::Data;
                    } else if byte == SB {
                        self.state = ParseState::SubnegotiationOption;
                    } else if matches!(byte, DO | DONT | WILL | WONT) {
                        self.state = ParseState::NegotiationCommand(byte);
                    } else {
                        events.push(TelnetEvent::Command(byte));
                        self.state = ParseState::Data;
                    }
                }
                ParseState::NegotiationCommand(cmd) => {
                    if let Some(command) = TelnetNegotiationCommand::from_byte(*cmd) {
                        events.push(TelnetEvent::Negotiation {
                            command,
                            option: byte,
                        });
                    }
                    self.state = ParseState::Data;
                }
                ParseState::SubnegotiationOption => {
                    self.state = ParseState::SubnegotiationData {
                        option: byte,
                        data: Vec::new(),
                        saw_iac: false,
                    };
                }
                ParseState::SubnegotiationData {
                    option,
                    data,
                    saw_iac,
                } => {
                    if *saw_iac {
                        if byte == IAC {
                            data.push(IAC);
                            *saw_iac = false;
                        } else if byte == SE {
                            let event = TelnetEvent::Subnegotiation {
                                option: *option,
                                data: data.clone(),
                            };
                            events.push(event);
                            self.state = ParseState::Data;
                        } else {
                            data.push(IAC);
                            data.push(byte);
                            *saw_iac = false;
                        }
                    } else if byte == IAC {
                        *saw_iac = true;
                    } else {
                        data.push(byte);
                    }
                }
            }
        }
        flush_data(&mut self.data_buf, &mut events);
        events
    }
}

impl Default for TelnetParser {
    fn default() -> Self {
        Self::new()
    }
}

fn flush_data(buf: &mut Vec<u8>, events: &mut Vec<TelnetEvent>) {
    if buf.is_empty() {
        return;
    }
    let data = std::mem::take(buf);
    events.push(TelnetEvent::Data(data));
}

pub fn build_negotiation(command: TelnetNegotiationCommand, option: u8) -> [u8; 3] {
    [IAC, command.as_byte(), option]
}

pub fn default_client_negotiation_reply(
    command: TelnetNegotiationCommand,
    option: u8,
) -> Option<[u8; 3]> {
    match command {
        TelnetNegotiationCommand::Do if option == NEW_ENVIRON => Some([IAC, WILL, option]),
        TelnetNegotiationCommand::Do => Some([IAC, WONT, option]),
        TelnetNegotiationCommand::Will => Some([IAC, DO, option]),
        _ => None,
    }
}

pub fn default_server_negotiation_reply(
    command: TelnetNegotiationCommand,
    option: u8,
) -> Option<[u8; 3]> {
    match command {
        TelnetNegotiationCommand::Will => Some([IAC, DO, option]),
        TelnetNegotiationCommand::Do => Some([IAC, WONT, option]),
        _ => None,
    }
}

pub fn build_subnegotiation(option: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(IAC);
    out.push(SB);
    out.push(option);
    out.extend_from_slice(&escape_iac(payload));
    out.push(IAC);
    out.push(SE);
    out
}

pub fn build_new_environ_user_is(user_value: &str) -> Vec<u8> {
    let vars = [("USER", user_value)];
    build_new_environ_is(&vars)
}

pub fn build_new_environ_is(vars: &[(&str, &str)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(NEW_ENVIRON_IS);
    for (name, value) in vars {
        payload.push(NEW_ENVIRON_VAR);
        push_new_environ_text(&mut payload, name.as_bytes());
        payload.push(NEW_ENVIRON_VALUE);
        push_new_environ_text(&mut payload, value.as_bytes());
    }
    build_subnegotiation(NEW_ENVIRON, &payload)
}

pub fn build_new_environ_send(vars: &[&str]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(NEW_ENVIRON_SEND);
    for name in vars {
        payload.push(NEW_ENVIRON_VAR);
        push_new_environ_text(&mut payload, name.as_bytes());
    }
    build_subnegotiation(NEW_ENVIRON, &payload)
}

pub fn is_new_environ_send(data: &[u8]) -> bool {
    matches!(data.first(), Some(&NEW_ENVIRON_SEND))
}

pub fn parse_new_environ(data: &[u8]) -> CoreResult<(u8, HashMap<String, String>)> {
    let Some(&kind) = data.first() else {
        return Err(CoreError::Parse("NEW-ENVIRON payload is empty".to_string()));
    };
    let mut vars = HashMap::new();
    let mut have_var = false;
    let mut in_value = false;
    let mut name = Vec::new();
    let mut value = Vec::new();

    let mut i = 1usize;
    while i < data.len() {
        match data[i] {
            NEW_ENVIRON_VAR | NEW_ENVIRON_USERVAR => {
                commit_new_environ_var(&mut vars, have_var, &name, &value);
                have_var = true;
                in_value = false;
                name.clear();
                value.clear();
                i += 1;
            }
            NEW_ENVIRON_VALUE => {
                in_value = true;
                i += 1;
            }
            NEW_ENVIRON_ESC => {
                i += 1;
                if i < data.len() && have_var {
                    if in_value {
                        value.push(data[i]);
                    } else {
                        name.push(data[i]);
                    }
                }
                i += 1;
            }
            byte => {
                if have_var {
                    if in_value {
                        value.push(byte);
                    } else {
                        name.push(byte);
                    }
                }
                i += 1;
            }
        }
    }

    commit_new_environ_var(&mut vars, have_var, &name, &value);
    Ok((kind, vars))
}

fn commit_new_environ_var(
    vars: &mut HashMap<String, String>,
    have_var: bool,
    name: &[u8],
    value: &[u8],
) {
    if !have_var || name.is_empty() {
        return;
    }
    let key = String::from_utf8_lossy(name).to_string();
    let val = String::from_utf8_lossy(value).to_string();
    vars.insert(key, val);
}

fn push_new_environ_text(out: &mut Vec<u8>, text: &[u8]) {
    for &b in text {
        if matches!(
            b,
            NEW_ENVIRON_VAR | NEW_ENVIRON_VALUE | NEW_ENVIRON_ESC | NEW_ENVIRON_USERVAR
        ) {
            out.push(NEW_ENVIRON_ESC);
        }
        out.push(b);
    }
}

pub fn escape_iac(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct EchoSuppressor {
    waiting_for_newline: bool,
}

impl EchoSuppressor {
    pub fn new() -> Self {
        Self {
            waiting_for_newline: false,
        }
    }

    pub fn note_local_input(&mut self, input: &[u8]) {
        if input.iter().any(|b| *b == b'\n' || *b == b'\r') {
            self.waiting_for_newline = true;
        }
    }

    pub fn filter_incoming(&mut self, input: &[u8]) -> Vec<u8> {
        if !self.waiting_for_newline {
            return input.to_vec();
        }
        if let Some(idx) = input.iter().position(|b| *b == b'\n' || *b == b'\r') {
            self.waiting_for_newline = false;
            return input[idx + 1..].to_vec();
        }
        Vec::new()
    }
}

impl Default for EchoSuppressor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
enum AnsiState {
    Plain,
    EscSeen,
    Csi,
}

#[derive(Debug, Clone)]
pub struct AnsiStripper {
    state: AnsiState,
}

impl AnsiStripper {
    pub fn new() -> Self {
        Self {
            state: AnsiState::Plain,
        }
    }

    pub fn strip(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            match self.state {
                AnsiState::Plain => {
                    if b == 0x1b {
                        self.state = AnsiState::EscSeen;
                    } else {
                        out.push(b);
                    }
                }
                AnsiState::EscSeen => {
                    if b == b'[' {
                        self.state = AnsiState::Csi;
                    } else {
                        out.push(0x1b);
                        if b == 0x1b {
                            self.state = AnsiState::EscSeen;
                        } else {
                            out.push(b);
                            self.state = AnsiState::Plain;
                        }
                    }
                }
                AnsiState::Csi => {
                    if (0x40..=0x7e).contains(&b) {
                        self.state = AnsiState::Plain;
                    }
                }
            }
        }
        out
    }
}

impl Default for AnsiStripper {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct TelnetOutputFilter {
    pub strip_ansi: bool,
    pub suppress_echo: bool,
    ansi: AnsiStripper,
    echo: EchoSuppressor,
}

impl TelnetOutputFilter {
    pub fn new(strip_ansi: bool, suppress_echo: bool) -> Self {
        Self {
            strip_ansi,
            suppress_echo,
            ansi: AnsiStripper::new(),
            echo: EchoSuppressor::new(),
        }
    }

    pub fn note_local_input(&mut self, input: &[u8]) {
        if self.suppress_echo {
            self.echo.note_local_input(input);
        }
    }

    pub fn process_incoming(&mut self, input: &[u8]) -> Vec<u8> {
        let mut data = input.to_vec();
        if self.strip_ansi {
            data = self.ansi.strip(&data);
        }
        if self.suppress_echo {
            data = self.echo.filter_incoming(&data);
        }
        data
    }
}

#[derive(Debug, Clone)]
pub struct TelnetClientConfig {
    pub timeouts: Timeouts,
}

impl Default for TelnetClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct TelnetClient {
    transport: TcpTransport,
    parser: TelnetParser,
}

impl TelnetClient {
    pub fn connect(addr: &net::NetAddr, config: TelnetClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self {
            transport,
            parser: TelnetParser::new(),
        })
    }

    pub fn from_stream(stream: TcpStream, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = TcpTransport::from_stream(stream, timeouts)?;
        Ok(Self {
            transport,
            parser: TelnetParser::new(),
        })
    }

    pub fn send_raw(&mut self, bytes: &[u8]) -> CoreResult<()> {
        self.transport.write_all(bytes)
    }

    pub fn send_text(&mut self, text: &str) -> CoreResult<()> {
        self.send_raw(text.as_bytes())
    }

    pub fn recv_events(&mut self) -> CoreResult<Vec<TelnetEvent>> {
        let mut buf = [0u8; READ_BUF];
        let read = self.transport.read(&mut buf)?;
        if read == 0 {
            return Ok(Vec::new());
        }
        Ok(self.parser.push(&buf[..read]))
    }

    pub fn read_cycle_with_new_environ(
        &mut self,
        user_payload: Option<&str>,
    ) -> CoreResult<Vec<u8>> {
        let events = self.recv_events()?;
        let mut data = Vec::new();
        for event in events {
            match event {
                TelnetEvent::Data(chunk) => data.extend_from_slice(&chunk),
                TelnetEvent::Negotiation { command, option } => {
                    if let Some(reply) = default_client_negotiation_reply(command, option) {
                        self.send_raw(&reply)?;
                    }
                }
                TelnetEvent::Subnegotiation { option, data: sb } => {
                    if option == NEW_ENVIRON && is_new_environ_send(&sb) {
                        if let Some(payload) = user_payload {
                            let msg = build_new_environ_user_is(payload);
                            self.send_raw(&msg)?;
                        }
                    }
                }
                TelnetEvent::Command(_) => {}
            }
        }
        Ok(data)
    }
}

pub struct AsyncTelnetClient {
    transport: AsyncTcpTransport,
    parser: TelnetParser,
}

impl AsyncTelnetClient {
    pub async fn connect(addr: &net::NetAddr, config: TelnetClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self {
            transport,
            parser: TelnetParser::new(),
        })
    }

    pub fn from_stream(stream: tokio::net::TcpStream) -> Self {
        Self {
            transport: AsyncTcpTransport::from_stream(stream),
            parser: TelnetParser::new(),
        }
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) -> CoreResult<()> {
        self.transport.write_all(bytes).await
    }

    pub async fn send_text(&mut self, text: &str) -> CoreResult<()> {
        self.send_raw(text.as_bytes()).await
    }

    pub async fn recv_events(&mut self) -> CoreResult<Vec<TelnetEvent>> {
        let mut buf = [0u8; READ_BUF];
        let read = self.transport.read(&mut buf).await?;
        if read == 0 {
            return Ok(Vec::new());
        }
        Ok(self.parser.push(&buf[..read]))
    }

    pub async fn read_cycle_with_new_environ(
        &mut self,
        user_payload: Option<&str>,
    ) -> CoreResult<Vec<u8>> {
        let events = self.recv_events().await?;
        let mut data = Vec::new();
        for event in events {
            match event {
                TelnetEvent::Data(chunk) => data.extend_from_slice(&chunk),
                TelnetEvent::Negotiation { command, option } => {
                    if let Some(reply) = default_client_negotiation_reply(command, option) {
                        self.send_raw(&reply).await?;
                    }
                }
                TelnetEvent::Subnegotiation { option, data: sb } => {
                    if option == NEW_ENVIRON && is_new_environ_send(&sb) {
                        if let Some(payload) = user_payload {
                            let msg = build_new_environ_user_is(payload);
                            self.send_raw(&msg).await?;
                        }
                    }
                }
                TelnetEvent::Command(_) => {}
            }
        }
        Ok(data)
    }
}

#[derive(Debug, Clone)]
pub struct TelnetServerConfig {
    pub timeouts: Timeouts,
    pub banner: String,
    pub prompt: String,
    pub request_new_environ: bool,
}

impl Default for TelnetServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            banner: "Moonlight Telnet".to_string(),
            prompt: "moonlight$ ".to_string(),
            request_new_environ: true,
        }
    }
}

pub struct TelnetServer {
    listener: TcpListener,
    config: TelnetServerConfig,
}

impl TelnetServer {
    pub fn bind(addr: SocketAddr, config: TelnetServerConfig) -> CoreResult<Self> {
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
                let _ = handle_telnet_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncTelnetServer {
    listener: tokio::net::TcpListener,
    config: TelnetServerConfig,
}

impl AsyncTelnetServer {
    pub async fn bind(addr: SocketAddr, config: TelnetServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_telnet_stream_async(stream, config).await;
            });
        }
    }
}

fn handle_telnet_stream(stream: TcpStream, config: TelnetServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    if !config.banner.is_empty() {
        transport.write_all(config.banner.as_bytes())?;
        transport.write_all(b"\r\n")?;
    }
    if config.request_new_environ {
        let req = build_negotiation(TelnetNegotiationCommand::Do, NEW_ENVIRON);
        transport.write_all(&req)?;
        let send = build_new_environ_send(&["USER"]);
        transport.write_all(&send)?;
    }
    if !config.prompt.is_empty() {
        transport.write_all(config.prompt.as_bytes())?;
    }

    let mut parser = TelnetParser::new();
    let mut line_buf = Vec::new();
    let mut env_vars = HashMap::<String, String>::new();

    loop {
        let mut buf = [0u8; READ_BUF];
        let read = transport.read(&mut buf)?;
        if read == 0 {
            return Ok(());
        }
        let events = parser.push(&buf[..read]);
        for event in events {
            match event {
                TelnetEvent::Data(chunk) => {
                    transport.write_all(&chunk)?;
                    line_buf.extend_from_slice(&chunk);
                    while let Some(line) = drain_line(&mut line_buf) {
                        let keep_open =
                            handle_line(line.as_str(), &mut transport, &config.prompt, &env_vars)?;
                        if !keep_open {
                            return Ok(());
                        }
                    }
                }
                TelnetEvent::Negotiation { command, option } => {
                    if let Some(reply) = default_server_negotiation_reply(command, option) {
                        transport.write_all(&reply)?;
                    }
                }
                TelnetEvent::Subnegotiation { option, data } => {
                    if option == NEW_ENVIRON {
                        let (_, vars) = parse_new_environ(&data)?;
                        env_vars.extend(vars);
                    }
                }
                TelnetEvent::Command(cmd) => {
                    if cmd == AYT {
                        transport.write_all(b"[yes]\r\n")?;
                    }
                }
            }
        }
    }
}

async fn handle_telnet_stream_async(
    stream: tokio::net::TcpStream,
    config: TelnetServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    if !config.banner.is_empty() {
        transport.write_all(config.banner.as_bytes()).await?;
        transport.write_all(b"\r\n").await?;
    }
    if config.request_new_environ {
        let req = build_negotiation(TelnetNegotiationCommand::Do, NEW_ENVIRON);
        transport.write_all(&req).await?;
        let send = build_new_environ_send(&["USER"]);
        transport.write_all(&send).await?;
    }
    if !config.prompt.is_empty() {
        transport.write_all(config.prompt.as_bytes()).await?;
    }

    let mut parser = TelnetParser::new();
    let mut line_buf = Vec::new();
    let mut env_vars = HashMap::<String, String>::new();

    loop {
        let mut buf = [0u8; READ_BUF];
        let read = transport.read(&mut buf).await?;
        if read == 0 {
            return Ok(());
        }
        let events = parser.push(&buf[..read]);
        for event in events {
            match event {
                TelnetEvent::Data(chunk) => {
                    transport.write_all(&chunk).await?;
                    line_buf.extend_from_slice(&chunk);
                    while let Some(line) = drain_line(&mut line_buf) {
                        let keep_open = handle_line_async(
                            line.as_str(),
                            &mut transport,
                            &config.prompt,
                            &env_vars,
                        )
                        .await?;
                        if !keep_open {
                            return Ok(());
                        }
                    }
                }
                TelnetEvent::Negotiation { command, option } => {
                    if let Some(reply) = default_server_negotiation_reply(command, option) {
                        transport.write_all(&reply).await?;
                    }
                }
                TelnetEvent::Subnegotiation { option, data } => {
                    if option == NEW_ENVIRON {
                        let (_, vars) = parse_new_environ(&data)?;
                        env_vars.extend(vars);
                    }
                }
                TelnetEvent::Command(cmd) => {
                    if cmd == AYT {
                        transport.write_all(b"[yes]\r\n").await?;
                    }
                }
            }
        }
    }
}

fn handle_line<T: StreamTransport>(
    line: &str,
    transport: &mut T,
    prompt: &str,
    env: &HashMap<String, String>,
) -> CoreResult<bool> {
    let line = line.trim_end_matches(['\r', '\n']);
    match line.to_ascii_lowercase().as_str() {
        "exit" | "quit" => {
            transport.write_all(b"\r\nbye\r\n")?;
            Ok(false)
        }
        "env" => {
            if env.is_empty() {
                transport.write_all(b"\r\nENV: (none)\r\n")?;
            } else {
                for (key, value) in env {
                    let line = format!("\r\n{key}={value}\r\n");
                    transport.write_all(line.as_bytes())?;
                }
            }
            if !prompt.is_empty() {
                transport.write_all(prompt.as_bytes())?;
            }
            Ok(true)
        }
        _ => {
            transport.write_all(b"\r\n")?;
            if !prompt.is_empty() {
                transport.write_all(prompt.as_bytes())?;
            }
            Ok(true)
        }
    }
}

async fn handle_line_async<T: AsyncStreamTransport>(
    line: &str,
    transport: &mut T,
    prompt: &str,
    env: &HashMap<String, String>,
) -> CoreResult<bool> {
    let line = line.trim_end_matches(['\r', '\n']);
    match line.to_ascii_lowercase().as_str() {
        "exit" | "quit" => {
            transport.write_all(b"\r\nbye\r\n").await?;
            Ok(false)
        }
        "env" => {
            if env.is_empty() {
                transport.write_all(b"\r\nENV: (none)\r\n").await?;
            } else {
                for (key, value) in env {
                    let line = format!("\r\n{key}={value}\r\n");
                    transport.write_all(line.as_bytes()).await?;
                }
            }
            if !prompt.is_empty() {
                transport.write_all(prompt.as_bytes()).await?;
            }
            Ok(true)
        }
        _ => {
            transport.write_all(b"\r\n").await?;
            if !prompt.is_empty() {
                transport.write_all(prompt.as_bytes()).await?;
            }
            Ok(true)
        }
    }
}

fn drain_line(buf: &mut Vec<u8>) -> Option<String> {
    let pos = buf.iter().position(|b| *b == b'\n' || *b == b'\r')?;
    let line = buf.drain(..=pos).collect::<Vec<_>>();
    Some(String::from_utf8_lossy(&line).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_parses_negotiation_and_data() {
        let mut parser = TelnetParser::new();
        let events = parser.push(&[b'h', b'i', IAC, DO, NEW_ENVIRON, b'!']);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], TelnetEvent::Data(b"hi".to_vec()));
        assert_eq!(
            events[1],
            TelnetEvent::Negotiation {
                command: TelnetNegotiationCommand::Do,
                option: NEW_ENVIRON
            }
        );
        assert_eq!(events[2], TelnetEvent::Data(b"!".to_vec()));
    }

    #[test]
    fn parser_handles_fragmented_subnegotiation() {
        let mut parser = TelnetParser::new();
        let part1 = [
            IAC,
            SB,
            NEW_ENVIRON,
            NEW_ENVIRON_SEND,
            NEW_ENVIRON_VAR,
            b'U',
        ];
        let part2 = [b'S', b'E', b'R', IAC, SE];
        let first = parser.push(&part1);
        assert!(first.is_empty());
        let second = parser.push(&part2);
        assert_eq!(second.len(), 1);
        let TelnetEvent::Subnegotiation { option, data } = &second[0] else {
            panic!("expected subnegotiation");
        };
        assert_eq!(*option, NEW_ENVIRON);
        assert_eq!(data[0], NEW_ENVIRON_SEND);
    }

    #[test]
    fn new_environ_roundtrip_user() {
        let msg = build_new_environ_user_is("-f root");
        let mut parser = TelnetParser::new();
        let events = parser.push(&msg);
        assert_eq!(events.len(), 1);
        let TelnetEvent::Subnegotiation { option, data } = &events[0] else {
            panic!("expected subneg");
        };
        assert_eq!(*option, NEW_ENVIRON);
        let (kind, vars) = parse_new_environ(data).expect("parse");
        assert_eq!(kind, NEW_ENVIRON_IS);
        assert_eq!(vars.get("USER"), Some(&"-f root".to_string()));
    }

    #[test]
    fn ansi_stripper_removes_csi() {
        let mut filter = TelnetOutputFilter::new(true, false);
        let in_data = b"abc\x1b[?2004hdef\x1b[31mX\x1b[0m";
        let out = filter.process_incoming(in_data);
        assert_eq!(out, b"abcdefX");
    }

    #[test]
    fn echo_suppressor_skips_until_newline() {
        let mut filter = TelnetOutputFilter::new(false, true);
        filter.note_local_input(b"id\r");
        let out1 = filter.process_incoming(b"id");
        assert!(out1.is_empty());
        let out2 = filter.process_incoming(b"\r\nuid=0(root)\r\n");
        assert_eq!(out2, b"\nuid=0(root)\r\n");
    }

    #[test]
    fn client_server_basic_flow() {
        let server = crate::skip_if_perm!(TelnetServer::bind(
            "127.0.0.1:0".parse().expect("addr"),
            TelnetServerConfig::default(),
        ));
        let addr = server.local_addr().expect("local addr");
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = TelnetClient::connect(
            &net::NetAddr::from_socket(addr),
            TelnetClientConfig::default(),
        )
        .expect("connect");

        for _ in 0..3 {
            let _ = client
                .read_cycle_with_new_environ(Some("-f root"))
                .expect("cycle");
        }

        client.send_text("env\r\n").expect("send");
        let mut got = Vec::new();
        for _ in 0..8 {
            let chunk = client
                .read_cycle_with_new_environ(Some("-f root"))
                .expect("read");
            if !chunk.is_empty() {
                got.extend_from_slice(&chunk);
            }
            if String::from_utf8_lossy(&got).contains("USER=-f root") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("USER=-f root"), "output: {text}");

        client.send_text("quit\r\n").expect("send quit");
    }

    #[tokio::test]
    async fn async_client_server_basic_flow() {
        let server = crate::skip_if_perm!(
            AsyncTelnetServer::bind(
                "127.0.0.1:0".parse().expect("addr"),
                TelnetServerConfig::default(),
            )
            .await
        );
        let addr = server.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = server.serve().await;
        });

        let mut client = AsyncTelnetClient::connect(
            &net::NetAddr::from_socket(addr),
            TelnetClientConfig::default(),
        )
        .await
        .expect("connect");

        for _ in 0..3 {
            let _ = client
                .read_cycle_with_new_environ(Some("-f root"))
                .await
                .expect("cycle");
        }

        client.send_text("env\r\n").await.expect("send");
        let mut got = Vec::new();
        for _ in 0..8 {
            let chunk = client
                .read_cycle_with_new_environ(Some("-f root"))
                .await
                .expect("read");
            if !chunk.is_empty() {
                got.extend_from_slice(&chunk);
            }
            if String::from_utf8_lossy(&got).contains("USER=-f root") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("USER=-f root"), "output: {text}");
    }
}
