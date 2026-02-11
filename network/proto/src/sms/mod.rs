use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const MAGIC: [u8; 4] = *b"SMS1";
const HEADER_LEN: usize = 13;
pub const SMS_DEFAULT_PORT: u16 = 2775;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmsCommand {
    Bind = 0x01,
    BindOk = 0x02,
    Submit = 0x03,
    Deliver = 0x04,
    StatusReq = 0x05,
    StatusResp = 0x06,
    DeliverAck = 0x07,
    Unbind = 0x08,
    UnbindOk = 0x09,
    Ping = 0x0A,
    Pong = 0x0B,
    Error = 0x0C,
}

impl SmsCommand {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            0x01 => Ok(SmsCommand::Bind),
            0x02 => Ok(SmsCommand::BindOk),
            0x03 => Ok(SmsCommand::Submit),
            0x04 => Ok(SmsCommand::Deliver),
            0x05 => Ok(SmsCommand::StatusReq),
            0x06 => Ok(SmsCommand::StatusResp),
            0x07 => Ok(SmsCommand::DeliverAck),
            0x08 => Ok(SmsCommand::Unbind),
            0x09 => Ok(SmsCommand::UnbindOk),
            0x0A => Ok(SmsCommand::Ping),
            0x0B => Ok(SmsCommand::Pong),
            0x0C => Ok(SmsCommand::Error),
            other => Err(CoreError::Parse(format!("sms unknown command {other}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmsFrame {
    pub command: SmsCommand,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl SmsFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.command as u8);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsBind {
    pub system_id: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsSubmit {
    pub source: String,
    pub destination: String,
    pub text: String,
    pub validity_secs: u32,
    pub request_status: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsDeliver {
    pub message_id: String,
    pub source: String,
    pub destination: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsStatus {
    pub message_id: String,
    pub status: SmsDeliveryStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmsDeliveryStatus {
    Accepted,
    Delivered,
    Failed,
    Rejected,
    Unknown,
}

impl SmsDeliveryStatus {
    fn as_str(self) -> &'static str {
        match self {
            SmsDeliveryStatus::Accepted => "accepted",
            SmsDeliveryStatus::Delivered => "delivered",
            SmsDeliveryStatus::Failed => "failed",
            SmsDeliveryStatus::Rejected => "rejected",
            SmsDeliveryStatus::Unknown => "unknown",
        }
    }

    fn from_str(value: &str) -> CoreResult<Self> {
        match value.to_ascii_lowercase().as_str() {
            "accepted" => Ok(SmsDeliveryStatus::Accepted),
            "delivered" => Ok(SmsDeliveryStatus::Delivered),
            "failed" => Ok(SmsDeliveryStatus::Failed),
            "rejected" => Ok(SmsDeliveryStatus::Rejected),
            "unknown" => Ok(SmsDeliveryStatus::Unknown),
            _ => Err(CoreError::Parse("sms invalid status".to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsError {
    pub code: u16,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmsMessage {
    Bind(SmsBind),
    BindOk { system_id: String },
    Submit(SmsSubmit),
    Deliver(SmsDeliver),
    StatusReq { message_id: String },
    StatusResp(SmsStatus),
    DeliverAck { message_id: String, status: SmsDeliveryStatus },
    Unbind,
    UnbindOk,
    Ping,
    Pong,
    Error(SmsError),
}

impl SmsMessage {
    fn command(&self) -> SmsCommand {
        match self {
            SmsMessage::Bind(_) => SmsCommand::Bind,
            SmsMessage::BindOk { .. } => SmsCommand::BindOk,
            SmsMessage::Submit(_) => SmsCommand::Submit,
            SmsMessage::Deliver(_) => SmsCommand::Deliver,
            SmsMessage::StatusReq { .. } => SmsCommand::StatusReq,
            SmsMessage::StatusResp(_) => SmsCommand::StatusResp,
            SmsMessage::DeliverAck { .. } => SmsCommand::DeliverAck,
            SmsMessage::Unbind => SmsCommand::Unbind,
            SmsMessage::UnbindOk => SmsCommand::UnbindOk,
            SmsMessage::Ping => SmsCommand::Ping,
            SmsMessage::Pong => SmsCommand::Pong,
            SmsMessage::Error(_) => SmsCommand::Error,
        }
    }

    fn encode_payload(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        match self {
            SmsMessage::Bind(bind) => {
                push_kv(&mut out, "system_id", &bind.system_id);
                push_kv(&mut out, "password", &bind.password);
            }
            SmsMessage::BindOk { system_id } => {
                push_kv(&mut out, "system_id", system_id);
            }
            SmsMessage::Submit(submit) => {
                push_kv(&mut out, "source", &submit.source);
                push_kv(&mut out, "destination", &submit.destination);
                push_kv(&mut out, "text", &submit.text);
                push_kv(&mut out, "validity_secs", &submit.validity_secs.to_string());
                push_kv(
                    &mut out,
                    "request_status",
                    if submit.request_status { "1" } else { "0" },
                );
            }
            SmsMessage::Deliver(deliver) => {
                push_kv(&mut out, "message_id", &deliver.message_id);
                push_kv(&mut out, "source", &deliver.source);
                push_kv(&mut out, "destination", &deliver.destination);
                push_kv(&mut out, "text", &deliver.text);
            }
            SmsMessage::StatusReq { message_id } => {
                push_kv(&mut out, "message_id", message_id);
            }
            SmsMessage::StatusResp(status) => {
                push_kv(&mut out, "message_id", &status.message_id);
                push_kv(&mut out, "status", status.status.as_str());
                if let Some(err) = &status.error {
                    push_kv(&mut out, "error", err);
                }
            }
            SmsMessage::DeliverAck { message_id, status } => {
                push_kv(&mut out, "message_id", message_id);
                push_kv(&mut out, "status", status.as_str());
            }
            SmsMessage::Unbind | SmsMessage::UnbindOk | SmsMessage::Ping | SmsMessage::Pong => {}
            SmsMessage::Error(err) => {
                push_kv(&mut out, "code", &err.code.to_string());
                push_kv(&mut out, "message", &err.message);
            }
        }
        Ok(out)
    }

    fn to_frame(&self, seq: u32) -> CoreResult<SmsFrame> {
        Ok(SmsFrame {
            command: self.command(),
            seq,
            payload: self.encode_payload()?,
        })
    }

    fn from_frame(frame: &SmsFrame) -> CoreResult<Self> {
        match frame.command {
            SmsCommand::Bind => {
                let fields = decode_kv(&frame.payload)?;
                Ok(SmsMessage::Bind(SmsBind {
                    system_id: get_required(&fields, "system_id")?,
                    password: get_required(&fields, "password")?,
                }))
            }
            SmsCommand::BindOk => {
                let fields = decode_kv(&frame.payload)?;
                Ok(SmsMessage::BindOk {
                    system_id: get_required(&fields, "system_id")?,
                })
            }
            SmsCommand::Submit => {
                let fields = decode_kv(&frame.payload)?;
                let validity = get_required(&fields, "validity_secs")?
                    .parse::<u32>()
                    .map_err(|_| CoreError::Parse("sms invalid validity".to_string()))?;
                let request_status = match fields.get("request_status") {
                    Some(value) => value == "1" || value.eq_ignore_ascii_case("true"),
                    None => false,
                };
                Ok(SmsMessage::Submit(SmsSubmit {
                    source: get_required(&fields, "source")?,
                    destination: get_required(&fields, "destination")?,
                    text: get_required(&fields, "text")?,
                    validity_secs: validity,
                    request_status,
                }))
            }
            SmsCommand::Deliver => {
                let fields = decode_kv(&frame.payload)?;
                Ok(SmsMessage::Deliver(SmsDeliver {
                    message_id: get_required(&fields, "message_id")?,
                    source: get_required(&fields, "source")?,
                    destination: get_required(&fields, "destination")?,
                    text: get_required(&fields, "text")?,
                }))
            }
            SmsCommand::StatusReq => {
                let fields = decode_kv(&frame.payload)?;
                Ok(SmsMessage::StatusReq {
                    message_id: get_required(&fields, "message_id")?,
                })
            }
            SmsCommand::StatusResp => {
                let fields = decode_kv(&frame.payload)?;
                let status = SmsDeliveryStatus::from_str(&get_required(&fields, "status")?)?;
                Ok(SmsMessage::StatusResp(SmsStatus {
                    message_id: get_required(&fields, "message_id")?,
                    status,
                    error: fields.get("error").cloned(),
                }))
            }
            SmsCommand::DeliverAck => {
                let fields = decode_kv(&frame.payload)?;
                let status = SmsDeliveryStatus::from_str(&get_required(&fields, "status")?)?;
                Ok(SmsMessage::DeliverAck {
                    message_id: get_required(&fields, "message_id")?,
                    status,
                })
            }
            SmsCommand::Unbind => Ok(SmsMessage::Unbind),
            SmsCommand::UnbindOk => Ok(SmsMessage::UnbindOk),
            SmsCommand::Ping => Ok(SmsMessage::Ping),
            SmsCommand::Pong => Ok(SmsMessage::Pong),
            SmsCommand::Error => {
                let fields = decode_kv(&frame.payload)?;
                let code = get_required(&fields, "code")?
                    .parse::<u16>()
                    .map_err(|_| CoreError::Parse("sms error code invalid".to_string()))?;
                let message = get_required(&fields, "message")?;
                Ok(SmsMessage::Error(SmsError { code, message }))
            }
        }
    }
}

fn push_kv(out: &mut Vec<u8>, key: &str, value: &str) {
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(escape_value(value).as_bytes());
    out.push(b'\n');
}

fn decode_kv(payload: &[u8]) -> CoreResult<HashMap<String, String>> {
    let text = String::from_utf8_lossy(payload);
    let mut out = HashMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts
            .next()
            .ok_or_else(|| CoreError::Parse("sms kv missing key".to_string()))?;
        let value = parts.next().unwrap_or("");
        out.insert(key.to_string(), unescape_value(value));
    }
    Ok(out)
}

fn get_required(map: &HashMap<String, String>, key: &str) -> CoreResult<String> {
    map.get(key)
        .cloned()
        .ok_or_else(|| CoreError::Parse(format!("sms missing field {key}")))
}

fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out
}

fn unescape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct SmsServerConfig {
    pub timeouts: Timeouts,
    pub max_payload: usize,
    pub require_auth: bool,
}

impl Default for SmsServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            max_payload: 16 * 1024,
            require_auth: true,
        }
    }
}

pub trait SmsHandler: Send + Sync {
    fn authenticate(&self, system_id: &str, password: &str) -> CoreResult<bool>;
    fn submit(&self, submit: SmsSubmit) -> CoreResult<SmsStatus>;
    fn status(&self, message_id: &str) -> CoreResult<Option<SmsStatus>>;
    fn next_delivery(&self, system_id: &str) -> CoreResult<Option<SmsDeliver>>;
    fn acknowledge(&self, message_id: &str, status: SmsDeliveryStatus) -> CoreResult<()>;
}

#[derive(Debug)]
pub struct InMemorySmsHandler {
    users: HashMap<String, String>,
    next_id: AtomicU64,
    messages: Mutex<HashMap<String, SmsStatus>>,
    deliveries: Mutex<HashMap<String, VecDeque<SmsDeliver>>>,
}

impl InMemorySmsHandler {
    pub fn new(users: HashMap<String, String>) -> Self {
        Self {
            users,
            next_id: AtomicU64::new(1),
            messages: Mutex::new(HashMap::new()),
            deliveries: Mutex::new(HashMap::new()),
        }
    }

    pub fn add_user(&mut self, system_id: impl Into<String>, password: impl Into<String>) {
        self.users.insert(system_id.into(), password.into());
    }

    pub fn enqueue_delivery(&self, system_id: &str, mut deliver: SmsDeliver) {
        if deliver.message_id.is_empty() {
            deliver.message_id = self.next_message_id();
        }
        let mut guard = self.deliveries.lock().expect("sms deliveries lock");
        guard
            .entry(system_id.to_string())
            .or_insert_with(VecDeque::new)
            .push_back(deliver);
    }

    fn next_message_id(&self) -> String {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("msg-{id}")
    }
}

impl SmsHandler for InMemorySmsHandler {
    fn authenticate(&self, system_id: &str, password: &str) -> CoreResult<bool> {
        Ok(self
            .users
            .get(system_id)
            .map(|p| p == password)
            .unwrap_or(false))
    }

    fn submit(&self, submit: SmsSubmit) -> CoreResult<SmsStatus> {
        let mut status = SmsStatus {
            message_id: self.next_message_id(),
            status: SmsDeliveryStatus::Accepted,
            error: None,
        };
        if submit.text.is_empty() {
            status.status = SmsDeliveryStatus::Rejected;
            status.error = Some("empty message".to_string());
        }
        let mut guard = self.messages.lock().expect("sms messages lock");
        guard.insert(status.message_id.clone(), status.clone());
        Ok(status)
    }

    fn status(&self, message_id: &str) -> CoreResult<Option<SmsStatus>> {
        let guard = self.messages.lock().expect("sms messages lock");
        Ok(guard.get(message_id).cloned())
    }

    fn next_delivery(&self, system_id: &str) -> CoreResult<Option<SmsDeliver>> {
        let mut guard = self.deliveries.lock().expect("sms deliveries lock");
        let queue = guard.get_mut(system_id);
        Ok(queue.and_then(|q| q.pop_front()))
    }

    fn acknowledge(&self, message_id: &str, status: SmsDeliveryStatus) -> CoreResult<()> {
        let mut guard = self.messages.lock().expect("sms messages lock");
        if let Some(entry) = guard.get_mut(message_id) {
            entry.status = status;
        }
        Ok(())
    }
}

pub struct SmsServer {
    listener: TcpListener,
    handler: Arc<dyn SmsHandler>,
    config: SmsServerConfig,
}

impl SmsServer {
    pub fn bind(
        addr: SocketAddr,
        handler: Arc<dyn SmsHandler>,
        config: SmsServerConfig,
    ) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            handler,
            config,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_sms_stream(stream, handler, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncSmsServer {
    listener: tokio::net::TcpListener,
    handler: Arc<dyn SmsHandler>,
    config: SmsServerConfig,
}

impl AsyncSmsServer {
    pub async fn bind(
        addr: SocketAddr,
        handler: Arc<dyn SmsHandler>,
        config: SmsServerConfig,
    ) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            handler,
            config,
        })
    }

    pub async fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_sms_stream_async(stream, handler, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub struct SmsClientConfig {
    pub timeouts: Timeouts,
    pub max_payload: usize,
}

impl Default for SmsClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            max_payload: 16 * 1024,
        }
    }
}

pub struct SmsClient {
    transport: TcpTransport,
    seq: u32,
    max_payload: usize,
    pending: VecDeque<SmsDeliver>,
}

impl SmsClient {
    pub fn connect(addr: &NetAddr, config: SmsClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self {
            transport,
            seq: 1,
            max_payload: config.max_payload,
            pending: VecDeque::new(),
        })
    }

    pub fn bind(&mut self, system_id: &str, password: &str) -> CoreResult<()> {
        let msg = SmsMessage::Bind(SmsBind {
            system_id: system_id.to_string(),
            password: password.to_string(),
        });
        let seq = self.send_message(msg)?;
        loop {
            let (resp_seq, resp) = self.receive_message()?;
            if resp_seq != seq {
                self.handle_async_message(resp)?;
                continue;
            }
            return match resp {
                SmsMessage::BindOk { .. } => Ok(()),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected bind response {other:?}"))),
            };
        }
    }

    pub fn submit(&mut self, submit: SmsSubmit) -> CoreResult<SmsStatus> {
        let seq = self.send_message(SmsMessage::Submit(submit))?;
        loop {
            let (resp_seq, resp) = self.receive_message()?;
            if resp_seq != seq {
                self.handle_async_message(resp)?;
                continue;
            }
            return match resp {
                SmsMessage::StatusResp(status) => Ok(status),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected submit response {other:?}"))),
            };
        }
    }

    pub fn status(&mut self, message_id: &str) -> CoreResult<SmsStatus> {
        let seq = self.send_message(SmsMessage::StatusReq {
            message_id: message_id.to_string(),
        })?;
        loop {
            let (resp_seq, resp) = self.receive_message()?;
            if resp_seq != seq {
                self.handle_async_message(resp)?;
                continue;
            }
            return match resp {
                SmsMessage::StatusResp(status) => Ok(status),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected status response {other:?}"))),
            };
        }
    }

    pub fn next_delivery(&mut self) -> CoreResult<SmsDeliver> {
        if let Some(deliver) = self.pending.pop_front() {
            return Ok(deliver);
        }
        loop {
            let (_, msg) = self.receive_message()?;
            match msg {
                SmsMessage::Deliver(deliver) => return Ok(deliver),
                SmsMessage::Ping => {
                    let _ = self.send_message(SmsMessage::Pong)?;
                }
                _ => {}
            }
        }
    }

    pub fn ack_delivery(&mut self, message_id: &str, status: SmsDeliveryStatus) -> CoreResult<()> {
        let _ = self.send_message(SmsMessage::DeliverAck {
            message_id: message_id.to_string(),
            status,
        })?;
        Ok(())
    }

    pub fn unbind(&mut self) -> CoreResult<()> {
        let seq = self.send_message(SmsMessage::Unbind)?;
        loop {
            let (resp_seq, resp) = self.receive_message()?;
            if resp_seq != seq {
                self.handle_async_message(resp)?;
                continue;
            }
            return match resp {
                SmsMessage::UnbindOk => Ok(()),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected unbind response {other:?}"))),
            };
        }
    }

    fn send_message(&mut self, message: SmsMessage) -> CoreResult<u32> {
        let seq = self.next_seq();
        let frame = message.to_frame(seq)?;
        write_frame(&mut self.transport, &frame)?;
        Ok(seq)
    }

    fn receive_message(&mut self) -> CoreResult<(u32, SmsMessage)> {
        let frame = read_frame_with_limit(&mut self.transport, self.max_payload)?;
        let seq = frame.seq;
        let msg = SmsMessage::from_frame(&frame)?;
        Ok((seq, msg))
    }

    fn handle_async_message(&mut self, message: SmsMessage) -> CoreResult<()> {
        match message {
            SmsMessage::Deliver(deliver) => {
                self.pending.push_back(deliver);
            }
            SmsMessage::Ping => {
                let _ = self.send_message(SmsMessage::Pong)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }
}

pub struct AsyncSmsClient {
    transport: AsyncTcpTransport,
    seq: u32,
    max_payload: usize,
    pending: VecDeque<SmsDeliver>,
}

impl AsyncSmsClient {
    pub async fn connect(addr: &NetAddr, config: SmsClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self {
            transport,
            seq: 1,
            max_payload: config.max_payload,
            pending: VecDeque::new(),
        })
    }

    pub async fn bind(&mut self, system_id: &str, password: &str) -> CoreResult<()> {
        let msg = SmsMessage::Bind(SmsBind {
            system_id: system_id.to_string(),
            password: password.to_string(),
        });
        let seq = self.send_message(msg).await?;
        loop {
            let (resp_seq, resp) = self.receive_message().await?;
            if resp_seq != seq {
                self.handle_async_message(resp).await?;
                continue;
            }
            return match resp {
                SmsMessage::BindOk { .. } => Ok(()),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected bind response {other:?}"))),
            };
        }
    }

    pub async fn submit(&mut self, submit: SmsSubmit) -> CoreResult<SmsStatus> {
        let seq = self.send_message(SmsMessage::Submit(submit)).await?;
        loop {
            let (resp_seq, resp) = self.receive_message().await?;
            if resp_seq != seq {
                self.handle_async_message(resp).await?;
                continue;
            }
            return match resp {
                SmsMessage::StatusResp(status) => Ok(status),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected submit response {other:?}"))),
            };
        }
    }

    pub async fn status(&mut self, message_id: &str) -> CoreResult<SmsStatus> {
        let seq = self
            .send_message(SmsMessage::StatusReq {
                message_id: message_id.to_string(),
            })
            .await?;
        loop {
            let (resp_seq, resp) = self.receive_message().await?;
            if resp_seq != seq {
                self.handle_async_message(resp).await?;
                continue;
            }
            return match resp {
                SmsMessage::StatusResp(status) => Ok(status),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected status response {other:?}"))),
            };
        }
    }

    pub async fn next_delivery(&mut self) -> CoreResult<SmsDeliver> {
        if let Some(deliver) = self.pending.pop_front() {
            return Ok(deliver);
        }
        loop {
            let (_, msg) = self.receive_message().await?;
            match msg {
                SmsMessage::Deliver(deliver) => return Ok(deliver),
                SmsMessage::Ping => {
                    let _ = self.send_message(SmsMessage::Pong).await?;
                }
                _ => {}
            }
        }
    }

    pub async fn ack_delivery(&mut self, message_id: &str, status: SmsDeliveryStatus) -> CoreResult<()> {
        let _ = self
            .send_message(SmsMessage::DeliverAck {
                message_id: message_id.to_string(),
                status,
            })
            .await?;
        Ok(())
    }

    pub async fn unbind(&mut self) -> CoreResult<()> {
        let seq = self.send_message(SmsMessage::Unbind).await?;
        loop {
            let (resp_seq, resp) = self.receive_message().await?;
            if resp_seq != seq {
                self.handle_async_message(resp).await?;
                continue;
            }
            return match resp {
                SmsMessage::UnbindOk => Ok(()),
                SmsMessage::Error(err) => Err(CoreError::Message(err.message)),
                other => Err(CoreError::Parse(format!("sms unexpected unbind response {other:?}"))),
            };
        }
    }

    async fn send_message(&mut self, message: SmsMessage) -> CoreResult<u32> {
        let seq = self.next_seq();
        let frame = message.to_frame(seq)?;
        write_frame_async(&mut self.transport, &frame).await?;
        Ok(seq)
    }

    async fn receive_message(&mut self) -> CoreResult<(u32, SmsMessage)> {
        let frame = read_frame_with_limit_async(&mut self.transport, self.max_payload).await?;
        let seq = frame.seq;
        let msg = SmsMessage::from_frame(&frame)?;
        Ok((seq, msg))
    }

    async fn handle_async_message(&mut self, message: SmsMessage) -> CoreResult<()> {
        match message {
            SmsMessage::Deliver(deliver) => {
                self.pending.push_back(deliver);
            }
            SmsMessage::Ping => {
                let _ = self.send_message(SmsMessage::Pong).await?;
            }
            _ => {}
        }
        Ok(())
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }
}

fn handle_sms_stream(
    stream: TcpStream,
    handler: Arc<dyn SmsHandler>,
    config: SmsServerConfig,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let mut bound = false;
    let mut system_id = String::new();
    let mut server_seq: u32 = 1;
    loop {
        let frame = read_frame_with_limit(&mut transport, config.max_payload)?;
        let seq = frame.seq;
        let msg = SmsMessage::from_frame(&frame)?;
        match msg {
            SmsMessage::Bind(bind) => {
                if bound {
                    send_error(&mut transport, seq, 400, "already bound")?;
                    continue;
                }
                let allowed = if config.require_auth {
                    handler.authenticate(&bind.system_id, &bind.password)?
                } else {
                    true
                };
                if allowed {
                    bound = true;
                    system_id = bind.system_id.clone();
                    send_message(
                        &mut transport,
                        seq,
                        SmsMessage::BindOk {
                            system_id: bind.system_id,
                        },
                    )?;
                } else {
                    send_error(&mut transport, seq, 403, "auth failed")?;
                }
            }
            SmsMessage::Submit(submit) => {
                if !bound {
                    send_error(&mut transport, seq, 401, "not bound")?;
                    continue;
                }
                let status = handler.submit(submit)?;
                send_message(&mut transport, seq, SmsMessage::StatusResp(status))?;
            }
            SmsMessage::StatusReq { message_id } => {
                if !bound {
                    send_error(&mut transport, seq, 401, "not bound")?;
                    continue;
                }
                let status = handler.status(&message_id)?.unwrap_or(SmsStatus {
                    message_id,
                    status: SmsDeliveryStatus::Unknown,
                    error: None,
                });
                send_message(&mut transport, seq, SmsMessage::StatusResp(status))?;
            }
            SmsMessage::DeliverAck { message_id, status } => {
                let _ = handler.acknowledge(&message_id, status);
            }
            SmsMessage::Ping => {
                send_message(&mut transport, seq, SmsMessage::Pong)?;
            }
            SmsMessage::Unbind => {
                send_message(&mut transport, seq, SmsMessage::UnbindOk)?;
                break;
            }
            SmsMessage::Error(_) => {}
            _ => {
                send_error(&mut transport, seq, 400, "invalid request")?;
            }
        }
        if bound {
            send_pending_deliveries(&mut transport, &handler, &system_id, &mut server_seq)?;
        }
    }
    let _ = transport.shutdown();
    Ok(())
}

async fn handle_sms_stream_async(
    stream: tokio::net::TcpStream,
    handler: Arc<dyn SmsHandler>,
    config: SmsServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut bound = false;
    let mut system_id = String::new();
    let mut server_seq: u32 = 1;
    loop {
        let frame = read_frame_with_limit_async(&mut transport, config.max_payload).await?;
        let seq = frame.seq;
        let msg = SmsMessage::from_frame(&frame)?;
        match msg {
            SmsMessage::Bind(bind) => {
                if bound {
                    send_error_async(&mut transport, seq, 400, "already bound").await?;
                    continue;
                }
                let allowed = if config.require_auth {
                    handler.authenticate(&bind.system_id, &bind.password)?
                } else {
                    true
                };
                if allowed {
                    bound = true;
                    system_id = bind.system_id.clone();
                    send_message_async(
                        &mut transport,
                        seq,
                        SmsMessage::BindOk {
                            system_id: bind.system_id,
                        },
                    )
                    .await?;
                } else {
                    send_error_async(&mut transport, seq, 403, "auth failed").await?;
                }
            }
            SmsMessage::Submit(submit) => {
                if !bound {
                    send_error_async(&mut transport, seq, 401, "not bound").await?;
                    continue;
                }
                let status = handler.submit(submit)?;
                send_message_async(&mut transport, seq, SmsMessage::StatusResp(status)).await?;
            }
            SmsMessage::StatusReq { message_id } => {
                if !bound {
                    send_error_async(&mut transport, seq, 401, "not bound").await?;
                    continue;
                }
                let status = handler.status(&message_id)?.unwrap_or(SmsStatus {
                    message_id,
                    status: SmsDeliveryStatus::Unknown,
                    error: None,
                });
                send_message_async(&mut transport, seq, SmsMessage::StatusResp(status)).await?;
            }
            SmsMessage::DeliverAck { message_id, status } => {
                let _ = handler.acknowledge(&message_id, status);
            }
            SmsMessage::Ping => {
                send_message_async(&mut transport, seq, SmsMessage::Pong).await?;
            }
            SmsMessage::Unbind => {
                send_message_async(&mut transport, seq, SmsMessage::UnbindOk).await?;
                break;
            }
            SmsMessage::Error(_) => {}
            _ => {
                send_error_async(&mut transport, seq, 400, "invalid request").await?;
            }
        }
        if bound {
            send_pending_deliveries_async(&mut transport, &handler, &system_id, &mut server_seq).await?;
        }
    }
    let _ = transport.shutdown().await;
    Ok(())
}

fn send_pending_deliveries(
    transport: &mut TcpTransport,
    handler: &Arc<dyn SmsHandler>,
    system_id: &str,
    server_seq: &mut u32,
) -> CoreResult<()> {
    loop {
        let deliver = handler.next_delivery(system_id)?;
        if let Some(deliver) = deliver {
            let seq = *server_seq;
            *server_seq = server_seq.wrapping_add(1);
            let frame = SmsMessage::Deliver(deliver).to_frame(seq)?;
            write_frame(transport, &frame)?;
        } else {
            break;
        }
    }
    Ok(())
}

async fn send_pending_deliveries_async(
    transport: &mut AsyncTcpTransport,
    handler: &Arc<dyn SmsHandler>,
    system_id: &str,
    server_seq: &mut u32,
) -> CoreResult<()> {
    loop {
        let deliver = handler.next_delivery(system_id)?;
        if let Some(deliver) = deliver {
            let seq = *server_seq;
            *server_seq = server_seq.wrapping_add(1);
            let frame = SmsMessage::Deliver(deliver).to_frame(seq)?;
            write_frame_async(transport, &frame).await?;
        } else {
            break;
        }
    }
    Ok(())
}

fn send_message(transport: &mut TcpTransport, seq: u32, message: SmsMessage) -> CoreResult<()> {
    let frame = message.to_frame(seq)?;
    write_frame(transport, &frame)
}

async fn send_message_async(
    transport: &mut AsyncTcpTransport,
    seq: u32,
    message: SmsMessage,
) -> CoreResult<()> {
    let frame = message.to_frame(seq)?;
    write_frame_async(transport, &frame).await
}

fn send_error(transport: &mut TcpTransport, seq: u32, code: u16, message: &str) -> CoreResult<()> {
    send_message(
        transport,
        seq,
        SmsMessage::Error(SmsError {
            code,
            message: message.to_string(),
        }),
    )
}

async fn send_error_async(
    transport: &mut AsyncTcpTransport,
    seq: u32,
    code: u16,
    message: &str,
) -> CoreResult<()> {
    send_message_async(
        transport,
        seq,
        SmsMessage::Error(SmsError {
            code,
            message: message.to_string(),
        }),
    )
    .await
}

fn read_frame_with_limit<T: StreamTransport>(transport: &mut T, max_payload: usize) -> CoreResult<SmsFrame> {
    let mut header = [0u8; HEADER_LEN];
    transport.read_exact(&mut header)?;
    if &header[0..4] != MAGIC {
        return Err(CoreError::Parse("sms bad magic".to_string()));
    }
    let command = SmsCommand::from_u8(header[4])?;
    let seq = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    let len = u32::from_be_bytes([header[9], header[10], header[11], header[12]]) as usize;
    if len > max_payload {
        return Err(CoreError::Parse("sms payload too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload)?;
    }
    Ok(SmsFrame {
        command,
        seq,
        payload,
    })
}

fn write_frame<T: StreamTransport>(transport: &mut T, frame: &SmsFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode())
}

async fn read_frame_with_limit_async<T: AsyncStreamTransport>(
    transport: &mut T,
    max_payload: usize,
) -> CoreResult<SmsFrame> {
    let mut header = [0u8; HEADER_LEN];
    transport.read_exact(&mut header).await?;
    if &header[0..4] != MAGIC {
        return Err(CoreError::Parse("sms bad magic".to_string()));
    }
    let command = SmsCommand::from_u8(header[4])?;
    let seq = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    let len = u32::from_be_bytes([header[9], header[10], header[11], header[12]]) as usize;
    if len > max_payload {
        return Err(CoreError::Parse("sms payload too large".to_string()));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        transport.read_exact(&mut payload).await?;
    }
    Ok(SmsFrame {
        command,
        seq,
        payload,
    })
}

async fn write_frame_async<T: AsyncStreamTransport>(transport: &mut T, frame: &SmsFrame) -> CoreResult<()> {
    transport.write_all(&frame.encode()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_frame_roundtrip() {
        let message = SmsMessage::Submit(SmsSubmit {
            source: "+1000".to_string(),
            destination: "+2000".to_string(),
            text: "hello".to_string(),
            validity_secs: 60,
            request_status: true,
        });
        let frame = message.to_frame(42).unwrap();
        let decoded = SmsMessage::from_frame(&frame).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn sms_submit_flow() {
        let mut users = HashMap::new();
        users.insert("client".to_string(), "secret".to_string());
        let handler = Arc::new(InMemorySmsHandler::new(users));
        handler.enqueue_delivery(
            "client",
            SmsDeliver {
                message_id: "".to_string(),
                source: "+1000".to_string(),
                destination: "+2000".to_string(),
                text: "welcome".to_string(),
            },
        );

        let server = SmsServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            SmsServerConfig::default(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let client_addr = NetAddr::from_socket(addr);
        let mut client = SmsClient::connect(&client_addr, SmsClientConfig::default()).unwrap();
        client.bind("client", "secret").unwrap();

        let status = client
            .submit(SmsSubmit {
                source: "+2000".to_string(),
                destination: "+1000".to_string(),
                text: "ping".to_string(),
                validity_secs: 30,
                request_status: true,
            })
            .unwrap();
        assert_eq!(status.status, SmsDeliveryStatus::Accepted);

        let deliver = client.next_delivery().unwrap();
        assert_eq!(deliver.text, "welcome");
        client
            .ack_delivery(&deliver.message_id, SmsDeliveryStatus::Delivered)
            .unwrap();

        client.unbind().unwrap();

        drop(handle);
    }
}
