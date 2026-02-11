use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const PROTOCOL_HEADER: [u8; 8] = [b'A', b'M', b'Q', b'P', 0, 0, 9, 1];
const FRAME_END: u8 = 0xCE;

const FRAME_METHOD: u8 = 1;
const FRAME_HEADER: u8 = 2;
const FRAME_BODY: u8 = 3;
const FRAME_HEARTBEAT: u8 = 8;

const CLASS_CONNECTION: u16 = 10;
const CLASS_CHANNEL: u16 = 20;
const CLASS_QUEUE: u16 = 50;
const CLASS_BASIC: u16 = 60;

const METHOD_CONNECTION_START: u16 = 10;
const METHOD_CONNECTION_START_OK: u16 = 11;
const METHOD_CONNECTION_TUNE: u16 = 30;
const METHOD_CONNECTION_TUNE_OK: u16 = 31;
const METHOD_CONNECTION_OPEN: u16 = 40;
const METHOD_CONNECTION_OPEN_OK: u16 = 41;
const METHOD_CONNECTION_CLOSE: u16 = 50;
const METHOD_CONNECTION_CLOSE_OK: u16 = 51;

const METHOD_CHANNEL_OPEN: u16 = 10;
const METHOD_CHANNEL_OPEN_OK: u16 = 11;

const METHOD_QUEUE_DECLARE: u16 = 10;
const METHOD_QUEUE_DECLARE_OK: u16 = 11;

const METHOD_BASIC_PUBLISH: u16 = 40;
const METHOD_BASIC_CONSUME: u16 = 20;
const METHOD_BASIC_CONSUME_OK: u16 = 21;
const METHOD_BASIC_DELIVER: u16 = 60;

#[derive(Debug, Clone)]
pub struct AmqpFrame {
    pub frame_type: u8,
    pub channel: u16,
    pub payload: Vec<u8>,
}

impl AmqpFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + self.payload.len());
        out.push(self.frame_type);
        out.extend_from_slice(&self.channel.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.push(FRAME_END);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 8 {
            return Err(CoreError::Parse("amqp frame too short".to_string()));
        }
        if data[data.len() - 1] != FRAME_END {
            return Err(CoreError::Parse("amqp frame end missing".to_string()));
        }
        let frame_type = data[0];
        let channel = u16::from_be_bytes([data[1], data[2]]);
        let size = u32::from_be_bytes([data[3], data[4], data[5], data[6]]) as usize;
        if data.len() < 7 + size + 1 {
            return Err(CoreError::Parse("amqp frame size mismatch".to_string()));
        }
        let payload = data[7..7 + size].to_vec();
        Ok(Self {
            frame_type,
            channel,
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmqpMethod {
    pub class_id: u16,
    pub method_id: u16,
    pub args: Vec<u8>,
}

impl AmqpMethod {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.args.len());
        out.extend_from_slice(&self.class_id.to_be_bytes());
        out.extend_from_slice(&self.method_id.to_be_bytes());
        out.extend_from_slice(&self.args);
        out
    }

    pub fn decode(payload: &[u8]) -> CoreResult<Self> {
        if payload.len() < 4 {
            return Err(CoreError::Parse("amqp method too short".to_string()));
        }
        let class_id = u16::from_be_bytes([payload[0], payload[1]]);
        let method_id = u16::from_be_bytes([payload[2], payload[3]]);
        Ok(Self {
            class_id,
            method_id,
            args: payload[4..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmqpContentHeader {
    pub class_id: u16,
    pub body_size: u64,
}

impl AmqpContentHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14);
        out.extend_from_slice(&self.class_id.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.body_size.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    pub fn decode(payload: &[u8]) -> CoreResult<Self> {
        if payload.len() < 14 {
            return Err(CoreError::Parse("amqp header too short".to_string()));
        }
        let class_id = u16::from_be_bytes([payload[0], payload[1]]);
        let body_size = u64::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ]);
        Ok(Self {
            class_id,
            body_size,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AmqpClientConfig {
    pub timeouts: Timeouts,
    pub username: String,
    pub password: String,
    pub vhost: String,
    pub channel_max: u16,
    pub frame_max: u32,
    pub heartbeat: u16,
}

impl Default for AmqpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: "guest".to_string(),
            password: "guest".to_string(),
            vhost: "/".to_string(),
            channel_max: 0,
            frame_max: 131072,
            heartbeat: 0,
        }
    }
}

pub struct AmqpClient {
    transport: TcpTransport,
    config: AmqpClientConfig,
}

impl AmqpClient {
    pub fn connect(addr: &NetAddr, config: AmqpClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self { transport, config })
    }

    pub fn handshake(&mut self) -> CoreResult<()> {
        self.transport.write_all(&PROTOCOL_HEADER)?;
        let start = read_method_frame(&mut self.transport)?;
        if start.class_id != CLASS_CONNECTION || start.method_id != METHOD_CONNECTION_START {
            return Err(CoreError::Parse("expected connection.start".to_string()));
        }
        let start_ok = method_start_ok(&self.config.username, &self.config.password);
        write_method_frame(&mut self.transport, 0, &start_ok)?;
        let tune = read_method_frame(&mut self.transport)?;
        if tune.class_id != CLASS_CONNECTION || tune.method_id != METHOD_CONNECTION_TUNE {
            return Err(CoreError::Parse("expected connection.tune".to_string()));
        }
        let (channel_max, frame_max, heartbeat) = decode_tune(&tune.args)?;
        let tune_ok = method_tune_ok(
            if self.config.channel_max == 0 {
                channel_max
            } else {
                self.config.channel_max
            },
            if self.config.frame_max == 0 {
                frame_max
            } else {
                self.config.frame_max
            },
            if self.config.heartbeat == 0 {
                heartbeat
            } else {
                self.config.heartbeat
            },
        );
        write_method_frame(&mut self.transport, 0, &tune_ok)?;
        let open = method_open(&self.config.vhost);
        write_method_frame(&mut self.transport, 0, &open)?;
        let open_ok = read_method_frame(&mut self.transport)?;
        if open_ok.class_id != CLASS_CONNECTION || open_ok.method_id != METHOD_CONNECTION_OPEN_OK {
            return Err(CoreError::Parse("expected connection.open-ok".to_string()));
        }
        Ok(())
    }

    pub fn channel_open(&mut self, channel: u16) -> CoreResult<()> {
        let method = AmqpMethod {
            class_id: CLASS_CHANNEL,
            method_id: METHOD_CHANNEL_OPEN,
            args: vec![0],
        };
        write_method_frame(&mut self.transport, channel, &method)?;
        let resp = read_method_frame(&mut self.transport)?;
        if resp.class_id != CLASS_CHANNEL || resp.method_id != METHOD_CHANNEL_OPEN_OK {
            return Err(CoreError::Parse("expected channel.open-ok".to_string()));
        }
        Ok(())
    }

    pub fn queue_declare(&mut self, channel: u16, queue: &str) -> CoreResult<()> {
        let method = method_queue_declare(queue);
        write_method_frame(&mut self.transport, channel, &method)?;
        let resp = read_method_frame(&mut self.transport)?;
        if resp.class_id != CLASS_QUEUE || resp.method_id != METHOD_QUEUE_DECLARE_OK {
            return Err(CoreError::Parse("expected queue.declare-ok".to_string()));
        }
        Ok(())
    }

    pub fn basic_publish(
        &mut self,
        channel: u16,
        exchange: &str,
        routing_key: &str,
        body: &[u8],
    ) -> CoreResult<()> {
        let method = method_basic_publish(exchange, routing_key);
        write_method_frame(&mut self.transport, channel, &method)?;
        write_content(&mut self.transport, channel, body)?;
        Ok(())
    }

    pub fn basic_consume(
        &mut self,
        channel: u16,
        queue: &str,
        consumer_tag: &str,
    ) -> CoreResult<()> {
        let method = method_basic_consume(queue, consumer_tag);
        write_method_frame(&mut self.transport, channel, &method)?;
        let resp = read_method_frame(&mut self.transport)?;
        if resp.class_id != CLASS_BASIC || resp.method_id != METHOD_BASIC_CONSUME_OK {
            return Err(CoreError::Parse("expected basic.consume-ok".to_string()));
        }
        Ok(())
    }

    pub fn consume_next(&mut self) -> CoreResult<AmqpDeliveredMessage> {
        loop {
            let frame = read_frame(&mut self.transport)?;
            if frame.frame_type == FRAME_METHOD {
                let method = AmqpMethod::decode(&frame.payload)?;
                if method.class_id == CLASS_BASIC && method.method_id == METHOD_BASIC_DELIVER {
                    let delivered = decode_basic_deliver(&method.args)?;
                    let body = read_content_after_deliver(&mut self.transport)?;
                    return Ok(AmqpDeliveredMessage {
                        exchange: delivered.0,
                        routing_key: delivered.1,
                        body,
                    });
                }
            } else if frame.frame_type == FRAME_HEARTBEAT {
                continue;
            }
        }
    }
}

pub struct AsyncAmqpClient {
    transport: AsyncTcpTransport,
    config: AmqpClientConfig,
}

impl AsyncAmqpClient {
    pub async fn connect(addr: &NetAddr, config: AmqpClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self { transport, config })
    }

    pub async fn handshake(&mut self) -> CoreResult<()> {
        self.transport.write_all(&PROTOCOL_HEADER).await?;
        let start = read_method_frame_async(&mut self.transport).await?;
        if start.class_id != CLASS_CONNECTION || start.method_id != METHOD_CONNECTION_START {
            return Err(CoreError::Parse("expected connection.start".to_string()));
        }
        let start_ok = method_start_ok(&self.config.username, &self.config.password);
        write_method_frame_async(&mut self.transport, 0, &start_ok).await?;
        let tune = read_method_frame_async(&mut self.transport).await?;
        if tune.class_id != CLASS_CONNECTION || tune.method_id != METHOD_CONNECTION_TUNE {
            return Err(CoreError::Parse("expected connection.tune".to_string()));
        }
        let (channel_max, frame_max, heartbeat) = decode_tune(&tune.args)?;
        let tune_ok = method_tune_ok(
            if self.config.channel_max == 0 {
                channel_max
            } else {
                self.config.channel_max
            },
            if self.config.frame_max == 0 {
                frame_max
            } else {
                self.config.frame_max
            },
            if self.config.heartbeat == 0 {
                heartbeat
            } else {
                self.config.heartbeat
            },
        );
        write_method_frame_async(&mut self.transport, 0, &tune_ok).await?;
        let open = method_open(&self.config.vhost);
        write_method_frame_async(&mut self.transport, 0, &open).await?;
        let open_ok = read_method_frame_async(&mut self.transport).await?;
        if open_ok.class_id != CLASS_CONNECTION || open_ok.method_id != METHOD_CONNECTION_OPEN_OK {
            return Err(CoreError::Parse("expected connection.open-ok".to_string()));
        }
        Ok(())
    }

    pub async fn channel_open(&mut self, channel: u16) -> CoreResult<()> {
        let method = AmqpMethod {
            class_id: CLASS_CHANNEL,
            method_id: METHOD_CHANNEL_OPEN,
            args: vec![0],
        };
        write_method_frame_async(&mut self.transport, channel, &method).await?;
        let resp = read_method_frame_async(&mut self.transport).await?;
        if resp.class_id != CLASS_CHANNEL || resp.method_id != METHOD_CHANNEL_OPEN_OK {
            return Err(CoreError::Parse("expected channel.open-ok".to_string()));
        }
        Ok(())
    }

    pub async fn queue_declare(&mut self, channel: u16, queue: &str) -> CoreResult<()> {
        let method = method_queue_declare(queue);
        write_method_frame_async(&mut self.transport, channel, &method).await?;
        let resp = read_method_frame_async(&mut self.transport).await?;
        if resp.class_id != CLASS_QUEUE || resp.method_id != METHOD_QUEUE_DECLARE_OK {
            return Err(CoreError::Parse("expected queue.declare-ok".to_string()));
        }
        Ok(())
    }

    pub async fn basic_publish(
        &mut self,
        channel: u16,
        exchange: &str,
        routing_key: &str,
        body: &[u8],
    ) -> CoreResult<()> {
        let method = method_basic_publish(exchange, routing_key);
        write_method_frame_async(&mut self.transport, channel, &method).await?;
        write_content_async(&mut self.transport, channel, body).await?;
        Ok(())
    }

    pub async fn basic_consume(
        &mut self,
        channel: u16,
        queue: &str,
        consumer_tag: &str,
    ) -> CoreResult<()> {
        let method = method_basic_consume(queue, consumer_tag);
        write_method_frame_async(&mut self.transport, channel, &method).await?;
        let resp = read_method_frame_async(&mut self.transport).await?;
        if resp.class_id != CLASS_BASIC || resp.method_id != METHOD_BASIC_CONSUME_OK {
            return Err(CoreError::Parse("expected basic.consume-ok".to_string()));
        }
        Ok(())
    }

    pub async fn consume_next(&mut self) -> CoreResult<AmqpDeliveredMessage> {
        loop {
            let frame = read_frame_async(&mut self.transport).await?;
            if frame.frame_type == FRAME_METHOD {
                let method = AmqpMethod::decode(&frame.payload)?;
                if method.class_id == CLASS_BASIC && method.method_id == METHOD_BASIC_DELIVER {
                    let delivered = decode_basic_deliver(&method.args)?;
                    let body = read_content_after_deliver_async(&mut self.transport).await?;
                    return Ok(AmqpDeliveredMessage {
                        exchange: delivered.0,
                        routing_key: delivered.1,
                        body,
                    });
                }
            } else if frame.frame_type == FRAME_HEARTBEAT {
                continue;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct AmqpDeliveredMessage {
    pub exchange: String,
    pub routing_key: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AmqpServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
    pub vhost: String,
    pub channel_max: u16,
    pub frame_max: u32,
    pub heartbeat: u16,
}

impl Default for AmqpServerConfig {
    fn default() -> Self {
        let mut users = HashMap::new();
        users.insert("guest".to_string(), "guest".to_string());
        Self {
            timeouts: Timeouts::default(),
            users,
            vhost: "/".to_string(),
            channel_max: 0,
            frame_max: 131072,
            heartbeat: 0,
        }
    }
}

pub trait AmqpBroker: Send + Sync {
    fn declare_queue(&self, name: &str);
    fn publish(&self, queue: &str, payload: Vec<u8>);
    fn consume(&self, queue: &str) -> Option<Vec<u8>>;
}

#[derive(Debug, Default)]
pub struct InMemoryAmqpBroker {
    queues: Mutex<HashMap<String, VecDeque<Vec<u8>>>>,
}

impl InMemoryAmqpBroker {
    pub fn with_queue(self, name: &str) -> Self {
        self.declare_queue(name);
        self
    }
}

impl AmqpBroker for InMemoryAmqpBroker {
    fn declare_queue(&self, name: &str) {
        let mut guard = self.queues.lock().expect("queues");
        guard.entry(name.to_string()).or_insert_with(VecDeque::new);
    }

    fn publish(&self, queue: &str, payload: Vec<u8>) {
        let mut guard = self.queues.lock().expect("queues");
        guard
            .entry(queue.to_string())
            .or_insert_with(VecDeque::new)
            .push_back(payload);
    }

    fn consume(&self, queue: &str) -> Option<Vec<u8>> {
        let mut guard = self.queues.lock().expect("queues");
        guard.get_mut(queue).and_then(|q| q.pop_front())
    }
}

pub struct AmqpServer {
    listener: TcpListener,
    config: AmqpServerConfig,
    broker: Arc<dyn AmqpBroker>,
}

impl AmqpServer {
    pub fn bind(
        addr: SocketAddr,
        config: AmqpServerConfig,
        broker: Arc<dyn AmqpBroker>,
    ) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            broker,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let config = self.config.clone();
            let broker = Arc::clone(&self.broker);
            thread::spawn(move || {
                let _ = handle_connection(stream, config, broker);
            });
        }
        Ok(())
    }
}

pub struct AsyncAmqpServer {
    listener: tokio::net::TcpListener,
    config: AmqpServerConfig,
    broker: Arc<dyn AmqpBroker>,
}

impl AsyncAmqpServer {
    pub async fn bind(
        addr: SocketAddr,
        config: AmqpServerConfig,
        broker: Arc<dyn AmqpBroker>,
    ) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            broker,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            let broker = Arc::clone(&self.broker);
            tokio::spawn(async move {
                let _ = handle_connection_async(stream, config, broker).await;
            });
        }
    }
}

fn handle_connection(
    stream: TcpStream,
    config: AmqpServerConfig,
    broker: Arc<dyn AmqpBroker>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let mut header = [0u8; 8];
    transport.read_exact(&mut header)?;
    if header != PROTOCOL_HEADER {
        return Err(CoreError::Parse("invalid amqp header".to_string()));
    }
    let start = method_start();
    write_method_frame(&mut transport, 0, &start)?;
    let start_ok = read_method_frame(&mut transport)?;
    if start_ok.class_id != CLASS_CONNECTION || start_ok.method_id != METHOD_CONNECTION_START_OK {
        return Err(CoreError::Parse("expected connection.start-ok".to_string()));
    }
    let (user, pass) = decode_start_ok(&start_ok.args)?;
    if let Some(expected) = config.users.get(&user) {
        if expected != &pass {
            return Err(CoreError::Message("amqp auth failed".to_string()));
        }
    }
    let tune = method_tune(config.channel_max, config.frame_max, config.heartbeat);
    write_method_frame(&mut transport, 0, &tune)?;
    let tune_ok = read_method_frame(&mut transport)?;
    if tune_ok.class_id != CLASS_CONNECTION || tune_ok.method_id != METHOD_CONNECTION_TUNE_OK {
        return Err(CoreError::Parse("expected connection.tune-ok".to_string()));
    }
    let open = read_method_frame(&mut transport)?;
    if open.class_id != CLASS_CONNECTION || open.method_id != METHOD_CONNECTION_OPEN {
        return Err(CoreError::Parse("expected connection.open".to_string()));
    }
    let open_ok = method_open_ok();
    write_method_frame(&mut transport, 0, &open_ok)?;

    let mut consumers: HashMap<u16, String> = HashMap::new();
    loop {
        let frame = read_frame(&mut transport)?;
        if frame.frame_type == FRAME_METHOD {
            let method = AmqpMethod::decode(&frame.payload)?;
            if method.class_id == CLASS_CHANNEL && method.method_id == METHOD_CHANNEL_OPEN {
                let resp = AmqpMethod {
                    class_id: CLASS_CHANNEL,
                    method_id: METHOD_CHANNEL_OPEN_OK,
                    args: vec![0],
                };
                write_method_frame(&mut transport, frame.channel, &resp)?;
            } else if method.class_id == CLASS_QUEUE && method.method_id == METHOD_QUEUE_DECLARE {
                let name = decode_queue_declare(&method.args)?;
                broker.declare_queue(&name);
                let resp = method_queue_declare_ok(&name);
                write_method_frame(&mut transport, frame.channel, &resp)?;
            } else if method.class_id == CLASS_BASIC && method.method_id == METHOD_BASIC_PUBLISH {
                let (exchange, routing_key) = decode_basic_publish(&method.args)?;
                let body = read_content_after_deliver(&mut transport)?;
                let target = if routing_key.is_empty() {
                    exchange
                } else {
                    routing_key
                };
                broker.publish(&target, body);
            } else if method.class_id == CLASS_BASIC && method.method_id == METHOD_BASIC_CONSUME {
                let (queue, consumer_tag) = decode_basic_consume(&method.args)?;
                consumers.insert(frame.channel, queue.clone());
                let resp = method_basic_consume_ok(&consumer_tag);
                write_method_frame(&mut transport, frame.channel, &resp)?;
                if let Some(payload) = broker.consume(&queue) {
                    send_basic_deliver(&mut transport, frame.channel, &queue, &payload)?;
                }
            } else if method.class_id == CLASS_CONNECTION
                && method.method_id == METHOD_CONNECTION_CLOSE
            {
                let resp = AmqpMethod {
                    class_id: CLASS_CONNECTION,
                    method_id: METHOD_CONNECTION_CLOSE_OK,
                    args: Vec::new(),
                };
                write_method_frame(&mut transport, 0, &resp)?;
                return Ok(());
            } else {
                if let Some(queue) = consumers.get(&frame.channel).cloned() {
                    if let Some(payload) = broker.consume(&queue) {
                        send_basic_deliver(&mut transport, frame.channel, &queue, &payload)?;
                    }
                }
            }
        } else if frame.frame_type == FRAME_HEARTBEAT {
            continue;
        }
    }
}

async fn handle_connection_async(
    stream: tokio::net::TcpStream,
    config: AmqpServerConfig,
    broker: Arc<dyn AmqpBroker>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let mut header = [0u8; 8];
    transport.read_exact(&mut header).await?;
    if header != PROTOCOL_HEADER {
        return Err(CoreError::Parse("invalid amqp header".to_string()));
    }
    let start = method_start();
    write_method_frame_async(&mut transport, 0, &start).await?;
    let start_ok = read_method_frame_async(&mut transport).await?;
    if start_ok.class_id != CLASS_CONNECTION || start_ok.method_id != METHOD_CONNECTION_START_OK {
        return Err(CoreError::Parse("expected connection.start-ok".to_string()));
    }
    let (user, pass) = decode_start_ok(&start_ok.args)?;
    if let Some(expected) = config.users.get(&user) {
        if expected != &pass {
            return Err(CoreError::Message("amqp auth failed".to_string()));
        }
    }
    let tune = method_tune(config.channel_max, config.frame_max, config.heartbeat);
    write_method_frame_async(&mut transport, 0, &tune).await?;
    let tune_ok = read_method_frame_async(&mut transport).await?;
    if tune_ok.class_id != CLASS_CONNECTION || tune_ok.method_id != METHOD_CONNECTION_TUNE_OK {
        return Err(CoreError::Parse("expected connection.tune-ok".to_string()));
    }
    let open = read_method_frame_async(&mut transport).await?;
    if open.class_id != CLASS_CONNECTION || open.method_id != METHOD_CONNECTION_OPEN {
        return Err(CoreError::Parse("expected connection.open".to_string()));
    }
    let open_ok = method_open_ok();
    write_method_frame_async(&mut transport, 0, &open_ok).await?;

    let mut consumers: HashMap<u16, String> = HashMap::new();
    loop {
        let frame = read_frame_async(&mut transport).await?;
        if frame.frame_type == FRAME_METHOD {
            let method = AmqpMethod::decode(&frame.payload)?;
            if method.class_id == CLASS_CHANNEL && method.method_id == METHOD_CHANNEL_OPEN {
                let resp = AmqpMethod {
                    class_id: CLASS_CHANNEL,
                    method_id: METHOD_CHANNEL_OPEN_OK,
                    args: vec![0],
                };
                write_method_frame_async(&mut transport, frame.channel, &resp).await?;
            } else if method.class_id == CLASS_QUEUE && method.method_id == METHOD_QUEUE_DECLARE {
                let name = decode_queue_declare(&method.args)?;
                broker.declare_queue(&name);
                let resp = method_queue_declare_ok(&name);
                write_method_frame_async(&mut transport, frame.channel, &resp).await?;
            } else if method.class_id == CLASS_BASIC && method.method_id == METHOD_BASIC_PUBLISH {
                let (exchange, routing_key) = decode_basic_publish(&method.args)?;
                let body = read_content_after_deliver_async(&mut transport).await?;
                let target = if routing_key.is_empty() {
                    exchange
                } else {
                    routing_key
                };
                broker.publish(&target, body);
            } else if method.class_id == CLASS_BASIC && method.method_id == METHOD_BASIC_CONSUME {
                let (queue, consumer_tag) = decode_basic_consume(&method.args)?;
                consumers.insert(frame.channel, queue.clone());
                let resp = method_basic_consume_ok(&consumer_tag);
                write_method_frame_async(&mut transport, frame.channel, &resp).await?;
                if let Some(payload) = broker.consume(&queue) {
                    send_basic_deliver_async(&mut transport, frame.channel, &queue, &payload)
                        .await?;
                }
            } else if method.class_id == CLASS_CONNECTION
                && method.method_id == METHOD_CONNECTION_CLOSE
            {
                let resp = AmqpMethod {
                    class_id: CLASS_CONNECTION,
                    method_id: METHOD_CONNECTION_CLOSE_OK,
                    args: Vec::new(),
                };
                write_method_frame_async(&mut transport, 0, &resp).await?;
                return Ok(());
            } else {
                if let Some(queue) = consumers.get(&frame.channel).cloned() {
                    if let Some(payload) = broker.consume(&queue) {
                        send_basic_deliver_async(&mut transport, frame.channel, &queue, &payload)
                            .await?;
                    }
                }
            }
        }
    }
}

fn write_method_frame(
    transport: &mut TcpTransport,
    channel: u16,
    method: &AmqpMethod,
) -> CoreResult<()> {
    let frame = AmqpFrame {
        frame_type: FRAME_METHOD,
        channel,
        payload: method.encode(),
    };
    transport.write_all(&frame.encode())
}

async fn write_method_frame_async(
    transport: &mut AsyncTcpTransport,
    channel: u16,
    method: &AmqpMethod,
) -> CoreResult<()> {
    let frame = AmqpFrame {
        frame_type: FRAME_METHOD,
        channel,
        payload: method.encode(),
    };
    transport.write_all(&frame.encode()).await
}

fn read_method_frame(transport: &mut TcpTransport) -> CoreResult<AmqpMethod> {
    let frame = read_frame(transport)?;
    if frame.frame_type != FRAME_METHOD {
        return Err(CoreError::Parse("expected method frame".to_string()));
    }
    AmqpMethod::decode(&frame.payload)
}

async fn read_method_frame_async(transport: &mut AsyncTcpTransport) -> CoreResult<AmqpMethod> {
    let frame = read_frame_async(transport).await?;
    if frame.frame_type != FRAME_METHOD {
        return Err(CoreError::Parse("expected method frame".to_string()));
    }
    AmqpMethod::decode(&frame.payload)
}

fn read_frame(transport: &mut TcpTransport) -> CoreResult<AmqpFrame> {
    let mut header = [0u8; 7];
    transport.read_exact(&mut header)?;
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    let mut payload = vec![0u8; size + 1];
    transport.read_exact(&mut payload)?;
    let mut data = Vec::with_capacity(7 + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    AmqpFrame::decode(&data)
}

async fn read_frame_async(transport: &mut AsyncTcpTransport) -> CoreResult<AmqpFrame> {
    let mut header = [0u8; 7];
    transport.read_exact(&mut header).await?;
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    let mut payload = vec![0u8; size + 1];
    transport.read_exact(&mut payload).await?;
    let mut data = Vec::with_capacity(7 + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&payload);
    AmqpFrame::decode(&data)
}

fn write_content(transport: &mut TcpTransport, channel: u16, body: &[u8]) -> CoreResult<()> {
    let header = AmqpContentHeader {
        class_id: CLASS_BASIC,
        body_size: body.len() as u64,
    };
    let header_frame = AmqpFrame {
        frame_type: FRAME_HEADER,
        channel,
        payload: header.encode(),
    };
    transport.write_all(&header_frame.encode())?;
    let body_frame = AmqpFrame {
        frame_type: FRAME_BODY,
        channel,
        payload: body.to_vec(),
    };
    transport.write_all(&body_frame.encode())
}

async fn write_content_async(
    transport: &mut AsyncTcpTransport,
    channel: u16,
    body: &[u8],
) -> CoreResult<()> {
    let header = AmqpContentHeader {
        class_id: CLASS_BASIC,
        body_size: body.len() as u64,
    };
    let header_frame = AmqpFrame {
        frame_type: FRAME_HEADER,
        channel,
        payload: header.encode(),
    };
    transport.write_all(&header_frame.encode()).await?;
    let body_frame = AmqpFrame {
        frame_type: FRAME_BODY,
        channel,
        payload: body.to_vec(),
    };
    transport.write_all(&body_frame.encode()).await
}

fn read_content_after_deliver(transport: &mut TcpTransport) -> CoreResult<Vec<u8>> {
    let header_frame = read_frame(transport)?;
    if header_frame.frame_type != FRAME_HEADER {
        return Err(CoreError::Parse("expected content header".to_string()));
    }
    let header = AmqpContentHeader::decode(&header_frame.payload)?;
    let mut body = Vec::with_capacity(header.body_size as usize);
    while body.len() < header.body_size as usize {
        let frame = read_frame(transport)?;
        if frame.frame_type != FRAME_BODY {
            return Err(CoreError::Parse("expected content body".to_string()));
        }
        body.extend_from_slice(&frame.payload);
    }
    Ok(body)
}

async fn read_content_after_deliver_async(
    transport: &mut AsyncTcpTransport,
) -> CoreResult<Vec<u8>> {
    let header_frame = read_frame_async(transport).await?;
    if header_frame.frame_type != FRAME_HEADER {
        return Err(CoreError::Parse("expected content header".to_string()));
    }
    let header = AmqpContentHeader::decode(&header_frame.payload)?;
    let mut body = Vec::with_capacity(header.body_size as usize);
    while body.len() < header.body_size as usize {
        let frame = read_frame_async(transport).await?;
        if frame.frame_type != FRAME_BODY {
            return Err(CoreError::Parse("expected content body".to_string()));
        }
        body.extend_from_slice(&frame.payload);
    }
    Ok(body)
}

fn method_start() -> AmqpMethod {
    let mut args = Vec::new();
    args.push(0);
    args.push(9);
    write_table(&mut args, &HashMap::new());
    write_longstr(&mut args, b"PLAIN");
    write_longstr(&mut args, b"en_US");
    AmqpMethod {
        class_id: CLASS_CONNECTION,
        method_id: METHOD_CONNECTION_START,
        args,
    }
}

fn method_start_ok(username: &str, password: &str) -> AmqpMethod {
    let mut args = Vec::new();
    write_table(&mut args, &HashMap::new());
    write_shortstr(&mut args, "PLAIN");
    let mut response = Vec::new();
    response.push(0);
    response.extend_from_slice(username.as_bytes());
    response.push(0);
    response.extend_from_slice(password.as_bytes());
    write_longstr(&mut args, &response);
    write_shortstr(&mut args, "en_US");
    AmqpMethod {
        class_id: CLASS_CONNECTION,
        method_id: METHOD_CONNECTION_START_OK,
        args,
    }
}

fn decode_start_ok(args: &[u8]) -> CoreResult<(String, String)> {
    let mut cursor = Cursor::new(args);
    let _props = read_table(&mut cursor)?;
    let _mechanism = read_shortstr(&mut cursor)?;
    let response = read_longstr(&mut cursor)?;
    let response = String::from_utf8_lossy(&response);
    let mut parts = response.split('\0');
    let _ = parts.next();
    let user = parts.next().unwrap_or("").to_string();
    let pass = parts.next().unwrap_or("").to_string();
    Ok((user, pass))
}

fn method_tune(channel_max: u16, frame_max: u32, heartbeat: u16) -> AmqpMethod {
    let mut args = Vec::new();
    args.extend_from_slice(&channel_max.to_be_bytes());
    args.extend_from_slice(&frame_max.to_be_bytes());
    args.extend_from_slice(&heartbeat.to_be_bytes());
    AmqpMethod {
        class_id: CLASS_CONNECTION,
        method_id: METHOD_CONNECTION_TUNE,
        args,
    }
}

fn decode_tune(args: &[u8]) -> CoreResult<(u16, u32, u16)> {
    if args.len() < 8 {
        return Err(CoreError::Parse("tune args too short".to_string()));
    }
    let channel_max = u16::from_be_bytes([args[0], args[1]]);
    let frame_max = u32::from_be_bytes([args[2], args[3], args[4], args[5]]);
    let heartbeat = u16::from_be_bytes([args[6], args[7]]);
    Ok((channel_max, frame_max, heartbeat))
}

fn method_tune_ok(channel_max: u16, frame_max: u32, heartbeat: u16) -> AmqpMethod {
    let mut args = Vec::new();
    args.extend_from_slice(&channel_max.to_be_bytes());
    args.extend_from_slice(&frame_max.to_be_bytes());
    args.extend_from_slice(&heartbeat.to_be_bytes());
    AmqpMethod {
        class_id: CLASS_CONNECTION,
        method_id: METHOD_CONNECTION_TUNE_OK,
        args,
    }
}

fn method_open(vhost: &str) -> AmqpMethod {
    let mut args = Vec::new();
    write_shortstr(&mut args, vhost);
    write_shortstr(&mut args, "");
    args.push(0);
    AmqpMethod {
        class_id: CLASS_CONNECTION,
        method_id: METHOD_CONNECTION_OPEN,
        args,
    }
}

fn method_open_ok() -> AmqpMethod {
    AmqpMethod {
        class_id: CLASS_CONNECTION,
        method_id: METHOD_CONNECTION_OPEN_OK,
        args: vec![0],
    }
}

fn method_queue_declare(queue: &str) -> AmqpMethod {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    write_shortstr(&mut args, queue);
    args.push(0);
    args.push(0);
    args.push(0);
    args.push(0);
    args.push(0);
    write_table(&mut args, &HashMap::new());
    AmqpMethod {
        class_id: CLASS_QUEUE,
        method_id: METHOD_QUEUE_DECLARE,
        args,
    }
}

fn method_queue_declare_ok(queue: &str) -> AmqpMethod {
    let mut args = Vec::new();
    write_shortstr(&mut args, queue);
    args.extend_from_slice(&0u32.to_be_bytes());
    args.extend_from_slice(&0u32.to_be_bytes());
    AmqpMethod {
        class_id: CLASS_QUEUE,
        method_id: METHOD_QUEUE_DECLARE_OK,
        args,
    }
}

fn decode_queue_declare(args: &[u8]) -> CoreResult<String> {
    let mut cursor = Cursor::new(args);
    let _reserved = cursor.read_u16()?;
    let queue = read_shortstr(&mut cursor)?;
    Ok(queue)
}

fn method_basic_publish(exchange: &str, routing_key: &str) -> AmqpMethod {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    write_shortstr(&mut args, exchange);
    write_shortstr(&mut args, routing_key);
    args.push(0);
    AmqpMethod {
        class_id: CLASS_BASIC,
        method_id: METHOD_BASIC_PUBLISH,
        args,
    }
}

fn decode_basic_publish(args: &[u8]) -> CoreResult<(String, String)> {
    let mut cursor = Cursor::new(args);
    let _reserved = cursor.read_u16()?;
    let exchange = read_shortstr(&mut cursor)?;
    let routing_key = read_shortstr(&mut cursor)?;
    Ok((exchange, routing_key))
}

fn method_basic_consume(queue: &str, consumer_tag: &str) -> AmqpMethod {
    let mut args = Vec::new();
    args.extend_from_slice(&0u16.to_be_bytes());
    write_shortstr(&mut args, queue);
    write_shortstr(&mut args, consumer_tag);
    args.push(0);
    args.push(0);
    args.push(0);
    args.push(0);
    write_table(&mut args, &HashMap::new());
    AmqpMethod {
        class_id: CLASS_BASIC,
        method_id: METHOD_BASIC_CONSUME,
        args,
    }
}

fn decode_basic_consume(args: &[u8]) -> CoreResult<(String, String)> {
    let mut cursor = Cursor::new(args);
    let _reserved = cursor.read_u16()?;
    let queue = read_shortstr(&mut cursor)?;
    let consumer_tag = read_shortstr(&mut cursor)?;
    Ok((queue, consumer_tag))
}

fn method_basic_consume_ok(consumer_tag: &str) -> AmqpMethod {
    let mut args = Vec::new();
    write_shortstr(&mut args, consumer_tag);
    AmqpMethod {
        class_id: CLASS_BASIC,
        method_id: METHOD_BASIC_CONSUME_OK,
        args,
    }
}

fn send_basic_deliver(
    transport: &mut TcpTransport,
    channel: u16,
    routing_key: &str,
    body: &[u8],
) -> CoreResult<()> {
    let mut args = Vec::new();
    write_shortstr(&mut args, "ctag");
    args.extend_from_slice(&1u64.to_be_bytes());
    args.push(0);
    write_shortstr(&mut args, "");
    write_shortstr(&mut args, routing_key);
    let method = AmqpMethod {
        class_id: CLASS_BASIC,
        method_id: METHOD_BASIC_DELIVER,
        args,
    };
    write_method_frame(transport, channel, &method)?;
    write_content(transport, channel, body)?;
    Ok(())
}

async fn send_basic_deliver_async(
    transport: &mut AsyncTcpTransport,
    channel: u16,
    routing_key: &str,
    body: &[u8],
) -> CoreResult<()> {
    let mut args = Vec::new();
    write_shortstr(&mut args, "ctag");
    args.extend_from_slice(&1u64.to_be_bytes());
    args.push(0);
    write_shortstr(&mut args, "");
    write_shortstr(&mut args, routing_key);
    let method = AmqpMethod {
        class_id: CLASS_BASIC,
        method_id: METHOD_BASIC_DELIVER,
        args,
    };
    write_method_frame_async(transport, channel, &method).await?;
    write_content_async(transport, channel, body).await?;
    Ok(())
}

fn decode_basic_deliver(args: &[u8]) -> CoreResult<(String, String)> {
    let mut cursor = Cursor::new(args);
    let _ctag = read_shortstr(&mut cursor)?;
    let _delivery_tag = cursor.read_u64()?;
    let _redelivered = cursor.read_u8()?;
    let exchange = read_shortstr(&mut cursor)?;
    let routing_key = read_shortstr(&mut cursor)?;
    Ok((exchange, routing_key))
}

fn write_shortstr(out: &mut Vec<u8>, value: &str) {
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

fn read_shortstr(cursor: &mut Cursor) -> CoreResult<String> {
    let len = cursor.read_u8()? as usize;
    let bytes = cursor.read_bytes(len)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn write_longstr(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn read_longstr(cursor: &mut Cursor) -> CoreResult<Vec<u8>> {
    let len = cursor.read_u32()? as usize;
    cursor.read_bytes(len)
}

fn write_table(out: &mut Vec<u8>, table: &HashMap<String, String>) {
    let mut buf = Vec::new();
    for (key, value) in table {
        write_shortstr(&mut buf, key);
        buf.push(b'S');
        write_longstr(&mut buf, value.as_bytes());
    }
    out.extend_from_slice(&(buf.len() as u32).to_be_bytes());
    out.extend_from_slice(&buf);
}

fn read_table(cursor: &mut Cursor) -> CoreResult<HashMap<String, String>> {
    let len = cursor.read_u32()? as usize;
    let bytes = cursor.read_bytes(len)?;
    let mut table = HashMap::new();
    let mut inner = Cursor::new(&bytes);
    while inner.remaining() > 0 {
        let key = read_shortstr(&mut inner)?;
        let field_type = inner.read_u8()?;
        if field_type == b'S' {
            let value = read_longstr(&mut inner)?;
            table.insert(key, String::from_utf8_lossy(&value).to_string());
        } else {
            return Err(CoreError::Parse("unsupported field type".to_string()));
        }
    }
    Ok(table)
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> CoreResult<u8> {
        if self.pos + 1 > self.buf.len() {
            return Err(CoreError::Parse("cursor eof".to_string()));
        }
        let out = self.buf[self.pos];
        self.pos += 1;
        Ok(out)
    }

    fn read_u16(&mut self) -> CoreResult<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> CoreResult<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> CoreResult<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, len: usize) -> CoreResult<Vec<u8>> {
        if self.pos + len > self.buf.len() {
            return Err(CoreError::Parse("cursor eof".to_string()));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amqp_handshake_publish_consume() {
        let broker = Arc::new(InMemoryAmqpBroker::default());
        let server = crate::skip_if_perm!(AmqpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            AmqpServerConfig::default(),
            broker.clone(),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client =
            AmqpClient::connect(&NetAddr::from_socket(addr), AmqpClientConfig::default()).unwrap();
        client.handshake().unwrap();
        client.channel_open(1).unwrap();
        client.queue_declare(1, "queue").unwrap();
        client.basic_publish(1, "", "queue", b"hello").unwrap();
        client.basic_consume(1, "queue", "ctag").unwrap();
        let msg = client.consume_next().unwrap();
        assert_eq!(msg.body, b"hello".to_vec());
    }
}
