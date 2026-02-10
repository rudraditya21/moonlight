use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttPacketType {
    Connect = 1,
    ConnAck = 2,
    Publish = 3,
    PubAck = 4,
    Subscribe = 8,
    SubAck = 9,
    PingReq = 12,
    PingResp = 13,
    Disconnect = 14,
}

#[derive(Debug, Clone)]
pub enum MqttPacket {
    Connect {
        client_id: String,
        keep_alive: u16,
        username: Option<String>,
        password: Option<String>,
        clean_session: bool,
    },
    ConnAck {
        session_present: bool,
        return_code: u8,
    },
    Publish {
        topic: String,
        payload: Vec<u8>,
        qos: u8,
        retain: bool,
        packet_id: Option<u16>,
    },
    PubAck {
        packet_id: u16,
    },
    Subscribe {
        packet_id: u16,
        topics: Vec<(String, u8)>,
    },
    SubAck {
        packet_id: u16,
        return_codes: Vec<u8>,
    },
    PingReq,
    PingResp,
    Disconnect,
}

impl MqttPacket {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        match self {
            MqttPacket::Connect {
                client_id,
                keep_alive,
                username,
                password,
                clean_session,
            } => {
                let mut payload = Vec::new();
                encode_string(&mut payload, client_id);
                if let Some(name) = username {
                    encode_string(&mut payload, name);
                }
                if let Some(pass) = password {
                    encode_string(&mut payload, pass);
                }

                let mut vh = Vec::new();
                encode_string(&mut vh, "MQTT");
                vh.push(4);
                let mut flags = 0u8;
                if *clean_session {
                    flags |= 0b10;
                }
                if username.is_some() {
                    flags |= 0b1000_0000;
                }
                if password.is_some() {
                    flags |= 0b0100_0000;
                }
                vh.push(flags);
                vh.extend_from_slice(&keep_alive.to_be_bytes());

                let mut out = Vec::new();
                out.push((MqttPacketType::Connect as u8) << 4);
                let remaining = vh.len() + payload.len();
                encode_remaining_length(&mut out, remaining);
                out.extend_from_slice(&vh);
                out.extend_from_slice(&payload);
                Ok(out)
            }
            MqttPacket::ConnAck {
                session_present,
                return_code,
            } => {
                let mut out = vec![(MqttPacketType::ConnAck as u8) << 4, 2];
                out.push(if *session_present { 0x01 } else { 0x00 });
                out.push(*return_code);
                Ok(out)
            }
            MqttPacket::Publish {
                topic,
                payload,
                qos,
                retain,
                packet_id,
            } => {
                let mut vh = Vec::new();
                encode_string(&mut vh, topic);
                if *qos > 0 {
                    let id = packet_id.ok_or_else(|| CoreError::Parse("mqtt missing packet id".to_string()))?;
                    vh.extend_from_slice(&id.to_be_bytes());
                }
                let mut flags = (*qos & 0x03) << 1;
                if *retain {
                    flags |= 0x01;
                }
                let mut out = Vec::new();
                out.push(((MqttPacketType::Publish as u8) << 4) | flags);
                encode_remaining_length(&mut out, vh.len() + payload.len());
                out.extend_from_slice(&vh);
                out.extend_from_slice(payload);
                Ok(out)
            }
            MqttPacket::PubAck { packet_id } => {
                let mut out = vec![(MqttPacketType::PubAck as u8) << 4, 2];
                out.extend_from_slice(&packet_id.to_be_bytes());
                Ok(out)
            }
            MqttPacket::Subscribe { packet_id, topics } => {
                let mut vh = Vec::new();
                vh.extend_from_slice(&packet_id.to_be_bytes());
                for (topic, qos) in topics {
                    encode_string(&mut vh, topic);
                    vh.push(*qos);
                }
                let mut out = Vec::new();
                out.push(((MqttPacketType::Subscribe as u8) << 4) | 0x02);
                encode_remaining_length(&mut out, vh.len());
                out.extend_from_slice(&vh);
                Ok(out)
            }
            MqttPacket::SubAck {
                packet_id,
                return_codes,
            } => {
                let mut out = Vec::new();
                out.push((MqttPacketType::SubAck as u8) << 4);
                encode_remaining_length(&mut out, 2 + return_codes.len());
                out.extend_from_slice(&packet_id.to_be_bytes());
                out.extend_from_slice(return_codes);
                Ok(out)
            }
            MqttPacket::PingReq => Ok(vec![(MqttPacketType::PingReq as u8) << 4, 0]),
            MqttPacket::PingResp => Ok(vec![(MqttPacketType::PingResp as u8) << 4, 0]),
            MqttPacket::Disconnect => Ok(vec![(MqttPacketType::Disconnect as u8) << 4, 0]),
        }
    }

    pub fn decode(mut data: &[u8]) -> CoreResult<Self> {
        if data.is_empty() {
            return Err(CoreError::Parse("mqtt empty packet".to_string()));
        }
        let header = data[0];
        let packet_type = header >> 4;
        let flags = header & 0x0f;
        let (remaining, consumed) = decode_remaining_length(&data[1..])?;
        data = &data[1 + consumed..];
        if data.len() < remaining {
            return Err(CoreError::Parse("mqtt packet length mismatch".to_string()));
        }
        let payload = &data[..remaining];
        match packet_type {
            1 => decode_connect(payload),
            2 => {
                if payload.len() != 2 {
                    return Err(CoreError::Parse("mqtt connack len".to_string()));
                }
                Ok(MqttPacket::ConnAck {
                    session_present: payload[0] & 0x01 != 0,
                    return_code: payload[1],
                })
            }
            3 => decode_publish(payload, flags),
            4 => {
                if payload.len() != 2 {
                    return Err(CoreError::Parse("mqtt puback len".to_string()));
                }
                Ok(MqttPacket::PubAck {
                    packet_id: u16::from_be_bytes([payload[0], payload[1]]),
                })
            }
            8 => decode_subscribe(payload),
            9 => decode_suback(payload),
            12 => Ok(MqttPacket::PingReq),
            13 => Ok(MqttPacket::PingResp),
            14 => Ok(MqttPacket::Disconnect),
            _ => Err(CoreError::Parse("mqtt packet type unsupported".to_string())),
        }
    }
}

fn decode_connect(payload: &[u8]) -> CoreResult<MqttPacket> {
    let mut idx = 0;
    let protocol = decode_string(payload, &mut idx)?;
    if protocol != "MQTT" {
        return Err(CoreError::Parse("mqtt protocol name invalid".to_string()));
    }
    if idx >= payload.len() {
        return Err(CoreError::Parse("mqtt protocol level missing".to_string()));
    }
    let level = payload[idx];
    idx += 1;
    if level != 4 {
        return Err(CoreError::Parse("mqtt protocol level unsupported".to_string()));
    }
    if idx >= payload.len() {
        return Err(CoreError::Parse("mqtt flags missing".to_string()));
    }
    let flags = payload[idx];
    idx += 1;
    if idx + 2 > payload.len() {
        return Err(CoreError::Parse("mqtt keepalive missing".to_string()));
    }
    let keep_alive = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
    idx += 2;
    let client_id = decode_string(payload, &mut idx)?;
    let username = if flags & 0x80 != 0 {
        Some(decode_string(payload, &mut idx)?)
    } else {
        None
    };
    let password = if flags & 0x40 != 0 {
        Some(decode_string(payload, &mut idx)?)
    } else {
        None
    };
    Ok(MqttPacket::Connect {
        client_id,
        keep_alive,
        username,
        password,
        clean_session: flags & 0x02 != 0,
    })
}

fn decode_publish(payload: &[u8], flags: u8) -> CoreResult<MqttPacket> {
    let mut idx = 0;
    let topic = decode_string(payload, &mut idx)?;
    let qos = (flags >> 1) & 0x03;
    let packet_id = if qos > 0 {
        if idx + 2 > payload.len() {
            return Err(CoreError::Parse("mqtt publish missing packet id".to_string()));
        }
        let id = u16::from_be_bytes([payload[idx], payload[idx + 1]]);
        idx += 2;
        Some(id)
    } else {
        None
    };
    let data = payload[idx..].to_vec();
    Ok(MqttPacket::Publish {
        topic,
        payload: data,
        qos,
        retain: flags & 0x01 != 0,
        packet_id,
    })
}

fn decode_subscribe(payload: &[u8]) -> CoreResult<MqttPacket> {
    if payload.len() < 2 {
        return Err(CoreError::Parse("mqtt subscribe too short".to_string()));
    }
    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    let mut idx = 2;
    let mut topics = Vec::new();
    while idx < payload.len() {
        let topic = decode_string(payload, &mut idx)?;
        if idx >= payload.len() {
            return Err(CoreError::Parse("mqtt subscribe missing qos".to_string()));
        }
        let qos = payload[idx];
        idx += 1;
        topics.push((topic, qos));
    }
    Ok(MqttPacket::Subscribe { packet_id, topics })
}

fn decode_suback(payload: &[u8]) -> CoreResult<MqttPacket> {
    if payload.len() < 3 {
        return Err(CoreError::Parse("mqtt suback too short".to_string()));
    }
    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    let return_codes = payload[2..].to_vec();
    Ok(MqttPacket::SubAck {
        packet_id,
        return_codes,
    })
}

fn encode_remaining_length(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut encoded = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            encoded |= 0x80;
        }
        out.push(encoded);
        if value == 0 {
            break;
        }
    }
}

fn decode_remaining_length(data: &[u8]) -> CoreResult<(usize, usize)> {
    let mut multiplier = 1usize;
    let mut value = 0usize;
    let mut idx = 0;
    loop {
        if idx >= data.len() {
            return Err(CoreError::Parse("mqtt remaining length missing".to_string()));
        }
        let encoded = data[idx];
        idx += 1;
        value += ((encoded & 0x7F) as usize) * multiplier;
        if encoded & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 * 128 {
            return Err(CoreError::Parse("mqtt remaining length overflow".to_string()));
        }
    }
    Ok((value, idx))
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn decode_string(data: &[u8], idx: &mut usize) -> CoreResult<String> {
    if *idx + 2 > data.len() {
        return Err(CoreError::Parse("mqtt string len missing".to_string()));
    }
    let len = u16::from_be_bytes([data[*idx], data[*idx + 1]]) as usize;
    *idx += 2;
    if *idx + len > data.len() {
        return Err(CoreError::Parse("mqtt string length invalid".to_string()));
    }
    let value = String::from_utf8_lossy(&data[*idx..*idx + len]).to_string();
    *idx += len;
    Ok(value)
}

#[derive(Debug, Clone)]
pub struct MqttClientConfig {
    pub timeouts: Timeouts,
    pub client_id: String,
    pub keep_alive: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for MqttClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            client_id: format!("moonlight-{}", rand_seed()),
            keep_alive: 30,
            username: None,
            password: None,
        }
    }
}

pub struct MqttClient {
    transport: TcpTransport,
    config: MqttClientConfig,
    next_packet_id: u16,
}

impl MqttClient {
    pub fn connect(addr: &NetAddr, config: MqttClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let packet = MqttPacket::Connect {
            client_id: config.client_id.clone(),
            keep_alive: config.keep_alive,
            username: config.username.clone(),
            password: config.password.clone(),
            clean_session: true,
        };
        write_packet(&mut transport, &packet)?;
        let response = read_packet(&mut transport)?;
        match response {
            MqttPacket::ConnAck { return_code, .. } if return_code == 0 => Ok(Self {
                transport,
                config,
                next_packet_id: 1,
            }),
            MqttPacket::ConnAck { return_code, .. } => Err(CoreError::Message(format!(
                "mqtt connect failed code {return_code}"
            ))),
            _ => Err(CoreError::Parse("mqtt expected connack".to_string())),
        }
    }

    pub fn publish(&mut self, topic: &str, payload: Vec<u8>, qos: u8) -> CoreResult<()> {
        let packet_id = if qos > 0 {
            let id = self.next_packet_id;
            self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
            Some(id)
        } else {
            None
        };
        let packet = MqttPacket::Publish {
            topic: topic.to_string(),
            payload,
            qos,
            retain: false,
            packet_id,
        };
        write_packet(&mut self.transport, &packet)?;
        if qos == 1 {
            let ack = read_packet(&mut self.transport)?;
            if let MqttPacket::PubAck { .. } = ack {
                Ok(())
            } else {
                Err(CoreError::Parse("mqtt expected puback".to_string()))
            }
        } else {
            Ok(())
        }
    }

    pub fn subscribe(&mut self, topics: Vec<(String, u8)>) -> CoreResult<()> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
        let packet = MqttPacket::Subscribe { packet_id, topics };
        write_packet(&mut self.transport, &packet)?;
        let response = read_packet(&mut self.transport)?;
        match response {
            MqttPacket::SubAck { .. } => Ok(()),
            _ => Err(CoreError::Parse("mqtt expected suback".to_string())),
        }
    }

    pub fn ping(&mut self) -> CoreResult<()> {
        write_packet(&mut self.transport, &MqttPacket::PingReq)?;
        match read_packet(&mut self.transport)? {
            MqttPacket::PingResp => Ok(()),
            _ => Err(CoreError::Parse("mqtt expected pingresp".to_string())),
        }
    }

    pub fn recv(&mut self) -> CoreResult<MqttPacket> {
        read_packet(&mut self.transport)
    }
}

pub struct AsyncMqttClient {
    transport: AsyncTcpTransport,
    config: MqttClientConfig,
    next_packet_id: u16,
}

impl AsyncMqttClient {
    pub async fn connect(addr: &NetAddr, config: MqttClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let packet = MqttPacket::Connect {
            client_id: config.client_id.clone(),
            keep_alive: config.keep_alive,
            username: config.username.clone(),
            password: config.password.clone(),
            clean_session: true,
        };
        write_packet_async(&mut transport, &packet).await?;
        let response = read_packet_async(&mut transport).await?;
        match response {
            MqttPacket::ConnAck { return_code, .. } if return_code == 0 => Ok(Self {
                transport,
                config,
                next_packet_id: 1,
            }),
            MqttPacket::ConnAck { return_code, .. } => Err(CoreError::Message(format!(
                "mqtt connect failed code {return_code}"
            ))),
            _ => Err(CoreError::Parse("mqtt expected connack".to_string())),
        }
    }

    pub async fn publish(&mut self, topic: &str, payload: Vec<u8>, qos: u8) -> CoreResult<()> {
        let packet_id = if qos > 0 {
            let id = self.next_packet_id;
            self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
            Some(id)
        } else {
            None
        };
        let packet = MqttPacket::Publish {
            topic: topic.to_string(),
            payload,
            qos,
            retain: false,
            packet_id,
        };
        write_packet_async(&mut self.transport, &packet).await?;
        if qos == 1 {
            let ack = read_packet_async(&mut self.transport).await?;
            if let MqttPacket::PubAck { .. } = ack {
                Ok(())
            } else {
                Err(CoreError::Parse("mqtt expected puback".to_string()))
            }
        } else {
            Ok(())
        }
    }

    pub async fn subscribe(&mut self, topics: Vec<(String, u8)>) -> CoreResult<()> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);
        let packet = MqttPacket::Subscribe { packet_id, topics };
        write_packet_async(&mut self.transport, &packet).await?;
        let response = read_packet_async(&mut self.transport).await?;
        match response {
            MqttPacket::SubAck { .. } => Ok(()),
            _ => Err(CoreError::Parse("mqtt expected suback".to_string())),
        }
    }

    pub async fn recv(&mut self) -> CoreResult<MqttPacket> {
        read_packet_async(&mut self.transport).await
    }
}

#[derive(Debug, Clone)]
pub struct MqttServerConfig {
    pub timeouts: Timeouts,
    pub poll_interval: Duration,
    pub allow_anonymous: bool,
    pub users: HashMap<String, String>,
    pub max_clients: usize,
}

impl Default for MqttServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            poll_interval: Duration::from_millis(200),
            allow_anonymous: true,
            users: HashMap::new(),
            max_clients: 1000,
        }
    }
}

#[derive(Debug, Clone)]
struct Session {
    tx: tokio::sync::mpsc::UnboundedSender<MqttPacket>,
    subscriptions: Vec<(String, u8)>,
}

#[derive(Debug, Default)]
struct MqttBroker {
    sessions: HashMap<String, Session>,
}

impl MqttBroker {
    fn register(&mut self, client_id: String, tx: tokio::sync::mpsc::UnboundedSender<MqttPacket>) {
        self.sessions.insert(
            client_id,
            Session {
                tx,
                subscriptions: Vec::new(),
            },
        );
    }

    fn unregister(&mut self, client_id: &str) {
        self.sessions.remove(client_id);
    }

    fn add_subscription(&mut self, client_id: &str, topic: String, qos: u8) {
        if let Some(session) = self.sessions.get_mut(client_id) {
            session.subscriptions.push((topic, qos));
        }
    }

    fn publish(&self, topic: &str, payload: Vec<u8>, qos: u8) {
        for session in self.sessions.values() {
            for (filter, sub_qos) in &session.subscriptions {
                if topic_matches(filter, topic) {
                    let deliver_qos = qos.min(*sub_qos);
                    let packet = MqttPacket::Publish {
                        topic: topic.to_string(),
                        payload: payload.clone(),
                        qos: deliver_qos,
                        retain: false,
                        packet_id: if deliver_qos > 0 { Some(1) } else { None },
                    };
                    let _ = session.tx.send(packet);
                    break;
                }
            }
        }
    }
}

pub struct MqttServer {
    listener: TcpListener,
    config: MqttServerConfig,
    broker: Arc<Mutex<MqttBroker>>,
}

impl MqttServer {
    pub fn bind(addr: SocketAddr, config: MqttServerConfig) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            broker: Arc::new(Mutex::new(MqttBroker::default())),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let broker = Arc::clone(&self.broker);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_mqtt_client(stream, broker, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncMqttServer {
    listener: tokio::net::TcpListener,
    config: MqttServerConfig,
    broker: Arc<Mutex<MqttBroker>>,
}

impl AsyncMqttServer {
    pub async fn bind(addr: SocketAddr, config: MqttServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            broker: Arc::new(Mutex::new(MqttBroker::default())),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let broker = Arc::clone(&self.broker);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_mqtt_client_async(stream, broker, config).await;
            });
        }
    }
}

fn handle_mqtt_client(stream: TcpStream, broker: Arc<Mutex<MqttBroker>>, config: MqttServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    transport.set_read_timeout(Some(config.poll_interval))?;

    let connect = match read_packet(&mut transport) {
        Ok(packet) => packet,
        Err(err) => return Err(err),
    };
    let (client_id, username, password) = match connect {
        MqttPacket::Connect {
            client_id,
            username,
            password,
            ..
        } => (client_id, username, password),
        _ => {
            return Err(CoreError::Parse("mqtt expected connect".to_string()));
        }
    };
    if !config.allow_anonymous {
        let valid = match (username.clone(), password.clone()) {
            (Some(user), Some(pass)) => config.users.get(&user).map(|p| p == &pass).unwrap_or(false),
            _ => false,
        };
        if !valid {
            let packet = MqttPacket::ConnAck {
                session_present: false,
                return_code: 0x04,
            };
            write_packet(&mut transport, &packet)?;
            return Ok(());
        }
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = if client_id.is_empty() {
        format!("moonlight-{}", rand_seed())
    } else {
        client_id
    };
    if let Ok(mut broker) = broker.lock() {
        broker.register(client_id.clone(), tx);
    }

    let ack = MqttPacket::ConnAck {
        session_present: false,
        return_code: 0,
    };
    write_packet(&mut transport, &ack)?;

    loop {
        match read_packet(&mut transport) {
            Ok(packet) => {
                if handle_server_packet(&mut transport, &broker, &client_id, packet)? {
                    break;
                }
            }
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut => {
                while let Ok(packet) = rx.try_recv() {
                    let _ = write_packet(&mut transport, &packet);
                }
            }
            Err(_) => break,
        }
    }

    if let Ok(mut broker) = broker.lock() {
        broker.unregister(&client_id);
    }
    Ok(())
}

async fn handle_mqtt_client_async(
    stream: tokio::net::TcpStream,
    broker: Arc<Mutex<MqttBroker>>,
    config: MqttServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let connect = read_packet_async(&mut transport).await?;
    let (client_id, username, password) = match connect {
        MqttPacket::Connect {
            client_id,
            username,
            password,
            ..
        } => (client_id, username, password),
        _ => return Err(CoreError::Parse("mqtt expected connect".to_string())),
    };
    if !config.allow_anonymous {
        let valid = match (username.clone(), password.clone()) {
            (Some(user), Some(pass)) => config.users.get(&user).map(|p| p == &pass).unwrap_or(false),
            _ => false,
        };
        if !valid {
            let packet = MqttPacket::ConnAck {
                session_present: false,
                return_code: 0x04,
            };
            write_packet_async(&mut transport, &packet).await?;
            return Ok(());
        }
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let client_id = if client_id.is_empty() {
        format!("moonlight-{}", rand_seed())
    } else {
        client_id
    };
    if let Ok(mut broker) = broker.lock() {
        broker.register(client_id.clone(), tx);
    }

    let ack = MqttPacket::ConnAck {
        session_present: false,
        return_code: 0,
    };
    write_packet_async(&mut transport, &ack).await?;

    loop {
        tokio::select! {
            packet = read_packet_async(&mut transport) => {
                match packet {
                    Ok(packet) => {
                        if handle_server_packet_async(&mut transport, &broker, &client_id, packet).await? {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Some(packet) = rx.recv() => {
                let _ = write_packet_async(&mut transport, &packet).await;
            }
        }
    }

    if let Ok(mut broker) = broker.lock() {
        broker.unregister(&client_id);
    }
    Ok(())
}

fn handle_server_packet(
    transport: &mut TcpTransport,
    broker: &Arc<Mutex<MqttBroker>>,
    client_id: &str,
    packet: MqttPacket,
) -> CoreResult<bool> {
    match packet {
        MqttPacket::Publish { topic, payload, qos, packet_id, .. } => {
            if qos == 1 {
                if let Some(id) = packet_id {
                    write_packet(transport, &MqttPacket::PubAck { packet_id: id })?;
                }
            }
            if let Ok(broker) = broker.lock() {
                broker.publish(&topic, payload, qos);
            }
        }
        MqttPacket::Subscribe { packet_id, topics } => {
            if let Ok(mut broker) = broker.lock() {
                for (topic, qos) in &topics {
                    broker.add_subscription(client_id, topic.clone(), *qos);
                }
            }
            let return_codes = topics.iter().map(|(_, qos)| *qos).collect();
            write_packet(transport, &MqttPacket::SubAck { packet_id, return_codes })?;
        }
        MqttPacket::PingReq => {
            write_packet(transport, &MqttPacket::PingResp)?;
        }
        MqttPacket::Disconnect => return Ok(true),
        _ => {}
    }
    Ok(false)
}

async fn handle_server_packet_async(
    transport: &mut AsyncTcpTransport,
    broker: &Arc<Mutex<MqttBroker>>,
    client_id: &str,
    packet: MqttPacket,
) -> CoreResult<bool> {
    match packet {
        MqttPacket::Publish { topic, payload, qos, packet_id, .. } => {
            if qos == 1 {
                if let Some(id) = packet_id {
                    write_packet_async(transport, &MqttPacket::PubAck { packet_id: id }).await?;
                }
            }
            if let Ok(broker) = broker.lock() {
                broker.publish(&topic, payload, qos);
            }
        }
        MqttPacket::Subscribe { packet_id, topics } => {
            if let Ok(mut broker) = broker.lock() {
                for (topic, qos) in &topics {
                    broker.add_subscription(client_id, topic.clone(), *qos);
                }
            }
            let return_codes = topics.iter().map(|(_, qos)| *qos).collect();
            write_packet_async(transport, &MqttPacket::SubAck { packet_id, return_codes }).await?;
        }
        MqttPacket::PingReq => {
            write_packet_async(transport, &MqttPacket::PingResp).await?;
        }
        MqttPacket::Disconnect => return Ok(true),
        _ => {}
    }
    Ok(false)
}

fn read_packet<T: StreamTransport>(transport: &mut T) -> CoreResult<MqttPacket> {
    let mut header = [0u8; 1];
    transport.read_exact(&mut header)?;
    let mut len_bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        transport.read_exact(&mut b)?;
        len_bytes.push(b[0]);
        if b[0] & 0x80 == 0 {
            break;
        }
        if len_bytes.len() >= 4 {
            return Err(CoreError::Parse("mqtt remaining length too long".to_string()));
        }
    }
    let (remaining, _) = decode_remaining_length(&len_bytes)?;
    let mut payload = vec![0u8; remaining];
    if remaining > 0 {
        transport.read_exact(&mut payload)?;
    }
    let mut data = Vec::with_capacity(1 + len_bytes.len() + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&len_bytes);
    data.extend_from_slice(&payload);
    MqttPacket::decode(&data)
}

async fn read_packet_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<MqttPacket> {
    let mut header = [0u8; 1];
    transport.read_exact(&mut header).await?;
    let mut len_bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        transport.read_exact(&mut b).await?;
        len_bytes.push(b[0]);
        if b[0] & 0x80 == 0 {
            break;
        }
        if len_bytes.len() >= 4 {
            return Err(CoreError::Parse("mqtt remaining length too long".to_string()));
        }
    }
    let (remaining, _) = decode_remaining_length(&len_bytes)?;
    let mut payload = vec![0u8; remaining];
    if remaining > 0 {
        transport.read_exact(&mut payload).await?;
    }
    let mut data = Vec::with_capacity(1 + len_bytes.len() + payload.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&len_bytes);
    data.extend_from_slice(&payload);
    MqttPacket::decode(&data)
}

fn write_packet<T: StreamTransport>(transport: &mut T, packet: &MqttPacket) -> CoreResult<()> {
    let bytes = packet.encode()?;
    transport.write_all(&bytes)
}

async fn write_packet_async<T: AsyncStreamTransport>(transport: &mut T, packet: &MqttPacket) -> CoreResult<()> {
    let bytes = packet.encode()?;
    transport.write_all(&bytes).await
}

fn topic_matches(filter: &str, topic: &str) -> bool {
    let filter_parts: Vec<&str> = filter.split('/').collect();
    let topic_parts: Vec<&str> = topic.split('/').collect();
    let mut i = 0;
    while i < filter_parts.len() {
        let f = filter_parts[i];
        if f == "#" {
            return true;
        }
        if i >= topic_parts.len() {
            return false;
        }
        if f != "+" && f != topic_parts[i] {
            return false;
        }
        i += 1;
    }
    i == topic_parts.len()
}

fn rand_seed() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    now.as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mqtt_publish_subscribe() {
        let server = MqttServer::bind("127.0.0.1:0".parse().unwrap(), MqttServerConfig::default()).unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let mut sub = MqttClient::connect(&NetAddr::from_socket(addr), MqttClientConfig::default()).unwrap();
        sub.subscribe(vec![("test/#".to_string(), 0)]).unwrap();

        let mut pubc = MqttClient::connect(&NetAddr::from_socket(addr), MqttClientConfig::default()).unwrap();
        pubc.publish("test/hello", b"world".to_vec(), 0).unwrap();

        let packet = sub.recv().unwrap();
        match packet {
            MqttPacket::Publish { topic, payload, .. } => {
                assert_eq!(topic, "test/hello");
                assert_eq!(payload, b"world".to_vec());
            }
            _ => panic!("unexpected packet"),
        }

        drop(handle);
    }
}
