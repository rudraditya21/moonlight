use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const VERSION_1: i32 = 0x80010000u32 as i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThriftMessageType {
    Call = 1,
    Reply = 2,
    Exception = 3,
    Oneway = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThriftType {
    Stop = 0,
    Void = 1,
    Bool = 2,
    Byte = 3,
    Double = 4,
    I16 = 6,
    I32 = 8,
    I64 = 10,
    String = 11,
    Struct = 12,
    Map = 13,
    Set = 14,
    List = 15,
}

impl ThriftType {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            0 => Ok(ThriftType::Stop),
            1 => Ok(ThriftType::Void),
            2 => Ok(ThriftType::Bool),
            3 => Ok(ThriftType::Byte),
            4 => Ok(ThriftType::Double),
            6 => Ok(ThriftType::I16),
            8 => Ok(ThriftType::I32),
            10 => Ok(ThriftType::I64),
            11 => Ok(ThriftType::String),
            12 => Ok(ThriftType::Struct),
            13 => Ok(ThriftType::Map),
            14 => Ok(ThriftType::Set),
            15 => Ok(ThriftType::List),
            _ => Err(CoreError::Parse("invalid thrift type".to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThriftValue {
    Bool(bool),
    Byte(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    Double(f64),
    String(Vec<u8>),
    Struct(Vec<ThriftField>),
    Map(ThriftType, ThriftType, Vec<(ThriftValue, ThriftValue)>),
    Set(ThriftType, Vec<ThriftValue>),
    List(ThriftType, Vec<ThriftValue>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThriftField {
    pub id: i16,
    pub field_type: ThriftType,
    pub value: ThriftValue,
}

pub type ThriftStruct = Vec<ThriftField>;

#[derive(Debug, Clone)]
pub struct ThriftMessage {
    pub name: String,
    pub message_type: ThriftMessageType,
    pub seqid: i32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ThriftApplicationException {
    pub message: String,
    pub kind: i32,
}

impl ThriftApplicationException {
    pub fn encode(&self) -> Vec<u8> {
        let fields = vec![
            ThriftField {
                id: 1,
                field_type: ThriftType::String,
                value: ThriftValue::String(self.message.as_bytes().to_vec()),
            },
            ThriftField {
                id: 2,
                field_type: ThriftType::I32,
                value: ThriftValue::I32(self.kind),
            },
        ];
        encode_struct(&fields)
    }
}

#[derive(Debug, Clone)]
pub struct ThriftClientConfig {
    pub timeouts: Timeouts,
    pub framed: bool,
}

impl Default for ThriftClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            framed: true,
        }
    }
}

pub struct ThriftClient {
    transport: TcpTransport,
    config: ThriftClientConfig,
    seqid: i32,
}

impl ThriftClient {
    pub fn connect(addr: &NetAddr, config: ThriftClientConfig) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, config.timeouts)?;
        Ok(Self {
            transport,
            config,
            seqid: 1,
        })
    }

    pub fn call(&mut self, method: &str, args: ThriftStruct) -> CoreResult<ThriftStruct> {
        let payload = encode_struct(&args);
        let msg = ThriftMessage {
            name: method.to_string(),
            message_type: ThriftMessageType::Call,
            seqid: self.seqid,
            payload,
        };
        self.seqid = self.seqid.wrapping_add(1);
        write_message(&mut self.transport, &msg, self.config.framed)?;
        let reply = read_message(&mut self.transport, self.config.framed)?;
        match reply.message_type {
            ThriftMessageType::Reply => decode_struct(&reply.payload),
            ThriftMessageType::Exception => Err(CoreError::Message("thrift exception".to_string())),
            _ => Err(CoreError::Parse("unexpected thrift response".to_string())),
        }
    }

    pub fn oneway(&mut self, method: &str, args: ThriftStruct) -> CoreResult<()> {
        let payload = encode_struct(&args);
        let msg = ThriftMessage {
            name: method.to_string(),
            message_type: ThriftMessageType::Oneway,
            seqid: self.seqid,
            payload,
        };
        self.seqid = self.seqid.wrapping_add(1);
        write_message(&mut self.transport, &msg, self.config.framed)
    }
}

pub struct AsyncThriftClient {
    transport: AsyncTcpTransport,
    config: ThriftClientConfig,
    seqid: i32,
}

impl AsyncThriftClient {
    pub async fn connect(addr: &NetAddr, config: ThriftClientConfig) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        Ok(Self {
            transport,
            config,
            seqid: 1,
        })
    }

    pub async fn call(&mut self, method: &str, args: ThriftStruct) -> CoreResult<ThriftStruct> {
        let payload = encode_struct(&args);
        let msg = ThriftMessage {
            name: method.to_string(),
            message_type: ThriftMessageType::Call,
            seqid: self.seqid,
            payload,
        };
        self.seqid = self.seqid.wrapping_add(1);
        write_message_async(&mut self.transport, &msg, self.config.framed).await?;
        let reply = read_message_async(&mut self.transport, self.config.framed).await?;
        match reply.message_type {
            ThriftMessageType::Reply => decode_struct(&reply.payload),
            ThriftMessageType::Exception => Err(CoreError::Message("thrift exception".to_string())),
            _ => Err(CoreError::Parse("unexpected thrift response".to_string())),
        }
    }

    pub async fn oneway(&mut self, method: &str, args: ThriftStruct) -> CoreResult<()> {
        let payload = encode_struct(&args);
        let msg = ThriftMessage {
            name: method.to_string(),
            message_type: ThriftMessageType::Oneway,
            seqid: self.seqid,
            payload,
        };
        self.seqid = self.seqid.wrapping_add(1);
        write_message_async(&mut self.transport, &msg, self.config.framed).await
    }
}

#[derive(Debug, Clone)]
pub struct ThriftServerConfig {
    pub timeouts: Timeouts,
    pub framed: bool,
}

impl Default for ThriftServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            framed: true,
        }
    }
}

pub enum ThriftResponse {
    Reply(ThriftStruct),
    Exception(ThriftApplicationException),
    Oneway,
}

pub trait ThriftService: Send + Sync {
    fn handle(&self, method: &str, input: ThriftStruct) -> CoreResult<ThriftResponse>;
}

pub struct ThriftServer {
    listener: TcpListener,
    config: ThriftServerConfig,
    service: Arc<dyn ThriftService>,
}

impl ThriftServer {
    pub fn bind(
        addr: SocketAddr,
        config: ThriftServerConfig,
        service: Arc<dyn ThriftService>,
    ) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            service,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let service = Arc::clone(&self.service);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_connection(stream, config, service);
            });
        }
        Ok(())
    }
}

pub struct AsyncThriftServer {
    listener: tokio::net::TcpListener,
    config: ThriftServerConfig,
    service: Arc<dyn ThriftService>,
}

impl AsyncThriftServer {
    pub async fn bind(
        addr: SocketAddr,
        config: ThriftServerConfig,
        service: Arc<dyn ThriftService>,
    ) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self {
            listener,
            config,
            service,
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let service = Arc::clone(&self.service);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_connection_async(stream, config, service).await;
            });
        }
    }
}

fn handle_connection(
    stream: TcpStream,
    config: ThriftServerConfig,
    service: Arc<dyn ThriftService>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    loop {
        let msg = match read_message(&mut transport, config.framed) {
            Ok(msg) => msg,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(err) => return Err(err),
        };
        let input = decode_struct(&msg.payload)?;
        let response = match service.handle(&msg.name, input) {
            Ok(resp) => resp,
            Err(err) => ThriftResponse::Exception(ThriftApplicationException {
                message: format!("{err:?}"),
                kind: 1,
            }),
        };
        match response {
            ThriftResponse::Reply(output) => {
                let payload = encode_struct(&output);
                let reply = ThriftMessage {
                    name: msg.name,
                    message_type: ThriftMessageType::Reply,
                    seqid: msg.seqid,
                    payload,
                };
                write_message(&mut transport, &reply, config.framed)?;
            }
            ThriftResponse::Exception(ex) => {
                let reply = ThriftMessage {
                    name: msg.name,
                    message_type: ThriftMessageType::Exception,
                    seqid: msg.seqid,
                    payload: ex.encode(),
                };
                write_message(&mut transport, &reply, config.framed)?;
            }
            ThriftResponse::Oneway => {}
        }
    }
}

async fn handle_connection_async(
    stream: tokio::net::TcpStream,
    config: ThriftServerConfig,
    service: Arc<dyn ThriftService>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let msg = match read_message_async(&mut transport, config.framed).await {
            Ok(msg) => msg,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(err) => return Err(err),
        };
        let input = decode_struct(&msg.payload)?;
        let response = match service.handle(&msg.name, input) {
            Ok(resp) => resp,
            Err(err) => ThriftResponse::Exception(ThriftApplicationException {
                message: format!("{err:?}"),
                kind: 1,
            }),
        };
        match response {
            ThriftResponse::Reply(output) => {
                let payload = encode_struct(&output);
                let reply = ThriftMessage {
                    name: msg.name,
                    message_type: ThriftMessageType::Reply,
                    seqid: msg.seqid,
                    payload,
                };
                write_message_async(&mut transport, &reply, config.framed).await?;
            }
            ThriftResponse::Exception(ex) => {
                let reply = ThriftMessage {
                    name: msg.name,
                    message_type: ThriftMessageType::Exception,
                    seqid: msg.seqid,
                    payload: ex.encode(),
                };
                write_message_async(&mut transport, &reply, config.framed).await?;
            }
            ThriftResponse::Oneway => {}
        }
    }
}

fn write_message(
    transport: &mut TcpTransport,
    msg: &ThriftMessage,
    framed: bool,
) -> CoreResult<()> {
    let payload = encode_message(msg);
    if framed {
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        transport.write_all(&out)
    } else {
        transport.write_all(&payload)
    }
}

async fn write_message_async(
    transport: &mut AsyncTcpTransport,
    msg: &ThriftMessage,
    framed: bool,
) -> CoreResult<()> {
    let payload = encode_message(msg);
    if framed {
        let mut out = Vec::with_capacity(payload.len() + 4);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        transport.write_all(&out).await
    } else {
        transport.write_all(&payload).await
    }
}

fn read_message(transport: &mut TcpTransport, framed: bool) -> CoreResult<ThriftMessage> {
    if framed {
        let mut header = [0u8; 4];
        transport.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header) as usize;
        let mut payload = vec![0u8; len];
        transport.read_exact(&mut payload)?;
        decode_message(&payload)
    } else {
        let mut reader = ThriftStreamReader::new(transport);
        decode_message_stream(&mut reader)
    }
}

async fn read_message_async(
    transport: &mut AsyncTcpTransport,
    framed: bool,
) -> CoreResult<ThriftMessage> {
    if framed {
        let mut header = [0u8; 4];
        transport.read_exact(&mut header).await?;
        let len = u32::from_be_bytes(header) as usize;
        let mut payload = vec![0u8; len];
        transport.read_exact(&mut payload).await?;
        decode_message(&payload)
    } else {
        Err(CoreError::Message(
            "async thrift unframed not supported".to_string(),
        ))
    }
}

fn encode_message(msg: &ThriftMessage) -> Vec<u8> {
    let mut out = Vec::new();
    let versioned = VERSION_1 | (msg.message_type as i32);
    out.extend_from_slice(&versioned.to_be_bytes());
    write_string(&mut out, msg.name.as_bytes());
    out.extend_from_slice(&msg.seqid.to_be_bytes());
    out.extend_from_slice(&msg.payload);
    out
}

fn decode_message(buf: &[u8]) -> CoreResult<ThriftMessage> {
    let mut cursor = Cursor::new(buf);
    let version = cursor.read_i32()?;
    if (version & VERSION_1) != VERSION_1 {
        return Err(CoreError::Parse("unsupported thrift version".to_string()));
    }
    let mtype = (version & 0xFF) as u8;
    let message_type = match mtype {
        1 => ThriftMessageType::Call,
        2 => ThriftMessageType::Reply,
        3 => ThriftMessageType::Exception,
        4 => ThriftMessageType::Oneway,
        _ => return Err(CoreError::Parse("invalid thrift message type".to_string())),
    };
    let name = read_string_cursor(&mut cursor)?;
    let seqid = cursor.read_i32()?;
    let payload = cursor.read_remaining();
    Ok(ThriftMessage {
        name,
        message_type,
        seqid,
        payload,
    })
}

fn decode_message_stream(reader: &mut ThriftStreamReader<'_>) -> CoreResult<ThriftMessage> {
    let version = reader.read_i32()?;
    if (version & VERSION_1) != VERSION_1 {
        return Err(CoreError::Parse("unsupported thrift version".to_string()));
    }
    let mtype = (version & 0xFF) as u8;
    let message_type = match mtype {
        1 => ThriftMessageType::Call,
        2 => ThriftMessageType::Reply,
        3 => ThriftMessageType::Exception,
        4 => ThriftMessageType::Oneway,
        _ => return Err(CoreError::Parse("invalid thrift message type".to_string())),
    };
    let name = reader.read_string()?;
    let seqid = reader.read_i32()?;
    let payload = reader.read_struct_payload()?;
    Ok(ThriftMessage {
        name,
        message_type,
        seqid,
        payload,
    })
}

fn encode_struct(fields: &[ThriftField]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.push(field.field_type as u8);
        out.extend_from_slice(&field.id.to_be_bytes());
        encode_value(&mut out, field.field_type, &field.value);
    }
    out.push(ThriftType::Stop as u8);
    out
}

fn decode_struct(payload: &[u8]) -> CoreResult<ThriftStruct> {
    let mut cursor = Cursor::new(payload);
    let mut fields = Vec::new();
    loop {
        let field_type = ThriftType::from_u8(cursor.read_u8()?)?;
        if field_type == ThriftType::Stop {
            break;
        }
        let id = cursor.read_i16()?;
        let value = decode_value(&mut cursor, field_type)?;
        fields.push(ThriftField {
            id,
            field_type,
            value,
        });
    }
    Ok(fields)
}

fn encode_value(out: &mut Vec<u8>, field_type: ThriftType, value: &ThriftValue) {
    match (field_type, value) {
        (ThriftType::Bool, ThriftValue::Bool(v)) => out.push(if *v { 1 } else { 0 }),
        (ThriftType::Byte, ThriftValue::Byte(v)) => out.push(*v as u8),
        (ThriftType::I16, ThriftValue::I16(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (ThriftType::I32, ThriftValue::I32(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (ThriftType::I64, ThriftValue::I64(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (ThriftType::Double, ThriftValue::Double(v)) => out.extend_from_slice(&v.to_be_bytes()),
        (ThriftType::String, ThriftValue::String(v)) => write_string(out, v),
        (ThriftType::Struct, ThriftValue::Struct(fields)) => {
            out.extend_from_slice(&encode_struct(fields))
        }
        (ThriftType::Map, ThriftValue::Map(key_t, val_t, entries)) => {
            out.push(*key_t as u8);
            out.push(*val_t as u8);
            out.extend_from_slice(&(entries.len() as i32).to_be_bytes());
            for (k, v) in entries {
                encode_value(out, *key_t, k);
                encode_value(out, *val_t, v);
            }
        }
        (ThriftType::Set, ThriftValue::Set(elem_t, values)) => {
            out.push(*elem_t as u8);
            out.extend_from_slice(&(values.len() as i32).to_be_bytes());
            for item in values {
                encode_value(out, *elem_t, item);
            }
        }
        (ThriftType::List, ThriftValue::List(elem_t, values)) => {
            out.push(*elem_t as u8);
            out.extend_from_slice(&(values.len() as i32).to_be_bytes());
            for item in values {
                encode_value(out, *elem_t, item);
            }
        }
        _ => {}
    }
}

fn decode_value(cursor: &mut Cursor, field_type: ThriftType) -> CoreResult<ThriftValue> {
    match field_type {
        ThriftType::Bool => Ok(ThriftValue::Bool(cursor.read_u8()? != 0)),
        ThriftType::Byte => Ok(ThriftValue::Byte(cursor.read_u8()? as i8)),
        ThriftType::I16 => Ok(ThriftValue::I16(cursor.read_i16()?)),
        ThriftType::I32 => Ok(ThriftValue::I32(cursor.read_i32()?)),
        ThriftType::I64 => Ok(ThriftValue::I64(cursor.read_i64()?)),
        ThriftType::Double => Ok(ThriftValue::Double(cursor.read_f64()?)),
        ThriftType::String => Ok(ThriftValue::String(cursor.read_string_bytes()?)),
        ThriftType::Struct => {
            let mut fields = Vec::new();
            loop {
                let ty = ThriftType::from_u8(cursor.read_u8()?)?;
                if ty == ThriftType::Stop {
                    break;
                }
                let id = cursor.read_i16()?;
                let value = decode_value(cursor, ty)?;
                fields.push(ThriftField {
                    id,
                    field_type: ty,
                    value,
                });
            }
            Ok(ThriftValue::Struct(fields))
        }
        ThriftType::Map => {
            let key_t = ThriftType::from_u8(cursor.read_u8()?)?;
            let val_t = ThriftType::from_u8(cursor.read_u8()?)?;
            let len = cursor.read_i32()? as usize;
            let mut entries = Vec::with_capacity(len);
            for _ in 0..len {
                let key = decode_value(cursor, key_t)?;
                let value = decode_value(cursor, val_t)?;
                entries.push((key, value));
            }
            Ok(ThriftValue::Map(key_t, val_t, entries))
        }
        ThriftType::Set => {
            let elem_t = ThriftType::from_u8(cursor.read_u8()?)?;
            let len = cursor.read_i32()? as usize;
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                values.push(decode_value(cursor, elem_t)?);
            }
            Ok(ThriftValue::Set(elem_t, values))
        }
        ThriftType::List => {
            let elem_t = ThriftType::from_u8(cursor.read_u8()?)?;
            let len = cursor.read_i32()? as usize;
            let mut values = Vec::with_capacity(len);
            for _ in 0..len {
                values.push(decode_value(cursor, elem_t)?);
            }
            Ok(ThriftValue::List(elem_t, values))
        }
        _ => Err(CoreError::Parse("unsupported thrift type".to_string())),
    }
}

fn write_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as i32).to_be_bytes());
    out.extend_from_slice(value);
}

fn read_string_cursor(cursor: &mut Cursor) -> CoreResult<String> {
    let bytes = cursor.read_string_bytes()?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> CoreResult<u8> {
        if self.pos + 1 > self.buf.len() {
            return Err(CoreError::Parse("cursor eof".to_string()));
        }
        let out = self.buf[self.pos];
        self.pos += 1;
        Ok(out)
    }

    fn read_i16(&mut self) -> CoreResult<i16> {
        let bytes = self.read_bytes(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_i32(&mut self) -> CoreResult<i32> {
        let bytes = self.read_bytes(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_i64(&mut self) -> CoreResult<i64> {
        let bytes = self.read_bytes(8)?;
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_f64(&mut self) -> CoreResult<f64> {
        let bytes = self.read_bytes(8)?;
        Ok(f64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string_bytes(&mut self) -> CoreResult<Vec<u8>> {
        let len = self.read_i32()? as usize;
        self.read_bytes(len)
    }

    fn read_bytes(&mut self, len: usize) -> CoreResult<Vec<u8>> {
        if self.pos + len > self.buf.len() {
            return Err(CoreError::Parse("cursor eof".to_string()));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    fn read_remaining(&mut self) -> Vec<u8> {
        let out = self.buf[self.pos..].to_vec();
        self.pos = self.buf.len();
        out
    }
}

struct ThriftStreamReader<'a> {
    transport: &'a mut TcpTransport,
}

impl<'a> ThriftStreamReader<'a> {
    fn new(transport: &'a mut TcpTransport) -> Self {
        Self { transport }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> CoreResult<()> {
        self.transport.read_exact(buf)
    }

    fn read_u8(&mut self) -> CoreResult<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_i32(&mut self) -> CoreResult<i32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(i32::from_be_bytes(buf))
    }

    fn read_string(&mut self) -> CoreResult<String> {
        let len = self.read_i32()? as usize;
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    }

    fn read_struct_payload(&mut self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let field_type = self.read_u8()?;
            out.push(field_type);
            if field_type == ThriftType::Stop as u8 {
                break;
            }
            let mut id_buf = [0u8; 2];
            self.read_exact(&mut id_buf)?;
            out.extend_from_slice(&id_buf);
            read_value_stream(self, ThriftType::from_u8(field_type)?, &mut out)?;
        }
        Ok(out)
    }
}

fn read_value_stream(
    reader: &mut ThriftStreamReader<'_>,
    field_type: ThriftType,
    out: &mut Vec<u8>,
) -> CoreResult<()> {
    match field_type {
        ThriftType::Bool | ThriftType::Byte => {
            let v = reader.read_u8()?;
            out.push(v);
        }
        ThriftType::I16 => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            out.extend_from_slice(&buf);
        }
        ThriftType::I32 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            out.extend_from_slice(&buf);
        }
        ThriftType::I64 | ThriftType::Double => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            out.extend_from_slice(&buf);
        }
        ThriftType::String => {
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = i32::from_be_bytes(len_buf) as usize;
            out.extend_from_slice(&len_buf);
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf)?;
            out.extend_from_slice(&buf);
        }
        ThriftType::Struct => loop {
            let ty = reader.read_u8()?;
            out.push(ty);
            if ty == ThriftType::Stop as u8 {
                break;
            }
            let mut id_buf = [0u8; 2];
            reader.read_exact(&mut id_buf)?;
            out.extend_from_slice(&id_buf);
            read_value_stream(reader, ThriftType::from_u8(ty)?, out)?;
        },
        ThriftType::Map => {
            let key = reader.read_u8()?;
            let val = reader.read_u8()?;
            out.push(key);
            out.push(val);
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = i32::from_be_bytes(len_buf) as usize;
            out.extend_from_slice(&len_buf);
            for _ in 0..len {
                read_value_stream(reader, ThriftType::from_u8(key)?, out)?;
                read_value_stream(reader, ThriftType::from_u8(val)?, out)?;
            }
        }
        ThriftType::Set | ThriftType::List => {
            let elem = reader.read_u8()?;
            out.push(elem);
            let mut len_buf = [0u8; 4];
            reader.read_exact(&mut len_buf)?;
            let len = i32::from_be_bytes(len_buf) as usize;
            out.extend_from_slice(&len_buf);
            for _ in 0..len {
                read_value_stream(reader, ThriftType::from_u8(elem)?, out)?;
            }
        }
        _ => return Err(CoreError::Parse("unsupported thrift type".to_string())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::fuzz_bytes;

    struct EchoService;

    impl ThriftService for EchoService {
        fn handle(&self, method: &str, input: ThriftStruct) -> CoreResult<ThriftResponse> {
            match method {
                "echo" => Ok(ThriftResponse::Reply(input)),
                _ => Ok(ThriftResponse::Exception(ThriftApplicationException {
                    message: "unknown method".to_string(),
                    kind: 1,
                })),
            }
        }
    }

    #[test]
    fn thrift_roundtrip() {
        let server = crate::skip_if_perm!(ThriftServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            ThriftServerConfig::default(),
            Arc::new(EchoService),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client =
            ThriftClient::connect(&NetAddr::from_socket(addr), ThriftClientConfig::default())
                .unwrap();
        let args = vec![ThriftField {
            id: 1,
            field_type: ThriftType::String,
            value: ThriftValue::String(b"hello".to_vec()),
        }];
        let reply = client.call("echo", args.clone()).unwrap();
        assert_eq!(reply, args);
    }

    #[test]
    fn thrift_decode_negative() {
        assert!(decode_message(&[]).is_err());
    }

    #[test]
    fn thrift_decode_fuzz() {
        fuzz_bytes(128, 512, 0x7468, |data| {
            let _ = decode_message(data);
        });
    }
}
