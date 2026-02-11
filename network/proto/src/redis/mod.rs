use std::collections::HashMap;
use std::future::Future;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const READ_BUFFER: usize = 8 * 1024;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RespVersion {
    Resp2,
    Resp3,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RespFrame {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),
    Array(Option<Vec<RespFrame>>),
    Null,
    Boolean(bool),
    Double(f64),
    BigNumber(String),
    BulkError(Vec<u8>),
    Verbatim([u8; 3], Vec<u8>),
    Map(Vec<(RespFrame, RespFrame)>),
    Set(Vec<RespFrame>),
    Push(Vec<RespFrame>),
}

impl RespFrame {
    pub fn encode(&self, version: RespVersion) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(version, &mut out);
        out
    }

    fn encode_into(&self, version: RespVersion, out: &mut Vec<u8>) {
        match self {
            RespFrame::SimpleString(value) => {
                out.push(b'+');
                out.extend_from_slice(value.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            RespFrame::Error(value) => {
                out.push(b'-');
                out.extend_from_slice(value.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            RespFrame::Integer(value) => {
                out.push(b':');
                out.extend_from_slice(value.to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            RespFrame::BulkString(value) => match value {
                Some(bytes) => {
                    out.push(b'$');
                    out.extend_from_slice(bytes.len().to_string().as_bytes());
                    out.extend_from_slice(b"\r\n");
                    out.extend_from_slice(bytes);
                    out.extend_from_slice(b"\r\n");
                }
                None => {
                    out.extend_from_slice(b"$-1\r\n");
                }
            },
            RespFrame::Array(values) => match values {
                Some(items) => {
                    out.push(b'*');
                    out.extend_from_slice(items.len().to_string().as_bytes());
                    out.extend_from_slice(b"\r\n");
                    for item in items {
                        item.encode_into(version, out);
                    }
                }
                None => {
                    out.extend_from_slice(b"*-1\r\n");
                }
            },
            RespFrame::Null => match version {
                RespVersion::Resp2 => out.extend_from_slice(b"$-1\r\n"),
                RespVersion::Resp3 => out.extend_from_slice(b"_\r\n"),
            },
            RespFrame::Boolean(value) => {
                out.extend_from_slice(if *value { b"#t\r\n" } else { b"#f\r\n" });
            }
            RespFrame::Double(value) => {
                out.push(b',');
                out.extend_from_slice(value.to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            RespFrame::BigNumber(value) => {
                out.push(b'(');
                out.extend_from_slice(value.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            RespFrame::BulkError(value) => {
                out.push(b'!');
                out.extend_from_slice(value.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(value);
                out.extend_from_slice(b"\r\n");
            }
            RespFrame::Verbatim(format, value) => {
                let mut payload = Vec::with_capacity(4 + value.len());
                payload.extend_from_slice(format);
                payload.push(b':');
                payload.extend_from_slice(value);
                out.push(b'=');
                out.extend_from_slice(payload.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                out.extend_from_slice(&payload);
                out.extend_from_slice(b"\r\n");
            }
            RespFrame::Map(entries) => {
                out.push(b'%');
                out.extend_from_slice(entries.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                for (key, value) in entries {
                    key.encode_into(version, out);
                    value.encode_into(version, out);
                }
            }
            RespFrame::Set(items) => {
                out.push(b'~');
                out.extend_from_slice(items.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                for item in items {
                    item.encode_into(version, out);
                }
            }
            RespFrame::Push(items) => {
                out.push(b'>');
                out.extend_from_slice(items.len().to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
                for item in items {
                    item.encode_into(version, out);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisCommand {
    pub name: String,
    pub args: Vec<Vec<u8>>,
}

impl RedisCommand {
    pub fn new(name: &str, args: Vec<Vec<u8>>) -> Self {
        Self {
            name: name.to_ascii_uppercase(),
            args,
        }
    }

    pub fn to_frame(&self) -> RespFrame {
        let mut items = Vec::with_capacity(1 + self.args.len());
        items.push(RespFrame::BulkString(Some(self.name.as_bytes().to_vec())));
        for arg in &self.args {
            items.push(RespFrame::BulkString(Some(arg.clone())));
        }
        RespFrame::Array(Some(items))
    }

    pub fn from_frame(frame: &RespFrame) -> CoreResult<Self> {
        match frame {
            RespFrame::Array(Some(items)) if !items.is_empty() => {
                let mut iter = items.iter();
                let first = iter.next().unwrap();
                let name = frame_to_bytes(first)?;
                let name = String::from_utf8(name)
                    .map_err(|_| CoreError::Parse("invalid command name".to_string()))?
                    .to_ascii_uppercase();
                let mut args = Vec::new();
                for item in iter {
                    args.push(frame_to_bytes(item)?);
                }
                Ok(Self { name, args })
            }
            RespFrame::SimpleString(line) => {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    return Err(CoreError::Parse("empty command".to_string()));
                }
                let name = parts[0].to_ascii_uppercase();
                let args = parts[1..].iter().map(|s| s.as_bytes().to_vec()).collect();
                Ok(Self { name, args })
            }
            _ => Err(CoreError::Parse("invalid command frame".to_string())),
        }
    }
}

fn frame_to_bytes(frame: &RespFrame) -> CoreResult<Vec<u8>> {
    match frame {
        RespFrame::BulkString(Some(bytes)) => Ok(bytes.clone()),
        RespFrame::SimpleString(value) => Ok(value.as_bytes().to_vec()),
        RespFrame::Integer(value) => Ok(value.to_string().as_bytes().to_vec()),
        RespFrame::Null => Ok(Vec::new()),
        _ => Err(CoreError::Parse("invalid argument type".to_string())),
    }
}

#[derive(Debug, Clone)]
pub struct RedisContext {
    pub resp_version: RespVersion,
    pub authed: bool,
    pub db: usize,
    pub client_name: Option<String>,
}

impl Default for RedisContext {
    fn default() -> Self {
        Self {
            resp_version: RespVersion::Resp2,
            authed: true,
            db: 0,
            client_name: None,
        }
    }
}

pub trait RedisHandler: Send + Sync {
    fn handle(
        &self,
        cmd: &RedisCommand,
        ctx: &mut RedisContext,
        store: &mut RedisStore,
    ) -> CoreResult<RespFrame>;
}

#[derive(Debug, Clone)]
pub struct RedisServerConfig {
    pub timeouts: Timeouts,
    pub requirepass: Option<String>,
    pub databases: usize,
}

impl Default for RedisServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            requirepass: None,
            databases: 16,
        }
    }
}

#[derive(Debug, Default)]
pub struct RedisStore {
    dbs: Vec<HashMap<Vec<u8>, RedisValue>>,
}

#[derive(Debug, Clone)]
enum RedisValue {
    String(Vec<u8>),
    Hash(HashMap<Vec<u8>, Vec<u8>>),
}

impl RedisStore {
    pub fn new(databases: usize) -> Self {
        let mut dbs = Vec::with_capacity(databases.max(1));
        for _ in 0..databases.max(1) {
            dbs.push(HashMap::new());
        }
        Self { dbs }
    }

    fn get_db_mut(&mut self, idx: usize) -> CoreResult<&mut HashMap<Vec<u8>, RedisValue>> {
        self.dbs
            .get_mut(idx)
            .ok_or_else(|| CoreError::Message("invalid database".to_string()))
    }

    fn get_db(&self, idx: usize) -> CoreResult<&HashMap<Vec<u8>, RedisValue>> {
        self.dbs
            .get(idx)
            .ok_or_else(|| CoreError::Message("invalid database".to_string()))
    }

    fn set_string(&mut self, db: usize, key: Vec<u8>, value: Vec<u8>) -> CoreResult<()> {
        let db = self.get_db_mut(db)?;
        db.insert(key, RedisValue::String(value));
        Ok(())
    }

    fn get_string(&self, db: usize, key: &[u8]) -> CoreResult<Option<Vec<u8>>> {
        let db = self.get_db(db)?;
        Ok(match db.get(key) {
            Some(RedisValue::String(value)) => Some(value.clone()),
            Some(RedisValue::Hash(_)) => None,
            None => None,
        })
    }

    fn del_keys(&mut self, db: usize, keys: &[Vec<u8>]) -> CoreResult<i64> {
        let db = self.get_db_mut(db)?;
        let mut removed = 0i64;
        for key in keys {
            if db.remove(key).is_some() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn exists(&self, db: usize, keys: &[Vec<u8>]) -> CoreResult<i64> {
        let db = self.get_db(db)?;
        let mut count = 0i64;
        for key in keys {
            if db.contains_key(key) {
                count += 1;
            }
        }
        Ok(count)
    }

    fn incr_by(&mut self, db: usize, key: Vec<u8>, delta: i64) -> CoreResult<i64> {
        let db_ref = self.get_db_mut(db)?;
        let value = match db_ref.get(&key) {
            Some(RedisValue::String(value)) => parse_i64(value)?,
            Some(RedisValue::Hash(_)) => return Err(CoreError::Message("WRONGTYPE".to_string())),
            None => 0,
        };
        let new_value = value
            .checked_add(delta)
            .ok_or_else(|| CoreError::Message("overflow".to_string()))?;
        db_ref.insert(key, RedisValue::String(new_value.to_string().into_bytes()));
        Ok(new_value)
    }

    fn hset(&mut self, db: usize, key: Vec<u8>, pairs: &[(Vec<u8>, Vec<u8>)]) -> CoreResult<i64> {
        let db_ref = self.get_db_mut(db)?;
        let entry = db_ref
            .entry(key)
            .or_insert_with(|| RedisValue::Hash(HashMap::new()));
        match entry {
            RedisValue::Hash(map) => {
                let mut added = 0i64;
                for (field, value) in pairs {
                    if !map.contains_key(field) {
                        added += 1;
                    }
                    map.insert(field.clone(), value.clone());
                }
                Ok(added)
            }
            RedisValue::String(_) => Err(CoreError::Message("WRONGTYPE".to_string())),
        }
    }

    fn hget(&self, db: usize, key: &[u8], field: &[u8]) -> CoreResult<Option<Vec<u8>>> {
        let db_ref = self.get_db(db)?;
        match db_ref.get(key) {
            Some(RedisValue::Hash(map)) => Ok(map.get(field).cloned()),
            Some(RedisValue::String(_)) => Err(CoreError::Message("WRONGTYPE".to_string())),
            None => Ok(None),
        }
    }

    fn hdel(&mut self, db: usize, key: &[u8], fields: &[Vec<u8>]) -> CoreResult<i64> {
        let db_ref = self.get_db_mut(db)?;
        match db_ref.get_mut(key) {
            Some(RedisValue::Hash(map)) => {
                let mut removed = 0i64;
                for field in fields {
                    if map.remove(field).is_some() {
                        removed += 1;
                    }
                }
                Ok(removed)
            }
            Some(RedisValue::String(_)) => Err(CoreError::Message("WRONGTYPE".to_string())),
            None => Ok(0),
        }
    }

    fn hgetall(&self, db: usize, key: &[u8]) -> CoreResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let db_ref = self.get_db(db)?;
        match db_ref.get(key) {
            Some(RedisValue::Hash(map)) => {
                Ok(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            }
            Some(RedisValue::String(_)) => Err(CoreError::Message("WRONGTYPE".to_string())),
            None => Ok(Vec::new()),
        }
    }
}

pub struct RedisServer {
    listener: TcpListener,
    config: RedisServerConfig,
    handler: Arc<dyn RedisHandler>,
    store: Arc<Mutex<RedisStore>>,
}

impl RedisServer {
    pub fn bind(
        addr: SocketAddr,
        config: RedisServerConfig,
        handler: Arc<dyn RedisHandler>,
    ) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        let store = Arc::new(Mutex::new(RedisStore::new(config.databases)));
        Ok(Self {
            listener,
            handler,
            config,
            store,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let store = Arc::clone(&self.store);
            let config = self.config.clone();
            thread::spawn(move || {
                let _ = handle_connection(stream, config, handler, store);
            });
        }
        Ok(())
    }
}

pub struct AsyncRedisServer {
    listener: tokio::net::TcpListener,
    config: RedisServerConfig,
    handler: Arc<dyn RedisHandler>,
    store: Arc<Mutex<RedisStore>>,
}

impl AsyncRedisServer {
    pub async fn bind(
        addr: SocketAddr,
        config: RedisServerConfig,
        handler: Arc<dyn RedisHandler>,
    ) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        let store = Arc::new(Mutex::new(RedisStore::new(config.databases)));
        Ok(Self {
            listener,
            handler,
            config,
            store,
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&self.handler);
            let store = Arc::clone(&self.store);
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_async_connection(stream, config, handler, store).await;
            });
        }
    }
}

pub struct RedisClient {
    conn: RedisConnection<TcpTransport>,
    version: RespVersion,
}

impl RedisClient {
    pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, timeouts)?;
        Ok(Self {
            conn: RedisConnection::new(transport),
            version: RespVersion::Resp2,
        })
    }

    pub fn call(&mut self, cmd: RedisCommand) -> CoreResult<RespFrame> {
        let frame = cmd.to_frame();
        self.conn.write_frame(&frame, self.version)?;
        self.conn.read_frame()
    }

    pub fn auth(&mut self, password: &str) -> CoreResult<RespFrame> {
        self.call(RedisCommand::new(
            "AUTH",
            vec![password.as_bytes().to_vec()],
        ))
    }

    pub fn hello(&mut self, version: RespVersion) -> CoreResult<RespFrame> {
        let proto = match version {
            RespVersion::Resp2 => b"2".to_vec(),
            RespVersion::Resp3 => b"3".to_vec(),
        };
        let resp = self.call(RedisCommand::new("HELLO", vec![proto]))?;
        self.version = version;
        Ok(resp)
    }
}

pub struct AsyncRedisClient {
    conn: AsyncRedisConnection<AsyncTcpTransport>,
    version: RespVersion,
}

impl AsyncRedisClient {
    pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, timeouts).await?;
        Ok(Self {
            conn: AsyncRedisConnection::new(transport),
            version: RespVersion::Resp2,
        })
    }

    pub async fn call(&mut self, cmd: RedisCommand) -> CoreResult<RespFrame> {
        let frame = cmd.to_frame();
        self.conn.write_frame(&frame, self.version).await?;
        self.conn.read_frame().await
    }

    pub async fn auth(&mut self, password: &str) -> CoreResult<RespFrame> {
        self.call(RedisCommand::new(
            "AUTH",
            vec![password.as_bytes().to_vec()],
        ))
        .await
    }

    pub async fn hello(&mut self, version: RespVersion) -> CoreResult<RespFrame> {
        let proto = match version {
            RespVersion::Resp2 => b"2".to_vec(),
            RespVersion::Resp3 => b"3".to_vec(),
        };
        let resp = self.call(RedisCommand::new("HELLO", vec![proto])).await?;
        self.version = version;
        Ok(resp)
    }
}

pub struct RedisConnection<T: StreamTransport> {
    transport: T,
    buffer: ReadBuffer,
}

impl<T: StreamTransport> RedisConnection<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            buffer: ReadBuffer::new(),
        }
    }

    pub fn read_frame(&mut self) -> CoreResult<RespFrame> {
        read_frame(&mut self.transport, &mut self.buffer, 0)
    }

    pub fn write_frame(&mut self, frame: &RespFrame, version: RespVersion) -> CoreResult<()> {
        let bytes = frame.encode(version);
        self.transport.write_all(&bytes)
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

pub struct AsyncRedisConnection<T: AsyncStreamTransport + Send> {
    transport: T,
    buffer: AsyncReadBuffer,
}

impl<T: AsyncStreamTransport + Send> AsyncRedisConnection<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            buffer: AsyncReadBuffer::new(),
        }
    }

    pub async fn read_frame(&mut self) -> CoreResult<RespFrame> {
        read_frame_async(&mut self.transport, &mut self.buffer, 0).await
    }

    pub async fn write_frame(&mut self, frame: &RespFrame, version: RespVersion) -> CoreResult<()> {
        let bytes = frame.encode(version);
        self.transport.write_all(&bytes).await
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

fn handle_connection(
    stream: TcpStream,
    config: RedisServerConfig,
    handler: Arc<dyn RedisHandler>,
    store: Arc<Mutex<RedisStore>>,
) -> CoreResult<()> {
    let transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let mut conn = RedisConnection::new(transport);
    let mut ctx = RedisContext {
        resp_version: RespVersion::Resp2,
        authed: config.requirepass.is_none(),
        db: 0,
        client_name: None,
    };
    loop {
        let frame = match conn.read_frame() {
            Ok(frame) => frame,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(())
            }
            Err(err) => {
                conn.write_frame(&RespFrame::Error(format!("ERR {err}")), ctx.resp_version)?;
                continue;
            }
        };
        let cmd = match RedisCommand::from_frame(&frame) {
            Ok(cmd) => cmd,
            Err(err) => {
                conn.write_frame(&RespFrame::Error(format!("ERR {err}")), ctx.resp_version)?;
                continue;
            }
        };

        if !ctx.authed && cmd.name != "AUTH" && cmd.name != "HELLO" {
            conn.write_frame(
                &RespFrame::Error("NOAUTH Authentication required".to_string()),
                ctx.resp_version,
            )?;
            continue;
        }

        if cmd.name == "AUTH" {
            let ok = handle_auth(&cmd, &config)?;
            ctx.authed = ok;
            conn.write_frame(&RespFrame::SimpleString("OK".to_string()), ctx.resp_version)?;
            continue;
        }

        if cmd.name == "HELLO" {
            let response = handle_hello(&cmd, &mut ctx, &config)?;
            conn.write_frame(&response, ctx.resp_version)?;
            continue;
        }

        if cmd.name == "QUIT" {
            conn.write_frame(&RespFrame::SimpleString("OK".to_string()), ctx.resp_version)?;
            break;
        }

        if cmd.name == "SELECT" {
            let idx = parse_arg_i64(&cmd, 0)?;
            if idx < 0 {
                conn.write_frame(
                    &RespFrame::Error("ERR invalid DB index".to_string()),
                    ctx.resp_version,
                )?;
                continue;
            }
            ctx.db = idx as usize;
            conn.write_frame(&RespFrame::SimpleString("OK".to_string()), ctx.resp_version)?;
            continue;
        }

        let response = {
            let mut store = store
                .lock()
                .map_err(|_| CoreError::Message("store poisoned".to_string()))?;
            handler.handle(&cmd, &mut ctx, &mut store)
        };

        match response {
            Ok(frame) => conn.write_frame(&frame, ctx.resp_version)?,
            Err(err) => {
                conn.write_frame(&RespFrame::Error(format!("ERR {err}")), ctx.resp_version)?
            }
        };
    }
    Ok(())
}

async fn handle_async_connection(
    stream: tokio::net::TcpStream,
    config: RedisServerConfig,
    handler: Arc<dyn RedisHandler>,
    store: Arc<Mutex<RedisStore>>,
) -> CoreResult<()> {
    let transport = AsyncTcpTransport::from_stream(stream);
    let mut conn = AsyncRedisConnection::new(transport);
    let mut ctx = RedisContext {
        resp_version: RespVersion::Resp2,
        authed: config.requirepass.is_none(),
        db: 0,
        client_name: None,
    };

    loop {
        let frame = match conn.read_frame().await {
            Ok(frame) => frame,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(())
            }
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                return Ok(())
            }
            Err(err) => {
                conn.write_frame(&RespFrame::Error(format!("ERR {err}")), ctx.resp_version)
                    .await?;
                continue;
            }
        };
        let cmd = match RedisCommand::from_frame(&frame) {
            Ok(cmd) => cmd,
            Err(err) => {
                conn.write_frame(&RespFrame::Error(format!("ERR {err}")), ctx.resp_version)
                    .await?;
                continue;
            }
        };

        if !ctx.authed && cmd.name != "AUTH" && cmd.name != "HELLO" {
            conn.write_frame(
                &RespFrame::Error("NOAUTH Authentication required".to_string()),
                ctx.resp_version,
            )
            .await?;
            continue;
        }

        if cmd.name == "AUTH" {
            let ok = handle_auth(&cmd, &config)?;
            ctx.authed = ok;
            conn.write_frame(&RespFrame::SimpleString("OK".to_string()), ctx.resp_version)
                .await?;
            continue;
        }

        if cmd.name == "HELLO" {
            let response = handle_hello(&cmd, &mut ctx, &config)?;
            conn.write_frame(&response, ctx.resp_version).await?;
            continue;
        }

        if cmd.name == "QUIT" {
            conn.write_frame(&RespFrame::SimpleString("OK".to_string()), ctx.resp_version)
                .await?;
            break;
        }

        if cmd.name == "SELECT" {
            let idx = parse_arg_i64(&cmd, 0)?;
            if idx < 0 {
                conn.write_frame(
                    &RespFrame::Error("ERR invalid DB index".to_string()),
                    ctx.resp_version,
                )
                .await?;
                continue;
            }
            ctx.db = idx as usize;
            conn.write_frame(&RespFrame::SimpleString("OK".to_string()), ctx.resp_version)
                .await?;
            continue;
        }

        let response = {
            let mut store = store
                .lock()
                .map_err(|_| CoreError::Message("store poisoned".to_string()))?;
            handler.handle(&cmd, &mut ctx, &mut store)
        };

        match response {
            Ok(frame) => conn.write_frame(&frame, ctx.resp_version).await?,
            Err(err) => {
                conn.write_frame(&RespFrame::Error(format!("ERR {err}")), ctx.resp_version)
                    .await?
            }
        };
    }
    Ok(())
}

fn handle_auth(cmd: &RedisCommand, config: &RedisServerConfig) -> CoreResult<bool> {
    let pass = config
        .requirepass
        .as_ref()
        .ok_or_else(|| CoreError::Message("ERR no password".to_string()))?;
    if cmd.args.len() == 1 {
        let provided = String::from_utf8_lossy(&cmd.args[0]);
        if provided.as_ref() == pass {
            return Ok(true);
        }
    } else if cmd.args.len() == 2 {
        let provided = String::from_utf8_lossy(&cmd.args[1]);
        if provided.as_ref() == pass {
            return Ok(true);
        }
    }
    Err(CoreError::Message("ERR invalid password".to_string()))
}

fn handle_hello(
    cmd: &RedisCommand,
    ctx: &mut RedisContext,
    config: &RedisServerConfig,
) -> CoreResult<RespFrame> {
    let mut version = ctx.resp_version;
    let mut i = 0;
    if !cmd.args.is_empty() {
        let arg = String::from_utf8_lossy(&cmd.args[0]);
        if arg == "2" {
            version = RespVersion::Resp2;
            i = 1;
        } else if arg == "3" {
            version = RespVersion::Resp3;
            i = 1;
        }
    }
    while i < cmd.args.len() {
        let token = String::from_utf8_lossy(&cmd.args[i]).to_ascii_uppercase();
        if token == "AUTH" {
            if i + 1 >= cmd.args.len() {
                return Err(CoreError::Message("ERR syntax".to_string()));
            }
            let pass_idx = if i + 2 < cmd.args.len() { i + 2 } else { i + 1 };
            let auth_cmd = if pass_idx == i + 2 {
                RedisCommand::new(
                    "AUTH",
                    vec![cmd.args[i + 1].clone(), cmd.args[i + 2].clone()],
                )
            } else {
                RedisCommand::new("AUTH", vec![cmd.args[i + 1].clone()])
            };
            ctx.authed = handle_auth(&auth_cmd, config)?;
            i = pass_idx + 1;
            continue;
        }
        if token == "SETNAME" {
            if i + 1 >= cmd.args.len() {
                return Err(CoreError::Message("ERR syntax".to_string()));
            }
            ctx.client_name = Some(String::from_utf8_lossy(&cmd.args[i + 1]).to_string());
            i += 2;
            continue;
        }
        i += 1;
    }
    ctx.resp_version = version;
    let response = match version {
        RespVersion::Resp2 => RespFrame::Array(Some(vec![
            RespFrame::BulkString(Some(b"server".to_vec())),
            RespFrame::BulkString(Some(b"moonlight".to_vec())),
            RespFrame::BulkString(Some(b"version".to_vec())),
            RespFrame::BulkString(Some(b"1.0".to_vec())),
            RespFrame::BulkString(Some(b"proto".to_vec())),
            RespFrame::Integer(match version {
                RespVersion::Resp2 => 2,
                RespVersion::Resp3 => 3,
            }),
        ])),
        RespVersion::Resp3 => RespFrame::Map(vec![
            (
                RespFrame::SimpleString("server".to_string()),
                RespFrame::SimpleString("moonlight".to_string()),
            ),
            (
                RespFrame::SimpleString("version".to_string()),
                RespFrame::SimpleString("1.0".to_string()),
            ),
            (
                RespFrame::SimpleString("proto".to_string()),
                RespFrame::Integer(match version {
                    RespVersion::Resp2 => 2,
                    RespVersion::Resp3 => 3,
                }),
            ),
            (
                RespFrame::SimpleString("id".to_string()),
                RespFrame::Integer(1),
            ),
            (
                RespFrame::SimpleString("mode".to_string()),
                RespFrame::SimpleString("standalone".to_string()),
            ),
            (
                RespFrame::SimpleString("role".to_string()),
                RespFrame::SimpleString("master".to_string()),
            ),
        ]),
    };
    Ok(response)
}

pub struct DefaultRedisHandler;

impl RedisHandler for DefaultRedisHandler {
    fn handle(
        &self,
        cmd: &RedisCommand,
        ctx: &mut RedisContext,
        store: &mut RedisStore,
    ) -> CoreResult<RespFrame> {
        match cmd.name.as_str() {
            "PING" => {
                if cmd.args.is_empty() {
                    Ok(RespFrame::SimpleString("PONG".to_string()))
                } else {
                    Ok(RespFrame::BulkString(Some(cmd.args[0].clone())))
                }
            }
            "ECHO" => {
                if cmd.args.len() != 1 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                Ok(RespFrame::BulkString(Some(cmd.args[0].clone())))
            }
            "GET" => {
                if cmd.args.len() != 1 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let value = store.get_string(ctx.db, &cmd.args[0])?;
                Ok(match value {
                    Some(value) => RespFrame::BulkString(Some(value)),
                    None => RespFrame::Null,
                })
            }
            "SET" => {
                if cmd.args.len() < 2 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                store.set_string(ctx.db, cmd.args[0].clone(), cmd.args[1].clone())?;
                Ok(RespFrame::SimpleString("OK".to_string()))
            }
            "DEL" => {
                if cmd.args.is_empty() {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let count = store.del_keys(ctx.db, &cmd.args)?;
                Ok(RespFrame::Integer(count))
            }
            "EXISTS" => {
                if cmd.args.is_empty() {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let count = store.exists(ctx.db, &cmd.args)?;
                Ok(RespFrame::Integer(count))
            }
            "INCR" => {
                if cmd.args.len() != 1 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let value = store.incr_by(ctx.db, cmd.args[0].clone(), 1)?;
                Ok(RespFrame::Integer(value))
            }
            "INCRBY" => {
                if cmd.args.len() != 2 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let delta = parse_i64(&cmd.args[1])?;
                let value = store.incr_by(ctx.db, cmd.args[0].clone(), delta)?;
                Ok(RespFrame::Integer(value))
            }
            "DECR" => {
                if cmd.args.len() != 1 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let value = store.incr_by(ctx.db, cmd.args[0].clone(), -1)?;
                Ok(RespFrame::Integer(value))
            }
            "DECRBY" => {
                if cmd.args.len() != 2 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let delta = parse_i64(&cmd.args[1])?;
                let value = store.incr_by(ctx.db, cmd.args[0].clone(), -delta)?;
                Ok(RespFrame::Integer(value))
            }
            "HSET" => {
                if cmd.args.len() < 3 || cmd.args.len() % 2 == 0 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let mut pairs = Vec::new();
                let mut idx = 1;
                while idx < cmd.args.len() {
                    pairs.push((cmd.args[idx].clone(), cmd.args[idx + 1].clone()));
                    idx += 2;
                }
                let added = store.hset(ctx.db, cmd.args[0].clone(), &pairs)?;
                Ok(RespFrame::Integer(added))
            }
            "HGET" => {
                if cmd.args.len() != 2 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let value = store.hget(ctx.db, &cmd.args[0], &cmd.args[1])?;
                Ok(match value {
                    Some(value) => RespFrame::BulkString(Some(value)),
                    None => RespFrame::Null,
                })
            }
            "HDEL" => {
                if cmd.args.len() < 2 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let removed = store.hdel(ctx.db, &cmd.args[0], &cmd.args[1..])?;
                Ok(RespFrame::Integer(removed))
            }
            "HGETALL" => {
                if cmd.args.len() != 1 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let entries = store.hgetall(ctx.db, &cmd.args[0])?;
                let mut frames = Vec::with_capacity(entries.len() * 2);
                for (field, value) in entries {
                    frames.push(RespFrame::BulkString(Some(field)));
                    frames.push(RespFrame::BulkString(Some(value)));
                }
                Ok(RespFrame::Array(Some(frames)))
            }
            "MGET" => {
                if cmd.args.is_empty() {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let mut out = Vec::with_capacity(cmd.args.len());
                for key in &cmd.args {
                    let value = store.get_string(ctx.db, key)?;
                    out.push(match value {
                        Some(value) => RespFrame::BulkString(Some(value)),
                        None => RespFrame::Null,
                    });
                }
                Ok(RespFrame::Array(Some(out)))
            }
            "MSET" => {
                if cmd.args.is_empty() || cmd.args.len() % 2 != 0 {
                    return Err(CoreError::Message(
                        "ERR wrong number of arguments".to_string(),
                    ));
                }
                let mut idx = 0;
                while idx < cmd.args.len() {
                    let key = cmd.args[idx].clone();
                    let value = cmd.args[idx + 1].clone();
                    store.set_string(ctx.db, key, value)?;
                    idx += 2;
                }
                Ok(RespFrame::SimpleString("OK".to_string()))
            }
            "INFO" => {
                let info = "# Server\nmoonlight:1.0\n";
                Ok(RespFrame::BulkString(Some(info.as_bytes().to_vec())))
            }
            _ => Err(CoreError::Message("ERR unknown command".to_string())),
        }
    }
}

struct ReadBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl ReadBuffer {
    fn new() -> Self {
        Self {
            buf: vec![0u8; READ_BUFFER],
            start: 0,
            end: 0,
        }
    }

    fn read_line<T: StreamTransport>(&mut self, transport: &mut T) -> CoreResult<Vec<u8>> {
        loop {
            if let Some(pos) = find_crlf(&self.buf[self.start..self.end]) {
                let end = self.start + pos;
                let line = self.buf[self.start..end].to_vec();
                self.start = end + 2;
                return Ok(line);
            }
            if self.fill(transport)? == 0 {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
        }
    }

    fn read_exact<T: StreamTransport>(
        &mut self,
        transport: &mut T,
        len: usize,
    ) -> CoreResult<Vec<u8>> {
        while self.end - self.start < len {
            if self.fill(transport)? == 0 {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
        }
        let out = self.buf[self.start..self.start + len].to_vec();
        self.start += len;
        Ok(out)
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

struct AsyncReadBuffer {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl AsyncReadBuffer {
    fn new() -> Self {
        Self {
            buf: vec![0u8; READ_BUFFER],
            start: 0,
            end: 0,
        }
    }

    async fn read_line<T: AsyncStreamTransport>(
        &mut self,
        transport: &mut T,
    ) -> CoreResult<Vec<u8>> {
        loop {
            if let Some(pos) = find_crlf(&self.buf[self.start..self.end]) {
                let end = self.start + pos;
                let line = self.buf[self.start..end].to_vec();
                self.start = end + 2;
                return Ok(line);
            }
            if self.fill(transport).await? == 0 {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
        }
    }

    async fn read_exact<T: AsyncStreamTransport>(
        &mut self,
        transport: &mut T,
        len: usize,
    ) -> CoreResult<Vec<u8>> {
        while self.end - self.start < len {
            if self.fill(transport).await? == 0 {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
        }
        let out = self.buf[self.start..self.start + len].to_vec();
        self.start += len;
        Ok(out)
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

fn read_frame<T: StreamTransport>(
    transport: &mut T,
    buffer: &mut ReadBuffer,
    depth: usize,
) -> CoreResult<RespFrame> {
    if depth > MAX_DEPTH {
        return Err(CoreError::Parse("frame too deep".to_string()));
    }
    let line = buffer.read_line(transport)?;
    if line.is_empty() {
        return Err(CoreError::Parse("empty frame".to_string()));
    }
    let prefix = line[0];
    let rest = &line[1..];
    match prefix {
        b'+' => Ok(RespFrame::SimpleString(
            String::from_utf8_lossy(rest).to_string(),
        )),
        b'-' => Ok(RespFrame::Error(String::from_utf8_lossy(rest).to_string())),
        b':' => Ok(RespFrame::Integer(parse_i64(rest)?)),
        b'$' => {
            let len = parse_i64(rest)?;
            if len < 0 {
                return Ok(RespFrame::BulkString(None));
            }
            let bytes = buffer.read_exact(transport, len as usize)?;
            let crlf = buffer.read_exact(transport, 2)?;
            if crlf != b"\r\n" {
                return Err(CoreError::Parse("invalid bulk string".to_string()));
            }
            Ok(RespFrame::BulkString(Some(bytes)))
        }
        b'*' => {
            let len = parse_i64(rest)?;
            if len < 0 {
                return Ok(RespFrame::Array(None));
            }
            let mut items = Vec::with_capacity(len as usize);
            for _ in 0..len {
                items.push(read_frame(transport, buffer, depth + 1)?);
            }
            Ok(RespFrame::Array(Some(items)))
        }
        b'_' => Ok(RespFrame::Null),
        b'#' => {
            if rest == b"t" {
                Ok(RespFrame::Boolean(true))
            } else if rest == b"f" {
                Ok(RespFrame::Boolean(false))
            } else {
                Err(CoreError::Parse("invalid boolean".to_string()))
            }
        }
        b',' => {
            let value = String::from_utf8_lossy(rest)
                .parse::<f64>()
                .map_err(|_| CoreError::Parse("invalid double".to_string()))?;
            Ok(RespFrame::Double(value))
        }
        b'(' => Ok(RespFrame::BigNumber(
            String::from_utf8_lossy(rest).to_string(),
        )),
        b'!' => {
            let len = parse_i64(rest)?;
            if len < 0 {
                return Err(CoreError::Parse("invalid bulk error length".to_string()));
            }
            let bytes = buffer.read_exact(transport, len as usize)?;
            let crlf = buffer.read_exact(transport, 2)?;
            if crlf != b"\r\n" {
                return Err(CoreError::Parse("invalid bulk error".to_string()));
            }
            Ok(RespFrame::BulkError(bytes))
        }
        b'=' => {
            let len = parse_i64(rest)?;
            if len < 0 {
                return Err(CoreError::Parse("invalid verbatim length".to_string()));
            }
            let bytes = buffer.read_exact(transport, len as usize)?;
            let crlf = buffer.read_exact(transport, 2)?;
            if crlf != b"\r\n" {
                return Err(CoreError::Parse("invalid verbatim".to_string()));
            }
            if bytes.len() < 4 || bytes[3] != b':' {
                return Err(CoreError::Parse("invalid verbatim payload".to_string()));
            }
            let mut format = [0u8; 3];
            format.copy_from_slice(&bytes[..3]);
            Ok(RespFrame::Verbatim(format, bytes[4..].to_vec()))
        }
        b'%' => {
            let len = parse_i64(rest)?;
            if len < 0 {
                return Err(CoreError::Parse("invalid map length".to_string()));
            }
            let mut items = Vec::with_capacity(len as usize);
            for _ in 0..len {
                let key = read_frame(transport, buffer, depth + 1)?;
                let value = read_frame(transport, buffer, depth + 1)?;
                items.push((key, value));
            }
            Ok(RespFrame::Map(items))
        }
        b'~' => {
            let len = parse_i64(rest)?;
            if len < 0 {
                return Err(CoreError::Parse("invalid set length".to_string()));
            }
            let mut items = Vec::with_capacity(len as usize);
            for _ in 0..len {
                items.push(read_frame(transport, buffer, depth + 1)?);
            }
            Ok(RespFrame::Set(items))
        }
        b'>' => {
            let len = parse_i64(rest)?;
            if len < 0 {
                return Err(CoreError::Parse("invalid push length".to_string()));
            }
            let mut items = Vec::with_capacity(len as usize);
            for _ in 0..len {
                items.push(read_frame(transport, buffer, depth + 1)?);
            }
            Ok(RespFrame::Push(items))
        }
        _ => Err(CoreError::Parse("unknown frame prefix".to_string())),
    }
}

fn read_frame_async<'a, T: AsyncStreamTransport + Send + 'a>(
    transport: &'a mut T,
    buffer: &'a mut AsyncReadBuffer,
    depth: usize,
) -> Pin<Box<dyn Future<Output = CoreResult<RespFrame>> + Send + 'a>> {
    Box::pin(async move {
        if depth > MAX_DEPTH {
            return Err(CoreError::Parse("frame too deep".to_string()));
        }
        let line = buffer.read_line(transport).await?;
        if line.is_empty() {
            return Err(CoreError::Parse("empty frame".to_string()));
        }
        let prefix = line[0];
        let rest = &line[1..];
        match prefix {
            b'+' => Ok(RespFrame::SimpleString(
                String::from_utf8_lossy(rest).to_string(),
            )),
            b'-' => Ok(RespFrame::Error(String::from_utf8_lossy(rest).to_string())),
            b':' => Ok(RespFrame::Integer(parse_i64(rest)?)),
            b'$' => {
                let len = parse_i64(rest)?;
                if len < 0 {
                    return Ok(RespFrame::BulkString(None));
                }
                let bytes = buffer.read_exact(transport, len as usize).await?;
                let crlf = buffer.read_exact(transport, 2).await?;
                if crlf != b"\r\n" {
                    return Err(CoreError::Parse("invalid bulk string".to_string()));
                }
                Ok(RespFrame::BulkString(Some(bytes)))
            }
            b'*' => {
                let len = parse_i64(rest)?;
                if len < 0 {
                    return Ok(RespFrame::Array(None));
                }
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    items.push(read_frame_async(transport, buffer, depth + 1).await?);
                }
                Ok(RespFrame::Array(Some(items)))
            }
            b'_' => Ok(RespFrame::Null),
            b'#' => {
                if rest == b"t" {
                    Ok(RespFrame::Boolean(true))
                } else if rest == b"f" {
                    Ok(RespFrame::Boolean(false))
                } else {
                    Err(CoreError::Parse("invalid boolean".to_string()))
                }
            }
            b',' => {
                let value = String::from_utf8_lossy(rest)
                    .parse::<f64>()
                    .map_err(|_| CoreError::Parse("invalid double".to_string()))?;
                Ok(RespFrame::Double(value))
            }
            b'(' => Ok(RespFrame::BigNumber(
                String::from_utf8_lossy(rest).to_string(),
            )),
            b'!' => {
                let len = parse_i64(rest)?;
                if len < 0 {
                    return Err(CoreError::Parse("invalid bulk error length".to_string()));
                }
                let bytes = buffer.read_exact(transport, len as usize).await?;
                let crlf = buffer.read_exact(transport, 2).await?;
                if crlf != b"\r\n" {
                    return Err(CoreError::Parse("invalid bulk error".to_string()));
                }
                Ok(RespFrame::BulkError(bytes))
            }
            b'=' => {
                let len = parse_i64(rest)?;
                if len < 0 {
                    return Err(CoreError::Parse("invalid verbatim length".to_string()));
                }
                let bytes = buffer.read_exact(transport, len as usize).await?;
                let crlf = buffer.read_exact(transport, 2).await?;
                if crlf != b"\r\n" {
                    return Err(CoreError::Parse("invalid verbatim".to_string()));
                }
                if bytes.len() < 4 || bytes[3] != b':' {
                    return Err(CoreError::Parse("invalid verbatim payload".to_string()));
                }
                let mut format = [0u8; 3];
                format.copy_from_slice(&bytes[..3]);
                Ok(RespFrame::Verbatim(format, bytes[4..].to_vec()))
            }
            b'%' => {
                let len = parse_i64(rest)?;
                if len < 0 {
                    return Err(CoreError::Parse("invalid map length".to_string()));
                }
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    let key = read_frame_async(transport, buffer, depth + 1).await?;
                    let value = read_frame_async(transport, buffer, depth + 1).await?;
                    items.push((key, value));
                }
                Ok(RespFrame::Map(items))
            }
            b'~' => {
                let len = parse_i64(rest)?;
                if len < 0 {
                    return Err(CoreError::Parse("invalid set length".to_string()));
                }
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    items.push(read_frame_async(transport, buffer, depth + 1).await?);
                }
                Ok(RespFrame::Set(items))
            }
            b'>' => {
                let len = parse_i64(rest)?;
                if len < 0 {
                    return Err(CoreError::Parse("invalid push length".to_string()));
                }
                let mut items = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    items.push(read_frame_async(transport, buffer, depth + 1).await?);
                }
                Ok(RespFrame::Push(items))
            }
            _ => Err(CoreError::Parse("unknown frame prefix".to_string())),
        }
    })
}

fn parse_i64(bytes: &[u8]) -> CoreResult<i64> {
    let s =
        std::str::from_utf8(bytes).map_err(|_| CoreError::Parse("invalid number".to_string()))?;
    s.parse::<i64>()
        .map_err(|_| CoreError::Parse("invalid number".to_string()))
}

fn parse_arg_i64(cmd: &RedisCommand, idx: usize) -> CoreResult<i64> {
    if idx >= cmd.args.len() {
        return Err(CoreError::Message(
            "ERR wrong number of arguments".to_string(),
        ));
    }
    parse_i64(&cmd.args[idx])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::fuzz_bytes;

    #[test]
    fn resp_roundtrip_bulk() {
        let frame = RespFrame::BulkString(Some(b"hello".to_vec()));
        let encoded = frame.encode(RespVersion::Resp2);
        let mut transport = TestTransport::new(encoded);
        let mut buffer = ReadBuffer::new();
        let decoded = read_frame(&mut transport, &mut buffer, 0).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn resp_roundtrip_map() {
        let frame = RespFrame::Map(vec![
            (
                RespFrame::SimpleString("a".to_string()),
                RespFrame::Integer(1),
            ),
            (
                RespFrame::SimpleString("b".to_string()),
                RespFrame::Integer(2),
            ),
        ]);
        let encoded = frame.encode(RespVersion::Resp3);
        let mut transport = TestTransport::new(encoded);
        let mut buffer = ReadBuffer::new();
        let decoded = read_frame(&mut transport, &mut buffer, 0).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn server_client_roundtrip() {
        let handler = Arc::new(DefaultRedisHandler);
        let config = RedisServerConfig::default();
        let server = match RedisServer::bind("127.0.0.1:0".parse().unwrap(), config, handler) {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {err:?}"),
        };
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client =
            RedisClient::connect(&NetAddr::from_socket(addr), Timeouts::default()).unwrap();
        let resp = client.call(RedisCommand::new("PING", vec![])).unwrap();
        assert_eq!(resp, RespFrame::SimpleString("PONG".to_string()));
        let resp = client
            .call(RedisCommand::new("SET", vec![b"k".to_vec(), b"v".to_vec()]))
            .unwrap();
        assert_eq!(resp, RespFrame::SimpleString("OK".to_string()));
        let resp = client
            .call(RedisCommand::new("GET", vec![b"k".to_vec()]))
            .unwrap();
        assert_eq!(resp, RespFrame::BulkString(Some(b"v".to_vec())));
    }

    #[test]
    fn auth_required() {
        let handler = Arc::new(DefaultRedisHandler);
        let mut config = RedisServerConfig::default();
        config.requirepass = Some("secret".to_string());
        let server = match RedisServer::bind("127.0.0.1:0".parse().unwrap(), config, handler) {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {err:?}"),
        };
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client =
            RedisClient::connect(&NetAddr::from_socket(addr), Timeouts::default()).unwrap();
        let resp = client.call(RedisCommand::new("PING", vec![])).unwrap();
        match resp {
            RespFrame::Error(value) => assert!(value.contains("NOAUTH")),
            _ => panic!("expected NOAUTH"),
        }
        let resp = client.auth("secret").unwrap();
        assert_eq!(resp, RespFrame::SimpleString("OK".to_string()));
    }

    #[test]
    fn resp_decode_negative() {
        let mut transport = TestTransport::new(Vec::new());
        let mut buffer = ReadBuffer::new();
        assert!(read_frame(&mut transport, &mut buffer, 0).is_err());
    }

    #[test]
    fn resp_decode_fuzz() {
        fuzz_bytes(128, 512, 0x5253, |data| {
            let mut transport = TestTransport::new(data.to_vec());
            let mut buffer = ReadBuffer::new();
            let _ = read_frame(&mut transport, &mut buffer, 0);
        });
    }

    struct TestTransport {
        data: Vec<u8>,
        pos: usize,
    }

    impl TestTransport {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl StreamTransport for TestTransport {
        fn read(&mut self, buf: &mut [u8]) -> CoreResult<usize> {
            let remaining = self.data.len().saturating_sub(self.pos);
            let to_read = remaining.min(buf.len());
            if to_read == 0 {
                return Ok(0);
            }
            buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
            self.pos += to_read;
            Ok(to_read)
        }

        fn read_exact(&mut self, buf: &mut [u8]) -> CoreResult<()> {
            let remaining = self.data.len().saturating_sub(self.pos);
            if remaining < buf.len() {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
            buf.copy_from_slice(&self.data[self.pos..self.pos + buf.len()]);
            self.pos += buf.len();
            Ok(())
        }

        fn write_all(&mut self, _buf: &[u8]) -> CoreResult<()> {
            Err(CoreError::Message("write not supported".to_string()))
        }

        fn shutdown(&mut self) -> CoreResult<()> {
            Ok(())
        }

        fn peer_addr(&self) -> CoreResult<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }

        fn set_read_timeout(&self, _timeout: Option<std::time::Duration>) -> CoreResult<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: Option<std::time::Duration>) -> CoreResult<()> {
            Ok(())
        }
    }
}
