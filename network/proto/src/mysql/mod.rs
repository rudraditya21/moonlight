use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

const PROTOCOL_VERSION: u8 = 0x0A;
const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

const COM_QUIT: u8 = 0x01;
const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_PING: u8 = 0x0e;

static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone)]
struct MysqlHandshake {
    server_version: String,
    connection_id: u32,
    auth_plugin_data: [u8; 20],
    capability_flags: u32,
    character_set: u8,
    status_flags: u16,
    auth_plugin_name: String,
}

impl MysqlHandshake {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(PROTOCOL_VERSION);
        out.extend_from_slice(self.server_version.as_bytes());
        out.push(0x00);
        out.extend_from_slice(&self.connection_id.to_le_bytes());
        out.extend_from_slice(&self.auth_plugin_data[..8]);
        out.push(0x00);
        out.extend_from_slice(&(self.capability_flags as u16).to_le_bytes());
        out.push(self.character_set);
        out.extend_from_slice(&self.status_flags.to_le_bytes());
        out.extend_from_slice(&((self.capability_flags >> 16) as u16).to_le_bytes());
        out.push(self.auth_plugin_data.len() as u8 + 1);
        out.extend_from_slice(&[0u8; 10]);
        out.extend_from_slice(&self.auth_plugin_data[8..]);
        out.push(0x00);
        out.extend_from_slice(self.auth_plugin_name.as_bytes());
        out.push(0x00);
        out
    }

    fn decode(payload: &[u8]) -> CoreResult<Self> {
        if payload.is_empty() {
            return Err(CoreError::Parse("mysql handshake empty".to_string()));
        }
        let mut idx = 0;
        let protocol = payload[idx];
        idx += 1;
        if protocol != PROTOCOL_VERSION {
            return Err(CoreError::Parse("mysql protocol unsupported".to_string()));
        }
        let server_version = read_null_terminated(payload, &mut idx)?;
        if idx + 4 > payload.len() {
            return Err(CoreError::Parse("mysql handshake conn id".to_string()));
        }
        let connection_id = u32::from_le_bytes(payload[idx..idx + 4].try_into().unwrap());
        idx += 4;
        if idx + 8 > payload.len() {
            return Err(CoreError::Parse("mysql handshake scramble".to_string()));
        }
        let mut scramble = [0u8; 20];
        scramble[..8].copy_from_slice(&payload[idx..idx + 8]);
        idx += 8;
        idx += 1; // filler
        if idx + 2 > payload.len() {
            return Err(CoreError::Parse("mysql handshake caps".to_string()));
        }
        let caps_low = u16::from_le_bytes(payload[idx..idx + 2].try_into().unwrap()) as u32;
        idx += 2;
        if idx >= payload.len() {
            return Err(CoreError::Parse("mysql handshake charset".to_string()));
        }
        let character_set = payload[idx];
        idx += 1;
        if idx + 2 > payload.len() {
            return Err(CoreError::Parse("mysql handshake status".to_string()));
        }
        let status_flags = u16::from_le_bytes(payload[idx..idx + 2].try_into().unwrap());
        idx += 2;
        if idx + 2 > payload.len() {
            return Err(CoreError::Parse("mysql handshake caps2".to_string()));
        }
        let caps_high = u16::from_le_bytes(payload[idx..idx + 2].try_into().unwrap()) as u32;
        idx += 2;
        let capability_flags = caps_low | (caps_high << 16);
        let auth_data_len = if idx < payload.len() { payload[idx] } else { 0 } as usize;
        idx += 1;
        idx += 10; // reserved
        let remaining = payload.len().saturating_sub(idx);
        let needed = std::cmp::max(13, auth_data_len.saturating_sub(8));
        let second_len = std::cmp::min(remaining, needed);
        if idx + second_len > payload.len() {
            return Err(CoreError::Parse("mysql handshake scramble2".to_string()));
        }
        if second_len > 0 {
            let copy_len = std::cmp::min(12, second_len);
            scramble[8..8 + copy_len].copy_from_slice(&payload[idx..idx + copy_len]);
            idx += second_len;
        }
        let auth_plugin_name = if idx < payload.len() {
            read_null_terminated(payload, &mut idx)?
        } else {
            "mysql_native_password".to_string()
        };
        Ok(Self {
            server_version,
            connection_id,
            auth_plugin_data: scramble,
            capability_flags,
            character_set,
            status_flags,
            auth_plugin_name,
        })
    }
}

#[derive(Debug, Clone)]
struct MysqlHandshakeResponse {
    capability_flags: u32,
    max_packet_size: u32,
    character_set: u8,
    username: String,
    auth_response: Vec<u8>,
    database: Option<String>,
    auth_plugin_name: Option<String>,
}

impl MysqlHandshakeResponse {
    fn decode(payload: &[u8]) -> CoreResult<Self> {
        if payload.len() < 36 {
            return Err(CoreError::Parse("mysql handshake response too short".to_string()));
        }
        let mut idx = 0;
        let capability_flags = u32::from_le_bytes(payload[idx..idx + 4].try_into().unwrap());
        idx += 4;
        let max_packet_size = u32::from_le_bytes(payload[idx..idx + 4].try_into().unwrap());
        idx += 4;
        let character_set = payload[idx];
        idx += 1;
        idx += 23; // reserved
        let username = read_null_terminated(payload, &mut idx)?;

        let auth_response = if capability_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            let len = decode_lenenc_int(payload, &mut idx)? as usize;
            if idx + len > payload.len() {
                return Err(CoreError::Parse("mysql auth response len".to_string()));
            }
            let data = payload[idx..idx + len].to_vec();
            idx += len;
            data
        } else {
            if idx >= payload.len() {
                Vec::new()
            } else {
                let len = payload[idx] as usize;
                idx += 1;
                if idx + len > payload.len() {
                    return Err(CoreError::Parse("mysql auth response bounds".to_string()));
                }
                let data = payload[idx..idx + len].to_vec();
                idx += len;
                data
            }
        };

        let database = if capability_flags & CLIENT_CONNECT_WITH_DB != 0 {
            Some(read_null_terminated(payload, &mut idx)?)
        } else {
            None
        };

        let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && idx < payload.len() {
            Some(read_null_terminated(payload, &mut idx)?)
        } else {
            None
        };

        Ok(Self {
            capability_flags,
            max_packet_size,
            character_set,
            username,
            auth_response,
            database,
            auth_plugin_name,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct MysqlQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<Vec<u8>>>>,
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status_flags: u16,
    pub warnings: u16,
}

#[derive(Debug, Clone)]
pub struct MysqlClientConfig {
    pub timeouts: Timeouts,
    pub username: String,
    pub password: String,
    pub database: Option<String>,
    pub character_set: u8,
}

impl Default for MysqlClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            username: "root".to_string(),
            password: "moonlight".to_string(),
            database: None,
            character_set: 0x21,
        }
    }
}

pub struct MysqlClient {
    transport: TcpTransport,
    capability_flags: u32,
    status_flags: u16,
    server_version: String,
    connection_id: u32,
}

impl MysqlClient {
    pub fn connect(addr: &net::NetAddr, config: MysqlClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let (handshake_payload, _) = read_packet(&mut transport)?;
        let handshake = MysqlHandshake::decode(&handshake_payload)?;

        let mut capabilities = CLIENT_LONG_PASSWORD
            | CLIENT_LONG_FLAG
            | CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH;
        if config.database.is_some() {
            capabilities |= CLIENT_CONNECT_WITH_DB;
        }
        let auth_response = mysql_native_password_token(&config.password, &handshake.auth_plugin_data);

        let response = encode_handshake_response(
            capabilities,
            config.character_set,
            &config.username,
            &auth_response,
            config.database.as_deref(),
            &handshake.auth_plugin_name,
        );
        write_packet(&mut transport, 1, &response)?;
        let (payload, _) = read_packet(&mut transport)?;
        if is_err_packet(&payload) {
            let err = parse_err_packet(&payload)?;
            return Err(CoreError::Message(err.format()));
        }
        let ok = parse_ok_packet(&payload)?;
        Ok(Self {
            transport,
            capability_flags: capabilities,
            status_flags: ok.status_flags,
            server_version: handshake.server_version,
            connection_id: handshake.connection_id,
        })
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn capability_flags(&self) -> u32 {
        self.capability_flags
    }

    pub fn status_flags(&self) -> u16 {
        self.status_flags
    }

    pub fn query(&mut self, sql: &str) -> CoreResult<MysqlQueryResult> {
        let payload = build_command_packet(COM_QUERY, sql.as_bytes());
        write_packet(&mut self.transport, 0, &payload)?;
        self.read_query_result()
    }

    pub fn ping(&mut self) -> CoreResult<()> {
        let payload = build_command_packet(COM_PING, &[]);
        write_packet(&mut self.transport, 0, &payload)?;
        let (payload, _) = read_packet(&mut self.transport)?;
        if is_err_packet(&payload) {
            let err = parse_err_packet(&payload)?;
            return Err(CoreError::Message(err.format()));
        }
        let ok = parse_ok_packet(&payload)?;
        self.status_flags = ok.status_flags;
        Ok(())
    }

    fn read_query_result(&mut self) -> CoreResult<MysqlQueryResult> {
        let (payload, _) = read_packet(&mut self.transport)?;
        if is_err_packet(&payload) {
            let err = parse_err_packet(&payload)?;
            return Err(CoreError::Message(err.message));
        }
        if is_ok_packet(&payload) {
            let ok = parse_ok_packet(&payload)?;
            return Ok(MysqlQueryResult {
                affected_rows: ok.affected_rows,
                last_insert_id: ok.last_insert_id,
                status_flags: ok.status_flags,
                warnings: ok.warnings,
                ..MysqlQueryResult::default()
            });
        }
        let mut idx = 0;
        let column_count = decode_lenenc_int(&payload, &mut idx)? as usize;
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let (col_payload, _) = read_packet(&mut self.transport)?;
            let column = parse_column_definition(&col_payload)?;
            columns.push(column);
        }
        let (eof_payload, _) = read_packet(&mut self.transport)?;
        if !is_eof_packet(&eof_payload) && !is_ok_packet(&eof_payload) {
            return Err(CoreError::Parse("mysql expected eof".to_string()));
        }
        let mut rows = Vec::new();
        loop {
            let (row_payload, _) = read_packet(&mut self.transport)?;
            if is_eof_packet(&row_payload) || is_ok_packet(&row_payload) {
                break;
            }
            rows.push(parse_row(&row_payload, column_count)?);
        }
        Ok(MysqlQueryResult {
            columns,
            rows,
            ..MysqlQueryResult::default()
        })
    }
}

pub struct AsyncMysqlClient {
    transport: AsyncTcpTransport,
    capability_flags: u32,
    status_flags: u16,
    server_version: String,
    connection_id: u32,
}

impl AsyncMysqlClient {
    pub async fn connect(addr: &net::NetAddr, config: MysqlClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let (handshake_payload, _) = read_packet_async(&mut transport).await?;
        let handshake = MysqlHandshake::decode(&handshake_payload)?;

        let mut capabilities = CLIENT_LONG_PASSWORD
            | CLIENT_LONG_FLAG
            | CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH;
        if config.database.is_some() {
            capabilities |= CLIENT_CONNECT_WITH_DB;
        }
        let auth_response = mysql_native_password_token(&config.password, &handshake.auth_plugin_data);
        let response = encode_handshake_response(
            capabilities,
            config.character_set,
            &config.username,
            &auth_response,
            config.database.as_deref(),
            &handshake.auth_plugin_name,
        );
        write_packet_async(&mut transport, 1, &response).await?;
        let (payload, _) = read_packet_async(&mut transport).await?;
        if is_err_packet(&payload) {
            let err = parse_err_packet(&payload)?;
            return Err(CoreError::Message(err.format()));
        }
        let ok = parse_ok_packet(&payload)?;
        Ok(Self {
            transport,
            capability_flags: capabilities,
            status_flags: ok.status_flags,
            server_version: handshake.server_version,
            connection_id: handshake.connection_id,
        })
    }

    pub async fn query(&mut self, sql: &str) -> CoreResult<MysqlQueryResult> {
        let payload = build_command_packet(COM_QUERY, sql.as_bytes());
        write_packet_async(&mut self.transport, 0, &payload).await?;
        self.read_query_result().await
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn capability_flags(&self) -> u32 {
        self.capability_flags
    }

    pub fn status_flags(&self) -> u16 {
        self.status_flags
    }

    pub async fn ping(&mut self) -> CoreResult<()> {
        let payload = build_command_packet(COM_PING, &[]);
        write_packet_async(&mut self.transport, 0, &payload).await?;
        let (payload, _) = read_packet_async(&mut self.transport).await?;
        if is_err_packet(&payload) {
            let err = parse_err_packet(&payload)?;
            return Err(CoreError::Message(err.format()));
        }
        let ok = parse_ok_packet(&payload)?;
        self.status_flags = ok.status_flags;
        Ok(())
    }

    async fn read_query_result(&mut self) -> CoreResult<MysqlQueryResult> {
        let (payload, _) = read_packet_async(&mut self.transport).await?;
        if is_err_packet(&payload) {
            let err = parse_err_packet(&payload)?;
            return Err(CoreError::Message(err.message));
        }
        if is_ok_packet(&payload) {
            let ok = parse_ok_packet(&payload)?;
            return Ok(MysqlQueryResult {
                affected_rows: ok.affected_rows,
                last_insert_id: ok.last_insert_id,
                status_flags: ok.status_flags,
                warnings: ok.warnings,
                ..MysqlQueryResult::default()
            });
        }
        let mut idx = 0;
        let column_count = decode_lenenc_int(&payload, &mut idx)? as usize;
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let (col_payload, _) = read_packet_async(&mut self.transport).await?;
            let column = parse_column_definition(&col_payload)?;
            columns.push(column);
        }
        let (eof_payload, _) = read_packet_async(&mut self.transport).await?;
        if !is_eof_packet(&eof_payload) && !is_ok_packet(&eof_payload) {
            return Err(CoreError::Parse("mysql expected eof".to_string()));
        }
        let mut rows = Vec::new();
        loop {
            let (row_payload, _) = read_packet_async(&mut self.transport).await?;
            if is_eof_packet(&row_payload) || is_ok_packet(&row_payload) {
                break;
            }
            rows.push(parse_row(&row_payload, column_count)?);
        }
        Ok(MysqlQueryResult {
            columns,
            rows,
            ..MysqlQueryResult::default()
        })
    }
}

#[derive(Debug, Clone)]
pub struct MysqlServerConfig {
    pub timeouts: Timeouts,
    pub users: HashMap<String, String>,
    pub default_database: String,
    pub server_version: String,
    pub character_set: u8,
    pub status_flags: u16,
}

impl Default for MysqlServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            users: HashMap::new(),
            default_database: "mysql".to_string(),
            server_version: "5.7.0-moonlight".to_string(),
            character_set: 0x21,
            status_flags: SERVER_STATUS_AUTOCOMMIT,
        }
    }
}

#[derive(Debug)]
struct MysqlState {
    authenticated: bool,
    database: String,
}

pub struct MysqlServer {
    listener: TcpListener,
    config: MysqlServerConfig,
}

impl MysqlServer {
    pub fn bind(addr: SocketAddr, config: MysqlServerConfig) -> CoreResult<Self> {
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
                let _ = handle_mysql_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncMysqlServer {
    listener: tokio::net::TcpListener,
    config: MysqlServerConfig,
}

impl AsyncMysqlServer {
    pub async fn bind(addr: SocketAddr, config: MysqlServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_mysql_stream_async(stream, config).await;
            });
        }
    }
}

fn handle_mysql_stream(stream: TcpStream, config: MysqlServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    let connection_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let scramble = generate_scramble(connection_id as u64);
    let handshake = MysqlHandshake {
        server_version: config.server_version.clone(),
        connection_id,
        auth_plugin_data: scramble,
        capability_flags: server_capabilities(),
        character_set: config.character_set,
        status_flags: config.status_flags,
        auth_plugin_name: "mysql_native_password".to_string(),
    };
    write_packet(&mut transport, 0, &handshake.encode())?;

    let (response_payload, _) = read_packet(&mut transport)?;
    let response = MysqlHandshakeResponse::decode(&response_payload)?;
    if !authenticate_user(&config, &response, &handshake.auth_plugin_data) {
        let err = build_err_packet(1045, "28000", "access denied");
        write_packet(&mut transport, 2, &err)?;
        return Ok(());
    }
    let ok = build_ok_packet(0, 0, config.status_flags, 0);
    write_packet(&mut transport, 2, &ok)?;

    let mut state = MysqlState {
        authenticated: true,
        database: response.database.unwrap_or_else(|| config.default_database.clone()),
    };
    loop {
        let (payload, _) = match read_packet(&mut transport) {
            Ok(value) => value,
            Err(_) => break,
        };
        if payload.is_empty() {
            continue;
        }
        let command = payload[0];
        match command {
            COM_QUIT => break,
            COM_PING => {
                let ok = build_ok_packet(0, 0, config.status_flags, 0);
                write_packet(&mut transport, 1, &ok)?;
            }
            COM_INIT_DB => {
                let db = String::from_utf8_lossy(&payload[1..]).to_string();
                state.database = db;
                let ok = build_ok_packet(0, 0, config.status_flags, 0);
                write_packet(&mut transport, 1, &ok)?;
            }
            COM_QUERY => {
                let sql = String::from_utf8_lossy(&payload[1..]).to_string();
                respond_to_query(&mut transport, &config, &mut state, &sql)?;
            }
            _ => {
                let err = build_err_packet(1064, "42000", "unsupported command");
                write_packet(&mut transport, 1, &err)?;
            }
        }
    }
    Ok(())
}

async fn handle_mysql_stream_async(
    stream: tokio::net::TcpStream,
    config: MysqlServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    let connection_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let scramble = generate_scramble(connection_id as u64);
    let handshake = MysqlHandshake {
        server_version: config.server_version.clone(),
        connection_id,
        auth_plugin_data: scramble,
        capability_flags: server_capabilities(),
        character_set: config.character_set,
        status_flags: config.status_flags,
        auth_plugin_name: "mysql_native_password".to_string(),
    };
    write_packet_async(&mut transport, 0, &handshake.encode()).await?;

    let (response_payload, _) = read_packet_async(&mut transport).await?;
    let response = MysqlHandshakeResponse::decode(&response_payload)?;
    if !authenticate_user(&config, &response, &handshake.auth_plugin_data) {
        let err = build_err_packet(1045, "28000", "access denied");
        write_packet_async(&mut transport, 2, &err).await?;
        return Ok(());
    }
    let ok = build_ok_packet(0, 0, config.status_flags, 0);
    write_packet_async(&mut transport, 2, &ok).await?;

    let mut state = MysqlState {
        authenticated: true,
        database: response.database.unwrap_or_else(|| config.default_database.clone()),
    };
    loop {
        let (payload, _) = match read_packet_async(&mut transport).await {
            Ok(value) => value,
            Err(_) => break,
        };
        if payload.is_empty() {
            continue;
        }
        let command = payload[0];
        match command {
            COM_QUIT => break,
            COM_PING => {
                let ok = build_ok_packet(0, 0, config.status_flags, 0);
                write_packet_async(&mut transport, 1, &ok).await?;
            }
            COM_INIT_DB => {
                let db = String::from_utf8_lossy(&payload[1..]).to_string();
                state.database = db;
                let ok = build_ok_packet(0, 0, config.status_flags, 0);
                write_packet_async(&mut transport, 1, &ok).await?;
            }
            COM_QUERY => {
                let sql = String::from_utf8_lossy(&payload[1..]).to_string();
                respond_to_query_async(&mut transport, &config, &mut state, &sql).await?;
            }
            _ => {
                let err = build_err_packet(1064, "42000", "unsupported command");
                write_packet_async(&mut transport, 1, &err).await?;
            }
        }
    }
    Ok(())
}

fn respond_to_query(
    transport: &mut TcpTransport,
    config: &MysqlServerConfig,
    state: &mut MysqlState,
    sql: &str,
) -> CoreResult<()> {
    if !state.authenticated {
        let err = build_err_packet(1045, "28000", "not authenticated");
        write_packet(transport, 1, &err)?;
        return Ok(());
    }
    let lower = sql.trim().to_lowercase();
    if lower.starts_with("use ") {
        state.database = sql.trim()[4..].trim().to_string();
        let ok = build_ok_packet(0, 0, config.status_flags, 0);
        write_packet(transport, 1, &ok)?;
        return Ok(());
    }
    if lower.starts_with("select") {
        if lower.contains("@@version") {
            send_result_set(
                transport,
                &["@@version"],
                vec![vec![Some(b"Moonlight MySQL 0.1".to_vec())]],
            )?;
            return Ok(());
        }
        if lower.contains("1") {
            send_result_set(
                transport,
                &["1"],
                vec![vec![Some(b"1".to_vec())]],
            )?;
            return Ok(());
        }
        send_result_set(
            transport,
            &["database"],
            vec![vec![Some(state.database.as_bytes().to_vec())]],
        )?;
        return Ok(());
    }
    if lower.starts_with("show databases") {
        let rows = vec![
            vec![Some(state.database.as_bytes().to_vec())],
            vec![Some(b"information_schema".to_vec())],
        ];
        send_result_set(transport, &["Database"], rows)?;
        return Ok(());
    }
    let ok = build_ok_packet(0, 0, config.status_flags, 0);
    write_packet(transport, 1, &ok)?;
    Ok(())
}

async fn respond_to_query_async(
    transport: &mut AsyncTcpTransport,
    config: &MysqlServerConfig,
    state: &mut MysqlState,
    sql: &str,
) -> CoreResult<()> {
    if !state.authenticated {
        let err = build_err_packet(1045, "28000", "not authenticated");
        write_packet_async(transport, 1, &err).await?;
        return Ok(());
    }
    let lower = sql.trim().to_lowercase();
    if lower.starts_with("use ") {
        state.database = sql.trim()[4..].trim().to_string();
        let ok = build_ok_packet(0, 0, config.status_flags, 0);
        write_packet_async(transport, 1, &ok).await?;
        return Ok(());
    }
    if lower.starts_with("select") {
        if lower.contains("@@version") {
            send_result_set_async(
                transport,
                &["@@version"],
                vec![vec![Some(b"Moonlight MySQL 0.1".to_vec())]],
            )
            .await?;
            return Ok(());
        }
        if lower.contains("1") {
            send_result_set_async(
                transport,
                &["1"],
                vec![vec![Some(b"1".to_vec())]],
            )
            .await?;
            return Ok(());
        }
        send_result_set_async(
            transport,
            &["database"],
            vec![vec![Some(state.database.as_bytes().to_vec())]],
        )
        .await?;
        return Ok(());
    }
    if lower.starts_with("show databases") {
        let rows = vec![
            vec![Some(state.database.as_bytes().to_vec())],
            vec![Some(b"information_schema".to_vec())],
        ];
        send_result_set_async(transport, &["Database"], rows).await?;
        return Ok(());
    }
    let ok = build_ok_packet(0, 0, config.status_flags, 0);
    write_packet_async(transport, 1, &ok).await?;
    Ok(())
}

fn authenticate_user(config: &MysqlServerConfig, response: &MysqlHandshakeResponse, scramble: &[u8; 20]) -> bool {
    if response.capability_flags & CLIENT_PROTOCOL_41 == 0 {
        return false;
    }
    if let Some(name) = &response.auth_plugin_name {
        if name != "mysql_native_password" {
            return false;
        }
    }
    let _ = response.max_packet_size;
    let _ = response.character_set;
    if config.users.is_empty() {
        return true;
    }
    let Some(password) = config.users.get(&response.username) else {
        return false;
    };
    let token = mysql_native_password_token(password, scramble);
    token == response.auth_response
}

fn server_capabilities() -> u32 {
    CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
}

fn encode_handshake_response(
    capabilities: u32,
    character_set: u8,
    username: &str,
    auth_response: &[u8],
    database: Option<&str>,
    plugin_name: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&capabilities.to_le_bytes());
    out.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    out.push(character_set);
    out.extend_from_slice(&[0u8; 23]);
    out.extend_from_slice(username.as_bytes());
    out.push(0x00);
    out.push(auth_response.len() as u8);
    out.extend_from_slice(auth_response);
    if let Some(db) = database {
        out.extend_from_slice(db.as_bytes());
        out.push(0x00);
    }
    out.extend_from_slice(plugin_name.as_bytes());
    out.push(0x00);
    out
}

#[derive(Debug, Clone)]
struct MysqlOkPacket {
    affected_rows: u64,
    last_insert_id: u64,
    status_flags: u16,
    warnings: u16,
}

#[derive(Debug, Clone)]
struct MysqlErrPacket {
    code: u16,
    state: String,
    message: String,
}

impl MysqlErrPacket {
    fn format(&self) -> String {
        if self.state.is_empty() {
            format!("mysql error {}: {}", self.code, self.message)
        } else {
            format!("mysql error {} ({}) {}", self.code, self.state, self.message)
        }
    }
}

fn parse_ok_packet(payload: &[u8]) -> CoreResult<MysqlOkPacket> {
    if payload.is_empty() || payload[0] != 0x00 {
        return Err(CoreError::Parse("mysql ok packet".to_string()));
    }
    let mut idx = 1;
    let affected_rows = decode_lenenc_int(payload, &mut idx)?;
    let last_insert_id = decode_lenenc_int(payload, &mut idx)?;
    if idx + 4 > payload.len() {
        return Err(CoreError::Parse("mysql ok flags".to_string()));
    }
    let status_flags = u16::from_le_bytes(payload[idx..idx + 2].try_into().unwrap());
    idx += 2;
    let warnings = u16::from_le_bytes(payload[idx..idx + 2].try_into().unwrap());
    Ok(MysqlOkPacket {
        affected_rows,
        last_insert_id,
        status_flags,
        warnings,
    })
}

fn parse_err_packet(payload: &[u8]) -> CoreResult<MysqlErrPacket> {
    if payload.len() < 3 || payload[0] != 0xff {
        return Err(CoreError::Parse("mysql err packet".to_string()));
    }
    let code = u16::from_le_bytes([payload[1], payload[2]]);
    let mut idx = 3;
    let mut state = "HY000".to_string();
    if idx < payload.len() && payload[idx] == b'#' {
        idx += 1;
        if idx + 5 <= payload.len() {
            state = String::from_utf8_lossy(&payload[idx..idx + 5]).to_string();
            idx += 5;
        }
    }
    let message = if idx < payload.len() {
        String::from_utf8_lossy(&payload[idx..]).to_string()
    } else {
        String::new()
    };
    Ok(MysqlErrPacket { code, state, message })
}

fn build_ok_packet(affected_rows: u64, last_insert_id: u64, status_flags: u16, warnings: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x00);
    encode_lenenc_int(&mut out, affected_rows);
    encode_lenenc_int(&mut out, last_insert_id);
    out.extend_from_slice(&status_flags.to_le_bytes());
    out.extend_from_slice(&warnings.to_le_bytes());
    out
}

fn build_err_packet(code: u16, state: &str, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xff);
    out.extend_from_slice(&code.to_le_bytes());
    out.push(b'#');
    let state_bytes = state.as_bytes();
    let mut padded = [b'0'; 5];
    for (i, b) in state_bytes.iter().take(5).enumerate() {
        padded[i] = *b;
    }
    out.extend_from_slice(&padded);
    out.extend_from_slice(message.as_bytes());
    out
}

fn is_ok_packet(payload: &[u8]) -> bool {
    payload.first() == Some(&0x00)
}

fn is_err_packet(payload: &[u8]) -> bool {
    payload.first() == Some(&0xff)
}

fn is_eof_packet(payload: &[u8]) -> bool {
    payload.first() == Some(&0xfe) && payload.len() < 9
}

fn parse_column_definition(payload: &[u8]) -> CoreResult<String> {
    let mut idx = 0;
    let _catalog = decode_lenenc_string(payload, &mut idx)?;
    let _schema = decode_lenenc_string(payload, &mut idx)?;
    let _table = decode_lenenc_string(payload, &mut idx)?;
    let _org_table = decode_lenenc_string(payload, &mut idx)?;
    let name = decode_lenenc_string(payload, &mut idx)?;
    let _org_name = decode_lenenc_string(payload, &mut idx)?;
    Ok(String::from_utf8_lossy(&name.unwrap_or_default()).to_string())
}

fn parse_row(payload: &[u8], column_count: usize) -> CoreResult<Vec<Option<Vec<u8>>>> {
    let mut idx = 0;
    let mut row = Vec::with_capacity(column_count);
    for _ in 0..column_count {
        let value = decode_lenenc_string(payload, &mut idx)?;
        row.push(value);
    }
    Ok(row)
}

fn send_result_set(
    transport: &mut TcpTransport,
    columns: &[&str],
    rows: Vec<Vec<Option<Vec<u8>>>>,
) -> CoreResult<()> {
    let mut seq = 1;
    let mut count_payload = Vec::new();
    encode_lenenc_int(&mut count_payload, columns.len() as u64);
    write_packet(transport, seq, &count_payload)?;
    seq = seq.wrapping_add(1);

    for col in columns {
        let payload = build_column_definition(col, "def", "table", "table");
        write_packet(transport, seq, &payload)?;
        seq = seq.wrapping_add(1);
    }
    let eof = build_eof_packet();
    write_packet(transport, seq, &eof)?;
    seq = seq.wrapping_add(1);

    for row in rows {
        let payload = build_row_packet(&row);
        write_packet(transport, seq, &payload)?;
        seq = seq.wrapping_add(1);
    }
    let eof2 = build_eof_packet();
    write_packet(transport, seq, &eof2)?;
    Ok(())
}

async fn send_result_set_async(
    transport: &mut AsyncTcpTransport,
    columns: &[&str],
    rows: Vec<Vec<Option<Vec<u8>>>>,
) -> CoreResult<()> {
    let mut seq = 1;
    let mut count_payload = Vec::new();
    encode_lenenc_int(&mut count_payload, columns.len() as u64);
    write_packet_async(transport, seq, &count_payload).await?;
    seq = seq.wrapping_add(1);

    for col in columns {
        let payload = build_column_definition(col, "def", "table", "table");
        write_packet_async(transport, seq, &payload).await?;
        seq = seq.wrapping_add(1);
    }
    let eof = build_eof_packet();
    write_packet_async(transport, seq, &eof).await?;
    seq = seq.wrapping_add(1);

    for row in rows {
        let payload = build_row_packet(&row);
        write_packet_async(transport, seq, &payload).await?;
        seq = seq.wrapping_add(1);
    }
    let eof2 = build_eof_packet();
    write_packet_async(transport, seq, &eof2).await?;
    Ok(())
}

fn build_column_definition(name: &str, schema: &str, table: &str, org_table: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_lenenc_string(&mut out, Some(b"def"));
    encode_lenenc_string(&mut out, Some(schema.as_bytes()));
    encode_lenenc_string(&mut out, Some(table.as_bytes()));
    encode_lenenc_string(&mut out, Some(org_table.as_bytes()));
    encode_lenenc_string(&mut out, Some(name.as_bytes()));
    encode_lenenc_string(&mut out, Some(name.as_bytes()));
    out.push(0x0c);
    out.extend_from_slice(&0x21u16.to_le_bytes());
    out.extend_from_slice(&1024u32.to_le_bytes());
    out.push(0xfd);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(0);
    out.extend_from_slice(&[0, 0]);
    out
}

fn build_row_packet(values: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        encode_lenenc_string(&mut out, value.as_deref());
    }
    out
}

fn build_eof_packet() -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xfe);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&SERVER_STATUS_AUTOCOMMIT.to_le_bytes());
    out
}

fn build_command_packet(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(command);
    out.extend_from_slice(payload);
    out
}

fn mysql_native_password_token(password: &str, scramble: &[u8; 20]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = sha1::digest(password.as_bytes());
    let stage2 = sha1::digest(&stage1);
    let mut combined = Vec::with_capacity(scramble.len() + stage2.len());
    combined.extend_from_slice(scramble);
    combined.extend_from_slice(&stage2);
    let stage3 = sha1::digest(&combined);
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

fn generate_scramble(seed: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    let mut x = seed ^ current_time_seed();
    for byte in &mut out {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *byte = (x & 0xff) as u8;
    }
    out
}

fn current_time_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos() as u64
}

fn read_packet<T: StreamTransport>(transport: &mut T) -> CoreResult<(Vec<u8>, u8)> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header)?;
    let length = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let seq = header[3];
    let mut payload = vec![0u8; length];
    if length > 0 {
        transport.read_exact(&mut payload)?;
    }
    Ok((payload, seq))
}

async fn read_packet_async<T: AsyncStreamTransport>(transport: &mut T) -> CoreResult<(Vec<u8>, u8)> {
    let mut header = [0u8; 4];
    transport.read_exact(&mut header).await?;
    let length = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let seq = header[3];
    let mut payload = vec![0u8; length];
    if length > 0 {
        transport.read_exact(&mut payload).await?;
    }
    Ok((payload, seq))
}

fn write_packet<T: StreamTransport>(transport: &mut T, seq: u8, payload: &[u8]) -> CoreResult<()> {
    let length = payload.len();
    let header = [
        (length & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        ((length >> 16) & 0xff) as u8,
        seq,
    ];
    transport.write_all(&header)?;
    if !payload.is_empty() {
        transport.write_all(payload)?;
    }
    Ok(())
}

async fn write_packet_async<T: AsyncStreamTransport>(
    transport: &mut T,
    seq: u8,
    payload: &[u8],
) -> CoreResult<()> {
    let length = payload.len();
    let header = [
        (length & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        ((length >> 16) & 0xff) as u8,
        seq,
    ];
    transport.write_all(&header).await?;
    if !payload.is_empty() {
        transport.write_all(payload).await?;
    }
    Ok(())
}

fn encode_lenenc_int(out: &mut Vec<u8>, value: u64) {
    if value < 0xfb {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfc);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffff {
        out.push(0xfd);
        out.push((value & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push(((value >> 16) & 0xff) as u8);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn decode_lenenc_int(data: &[u8], idx: &mut usize) -> CoreResult<u64> {
    if *idx >= data.len() {
        return Err(CoreError::Parse("mysql lenenc int eof".to_string()));
    }
    let first = data[*idx];
    *idx += 1;
    match first {
        0xfb => Ok(0),
        0xfc => {
            if *idx + 2 > data.len() {
                return Err(CoreError::Parse("mysql lenenc int".to_string()));
            }
            let value = u16::from_le_bytes([data[*idx], data[*idx + 1]]) as u64;
            *idx += 2;
            Ok(value)
        }
        0xfd => {
            if *idx + 3 > data.len() {
                return Err(CoreError::Parse("mysql lenenc int".to_string()));
            }
            let value = (data[*idx] as u64) | ((data[*idx + 1] as u64) << 8) | ((data[*idx + 2] as u64) << 16);
            *idx += 3;
            Ok(value)
        }
        0xfe => {
            if *idx + 8 > data.len() {
                return Err(CoreError::Parse("mysql lenenc int".to_string()));
            }
            let value = u64::from_le_bytes(data[*idx..*idx + 8].try_into().unwrap());
            *idx += 8;
            Ok(value)
        }
        value => Ok(value as u64),
    }
}

fn encode_lenenc_string(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            encode_lenenc_int(out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        None => out.push(0xfb),
    }
}

fn decode_lenenc_string(data: &[u8], idx: &mut usize) -> CoreResult<Option<Vec<u8>>> {
    if *idx >= data.len() {
        return Err(CoreError::Parse("mysql lenenc string eof".to_string()));
    }
    let first = data[*idx];
    if first == 0xfb {
        *idx += 1;
        return Ok(None);
    }
    let len = decode_lenenc_int(data, idx)? as usize;
    if *idx + len > data.len() {
        return Err(CoreError::Parse("mysql lenenc string".to_string()));
    }
    let value = data[*idx..*idx + len].to_vec();
    *idx += len;
    Ok(Some(value))
}

fn read_null_terminated(data: &[u8], idx: &mut usize) -> CoreResult<String> {
    let start = *idx;
    while *idx < data.len() {
        if data[*idx] == 0 {
            let value = String::from_utf8_lossy(&data[start..*idx]).to_string();
            *idx += 1;
            return Ok(value);
        }
        *idx += 1;
    }
    Err(CoreError::Parse("mysql null terminated".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::fuzz_bytes;

    #[test]
    fn mysql_query_roundtrip() {
        let mut users = HashMap::new();
        users.insert("root".to_string(), "moonlight".to_string());
        let server = crate::skip_if_perm!(MysqlServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            MysqlServerConfig {
                users,
                ..MysqlServerConfig::default()
            },
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = MysqlClient::connect(
            &net::NetAddr::from_socket(addr),
            MysqlClientConfig::default(),
        )
        .unwrap();
        let result = client.query("SELECT 1").unwrap();
        assert_eq!(result.columns.len(), 1);
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn mysql_decode_negative() {
        assert!(MysqlHandshake::decode(&[]).is_err());
        assert!(MysqlHandshakeResponse::decode(&[]).is_err());
    }

    #[test]
    fn mysql_decode_fuzz() {
        fuzz_bytes(128, 512, 0x4D59, |data| {
            let _ = MysqlHandshake::decode(data);
            let _ = MysqlHandshakeResponse::decode(data);
            let mut idx = 0usize;
            let _ = decode_lenenc_int(data, &mut idx);
            idx = 0;
            let _ = decode_lenenc_string(data, &mut idx);
        });
    }
}
