use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

const HEADER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
const A2S_INFO: u8 = 0x54;
const A2S_PLAYER: u8 = 0x55;
const A2S_RULES: u8 = 0x56;

const S2A_INFO: u8 = 0x49;
const S2A_PLAYER: u8 = 0x44;
const S2A_RULES: u8 = 0x45;
const S2A_CHALLENGE: u8 = 0x41;

#[derive(Debug, Clone)]
pub struct SteamServerInfo {
    pub protocol: u8,
    pub name: String,
    pub map: String,
    pub folder: String,
    pub game: String,
    pub app_id: u16,
    pub players: u8,
    pub max_players: u8,
    pub bots: u8,
    pub server_type: char,
    pub environment: char,
    pub visibility: u8,
    pub vac: u8,
    pub version: String,
}

impl Default for SteamServerInfo {
    fn default() -> Self {
        Self {
            protocol: 17,
            name: "Moonlight Server".to_string(),
            map: "moonlight".to_string(),
            folder: "moonlight".to_string(),
            game: "Moonlight".to_string(),
            app_id: 0,
            players: 0,
            max_players: 32,
            bots: 0,
            server_type: 'd',
            environment: 'l',
            visibility: 0,
            vac: 0,
            version: "0.1".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SteamPlayer {
    pub name: String,
    pub score: i32,
    pub duration: f32,
}

#[derive(Debug, Clone)]
pub struct SteamServerConfig {
    pub timeouts: Timeouts,
    pub info: SteamServerInfo,
    pub players: Vec<SteamPlayer>,
    pub rules: HashMap<String, String>,
}

impl Default for SteamServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            info: SteamServerInfo::default(),
            players: Vec::new(),
            rules: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct SteamState {
    info: SteamServerInfo,
    players: Vec<SteamPlayer>,
    rules: HashMap<String, String>,
    challenges: HashMap<SocketAddr, i32>,
    next_challenge: u32,
}

impl SteamState {
    fn new(config: SteamServerConfig) -> Self {
        Self {
            info: config.info,
            players: config.players,
            rules: config.rules,
            challenges: HashMap::new(),
            next_challenge: 0x12345678,
        }
    }

    fn issue_challenge(&mut self, addr: SocketAddr) -> i32 {
        let value = self.next_challenge;
        self.next_challenge = self.next_challenge.wrapping_add(0x1020304);
        let signed = value as i32;
        self.challenges.insert(addr, signed);
        signed
    }

    fn validate_challenge(&self, addr: SocketAddr, value: i32) -> bool {
        self.challenges.get(&addr).copied() == Some(value)
    }
}

pub struct SteamServer {
    socket: UdpTransport,
    state: Arc<Mutex<SteamState>>,
}

impl SteamServer {
    pub fn bind(addr: SocketAddr, config: SteamServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            state: Arc::new(Mutex::new(SteamState::new(config))),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(1500)?;
            let state = Arc::clone(&self.state);
            let socket = self.socket.clone();
            thread::spawn(move || {
                let _ = handle_request(socket, state, data, addr);
            });
        }
    }
}

pub struct AsyncSteamServer {
    socket: AsyncUdpTransport,
    state: Arc<Mutex<SteamState>>,
}

impl AsyncSteamServer {
    pub async fn bind(addr: SocketAddr, config: SteamServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self {
            socket,
            state: Arc::new(Mutex::new(SteamState::new(config))),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(1500).await?;
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_request_async(socket, state, data, addr).await;
            });
        }
    }
}

pub struct SteamClientConfig {
    pub timeouts: Timeouts,
}

impl Default for SteamClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct SteamClient {
    socket: UdpTransport,
}

impl SteamClient {
    pub fn new(config: SteamClientConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket })
    }

    pub fn info(&self, addr: SocketAddr) -> CoreResult<SteamServerInfo> {
        let request = build_info_request();
        self.socket.send_to(&request, addr)?;
        let (data, _) = self.socket.recv_from(1500)?;
        parse_info_response(&data)
    }

    pub fn players(&self, addr: SocketAddr) -> CoreResult<Vec<SteamPlayer>> {
        let mut challenge = -1i32;
        loop {
            let request = build_challenge_request(A2S_PLAYER, challenge);
            self.socket.send_to(&request, addr)?;
            let (data, _) = self.socket.recv_from(1500)?;
            match parse_challenge(&data) {
                Some(value) => {
                    challenge = value;
                    continue;
                }
                None => return parse_player_response(&data),
            }
        }
    }

    pub fn rules(&self, addr: SocketAddr) -> CoreResult<HashMap<String, String>> {
        let mut challenge = -1i32;
        loop {
            let request = build_challenge_request(A2S_RULES, challenge);
            self.socket.send_to(&request, addr)?;
            let (data, _) = self.socket.recv_from(1500)?;
            match parse_challenge(&data) {
                Some(value) => {
                    challenge = value;
                    continue;
                }
                None => return parse_rules_response(&data),
            }
        }
    }
}

pub struct AsyncSteamClient {
    socket: AsyncUdpTransport,
}

impl AsyncSteamClient {
    pub async fn new(_config: SteamClientConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self { socket })
    }

    pub async fn info(&self, addr: SocketAddr) -> CoreResult<SteamServerInfo> {
        let request = build_info_request();
        self.socket.send_to(&request, addr).await?;
        let (data, _) = self.socket.recv_from(1500).await?;
        parse_info_response(&data)
    }

    pub async fn players(&self, addr: SocketAddr) -> CoreResult<Vec<SteamPlayer>> {
        let mut challenge = -1i32;
        loop {
            let request = build_challenge_request(A2S_PLAYER, challenge);
            self.socket.send_to(&request, addr).await?;
            let (data, _) = self.socket.recv_from(1500).await?;
            match parse_challenge(&data) {
                Some(value) => {
                    challenge = value;
                    continue;
                }
                None => return parse_player_response(&data),
            }
        }
    }

    pub async fn rules(&self, addr: SocketAddr) -> CoreResult<HashMap<String, String>> {
        let mut challenge = -1i32;
        loop {
            let request = build_challenge_request(A2S_RULES, challenge);
            self.socket.send_to(&request, addr).await?;
            let (data, _) = self.socket.recv_from(1500).await?;
            match parse_challenge(&data) {
                Some(value) => {
                    challenge = value;
                    continue;
                }
                None => return parse_rules_response(&data),
            }
        }
    }
}

fn build_info_request() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER);
    out.push(A2S_INFO);
    out.extend_from_slice(b"TSource Engine Query\0");
    out
}

fn build_challenge_request(op: u8, challenge: i32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER);
    out.push(op);
    out.extend_from_slice(&challenge.to_le_bytes());
    out
}

fn parse_challenge(data: &[u8]) -> Option<i32> {
    if data.len() < 9 || data[0..4] != HEADER || data[4] != S2A_CHALLENGE {
        return None;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[5..9]);
    Some(i32::from_le_bytes(buf))
}

fn parse_info_response(data: &[u8]) -> CoreResult<SteamServerInfo> {
    let mut cursor = Cursor::new(data);
    cursor.expect_header()?;
    let kind = cursor.read_u8()?;
    if kind != S2A_INFO {
        return Err(CoreError::Parse("invalid info response".to_string()));
    }
    let protocol = cursor.read_u8()?;
    let name = cursor.read_cstring()?;
    let map = cursor.read_cstring()?;
    let folder = cursor.read_cstring()?;
    let game = cursor.read_cstring()?;
    let app_id = cursor.read_u16_le()?;
    let players = cursor.read_u8()?;
    let max_players = cursor.read_u8()?;
    let bots = cursor.read_u8()?;
    let server_type = cursor.read_u8()? as char;
    let environment = cursor.read_u8()? as char;
    let visibility = cursor.read_u8()?;
    let vac = cursor.read_u8()?;
    let version = cursor.read_cstring()?;
    Ok(SteamServerInfo {
        protocol,
        name,
        map,
        folder,
        game,
        app_id,
        players,
        max_players,
        bots,
        server_type,
        environment,
        visibility,
        vac,
        version,
    })
}

fn parse_player_response(data: &[u8]) -> CoreResult<Vec<SteamPlayer>> {
    let mut cursor = Cursor::new(data);
    cursor.expect_header()?;
    let kind = cursor.read_u8()?;
    if kind != S2A_PLAYER {
        return Err(CoreError::Parse("invalid player response".to_string()));
    }
    let count = cursor.read_u8()?;
    let mut players = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let _index = cursor.read_u8()?;
        let name = cursor.read_cstring()?;
        let score = cursor.read_i32_le()?;
        let duration = cursor.read_f32_le()?;
        players.push(SteamPlayer {
            name,
            score,
            duration,
        });
    }
    Ok(players)
}

fn parse_rules_response(data: &[u8]) -> CoreResult<HashMap<String, String>> {
    let mut cursor = Cursor::new(data);
    cursor.expect_header()?;
    let kind = cursor.read_u8()?;
    if kind != S2A_RULES {
        return Err(CoreError::Parse("invalid rules response".to_string()));
    }
    let count = cursor.read_u16_le()?;
    let mut rules = HashMap::new();
    for _ in 0..count {
        let key = cursor.read_cstring()?;
        let value = cursor.read_cstring()?;
        rules.insert(key, value);
    }
    Ok(rules)
}

fn handle_request(
    socket: UdpTransport,
    state: Arc<Mutex<SteamState>>,
    data: Vec<u8>,
    addr: SocketAddr,
) -> CoreResult<()> {
    if data.len() < 5 || data[0..4] != HEADER {
        return Ok(());
    }
    match data[4] {
        A2S_INFO => {
            let response = build_info_response(&state.lock().unwrap().info);
            socket.send_to(&response, addr)?;
        }
        A2S_PLAYER => {
            let challenge = decode_challenge(&data);
            let mut guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            if challenge == -1 || !guard.validate_challenge(addr, challenge) {
                let value = guard.issue_challenge(addr);
                let response = build_challenge_response(value);
                socket.send_to(&response, addr)?;
            } else {
                let response = build_player_response(&guard.players);
                socket.send_to(&response, addr)?;
            }
        }
        A2S_RULES => {
            let challenge = decode_challenge(&data);
            let mut guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
            if challenge == -1 || !guard.validate_challenge(addr, challenge) {
                let value = guard.issue_challenge(addr);
                let response = build_challenge_response(value);
                socket.send_to(&response, addr)?;
            } else {
                let response = build_rules_response(&guard.rules);
                socket.send_to(&response, addr)?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_request_async(
    socket: AsyncUdpTransport,
    state: Arc<Mutex<SteamState>>,
    data: Vec<u8>,
    addr: SocketAddr,
) -> CoreResult<()> {
    if data.len() < 5 || data[0..4] != HEADER {
        return Ok(());
    }
    match data[4] {
        A2S_INFO => {
            let response = {
                let guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
                build_info_response(&guard.info)
            };
            socket.send_to(&response, addr).await?;
        }
        A2S_PLAYER => {
            let challenge = decode_challenge(&data);
            let response = {
                let mut guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
                if challenge == -1 || !guard.validate_challenge(addr, challenge) {
                    let value = guard.issue_challenge(addr);
                    build_challenge_response(value)
                } else {
                    build_player_response(&guard.players)
                }
            };
            socket.send_to(&response, addr).await?;
        }
        A2S_RULES => {
            let challenge = decode_challenge(&data);
            let response = {
                let mut guard = state.lock().map_err(|_| CoreError::Message("state poisoned".to_string()))?;
                if challenge == -1 || !guard.validate_challenge(addr, challenge) {
                    let value = guard.issue_challenge(addr);
                    build_challenge_response(value)
                } else {
                    build_rules_response(&guard.rules)
                }
            };
            socket.send_to(&response, addr).await?;
        }
        _ => {}
    }
    Ok(())
}

fn build_info_response(info: &SteamServerInfo) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER);
    out.push(S2A_INFO);
    out.push(info.protocol);
    write_cstring(&mut out, &info.name);
    write_cstring(&mut out, &info.map);
    write_cstring(&mut out, &info.folder);
    write_cstring(&mut out, &info.game);
    out.extend_from_slice(&info.app_id.to_le_bytes());
    out.push(info.players);
    out.push(info.max_players);
    out.push(info.bots);
    out.push(info.server_type as u8);
    out.push(info.environment as u8);
    out.push(info.visibility);
    out.push(info.vac);
    write_cstring(&mut out, &info.version);
    out.push(0);
    out
}

fn build_challenge_response(challenge: i32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER);
    out.push(S2A_CHALLENGE);
    out.extend_from_slice(&challenge.to_le_bytes());
    out
}

fn build_player_response(players: &[SteamPlayer]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER);
    out.push(S2A_PLAYER);
    out.push(players.len() as u8);
    for (idx, player) in players.iter().enumerate() {
        out.push(idx as u8);
        write_cstring(&mut out, &player.name);
        out.extend_from_slice(&player.score.to_le_bytes());
        out.extend_from_slice(&player.duration.to_le_bytes());
    }
    out
}

fn build_rules_response(rules: &HashMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER);
    out.push(S2A_RULES);
    out.extend_from_slice(&(rules.len() as u16).to_le_bytes());
    for (key, value) in rules {
        write_cstring(&mut out, key);
        write_cstring(&mut out, value);
    }
    out
}

fn decode_challenge(data: &[u8]) -> i32 {
    if data.len() < 9 {
        return -1;
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[5..9]);
    i32::from_le_bytes(buf)
}

fn write_cstring(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn expect_header(&mut self) -> CoreResult<()> {
        if self.data.len() < 4 || self.data[0..4] != HEADER {
            return Err(CoreError::Parse("invalid header".to_string()));
        }
        self.pos = 4;
        Ok(())
    }

    fn read_u8(&mut self) -> CoreResult<u8> {
        if self.pos >= self.data.len() {
            return Err(CoreError::Parse("eof".to_string()));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_u16_le(&mut self) -> CoreResult<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(CoreError::Parse("eof".to_string()));
        }
        let out = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(out)
    }

    fn read_i32_le(&mut self) -> CoreResult<i32> {
        if self.pos + 4 > self.data.len() {
            return Err(CoreError::Parse("eof".to_string()));
        }
        let out = i32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(out)
    }

    fn read_f32_le(&mut self) -> CoreResult<f32> {
        if self.pos + 4 > self.data.len() {
            return Err(CoreError::Parse("eof".to_string()));
        }
        let out = f32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(out)
    }

    fn read_cstring(&mut self) -> CoreResult<String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err(CoreError::Parse("unterminated string".to_string()));
        }
        let out = String::from_utf8_lossy(&self.data[start..self.pos]).to_string();
        self.pos += 1;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steam_roundtrip() {
        let mut config = SteamServerConfig::default();
        config.info.name = "Test".to_string();
        config.players = vec![SteamPlayer {
            name: "alice".to_string(),
            score: 5,
            duration: 12.5,
        }];
        config.rules.insert("rule".to_string(), "value".to_string());
        let server = SteamServer::bind("127.0.0.1:0".parse().unwrap(), config).unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let client = SteamClient::new(SteamClientConfig::default()).unwrap();
        let info = client.info(addr).unwrap();
        assert_eq!(info.name, "Test");
        let players = client.players(addr).unwrap();
        assert_eq!(players.len(), 1);
        let rules = client.rules(addr).unwrap();
        assert_eq!(rules.get("rule").unwrap(), "value");
    }
}
