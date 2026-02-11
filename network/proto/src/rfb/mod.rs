use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

pub const RFB_DEFAULT_PORT: u16 = 5900;
const RFB_VERSION_3_8: &str = "RFB 003.008\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfbSecurityType {
    None = 1,
    VncAuth = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfbPixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: u8,
    pub true_color: u8,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl Default for RfbPixelFormat {
    fn default() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: 0,
            true_color: 1,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }
}

impl RfbPixelFormat {
    pub fn encode(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0] = self.bits_per_pixel;
        out[1] = self.depth;
        out[2] = self.big_endian;
        out[3] = self.true_color;
        out[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        out[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        out[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        out[10] = self.red_shift;
        out[11] = self.green_shift;
        out[12] = self.blue_shift;
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 16 {
            return Err(CoreError::Parse("rfb pixel format".to_string()));
        }
        Ok(Self {
            bits_per_pixel: data[0],
            depth: data[1],
            big_endian: data[2],
            true_color: data[3],
            red_max: u16::from_be_bytes([data[4], data[5]]),
            green_max: u16::from_be_bytes([data[6], data[7]]),
            blue_max: u16::from_be_bytes([data[8], data[9]]),
            red_shift: data[10],
            green_shift: data[11],
            blue_shift: data[12],
        })
    }
}

#[derive(Debug, Clone)]
pub struct RfbServerInit {
    pub width: u16,
    pub height: u16,
    pub pixel_format: RfbPixelFormat,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct RfbServerConfig {
    pub timeouts: Timeouts,
    pub width: u16,
    pub height: u16,
    pub name: String,
    pub pixel_format: RfbPixelFormat,
    pub security: Vec<RfbSecurityType>,
}

impl Default for RfbServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            width: 1024,
            height: 768,
            name: "Moonlight RFB".to_string(),
            pixel_format: RfbPixelFormat::default(),
            security: vec![RfbSecurityType::None],
        }
    }
}

#[derive(Debug, Clone)]
pub struct RfbClientConfig {
    pub timeouts: Timeouts,
    pub shared: bool,
}

impl Default for RfbClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            shared: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RfbClientState {
    pub server_init: RfbServerInit,
}

pub struct RfbClient {
    transport: TcpTransport,
    pub state: RfbClientState,
}

impl RfbClient {
    pub fn connect(addr: &net::NetAddr, config: RfbClientConfig) -> CoreResult<Self> {
        let mut transport = TcpTransport::connect(addr, config.timeouts)?;
        let mut version = [0u8; 12];
        transport.read_exact(&mut version)?;
        let version_str = String::from_utf8_lossy(&version).to_string();
        if !version_str.starts_with("RFB") {
            return Err(CoreError::Parse("rfb version".to_string()));
        }
        transport.write_all(RFB_VERSION_3_8.as_bytes())?;

        let mut count = [0u8; 1];
        transport.read_exact(&mut count)?;
        let count = count[0] as usize;
        if count == 0 {
            let mut len_buf = [0u8; 4];
            transport.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut reason = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut reason)?;
            }
            return Err(CoreError::Message(
                String::from_utf8_lossy(&reason).to_string(),
            ));
        }
        let mut types = vec![0u8; count];
        transport.read_exact(&mut types)?;
        if !types.contains(&(RfbSecurityType::None as u8)) {
            return Err(CoreError::Message("rfb no supported security".to_string()));
        }
        transport.write_all(&[RfbSecurityType::None as u8])?;
        let mut status = [0u8; 4];
        transport.read_exact(&mut status)?;
        if u32::from_be_bytes(status) != 0 {
            let mut len_buf = [0u8; 4];
            transport.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut reason = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut reason)?;
            }
            return Err(CoreError::Message(
                String::from_utf8_lossy(&reason).to_string(),
            ));
        }

        transport.write_all(&[if config.shared { 1 } else { 0 }])?;
        let server_init = read_server_init(&mut transport)?;
        Ok(Self {
            transport,
            state: RfbClientState { server_init },
        })
    }

    pub fn framebuffer_update_request(
        &mut self,
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> CoreResult<()> {
        let mut msg = Vec::with_capacity(10);
        msg.push(3);
        msg.push(if incremental { 1 } else { 0 });
        msg.extend_from_slice(&x.to_be_bytes());
        msg.extend_from_slice(&y.to_be_bytes());
        msg.extend_from_slice(&width.to_be_bytes());
        msg.extend_from_slice(&height.to_be_bytes());
        self.transport.write_all(&msg)
    }

    pub fn read_message(&mut self) -> CoreResult<RfbServerMessage> {
        read_server_message(&mut self.transport)
    }
}

pub struct AsyncRfbClient {
    transport: AsyncTcpTransport,
    pub state: RfbClientState,
}

impl AsyncRfbClient {
    pub async fn connect(addr: &net::NetAddr, config: RfbClientConfig) -> CoreResult<Self> {
        let mut transport = AsyncTcpTransport::connect(addr, config.timeouts).await?;
        let mut version = [0u8; 12];
        transport.read_exact(&mut version).await?;
        let version_str = String::from_utf8_lossy(&version).to_string();
        if !version_str.starts_with("RFB") {
            return Err(CoreError::Parse("rfb version".to_string()));
        }
        transport.write_all(RFB_VERSION_3_8.as_bytes()).await?;

        let mut count = [0u8; 1];
        transport.read_exact(&mut count).await?;
        let count = count[0] as usize;
        if count == 0 {
            let mut len_buf = [0u8; 4];
            transport.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut reason = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut reason).await?;
            }
            return Err(CoreError::Message(
                String::from_utf8_lossy(&reason).to_string(),
            ));
        }
        let mut types = vec![0u8; count];
        transport.read_exact(&mut types).await?;
        if !types.contains(&(RfbSecurityType::None as u8)) {
            return Err(CoreError::Message("rfb no supported security".to_string()));
        }
        transport.write_all(&[RfbSecurityType::None as u8]).await?;
        let mut status = [0u8; 4];
        transport.read_exact(&mut status).await?;
        if u32::from_be_bytes(status) != 0 {
            let mut len_buf = [0u8; 4];
            transport.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut reason = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut reason).await?;
            }
            return Err(CoreError::Message(
                String::from_utf8_lossy(&reason).to_string(),
            ));
        }

        transport
            .write_all(&[if config.shared { 1 } else { 0 }])
            .await?;
        let server_init = read_server_init_async(&mut transport).await?;
        Ok(Self {
            transport,
            state: RfbClientState { server_init },
        })
    }

    pub async fn framebuffer_update_request(
        &mut self,
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> CoreResult<()> {
        let mut msg = Vec::with_capacity(10);
        msg.push(3);
        msg.push(if incremental { 1 } else { 0 });
        msg.extend_from_slice(&x.to_be_bytes());
        msg.extend_from_slice(&y.to_be_bytes());
        msg.extend_from_slice(&width.to_be_bytes());
        msg.extend_from_slice(&height.to_be_bytes());
        self.transport.write_all(&msg).await
    }

    pub async fn read_message(&mut self) -> CoreResult<RfbServerMessage> {
        read_server_message_async(&mut self.transport).await
    }
}

pub struct RfbServer {
    listener: TcpListener,
    config: RfbServerConfig,
}

impl RfbServer {
    pub fn bind(addr: SocketAddr, config: RfbServerConfig) -> CoreResult<Self> {
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
                let _ = handle_rfb_stream(stream, config);
            });
        }
        Ok(())
    }
}

pub struct AsyncRfbServer {
    listener: tokio::net::TcpListener,
    config: RfbServerConfig,
}

impl AsyncRfbServer {
    pub async fn bind(addr: SocketAddr, config: RfbServerConfig) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self { listener, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let config = self.config.clone();
            tokio::spawn(async move {
                let _ = handle_rfb_stream_async(stream, config).await;
            });
        }
    }
}

#[derive(Debug, Clone)]
pub enum RfbClientMessage {
    SetPixelFormat(RfbPixelFormat),
    SetEncodings(Vec<i32>),
    FramebufferUpdateRequest {
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    },
    KeyEvent {
        down: bool,
        key: u32,
    },
    PointerEvent {
        button_mask: u8,
        x: u16,
        y: u16,
    },
    ClientCutText(String),
    Unknown(u8, Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct RfbRectangle {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub encoding: i32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum RfbServerMessage {
    FramebufferUpdate(Vec<RfbRectangle>),
    Bell,
    ServerCutText(String),
    Unknown(u8, Vec<u8>),
}

fn handle_rfb_stream(stream: TcpStream, config: RfbServerConfig) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, config.timeouts)?;
    transport.write_all(RFB_VERSION_3_8.as_bytes())?;
    let mut version = [0u8; 12];
    transport.read_exact(&mut version)?;
    if &version[..3] != b"RFB" {
        return Err(CoreError::Parse("rfb client version".to_string()));
    }

    let security = if config.security.is_empty() {
        vec![RfbSecurityType::None]
    } else {
        config.security.clone()
    };
    transport.write_all(&[security.len() as u8])?;
    let types: Vec<u8> = security.iter().map(|t| *t as u8).collect();
    transport.write_all(&types)?;
    let mut selected = [0u8; 1];
    transport.read_exact(&mut selected)?;
    if selected[0] != RfbSecurityType::None as u8 {
        transport.write_all(&1u32.to_be_bytes())?;
        let reason = b"unsupported security";
        transport.write_all(&(reason.len() as u32).to_be_bytes())?;
        transport.write_all(reason)?;
        return Ok(());
    }
    transport.write_all(&0u32.to_be_bytes())?;

    let mut client_init = [0u8; 1];
    transport.read_exact(&mut client_init)?;
    let _ = client_init;

    let server_init = RfbServerInit {
        width: config.width,
        height: config.height,
        pixel_format: config.pixel_format,
        name: config.name.clone(),
    };
    write_server_init(&mut transport, &server_init)?;

    loop {
        let message = match read_client_message(&mut transport) {
            Ok(msg) => msg,
            Err(_) => break,
        };
        match message {
            RfbClientMessage::FramebufferUpdateRequest { .. } => {
                let response = build_framebuffer_update(Vec::new());
                transport.write_all(&response)?;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn handle_rfb_stream_async(
    stream: tokio::net::TcpStream,
    config: RfbServerConfig,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    transport.write_all(RFB_VERSION_3_8.as_bytes()).await?;
    let mut version = [0u8; 12];
    transport.read_exact(&mut version).await?;
    if &version[..3] != b"RFB" {
        return Err(CoreError::Parse("rfb client version".to_string()));
    }

    let security = if config.security.is_empty() {
        vec![RfbSecurityType::None]
    } else {
        config.security.clone()
    };
    transport.write_all(&[security.len() as u8]).await?;
    let types: Vec<u8> = security.iter().map(|t| *t as u8).collect();
    transport.write_all(&types).await?;
    let mut selected = [0u8; 1];
    transport.read_exact(&mut selected).await?;
    if selected[0] != RfbSecurityType::None as u8 {
        transport.write_all(&1u32.to_be_bytes()).await?;
        let reason = b"unsupported security";
        transport
            .write_all(&(reason.len() as u32).to_be_bytes())
            .await?;
        transport.write_all(reason).await?;
        return Ok(());
    }
    transport.write_all(&0u32.to_be_bytes()).await?;

    let mut client_init = [0u8; 1];
    transport.read_exact(&mut client_init).await?;
    let _ = client_init;

    let server_init = RfbServerInit {
        width: config.width,
        height: config.height,
        pixel_format: config.pixel_format,
        name: config.name.clone(),
    };
    write_server_init_async(&mut transport, &server_init).await?;

    loop {
        let message = match read_client_message_async(&mut transport).await {
            Ok(msg) => msg,
            Err(_) => break,
        };
        match message {
            RfbClientMessage::FramebufferUpdateRequest { .. } => {
                let response = build_framebuffer_update(Vec::new());
                transport.write_all(&response).await?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn write_server_init<T: StreamTransport>(
    transport: &mut T,
    init: &RfbServerInit,
) -> CoreResult<()> {
    let mut out = Vec::new();
    out.extend_from_slice(&init.width.to_be_bytes());
    out.extend_from_slice(&init.height.to_be_bytes());
    out.extend_from_slice(&init.pixel_format.encode());
    out.extend_from_slice(&(init.name.len() as u32).to_be_bytes());
    out.extend_from_slice(init.name.as_bytes());
    transport.write_all(&out)
}

async fn write_server_init_async<T: AsyncStreamTransport>(
    transport: &mut T,
    init: &RfbServerInit,
) -> CoreResult<()> {
    let mut out = Vec::new();
    out.extend_from_slice(&init.width.to_be_bytes());
    out.extend_from_slice(&init.height.to_be_bytes());
    out.extend_from_slice(&init.pixel_format.encode());
    out.extend_from_slice(&(init.name.len() as u32).to_be_bytes());
    out.extend_from_slice(init.name.as_bytes());
    transport.write_all(&out).await
}

fn read_server_init<T: StreamTransport>(transport: &mut T) -> CoreResult<RfbServerInit> {
    let mut header = [0u8; 24];
    transport.read_exact(&mut header)?;
    let width = u16::from_be_bytes([header[0], header[1]]);
    let height = u16::from_be_bytes([header[2], header[3]]);
    let pixel_format = RfbPixelFormat::decode(&header[4..20])?;
    let name_len = u32::from_be_bytes([header[20], header[21], header[22], header[23]]) as usize;
    let mut name = vec![0u8; name_len];
    if name_len > 0 {
        transport.read_exact(&mut name)?;
    }
    Ok(RfbServerInit {
        width,
        height,
        pixel_format,
        name: String::from_utf8_lossy(&name).to_string(),
    })
}

async fn read_server_init_async<T: AsyncStreamTransport>(
    transport: &mut T,
) -> CoreResult<RfbServerInit> {
    let mut header = [0u8; 24];
    transport.read_exact(&mut header).await?;
    let width = u16::from_be_bytes([header[0], header[1]]);
    let height = u16::from_be_bytes([header[2], header[3]]);
    let pixel_format = RfbPixelFormat::decode(&header[4..20])?;
    let name_len = u32::from_be_bytes([header[20], header[21], header[22], header[23]]) as usize;
    let mut name = vec![0u8; name_len];
    if name_len > 0 {
        transport.read_exact(&mut name).await?;
    }
    Ok(RfbServerInit {
        width,
        height,
        pixel_format,
        name: String::from_utf8_lossy(&name).to_string(),
    })
}

fn read_client_message<T: StreamTransport>(transport: &mut T) -> CoreResult<RfbClientMessage> {
    let mut msg_type = [0u8; 1];
    transport.read_exact(&mut msg_type)?;
    match msg_type[0] {
        0 => {
            let mut pad = [0u8; 3];
            transport.read_exact(&mut pad)?;
            let mut fmt = [0u8; 16];
            transport.read_exact(&mut fmt)?;
            Ok(RfbClientMessage::SetPixelFormat(RfbPixelFormat::decode(
                &fmt,
            )?))
        }
        2 => {
            let mut pad = [0u8; 1];
            transport.read_exact(&mut pad)?;
            let mut count = [0u8; 2];
            transport.read_exact(&mut count)?;
            let count = u16::from_be_bytes(count) as usize;
            let mut encodings = Vec::with_capacity(count);
            for _ in 0..count {
                let mut val = [0u8; 4];
                transport.read_exact(&mut val)?;
                encodings.push(i32::from_be_bytes(val));
            }
            Ok(RfbClientMessage::SetEncodings(encodings))
        }
        3 => {
            let mut buf = [0u8; 9];
            transport.read_exact(&mut buf)?;
            Ok(RfbClientMessage::FramebufferUpdateRequest {
                incremental: buf[0] != 0,
                x: u16::from_be_bytes([buf[1], buf[2]]),
                y: u16::from_be_bytes([buf[3], buf[4]]),
                width: u16::from_be_bytes([buf[5], buf[6]]),
                height: u16::from_be_bytes([buf[7], buf[8]]),
            })
        }
        4 => {
            let mut buf = [0u8; 7];
            transport.read_exact(&mut buf)?;
            let key = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);
            Ok(RfbClientMessage::KeyEvent {
                down: buf[0] != 0,
                key,
            })
        }
        5 => {
            let mut buf = [0u8; 5];
            transport.read_exact(&mut buf)?;
            Ok(RfbClientMessage::PointerEvent {
                button_mask: buf[0],
                x: u16::from_be_bytes([buf[1], buf[2]]),
                y: u16::from_be_bytes([buf[3], buf[4]]),
            })
        }
        6 => {
            let mut pad = [0u8; 3];
            transport.read_exact(&mut pad)?;
            let mut len = [0u8; 4];
            transport.read_exact(&mut len)?;
            let len = u32::from_be_bytes(len) as usize;
            let mut text = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut text)?;
            }
            Ok(RfbClientMessage::ClientCutText(
                String::from_utf8_lossy(&text).to_string(),
            ))
        }
        other => Ok(RfbClientMessage::Unknown(other, Vec::new())),
    }
}

async fn read_client_message_async<T: AsyncStreamTransport>(
    transport: &mut T,
) -> CoreResult<RfbClientMessage> {
    let mut msg_type = [0u8; 1];
    transport.read_exact(&mut msg_type).await?;
    match msg_type[0] {
        0 => {
            let mut pad = [0u8; 3];
            transport.read_exact(&mut pad).await?;
            let mut fmt = [0u8; 16];
            transport.read_exact(&mut fmt).await?;
            Ok(RfbClientMessage::SetPixelFormat(RfbPixelFormat::decode(
                &fmt,
            )?))
        }
        2 => {
            let mut pad = [0u8; 1];
            transport.read_exact(&mut pad).await?;
            let mut count = [0u8; 2];
            transport.read_exact(&mut count).await?;
            let count = u16::from_be_bytes(count) as usize;
            let mut encodings = Vec::with_capacity(count);
            for _ in 0..count {
                let mut val = [0u8; 4];
                transport.read_exact(&mut val).await?;
                encodings.push(i32::from_be_bytes(val));
            }
            Ok(RfbClientMessage::SetEncodings(encodings))
        }
        3 => {
            let mut buf = [0u8; 9];
            transport.read_exact(&mut buf).await?;
            Ok(RfbClientMessage::FramebufferUpdateRequest {
                incremental: buf[0] != 0,
                x: u16::from_be_bytes([buf[1], buf[2]]),
                y: u16::from_be_bytes([buf[3], buf[4]]),
                width: u16::from_be_bytes([buf[5], buf[6]]),
                height: u16::from_be_bytes([buf[7], buf[8]]),
            })
        }
        4 => {
            let mut buf = [0u8; 7];
            transport.read_exact(&mut buf).await?;
            let key = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);
            Ok(RfbClientMessage::KeyEvent {
                down: buf[0] != 0,
                key,
            })
        }
        5 => {
            let mut buf = [0u8; 5];
            transport.read_exact(&mut buf).await?;
            Ok(RfbClientMessage::PointerEvent {
                button_mask: buf[0],
                x: u16::from_be_bytes([buf[1], buf[2]]),
                y: u16::from_be_bytes([buf[3], buf[4]]),
            })
        }
        6 => {
            let mut pad = [0u8; 3];
            transport.read_exact(&mut pad).await?;
            let mut len = [0u8; 4];
            transport.read_exact(&mut len).await?;
            let len = u32::from_be_bytes(len) as usize;
            let mut text = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut text).await?;
            }
            Ok(RfbClientMessage::ClientCutText(
                String::from_utf8_lossy(&text).to_string(),
            ))
        }
        other => Ok(RfbClientMessage::Unknown(other, Vec::new())),
    }
}

fn read_server_message<T: StreamTransport>(transport: &mut T) -> CoreResult<RfbServerMessage> {
    let mut msg_type = [0u8; 1];
    transport.read_exact(&mut msg_type)?;
    match msg_type[0] {
        0 => {
            let mut pad = [0u8; 1];
            transport.read_exact(&mut pad)?;
            let mut count = [0u8; 2];
            transport.read_exact(&mut count)?;
            let count = u16::from_be_bytes(count) as usize;
            let mut rects = Vec::with_capacity(count);
            for _ in 0..count {
                let mut header = [0u8; 12];
                transport.read_exact(&mut header)?;
                let x = u16::from_be_bytes([header[0], header[1]]);
                let y = u16::from_be_bytes([header[2], header[3]]);
                let width = u16::from_be_bytes([header[4], header[5]]);
                let height = u16::from_be_bytes([header[6], header[7]]);
                let encoding = i32::from_be_bytes([header[8], header[9], header[10], header[11]]);
                let data_len = if encoding == 0 {
                    (width as usize) * (height as usize) * 4
                } else {
                    return Err(CoreError::Parse("rfb unsupported encoding".to_string()));
                };
                let mut data = vec![0u8; data_len];
                if data_len > 0 {
                    transport.read_exact(&mut data)?;
                }
                rects.push(RfbRectangle {
                    x,
                    y,
                    width,
                    height,
                    encoding,
                    data,
                });
            }
            Ok(RfbServerMessage::FramebufferUpdate(rects))
        }
        2 => Ok(RfbServerMessage::Bell),
        3 => {
            let mut pad = [0u8; 3];
            transport.read_exact(&mut pad)?;
            let mut len = [0u8; 4];
            transport.read_exact(&mut len)?;
            let len = u32::from_be_bytes(len) as usize;
            let mut text = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut text)?;
            }
            Ok(RfbServerMessage::ServerCutText(
                String::from_utf8_lossy(&text).to_string(),
            ))
        }
        other => Ok(RfbServerMessage::Unknown(other, Vec::new())),
    }
}

async fn read_server_message_async<T: AsyncStreamTransport>(
    transport: &mut T,
) -> CoreResult<RfbServerMessage> {
    let mut msg_type = [0u8; 1];
    transport.read_exact(&mut msg_type).await?;
    match msg_type[0] {
        0 => {
            let mut pad = [0u8; 1];
            transport.read_exact(&mut pad).await?;
            let mut count = [0u8; 2];
            transport.read_exact(&mut count).await?;
            let count = u16::from_be_bytes(count) as usize;
            let mut rects = Vec::with_capacity(count);
            for _ in 0..count {
                let mut header = [0u8; 12];
                transport.read_exact(&mut header).await?;
                let x = u16::from_be_bytes([header[0], header[1]]);
                let y = u16::from_be_bytes([header[2], header[3]]);
                let width = u16::from_be_bytes([header[4], header[5]]);
                let height = u16::from_be_bytes([header[6], header[7]]);
                let encoding = i32::from_be_bytes([header[8], header[9], header[10], header[11]]);
                let data_len = if encoding == 0 {
                    (width as usize) * (height as usize) * 4
                } else {
                    return Err(CoreError::Parse("rfb unsupported encoding".to_string()));
                };
                let mut data = vec![0u8; data_len];
                if data_len > 0 {
                    transport.read_exact(&mut data).await?;
                }
                rects.push(RfbRectangle {
                    x,
                    y,
                    width,
                    height,
                    encoding,
                    data,
                });
            }
            Ok(RfbServerMessage::FramebufferUpdate(rects))
        }
        2 => Ok(RfbServerMessage::Bell),
        3 => {
            let mut pad = [0u8; 3];
            transport.read_exact(&mut pad).await?;
            let mut len = [0u8; 4];
            transport.read_exact(&mut len).await?;
            let len = u32::from_be_bytes(len) as usize;
            let mut text = vec![0u8; len];
            if len > 0 {
                transport.read_exact(&mut text).await?;
            }
            Ok(RfbServerMessage::ServerCutText(
                String::from_utf8_lossy(&text).to_string(),
            ))
        }
        other => Ok(RfbServerMessage::Unknown(other, Vec::new())),
    }
}

fn build_framebuffer_update(rects: Vec<RfbRectangle>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0);
    out.push(0);
    out.extend_from_slice(&(rects.len() as u16).to_be_bytes());
    for rect in rects {
        out.extend_from_slice(&rect.x.to_be_bytes());
        out.extend_from_slice(&rect.y.to_be_bytes());
        out.extend_from_slice(&rect.width.to_be_bytes());
        out.extend_from_slice(&rect.height.to_be_bytes());
        out.extend_from_slice(&rect.encoding.to_be_bytes());
        out.extend_from_slice(&rect.data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfb_handshake_update() {
        let server = crate::skip_if_perm!(RfbServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            RfbServerConfig::default(),
        ));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client =
            RfbClient::connect(&net::NetAddr::from_socket(addr), RfbClientConfig::default())
                .unwrap();
        client
            .framebuffer_update_request(true, 0, 0, 10, 10)
            .unwrap();
        let msg = client.read_message().unwrap();
        match msg {
            RfbServerMessage::FramebufferUpdate(rects) => {
                assert!(rects.is_empty());
            }
            _ => panic!("unexpected message"),
        }
    }
}
