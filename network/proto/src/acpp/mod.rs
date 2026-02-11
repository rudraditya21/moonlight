use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};
use net::NetAddr;

use crate::transport::{AsyncStreamTransport, AsyncTcpTransport, StreamTransport, TcpTransport};
use crate::util::Timeouts;

pub const DEFAULT_PORT: u16 = 5009;
const MESSAGE_LEN: usize = 128;
const XOR_KEY: [u8; 256] = [
    14, 57, 248, 5, 196, 1, 85, 79, 12, 172, 133, 125, 134, 138, 181, 23, 62, 9, 200, 53, 244, 49,
    101, 127, 60, 156, 181, 109, 150, 154, 165, 7, 46, 25, 216, 37, 228, 33, 117, 111, 44, 140,
    165, 157, 102, 106, 85, 247, 222, 233, 40, 213, 20, 209, 133, 159, 220, 124, 85, 141, 118, 122,
    69, 231, 206, 249, 56, 197, 4, 193, 149, 143, 204, 108, 69, 189, 70, 74, 117, 215, 254, 201, 8,
    245, 52, 241, 165, 191, 252, 92, 117, 173, 86, 90, 101, 199, 238, 217, 24, 229, 36, 225, 181,
    175, 236, 76, 101, 221, 38, 42, 21, 183, 158, 169, 104, 149, 84, 145, 197, 223, 156, 60, 21,
    205, 54, 58, 5, 167, 142, 185, 120, 133, 68, 129, 213, 207, 140, 44, 5, 253, 6, 10, 53, 151,
    190, 137, 72, 181, 116, 177, 229, 255, 188, 28, 53, 237, 22, 26, 37, 135, 174, 153, 88, 165,
    100, 161, 245, 239, 172, 12, 37, 29, 230, 234, 213, 119, 94, 105, 168, 85, 148, 81, 5, 31, 92,
    252, 213, 13, 246, 250, 197, 103, 78, 121, 184, 69, 132, 65, 21, 15, 76, 236, 197, 61, 198,
    202, 245, 87, 126, 73, 136, 117, 180, 113, 37, 63, 124, 220, 245, 45, 214, 218, 229, 71, 110,
    89, 152, 101, 164, 97, 53, 47, 108, 204, 229, 93, 166, 170, 149, 55, 30, 41, 232, 21, 212, 17,
    69, 95, 28, 188, 149, 77, 182, 186, 133, 39,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub msg_type: u32,
    pub status: u32,
    pub password: String,
    pub payload: Vec<u8>,
    pub payload_size: u32,
    pub payload_checksum: u32,
    unknown1: u32,
    unknown2: [u8; 8],
    unknown3: [u8; 12],
    unknown4: [u8; 48],
}

impl Message {
    pub fn new() -> Self {
        Self {
            msg_type: 0,
            status: 0,
            password: String::new(),
            payload: Vec::new(),
            payload_size: 0,
            payload_checksum: 0,
            unknown1: 1,
            unknown2: [0u8; 8],
            unknown3: [0u8; 12],
            unknown4: [0u8; 48],
        }
    }

    pub fn login(password: &str) -> Self {
        let mut msg = Self::new();
        msg.msg_type = 20;
        msg.password = password.to_string();
        msg
    }

    pub fn successful(&self) -> bool {
        self.status == 0
    }

    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let (payload_size, payload_checksum) = compute_payload_meta(self.msg_type, &self.payload);
        let encrypted_password = encrypt_password(&self.password)?;
        let mut out = Vec::with_capacity(MESSAGE_LEN + self.payload.len());
        out.extend_from_slice(b"acpp");
        out.extend_from_slice(&self.unknown1.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&payload_checksum.to_be_bytes());
        out.extend_from_slice(&payload_size.to_be_bytes());
        out.extend_from_slice(&self.unknown2);
        out.extend_from_slice(&self.msg_type.to_be_bytes());
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&self.unknown3);
        out.extend_from_slice(&encrypted_password);
        out.extend_from_slice(&self.unknown4);
        out.extend_from_slice(&self.payload);
        let checksum = adler32(&out);
        out[8..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(out)
    }

    pub fn decode(data: &[u8], validate_checksums: bool) -> CoreResult<Self> {
        if data.len() < MESSAGE_LEN {
            return Err(CoreError::Parse("acpp message too short".to_string()));
        }
        let mut cursor = 0usize;
        let header = &data[..MESSAGE_LEN];
        if &header[0..4] != b"acpp" {
            return Err(CoreError::Parse("invalid acpp header".to_string()));
        }
        cursor += 4;
        let unknown1 = read_u32(header, &mut cursor)?;
        let read_message_checksum = read_u32(header, &mut cursor)?;
        let payload_checksum = read_u32(header, &mut cursor)?;
        let payload_size = read_u32(header, &mut cursor)?;
        let unknown2 = read_bytes::<8>(header, &mut cursor)?;
        let msg_type = read_u32(header, &mut cursor)?;
        let status = read_u32(header, &mut cursor)?;
        let unknown3 = read_bytes::<12>(header, &mut cursor)?;
        let password_raw = read_bytes::<32>(header, &mut cursor)?;
        let unknown4 = read_bytes::<48>(header, &mut cursor)?;

        let payload = if data.len() > MESSAGE_LEN {
            data[MESSAGE_LEN..].to_vec()
        } else {
            Vec::new()
        };

        if validate_checksums {
            let mut copy = data.to_vec();
            if copy.len() >= 12 {
                copy[8..12].copy_from_slice(&0u32.to_be_bytes());
            }
            let expected_msg = adler32(&copy);
            if expected_msg != read_message_checksum {
                return Err(CoreError::Parse(
                    "invalid acpp message checksum".to_string(),
                ));
            }
            if payload_size == 0xFFFFFFFF || payload.len() == payload_size as usize {
                let expected_payload = adler32(&payload);
                if expected_payload != payload_checksum {
                    return Err(CoreError::Parse(
                        "invalid acpp payload checksum".to_string(),
                    ));
                }
            }
        }

        let password = decrypt_password(&password_raw);
        Ok(Self {
            msg_type,
            status,
            password,
            payload,
            payload_size,
            payload_checksum,
            unknown1,
            unknown2,
            unknown3,
            unknown4,
        })
    }
}

pub struct Client {
    transport: TcpTransport,
}

impl Client {
    pub fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = TcpTransport::connect(addr, timeouts)?;
        Ok(Self { transport })
    }

    pub fn authenticate(&mut self, password: &str) -> CoreResult<Message> {
        let msg = Message::login(password);
        self.send(&msg)?;
        self.recv(false)
    }

    pub fn send(&mut self, message: &Message) -> CoreResult<()> {
        let bytes = message.encode()?;
        self.transport.write_all(&bytes)?;
        Ok(())
    }

    pub fn recv(&mut self, validate_checksums: bool) -> CoreResult<Message> {
        let mut header = [0u8; MESSAGE_LEN];
        self.transport.read_exact(&mut header)?;
        let payload_size = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
        let payload = if payload_size != 0 && payload_size != 0xFFFFFFFF {
            let mut buf = vec![0u8; payload_size as usize];
            self.transport.read_exact(&mut buf)?;
            buf
        } else {
            Vec::new()
        };
        let mut data = Vec::with_capacity(MESSAGE_LEN + payload.len());
        data.extend_from_slice(&header);
        data.extend_from_slice(&payload);
        Message::decode(&data, validate_checksums)
    }
}

pub struct Server {
    listener: TcpListener,
    timeouts: Timeouts,
}

impl Server {
    pub fn bind(addr: SocketAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let listener = TcpListener::bind(addr).map_err(CoreError::Io)?;
        Ok(Self { listener, timeouts })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(Message) -> Message + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        for stream in self.listener.incoming() {
            let stream = stream.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let timeouts = self.timeouts;
            thread::spawn(move || {
                let _ = handle_client(stream, timeouts, handler);
            });
        }
        Ok(())
    }
}

fn handle_client(
    stream: TcpStream,
    timeouts: Timeouts,
    handler: Arc<dyn Fn(Message) -> Message + Send + Sync>,
) -> CoreResult<()> {
    let mut transport = TcpTransport::from_stream(stream, timeouts)?;
    loop {
        let mut header = [0u8; MESSAGE_LEN];
        let read = transport.read(&mut header)?;
        if read == 0 {
            break;
        }
        if read != MESSAGE_LEN {
            return Err(CoreError::Parse("incomplete acpp header".to_string()));
        }
        let payload_size = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
        let payload = if payload_size != 0 && payload_size != 0xFFFFFFFF {
            let mut buf = vec![0u8; payload_size as usize];
            transport.read_exact(&mut buf)?;
            buf
        } else {
            Vec::new()
        };
        let mut data = Vec::with_capacity(MESSAGE_LEN + payload.len());
        data.extend_from_slice(&header);
        data.extend_from_slice(&payload);
        let request = Message::decode(&data, false)?;
        let response = (handler)(request);
        let bytes = response.encode()?;
        transport.write_all(&bytes)?;
    }
    Ok(())
}

pub struct AsyncClient {
    transport: AsyncTcpTransport,
}

impl AsyncClient {
    pub async fn connect(addr: &NetAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let transport = AsyncTcpTransport::connect(addr, timeouts).await?;
        Ok(Self { transport })
    }

    pub async fn authenticate(&mut self, password: &str) -> CoreResult<Message> {
        let msg = Message::login(password);
        self.send(&msg).await?;
        self.recv(false).await
    }

    pub async fn send(&mut self, message: &Message) -> CoreResult<()> {
        let bytes = message.encode()?;
        self.transport.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn recv(&mut self, validate_checksums: bool) -> CoreResult<Message> {
        let mut header = [0u8; MESSAGE_LEN];
        self.transport.read_exact(&mut header).await?;
        let payload_size = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
        let payload = if payload_size != 0 && payload_size != 0xFFFFFFFF {
            let mut buf = vec![0u8; payload_size as usize];
            self.transport.read_exact(&mut buf).await?;
            buf
        } else {
            Vec::new()
        };
        let mut data = Vec::with_capacity(MESSAGE_LEN + payload.len());
        data.extend_from_slice(&header);
        data.extend_from_slice(&payload);
        Message::decode(&data, validate_checksums)
    }
}

pub struct AsyncServer {
    listener: tokio::net::TcpListener,
    timeouts: Timeouts,
}

impl AsyncServer {
    pub async fn bind(addr: SocketAddr, timeouts: Timeouts) -> CoreResult<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(CoreError::Io)?;
        Ok(Self { listener, timeouts })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.listener.local_addr().map_err(CoreError::Io)
    }

    pub async fn serve<F>(&self, handler: F) -> CoreResult<()>
    where
        F: Fn(Message) -> Message + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        loop {
            let (stream, _) = self.listener.accept().await.map_err(CoreError::Io)?;
            let handler = Arc::clone(&handler);
            let timeouts = self.timeouts;
            tokio::spawn(async move {
                let _ = handle_client_async(stream, timeouts, handler).await;
            });
        }
    }
}

async fn handle_client_async(
    stream: tokio::net::TcpStream,
    timeouts: Timeouts,
    handler: Arc<dyn Fn(Message) -> Message + Send + Sync>,
) -> CoreResult<()> {
    let mut transport = AsyncTcpTransport::from_stream(stream);
    loop {
        let mut header = [0u8; MESSAGE_LEN];
        let read = tokio::time::timeout(timeouts.read, transport.read(&mut header))
            .await
            .map_err(|_| CoreError::Parse("acpp read timeout".to_string()))??;
        if read == 0 {
            break;
        }
        if read != MESSAGE_LEN {
            return Err(CoreError::Parse("incomplete acpp header".to_string()));
        }
        let payload_size = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
        let payload = if payload_size != 0 && payload_size != 0xFFFFFFFF {
            let mut buf = vec![0u8; payload_size as usize];
            tokio::time::timeout(timeouts.read, transport.read_exact(&mut buf))
                .await
                .map_err(|_| CoreError::Parse("acpp read timeout".to_string()))??;
            buf
        } else {
            Vec::new()
        };
        let mut data = Vec::with_capacity(MESSAGE_LEN + payload.len());
        data.extend_from_slice(&header);
        data.extend_from_slice(&payload);
        let request = Message::decode(&data, false)?;
        let response = (handler)(request);
        let bytes = response.encode()?;
        transport.write_all(&bytes).await?;
    }
    Ok(())
}

fn encrypt_password(password: &str) -> CoreResult<[u8; 32]> {
    let mut buf = [0u8; 32];
    let bytes = password.as_bytes();
    if bytes.len() > 32 {
        return Err(CoreError::Parse("password too long".to_string()));
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    let encrypted = xor_bytes(&buf, &XOR_KEY);
    let mut out = [0u8; 32];
    out.copy_from_slice(&encrypted[..32]);
    Ok(out)
}

fn decrypt_password(encrypted: &[u8; 32]) -> String {
    let decrypted = xor_bytes(encrypted, &XOR_KEY);
    let s = String::from_utf8_lossy(&decrypted);
    s.trim_end_matches(|c| c == '\0' || c == ' ').to_string()
}

fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (i, b) in data.iter().enumerate() {
        out.push(b ^ key[i % key.len()]);
    }
    out
}

fn compute_payload_meta(msg_type: u32, payload: &[u8]) -> (u32, u32) {
    if payload.is_empty() && msg_type != 20 && msg_type != 3 {
        return (0xFFFFFFFF, 1);
    }
    let size = payload.len() as u32;
    let checksum = adler32(payload);
    (size, checksum)
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> CoreResult<u32> {
    if *cursor + 4 > buf.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let value = u32::from_be_bytes([
        buf[*cursor],
        buf[*cursor + 1],
        buf[*cursor + 2],
        buf[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn read_bytes<const N: usize>(buf: &[u8], cursor: &mut usize) -> CoreResult<[u8; N]> {
    if *cursor + N > buf.len() {
        return Err(CoreError::Parse("unexpected eof".to_string()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn password_roundtrip() {
        let msg = Message::login("public");
        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded, true).unwrap();
        assert_eq!(decoded.password, "public");
    }

    #[test]
    fn message_roundtrip() {
        let mut msg = Message::new();
        msg.msg_type = 20;
        msg.password = "secret".to_string();
        msg.payload = b"payload".to_vec();
        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded, true).unwrap();
        assert_eq!(decoded.msg_type, msg.msg_type);
        assert_eq!(decoded.password, msg.password);
        assert_eq!(decoded.payload, msg.payload);
    }

    #[test]
    fn server_client_roundtrip() {
        let server = match Server::bind("127.0.0.1:0".parse().unwrap(), Timeouts::default()) {
            Ok(server) => server,
            Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind: {:?}", err),
        };
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve(|req| {
                let mut resp = Message::new();
                resp.msg_type = req.msg_type;
                resp.status = 0;
                resp.password = req.password;
                resp
            });
        });

        let mut client = Client::connect(&NetAddr::from_socket(addr), Timeouts::default()).unwrap();
        let resp = client.authenticate("public").unwrap();
        assert!(resp.successful());
        assert_eq!(resp.password, "public");
    }
}
