use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

pub const NTP_DEFAULT_PORT: u16 = 123;
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl NtpTimestamp {
    pub fn from_system_time(time: SystemTime) -> Self {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0));
        let seconds = duration.as_secs().saturating_add(NTP_EPOCH_OFFSET);
        let nanos = duration.subsec_nanos() as u64;
        let fraction = ((nanos << 32) / 1_000_000_000) as u32;
        Self {
            seconds: seconds as u32,
            fraction,
        }
    }

    pub fn to_system_time(&self) -> SystemTime {
        let seconds = self.seconds as u64;
        let nanos = ((self.fraction as u128 * 1_000_000_000u128) >> 32) as u32;
        let unix = seconds.saturating_sub(NTP_EPOCH_OFFSET);
        UNIX_EPOCH + Duration::new(unix, nanos)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpPacket {
    pub li_vn_mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    pub reference_timestamp: NtpTimestamp,
    pub originate_timestamp: NtpTimestamp,
    pub receive_timestamp: NtpTimestamp,
    pub transmit_timestamp: NtpTimestamp,
}

impl NtpPacket {
    pub fn client_request() -> Self {
        let transmit = NtpTimestamp::from_system_time(SystemTime::now());
        Self {
            li_vn_mode: (0 << 6) | (4 << 3) | 3,
            stratum: 0,
            poll: 4,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: 0,
            reference_timestamp: NtpTimestamp { seconds: 0, fraction: 0 },
            originate_timestamp: NtpTimestamp { seconds: 0, fraction: 0 },
            receive_timestamp: NtpTimestamp { seconds: 0, fraction: 0 },
            transmit_timestamp: transmit,
        }
    }

    pub fn server_response(
        request: &NtpPacket,
        stratum: u8,
        reference_id: u32,
    ) -> Self {
        let now = SystemTime::now();
        let timestamp = NtpTimestamp::from_system_time(now);
        Self {
            li_vn_mode: (0 << 6) | (4 << 3) | 4,
            stratum,
            poll: request.poll,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id,
            reference_timestamp: timestamp,
            originate_timestamp: request.transmit_timestamp,
            receive_timestamp: timestamp,
            transmit_timestamp: timestamp,
        }
    }

    pub fn encode(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[0] = self.li_vn_mode;
        out[1] = self.stratum;
        out[2] = self.poll as u8;
        out[3] = self.precision as u8;
        out[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        out[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        out[12..16].copy_from_slice(&self.reference_id.to_be_bytes());
        encode_timestamp(&mut out[16..24], self.reference_timestamp);
        encode_timestamp(&mut out[24..32], self.originate_timestamp);
        encode_timestamp(&mut out[32..40], self.receive_timestamp);
        encode_timestamp(&mut out[40..48], self.transmit_timestamp);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 48 {
            return Err(CoreError::Parse("ntp packet too short".to_string()));
        }
        Ok(Self {
            li_vn_mode: data[0],
            stratum: data[1],
            poll: data[2] as i8,
            precision: data[3] as i8,
            root_delay: u32::from_be_bytes(data[4..8].try_into().unwrap()),
            root_dispersion: u32::from_be_bytes(data[8..12].try_into().unwrap()),
            reference_id: u32::from_be_bytes(data[12..16].try_into().unwrap()),
            reference_timestamp: decode_timestamp(&data[16..24])?,
            originate_timestamp: decode_timestamp(&data[24..32])?,
            receive_timestamp: decode_timestamp(&data[32..40])?,
            transmit_timestamp: decode_timestamp(&data[40..48])?,
        })
    }

    pub fn mode(&self) -> u8 {
        self.li_vn_mode & 0x07
    }
}

#[derive(Debug, Clone)]
pub struct NtpClientConfig {
    pub timeouts: Timeouts,
}

impl Default for NtpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

pub struct NtpClient {
    transport: UdpTransport,
    server: SocketAddr,
}

impl NtpClient {
    pub fn new(server: SocketAddr, config: NtpClientConfig) -> CoreResult<Self> {
        let transport = UdpTransport::bind_any()?;
        transport.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { transport, server })
    }

    pub fn request_time(&self) -> CoreResult<SystemTime> {
        let request = NtpPacket::client_request();
        let payload = request.encode();
        self.transport.send_to(&payload, self.server)?;
        let (data, _) = self.transport.recv_from(512)?;
        let response = NtpPacket::decode(&data)?;
        if response.mode() != 4 {
            return Err(CoreError::Parse("ntp invalid mode".to_string()));
        }
        Ok(response.transmit_timestamp.to_system_time())
    }
}

pub struct AsyncNtpClient {
    transport: AsyncUdpTransport,
    server: SocketAddr,
}

impl AsyncNtpClient {
    pub async fn new(server: SocketAddr) -> CoreResult<Self> {
        let transport = AsyncUdpTransport::bind_any().await?;
        Ok(Self { transport, server })
    }

    pub async fn request_time(&self) -> CoreResult<SystemTime> {
        let request = NtpPacket::client_request();
        let payload = request.encode();
        self.transport.send_to(&payload, self.server).await?;
        let (data, _) = self.transport.recv_from(512).await?;
        let response = NtpPacket::decode(&data)?;
        if response.mode() != 4 {
            return Err(CoreError::Parse("ntp invalid mode".to_string()));
        }
        Ok(response.transmit_timestamp.to_system_time())
    }
}

#[derive(Debug, Clone)]
pub struct NtpServerConfig {
    pub timeouts: Timeouts,
    pub stratum: u8,
    pub reference_id: u32,
}

impl Default for NtpServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            stratum: 2,
            reference_id: u32::from_be_bytes(*b"LOCL"),
        }
    }
}

pub struct NtpServer {
    socket: UdpTransport,
    config: NtpServerConfig,
}

impl NtpServer {
    pub fn bind(addr: SocketAddr, config: NtpServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket, config })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(1024)?;
            let request = match NtpPacket::decode(&data) {
                Ok(pkt) => pkt,
                Err(_) => continue,
            };
            if request.mode() != 3 {
                continue;
            }
            let response = NtpPacket::server_response(
                &request,
                self.config.stratum,
                self.config.reference_id,
            );
            let payload = response.encode();
            let _ = self.socket.send_to(&payload, peer);
        }
    }
}

pub struct AsyncNtpServer {
    socket: AsyncUdpTransport,
    config: NtpServerConfig,
}

impl AsyncNtpServer {
    pub async fn bind(addr: SocketAddr, config: NtpServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self { socket, config })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, peer) = self.socket.recv_from(1024).await?;
            let request = match NtpPacket::decode(&data) {
                Ok(pkt) => pkt,
                Err(_) => continue,
            };
            if request.mode() != 3 {
                continue;
            }
            let response = NtpPacket::server_response(
                &request,
                self.config.stratum,
                self.config.reference_id,
            );
            let payload = response.encode();
            let _ = self.socket.send_to(&payload, peer).await;
        }
    }
}

fn encode_timestamp(out: &mut [u8], ts: NtpTimestamp) {
    out[..4].copy_from_slice(&ts.seconds.to_be_bytes());
    out[4..8].copy_from_slice(&ts.fraction.to_be_bytes());
}

fn decode_timestamp(data: &[u8]) -> CoreResult<NtpTimestamp> {
    if data.len() < 8 {
        return Err(CoreError::Parse("ntp timestamp".to_string()));
    }
    Ok(NtpTimestamp {
        seconds: u32::from_be_bytes(data[0..4].try_into().unwrap()),
        fraction: u32::from_be_bytes(data[4..8].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn ntp_roundtrip() {
        let server = NtpServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            NtpServerConfig::default(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let client = NtpClient::new(addr, NtpClientConfig::default()).unwrap();
        let server_time = client.request_time().unwrap();
        let diff = server_time
            .duration_since(SystemTime::now())
            .unwrap_or_else(|err| err.duration());
        assert!(diff.as_secs() < 5);
    }
}
