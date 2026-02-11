use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl DhcpMessageType {
    fn from_u8(value: u8) -> CoreResult<Self> {
        match value {
            1 => Ok(DhcpMessageType::Discover),
            2 => Ok(DhcpMessageType::Offer),
            3 => Ok(DhcpMessageType::Request),
            4 => Ok(DhcpMessageType::Decline),
            5 => Ok(DhcpMessageType::Ack),
            6 => Ok(DhcpMessageType::Nak),
            7 => Ok(DhcpMessageType::Release),
            8 => Ok(DhcpMessageType::Inform),
            _ => Err(CoreError::Parse("invalid DHCP message type".to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    MessageType(DhcpMessageType),
    ClientIdentifier(Vec<u8>),
    RequestedIp(Ipv4Addr),
    ServerIdentifier(Ipv4Addr),
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DomainNameServer(Vec<Ipv4Addr>),
    LeaseTime(u32),
    RenewalTime(u32),
    RebindingTime(u32),
    HostName(String),
    DomainName(String),
    ParameterRequestList(Vec<u8>),
    MaximumMessageSize(u16),
    VendorClassId(String),
    BroadcastAddress(Ipv4Addr),
    NtpServers(Vec<Ipv4Addr>),
    StaticRoutes(Vec<(Ipv4Addr, Ipv4Addr)>),
    Unknown(u8, Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacket {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<DhcpOption>,
}

impl DhcpPacket {
    pub fn new() -> Self {
        Self {
            op: BOOTREQUEST,
            htype: HTYPE_ETHERNET,
            hlen: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; 16],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::new(),
        }
    }

    pub fn client_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }

    pub fn get_option(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|opt| match opt {
            DhcpOption::MessageType(_) => code == 53,
            DhcpOption::ClientIdentifier(_) => code == 61,
            DhcpOption::RequestedIp(_) => code == 50,
            DhcpOption::ServerIdentifier(_) => code == 54,
            DhcpOption::SubnetMask(_) => code == 1,
            DhcpOption::Router(_) => code == 3,
            DhcpOption::DomainNameServer(_) => code == 6,
            DhcpOption::LeaseTime(_) => code == 51,
            DhcpOption::RenewalTime(_) => code == 58,
            DhcpOption::RebindingTime(_) => code == 59,
            DhcpOption::HostName(_) => code == 12,
            DhcpOption::DomainName(_) => code == 15,
            DhcpOption::ParameterRequestList(_) => code == 55,
            DhcpOption::MaximumMessageSize(_) => code == 57,
            DhcpOption::VendorClassId(_) => code == 60,
            DhcpOption::BroadcastAddress(_) => code == 28,
            DhcpOption::NtpServers(_) => code == 42,
            DhcpOption::StaticRoutes(_) => code == 33,
            DhcpOption::Unknown(other, _) => *other == code,
        })
    }

    pub fn message_type(&self) -> Option<DhcpMessageType> {
        for opt in &self.options {
            if let DhcpOption::MessageType(value) = opt {
                return Some(*value);
            }
        }
        None
    }

    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::with_capacity(240 + self.options.len() * 8);
        out.push(self.op);
        out.push(self.htype);
        out.push(self.hlen);
        out.push(self.hops);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.ciaddr.octets());
        out.extend_from_slice(&self.yiaddr.octets());
        out.extend_from_slice(&self.siaddr.octets());
        out.extend_from_slice(&self.giaddr.octets());
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&self.sname);
        out.extend_from_slice(&self.file);
        out.extend_from_slice(&MAGIC_COOKIE);
        for opt in &self.options {
            opt.encode(&mut out);
        }
        out.push(255);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 240 {
            return Err(CoreError::Parse("dhcp packet too short".to_string()));
        }
        let op = data[0];
        let htype = data[1];
        let hlen = data[2];
        let hops = data[3];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);
        let ciaddr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let yiaddr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let siaddr = Ipv4Addr::new(data[20], data[21], data[22], data[23]);
        let giaddr = Ipv4Addr::new(data[24], data[25], data[26], data[27]);
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&data[28..44]);
        let mut sname = [0u8; 64];
        sname.copy_from_slice(&data[44..108]);
        let mut file = [0u8; 128];
        file.copy_from_slice(&data[108..236]);
        if data[236..240] != MAGIC_COOKIE {
            return Err(CoreError::Parse("invalid dhcp cookie".to_string()));
        }
        let options = parse_options(&data[240..])?;
        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }
}

impl DhcpOption {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            DhcpOption::MessageType(value) => {
                out.push(53);
                out.push(1);
                out.push(*value as u8);
            }
            DhcpOption::ClientIdentifier(value) => encode_bytes_option(out, 61, value),
            DhcpOption::RequestedIp(value) => encode_ip_option(out, 50, *value),
            DhcpOption::ServerIdentifier(value) => encode_ip_option(out, 54, *value),
            DhcpOption::SubnetMask(value) => encode_ip_option(out, 1, *value),
            DhcpOption::Router(values) => encode_ip_list_option(out, 3, values),
            DhcpOption::DomainNameServer(values) => encode_ip_list_option(out, 6, values),
            DhcpOption::LeaseTime(value) => encode_u32_option(out, 51, *value),
            DhcpOption::RenewalTime(value) => encode_u32_option(out, 58, *value),
            DhcpOption::RebindingTime(value) => encode_u32_option(out, 59, *value),
            DhcpOption::HostName(value) => encode_string_option(out, 12, value),
            DhcpOption::DomainName(value) => encode_string_option(out, 15, value),
            DhcpOption::ParameterRequestList(value) => encode_bytes_option(out, 55, value),
            DhcpOption::MaximumMessageSize(value) => encode_u16_option(out, 57, *value),
            DhcpOption::VendorClassId(value) => encode_string_option(out, 60, value),
            DhcpOption::BroadcastAddress(value) => encode_ip_option(out, 28, *value),
            DhcpOption::NtpServers(values) => encode_ip_list_option(out, 42, values),
            DhcpOption::StaticRoutes(routes) => {
                out.push(33);
                out.push((routes.len() * 8) as u8);
                for (dst, gw) in routes {
                    out.extend_from_slice(&dst.octets());
                    out.extend_from_slice(&gw.octets());
                }
            }
            DhcpOption::Unknown(code, value) => {
                out.push(*code);
                out.push(value.len() as u8);
                out.extend_from_slice(value);
            }
        }
    }

    fn decode(code: u8, data: &[u8]) -> CoreResult<Self> {
        Ok(match code {
            53 => DhcpOption::MessageType(DhcpMessageType::from_u8(*data.get(0).unwrap_or(&0))?),
            61 => DhcpOption::ClientIdentifier(data.to_vec()),
            50 => DhcpOption::RequestedIp(parse_ip(data)?),
            54 => DhcpOption::ServerIdentifier(parse_ip(data)?),
            1 => DhcpOption::SubnetMask(parse_ip(data)?),
            3 => DhcpOption::Router(parse_ip_list(data)?),
            6 => DhcpOption::DomainNameServer(parse_ip_list(data)?),
            51 => DhcpOption::LeaseTime(parse_u32(data)?),
            58 => DhcpOption::RenewalTime(parse_u32(data)?),
            59 => DhcpOption::RebindingTime(parse_u32(data)?),
            12 => DhcpOption::HostName(String::from_utf8_lossy(data).to_string()),
            15 => DhcpOption::DomainName(String::from_utf8_lossy(data).to_string()),
            55 => DhcpOption::ParameterRequestList(data.to_vec()),
            57 => DhcpOption::MaximumMessageSize(parse_u16(data)?),
            60 => DhcpOption::VendorClassId(String::from_utf8_lossy(data).to_string()),
            28 => DhcpOption::BroadcastAddress(parse_ip(data)?),
            42 => DhcpOption::NtpServers(parse_ip_list(data)?),
            33 => DhcpOption::StaticRoutes(parse_routes(data)?),
            _ => DhcpOption::Unknown(code, data.to_vec()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DhcpClientConfig {
    pub timeouts: Timeouts,
    pub retry: usize,
}

impl Default for DhcpClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            retry: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub server_id: Ipv4Addr,
    pub subnet_mask: Option<Ipv4Addr>,
    pub router: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: Option<u32>,
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
}

pub struct DhcpClient {
    socket: UdpTransport,
    config: DhcpClientConfig,
    xid: u32,
    mac: [u8; 6],
}

impl DhcpClient {
    pub fn bind(config: DhcpClientConfig, mac: [u8; 6]) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self {
            socket,
            config,
            xid: rand_xid(),
            mac,
        })
    }

    pub fn discover(&mut self, server: SocketAddr) -> CoreResult<DhcpPacket> {
        for _ in 0..self.config.retry {
            let pkt = self.build_discover();
            self.send(&pkt, server)?;
            if let Ok(resp) = self.recv_response(DhcpMessageType::Offer) {
                return Ok(resp);
            }
        }
        Err(CoreError::Message("no DHCP offer".to_string()))
    }

    pub fn request(&mut self, server: SocketAddr, offer: &DhcpPacket) -> CoreResult<DhcpLease> {
        let requested_ip = offer.yiaddr;
        let server_id = match offer.get_option(54) {
            Some(DhcpOption::ServerIdentifier(ip)) => *ip,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let pkt = self.build_request(requested_ip, server_id);
        self.send(&pkt, server)?;
        let resp = self.recv_response_any(&[DhcpMessageType::Ack, DhcpMessageType::Nak])?;
        match resp.message_type() {
            Some(DhcpMessageType::Ack) => Ok(extract_lease(&resp)),
            Some(DhcpMessageType::Nak) => Err(CoreError::Message("dhcp nak".to_string())),
            _ => Err(CoreError::Message("unexpected response".to_string())),
        }
    }

    pub fn obtain_lease(&mut self, server: SocketAddr) -> CoreResult<DhcpLease> {
        let offer = self.discover(server)?;
        self.request(server, &offer)
    }

    fn send(&self, pkt: &DhcpPacket, addr: SocketAddr) -> CoreResult<()> {
        let bytes = pkt.encode()?;
        self.socket.send_to(&bytes, addr)?;
        Ok(())
    }

    fn recv_response(&self, msg_type: DhcpMessageType) -> CoreResult<DhcpPacket> {
        self.recv_response_any(&[msg_type])
    }

    fn recv_response_any(&self, types: &[DhcpMessageType]) -> CoreResult<DhcpPacket> {
        let deadline = SystemTime::now()
            .checked_add(self.config.timeouts.read)
            .unwrap_or(SystemTime::now() + Duration::from_secs(5));
        loop {
            let now = SystemTime::now();
            if now > deadline {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout",
                )));
            }
            let (data, _) = self.socket.recv_from(1500)?;
            let pkt = DhcpPacket::decode(&data)?;
            if pkt.xid != self.xid {
                continue;
            }
            if let Some(t) = pkt.message_type() {
                if types.contains(&t) {
                    return Ok(pkt);
                }
            }
        }
    }

    fn build_discover(&self) -> DhcpPacket {
        let mut pkt = DhcpPacket::new();
        pkt.op = BOOTREQUEST;
        pkt.htype = HTYPE_ETHERNET;
        pkt.hlen = 6;
        pkt.xid = self.xid;
        pkt.flags = 0x8000;
        pkt.chaddr[..6].copy_from_slice(&self.mac);
        pkt.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::ClientIdentifier(build_client_id(&self.mac)),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15, 51, 58, 59, 28, 42]),
        ];
        pkt
    }

    fn build_request(&self, ip: Ipv4Addr, server_id: Ipv4Addr) -> DhcpPacket {
        let mut pkt = DhcpPacket::new();
        pkt.op = BOOTREQUEST;
        pkt.htype = HTYPE_ETHERNET;
        pkt.hlen = 6;
        pkt.xid = self.xid;
        pkt.flags = 0x8000;
        pkt.chaddr[..6].copy_from_slice(&self.mac);
        pkt.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Request),
            DhcpOption::RequestedIp(ip),
            DhcpOption::ServerIdentifier(server_id),
            DhcpOption::ClientIdentifier(build_client_id(&self.mac)),
        ];
        pkt
    }
}

pub struct AsyncDhcpClient {
    socket: AsyncUdpTransport,
    config: DhcpClientConfig,
    xid: u32,
    mac: [u8; 6],
}

impl AsyncDhcpClient {
    pub async fn bind(config: DhcpClientConfig, mac: [u8; 6]) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self {
            socket,
            config,
            xid: rand_xid(),
            mac,
        })
    }

    pub async fn discover(&mut self, server: SocketAddr) -> CoreResult<DhcpPacket> {
        for _ in 0..self.config.retry {
            let pkt = self.build_discover();
            self.send(&pkt, server).await?;
            if let Ok(resp) = self.recv_response(DhcpMessageType::Offer).await {
                return Ok(resp);
            }
        }
        Err(CoreError::Message("no DHCP offer".to_string()))
    }

    pub async fn request(
        &mut self,
        server: SocketAddr,
        offer: &DhcpPacket,
    ) -> CoreResult<DhcpLease> {
        let requested_ip = offer.yiaddr;
        let server_id = match offer.get_option(54) {
            Some(DhcpOption::ServerIdentifier(ip)) => *ip,
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let pkt = self.build_request(requested_ip, server_id);
        self.send(&pkt, server).await?;
        let resp = self
            .recv_response_any(&[DhcpMessageType::Ack, DhcpMessageType::Nak])
            .await?;
        match resp.message_type() {
            Some(DhcpMessageType::Ack) => Ok(extract_lease(&resp)),
            Some(DhcpMessageType::Nak) => Err(CoreError::Message("dhcp nak".to_string())),
            _ => Err(CoreError::Message("unexpected response".to_string())),
        }
    }

    pub async fn obtain_lease(&mut self, server: SocketAddr) -> CoreResult<DhcpLease> {
        let offer = self.discover(server).await?;
        self.request(server, &offer).await
    }

    async fn send(&self, pkt: &DhcpPacket, addr: SocketAddr) -> CoreResult<()> {
        let bytes = pkt.encode()?;
        self.socket.send_to(&bytes, addr).await?;
        Ok(())
    }

    async fn recv_response(&self, msg_type: DhcpMessageType) -> CoreResult<DhcpPacket> {
        self.recv_response_any(&[msg_type]).await
    }

    async fn recv_response_any(&self, types: &[DhcpMessageType]) -> CoreResult<DhcpPacket> {
        let deadline = tokio::time::Instant::now() + self.config.timeouts.read;
        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout",
                )));
            }
            let (data, _) = self.socket.recv_from(1500).await?;
            let pkt = DhcpPacket::decode(&data)?;
            if pkt.xid != self.xid {
                continue;
            }
            if let Some(t) = pkt.message_type() {
                if types.contains(&t) {
                    return Ok(pkt);
                }
            }
        }
    }

    fn build_discover(&self) -> DhcpPacket {
        let mut pkt = DhcpPacket::new();
        pkt.op = BOOTREQUEST;
        pkt.htype = HTYPE_ETHERNET;
        pkt.hlen = 6;
        pkt.xid = self.xid;
        pkt.flags = 0x8000;
        pkt.chaddr[..6].copy_from_slice(&self.mac);
        pkt.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::ClientIdentifier(build_client_id(&self.mac)),
            DhcpOption::ParameterRequestList(vec![1, 3, 6, 15, 51, 58, 59, 28, 42]),
        ];
        pkt
    }

    fn build_request(&self, ip: Ipv4Addr, server_id: Ipv4Addr) -> DhcpPacket {
        let mut pkt = DhcpPacket::new();
        pkt.op = BOOTREQUEST;
        pkt.htype = HTYPE_ETHERNET;
        pkt.hlen = 6;
        pkt.xid = self.xid;
        pkt.flags = 0x8000;
        pkt.chaddr[..6].copy_from_slice(&self.mac);
        pkt.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Request),
            DhcpOption::RequestedIp(ip),
            DhcpOption::ServerIdentifier(server_id),
            DhcpOption::ClientIdentifier(build_client_id(&self.mac)),
        ];
        pkt
    }
}

#[derive(Debug, Clone)]
pub struct DhcpServerConfig {
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_time: u32,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub timeouts: Timeouts,
}

impl Default for DhcpServerConfig {
    fn default() -> Self {
        Self {
            server_ip: Ipv4Addr::new(192, 168, 0, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: vec![Ipv4Addr::new(192, 168, 0, 1)],
            dns: vec![Ipv4Addr::new(8, 8, 8, 8)],
            lease_time: 3600,
            renewal_time: 1800,
            rebinding_time: 3150,
            pool_start: Ipv4Addr::new(192, 168, 0, 100),
            pool_end: Ipv4Addr::new(192, 168, 0, 200),
            timeouts: Timeouts::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpLeaseEntry {
    pub ip: Ipv4Addr,
    pub expires_at: Option<SystemTime>,
}

pub struct DhcpServer {
    socket: UdpTransport,
    config: DhcpServerConfig,
    leases: Arc<Mutex<HashMap<[u8; 6], DhcpLeaseEntry>>>,
    pool: Arc<Mutex<VecDeque<Ipv4Addr>>>,
}

impl DhcpServer {
    pub fn bind(addr: SocketAddr, config: DhcpServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        let pool = build_pool(config.pool_start, config.pool_end);
        Ok(Self {
            socket,
            config,
            leases: Arc::new(Mutex::new(HashMap::new())),
            pool: Arc::new(Mutex::new(pool)),
        })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        match self.socket.try_clone() {
            Ok(sock) => sock.local_addr().map_err(CoreError::Io),
            Err(err) => Err(err),
        }
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = match self.socket.recv_from(1500) {
                Ok(data) => data,
                Err(CoreError::Io(err)) if err.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(err) => return Err(err),
            };
            let packet = match DhcpPacket::decode(&data) {
                Ok(pkt) => pkt,
                Err(_) => continue,
            };
            if packet.op != BOOTREQUEST {
                continue;
            }
            if let Err(err) = self.handle_packet(packet, addr) {
                let _ = err;
            }
        }
    }

    fn handle_packet(&self, packet: DhcpPacket, addr: SocketAddr) -> CoreResult<()> {
        let msg_type = match packet.message_type() {
            Some(value) => value,
            None => return Ok(()),
        };
        match msg_type {
            DhcpMessageType::Discover => {
                if let Some(offer) = self.build_offer(&packet)? {
                    self.send_reply(&offer, addr)?;
                }
            }
            DhcpMessageType::Request => {
                let reply = self.build_ack_or_nak(&packet)?;
                if let Some(reply) = reply {
                    self.send_reply(&reply, addr)?;
                }
            }
            DhcpMessageType::Release => {
                self.release(&packet.client_mac());
            }
            DhcpMessageType::Inform => {
                let ack = self.build_inform_ack(&packet)?;
                self.send_reply(&ack, addr)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn send_reply(&self, packet: &DhcpPacket, addr: SocketAddr) -> CoreResult<()> {
        let bytes = packet.encode()?;
        self.socket.send_to(&bytes, addr)?;
        Ok(())
    }

    fn build_offer(&self, packet: &DhcpPacket) -> CoreResult<Option<DhcpPacket>> {
        let mac = packet.client_mac();
        let ip = match self.allocate_ip(&mac) {
            Some(ip) => ip,
            None => return Ok(None),
        };
        let mut offer = base_reply(packet, ip, &self.config);
        offer
            .options
            .push(DhcpOption::MessageType(DhcpMessageType::Offer));
        Ok(Some(offer))
    }

    fn build_ack_or_nak(&self, packet: &DhcpPacket) -> CoreResult<Option<DhcpPacket>> {
        let mac = packet.client_mac();
        let requested = requested_ip(packet).unwrap_or(packet.ciaddr);
        if requested == Ipv4Addr::UNSPECIFIED {
            return Ok(None);
        }
        if !self.is_ip_available(&mac, requested) {
            let mut nak = base_reply(packet, Ipv4Addr::UNSPECIFIED, &self.config);
            nak.options
                .push(DhcpOption::MessageType(DhcpMessageType::Nak));
            return Ok(Some(nak));
        }
        self.commit_lease(&mac, requested);
        let mut ack = base_reply(packet, requested, &self.config);
        ack.options
            .push(DhcpOption::MessageType(DhcpMessageType::Ack));
        Ok(Some(ack))
    }

    fn build_inform_ack(&self, packet: &DhcpPacket) -> CoreResult<DhcpPacket> {
        let mut ack = base_reply(packet, Ipv4Addr::UNSPECIFIED, &self.config);
        ack.options
            .push(DhcpOption::MessageType(DhcpMessageType::Ack));
        Ok(ack)
    }

    fn allocate_ip(&self, mac: &[u8; 6]) -> Option<Ipv4Addr> {
        let mut leases = self.leases.lock().ok()?;
        if let Some(entry) = leases.get(mac) {
            return Some(entry.ip);
        }
        let mut pool = self.pool.lock().ok()?;
        let ip = pool.pop_front()?;
        leases.insert(
            *mac,
            DhcpLeaseEntry {
                ip,
                expires_at: Some(
                    SystemTime::now() + Duration::from_secs(self.config.lease_time as u64),
                ),
            },
        );
        Some(ip)
    }

    fn is_ip_available(&self, mac: &[u8; 6], ip: Ipv4Addr) -> bool {
        let leases = self.leases.lock().ok();
        if let Some(leases) = leases {
            for (key, entry) in leases.iter() {
                if entry.ip == ip {
                    return key == mac;
                }
            }
        }
        true
    }

    fn commit_lease(&self, mac: &[u8; 6], ip: Ipv4Addr) {
        let mut leases = match self.leases.lock() {
            Ok(leases) => leases,
            Err(_) => return,
        };
        leases.insert(
            *mac,
            DhcpLeaseEntry {
                ip,
                expires_at: Some(
                    SystemTime::now() + Duration::from_secs(self.config.lease_time as u64),
                ),
            },
        );
    }

    fn release(&self, mac: &[u8; 6]) {
        let mut leases = match self.leases.lock() {
            Ok(leases) => leases,
            Err(_) => return,
        };
        if let Some(entry) = leases.remove(mac) {
            if let Ok(mut pool) = self.pool.lock() {
                pool.push_back(entry.ip);
            }
        }
    }
}

pub struct AsyncDhcpServer {
    socket: AsyncUdpTransport,
    config: DhcpServerConfig,
    leases: Arc<Mutex<HashMap<[u8; 6], DhcpLeaseEntry>>>,
    pool: Arc<Mutex<VecDeque<Ipv4Addr>>>,
}

impl AsyncDhcpServer {
    pub async fn bind(addr: SocketAddr, config: DhcpServerConfig) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        let pool = build_pool(config.pool_start, config.pool_end);
        Ok(Self {
            socket,
            config,
            leases: Arc::new(Mutex::new(HashMap::new())),
            pool: Arc::new(Mutex::new(pool)),
        })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(1500).await?;
            let packet = match DhcpPacket::decode(&data) {
                Ok(pkt) => pkt,
                Err(_) => continue,
            };
            if packet.op != BOOTREQUEST {
                continue;
            }
            let _ = self.handle_packet(packet, addr).await;
        }
    }

    async fn handle_packet(&self, packet: DhcpPacket, addr: SocketAddr) -> CoreResult<()> {
        let msg_type = match packet.message_type() {
            Some(value) => value,
            None => return Ok(()),
        };
        match msg_type {
            DhcpMessageType::Discover => {
                if let Some(offer) = self.build_offer(&packet)? {
                    self.send_reply(&offer, addr).await?;
                }
            }
            DhcpMessageType::Request => {
                let reply = self.build_ack_or_nak(&packet)?;
                if let Some(reply) = reply {
                    self.send_reply(&reply, addr).await?;
                }
            }
            DhcpMessageType::Release => {
                self.release(&packet.client_mac());
            }
            DhcpMessageType::Inform => {
                let ack = self.build_inform_ack(&packet)?;
                self.send_reply(&ack, addr).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn send_reply(&self, packet: &DhcpPacket, addr: SocketAddr) -> CoreResult<()> {
        let bytes = packet.encode()?;
        self.socket.send_to(&bytes, addr).await?;
        Ok(())
    }

    fn build_offer(&self, packet: &DhcpPacket) -> CoreResult<Option<DhcpPacket>> {
        let mac = packet.client_mac();
        let ip = match self.allocate_ip(&mac) {
            Some(ip) => ip,
            None => return Ok(None),
        };
        let mut offer = base_reply(packet, ip, &self.config);
        offer
            .options
            .push(DhcpOption::MessageType(DhcpMessageType::Offer));
        Ok(Some(offer))
    }

    fn build_ack_or_nak(&self, packet: &DhcpPacket) -> CoreResult<Option<DhcpPacket>> {
        let mac = packet.client_mac();
        let requested = requested_ip(packet).unwrap_or(packet.ciaddr);
        if requested == Ipv4Addr::UNSPECIFIED {
            return Ok(None);
        }
        if !self.is_ip_available(&mac, requested) {
            let mut nak = base_reply(packet, Ipv4Addr::UNSPECIFIED, &self.config);
            nak.options
                .push(DhcpOption::MessageType(DhcpMessageType::Nak));
            return Ok(Some(nak));
        }
        self.commit_lease(&mac, requested);
        let mut ack = base_reply(packet, requested, &self.config);
        ack.options
            .push(DhcpOption::MessageType(DhcpMessageType::Ack));
        Ok(Some(ack))
    }

    fn build_inform_ack(&self, packet: &DhcpPacket) -> CoreResult<DhcpPacket> {
        let mut ack = base_reply(packet, Ipv4Addr::UNSPECIFIED, &self.config);
        ack.options
            .push(DhcpOption::MessageType(DhcpMessageType::Ack));
        Ok(ack)
    }

    fn allocate_ip(&self, mac: &[u8; 6]) -> Option<Ipv4Addr> {
        let mut leases = self.leases.lock().ok()?;
        if let Some(entry) = leases.get(mac) {
            return Some(entry.ip);
        }
        let mut pool = self.pool.lock().ok()?;
        let ip = pool.pop_front()?;
        leases.insert(
            *mac,
            DhcpLeaseEntry {
                ip,
                expires_at: Some(
                    SystemTime::now() + Duration::from_secs(self.config.lease_time as u64),
                ),
            },
        );
        Some(ip)
    }

    fn is_ip_available(&self, mac: &[u8; 6], ip: Ipv4Addr) -> bool {
        let leases = self.leases.lock().ok();
        if let Some(leases) = leases {
            for (key, entry) in leases.iter() {
                if entry.ip == ip {
                    return key == mac;
                }
            }
        }
        true
    }

    fn commit_lease(&self, mac: &[u8; 6], ip: Ipv4Addr) {
        let mut leases = match self.leases.lock() {
            Ok(leases) => leases,
            Err(_) => return,
        };
        leases.insert(
            *mac,
            DhcpLeaseEntry {
                ip,
                expires_at: Some(
                    SystemTime::now() + Duration::from_secs(self.config.lease_time as u64),
                ),
            },
        );
    }

    fn release(&self, mac: &[u8; 6]) {
        let mut leases = match self.leases.lock() {
            Ok(leases) => leases,
            Err(_) => return,
        };
        if let Some(entry) = leases.remove(mac) {
            if let Ok(mut pool) = self.pool.lock() {
                pool.push_back(entry.ip);
            }
        }
    }
}

fn base_reply(request: &DhcpPacket, yiaddr: Ipv4Addr, config: &DhcpServerConfig) -> DhcpPacket {
    let mut packet = DhcpPacket::new();
    packet.op = BOOTREPLY;
    packet.htype = request.htype;
    packet.hlen = request.hlen;
    packet.xid = request.xid;
    packet.flags = request.flags;
    packet.ciaddr = request.ciaddr;
    packet.yiaddr = yiaddr;
    packet.siaddr = config.server_ip;
    packet.chaddr = request.chaddr;
    packet.options = vec![
        DhcpOption::ServerIdentifier(config.server_ip),
        DhcpOption::SubnetMask(config.subnet_mask),
        DhcpOption::Router(config.router.clone()),
        DhcpOption::DomainNameServer(config.dns.clone()),
        DhcpOption::LeaseTime(config.lease_time),
        DhcpOption::RenewalTime(config.renewal_time),
        DhcpOption::RebindingTime(config.rebinding_time),
    ];
    packet
}

fn requested_ip(packet: &DhcpPacket) -> Option<Ipv4Addr> {
    for opt in &packet.options {
        if let DhcpOption::RequestedIp(ip) = opt {
            return Some(*ip);
        }
    }
    None
}

fn extract_lease(packet: &DhcpPacket) -> DhcpLease {
    let mut lease = DhcpLease {
        ip: packet.yiaddr,
        server_id: Ipv4Addr::UNSPECIFIED,
        subnet_mask: None,
        router: Vec::new(),
        dns: Vec::new(),
        lease_time: None,
        renewal_time: None,
        rebinding_time: None,
    };
    for opt in &packet.options {
        match opt {
            DhcpOption::ServerIdentifier(ip) => lease.server_id = *ip,
            DhcpOption::SubnetMask(ip) => lease.subnet_mask = Some(*ip),
            DhcpOption::Router(list) => lease.router = list.clone(),
            DhcpOption::DomainNameServer(list) => lease.dns = list.clone(),
            DhcpOption::LeaseTime(v) => lease.lease_time = Some(*v),
            DhcpOption::RenewalTime(v) => lease.renewal_time = Some(*v),
            DhcpOption::RebindingTime(v) => lease.rebinding_time = Some(*v),
            _ => {}
        }
    }
    lease
}

fn build_pool(start: Ipv4Addr, end: Ipv4Addr) -> VecDeque<Ipv4Addr> {
    let start_u32 = ipv4_to_u32(start);
    let end_u32 = ipv4_to_u32(end);
    let mut pool = VecDeque::new();
    for ip in start_u32..=end_u32 {
        pool.push_back(u32_to_ipv4(ip));
    }
    pool
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    let octets = ip.octets();
    u32::from_be_bytes(octets)
}

fn u32_to_ipv4(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(value.to_be_bytes())
}

fn rand_xid() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(1))
        .subsec_nanos();
    0xfeed_0000u32 ^ nanos
}

fn build_client_id(mac: &[u8; 6]) -> Vec<u8> {
    let mut id = Vec::with_capacity(7);
    id.push(HTYPE_ETHERNET);
    id.extend_from_slice(mac);
    id
}

fn parse_options(data: &[u8]) -> CoreResult<Vec<DhcpOption>> {
    let mut options = Vec::new();
    let mut idx = 0;
    while idx < data.len() {
        let code = data[idx];
        idx += 1;
        match code {
            0 => continue,
            255 => break,
            _ => {
                if idx >= data.len() {
                    return Err(CoreError::Parse("invalid option length".to_string()));
                }
                let len = data[idx] as usize;
                idx += 1;
                if idx + len > data.len() {
                    return Err(CoreError::Parse("invalid option length".to_string()));
                }
                let value = &data[idx..idx + len];
                idx += len;
                options.push(DhcpOption::decode(code, value)?);
            }
        }
    }
    Ok(options)
}

fn encode_ip_option(out: &mut Vec<u8>, code: u8, ip: Ipv4Addr) {
    out.push(code);
    out.push(4);
    out.extend_from_slice(&ip.octets());
}

fn encode_ip_list_option(out: &mut Vec<u8>, code: u8, ips: &[Ipv4Addr]) {
    out.push(code);
    out.push((ips.len() * 4) as u8);
    for ip in ips {
        out.extend_from_slice(&ip.octets());
    }
}

fn encode_u32_option(out: &mut Vec<u8>, code: u8, value: u32) {
    out.push(code);
    out.push(4);
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_u16_option(out: &mut Vec<u8>, code: u8, value: u16) {
    out.push(code);
    out.push(2);
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_bytes_option(out: &mut Vec<u8>, code: u8, value: &[u8]) {
    out.push(code);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

fn encode_string_option(out: &mut Vec<u8>, code: u8, value: &str) {
    encode_bytes_option(out, code, value.as_bytes());
}

fn parse_ip(data: &[u8]) -> CoreResult<Ipv4Addr> {
    if data.len() != 4 {
        return Err(CoreError::Parse("invalid ip".to_string()));
    }
    Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

fn parse_ip_list(data: &[u8]) -> CoreResult<Vec<Ipv4Addr>> {
    if data.len() % 4 != 0 {
        return Err(CoreError::Parse("invalid ip list".to_string()));
    }
    let mut out = Vec::new();
    for chunk in data.chunks(4) {
        out.push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
    }
    Ok(out)
}

fn parse_u32(data: &[u8]) -> CoreResult<u32> {
    if data.len() != 4 {
        return Err(CoreError::Parse("invalid u32".to_string()));
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

fn parse_u16(data: &[u8]) -> CoreResult<u16> {
    if data.len() != 2 {
        return Err(CoreError::Parse("invalid u16".to_string()));
    }
    Ok(u16::from_be_bytes([data[0], data[1]]))
}

fn parse_routes(data: &[u8]) -> CoreResult<Vec<(Ipv4Addr, Ipv4Addr)>> {
    if data.len() % 8 != 0 {
        return Err(CoreError::Parse("invalid routes".to_string()));
    }
    let mut routes = Vec::new();
    for chunk in data.chunks(8) {
        let dst = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let gw = Ipv4Addr::new(chunk[4], chunk[5], chunk[6], chunk[7]);
        routes.push((dst, gw));
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn packet_roundtrip() {
        let mut pkt = DhcpPacket::new();
        pkt.xid = 0x12345678;
        pkt.chaddr[..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        pkt.options = vec![
            DhcpOption::MessageType(DhcpMessageType::Discover),
            DhcpOption::RequestedIp(Ipv4Addr::new(192, 168, 0, 100)),
            DhcpOption::HostName("host".to_string()),
        ];
        let encoded = pkt.encode().unwrap();
        let decoded = DhcpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.xid, pkt.xid);
        assert_eq!(decoded.client_mac(), pkt.client_mac());
        assert_eq!(decoded.message_type(), Some(DhcpMessageType::Discover));
    }

    #[test]
    fn server_client_roundtrip() {
        let mut config = DhcpServerConfig::default();
        config.server_ip = Ipv4Addr::new(10, 0, 0, 1);
        config.pool_start = Ipv4Addr::new(10, 0, 0, 100);
        config.pool_end = Ipv4Addr::new(10, 0, 0, 110);
        let server = crate::skip_if_perm!(DhcpServer::bind("127.0.0.1:0".parse().unwrap(), config));
        let addr = server.local_addr().unwrap();
        thread::spawn(move || {
            let _ = server.serve();
        });

        let mut client = DhcpClient::bind(
            DhcpClientConfig::default(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        )
        .unwrap();
        let lease = client.obtain_lease(addr).unwrap();
        assert_eq!(lease.ip, Ipv4Addr::new(10, 0, 0, 100));
    }
}
