use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;

use corelib::error::{CoreError, CoreResult};

use crate::transport::{AsyncUdpTransport, UdpTransport};
use crate::util::Timeouts;

pub const IPMI_DEFAULT_PORT: u16 = 623;

const RMCP_VERSION: u8 = 0x06;
const RMCP_CLASS_IPMI: u8 = 0x07;

const AUTH_TYPE_NONE: u8 = 0x00;

const NETFN_APP: u8 = 0x06;
const CMD_GET_DEVICE_ID: u8 = 0x01;
const CMD_GET_CHANNEL_AUTH_CAP: u8 = 0x38;

#[derive(Debug, Clone)]
pub struct IpmiClientConfig {
    pub timeouts: Timeouts,
}

impl Default for IpmiClientConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpmiServerConfig {
    pub timeouts: Timeouts,
    pub device_id: u8,
    pub device_revision: u8,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub ipmi_version: u8,
    pub manufacturer_id: [u8; 3],
    pub product_id: u16,
}

impl Default for IpmiServerConfig {
    fn default() -> Self {
        Self {
            timeouts: Timeouts::default(),
            device_id: 0x20,
            device_revision: 0x01,
            firmware_major: 1,
            firmware_minor: 0,
            ipmi_version: 0x51,
            manufacturer_id: [0x57, 0x01, 0x00],
            product_id: 0x0001,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpmiRequest {
    pub netfn: u8,
    pub cmd: u8,
    pub data: Vec<u8>,
    pub rq_addr: u8,
    pub rq_seq: u8,
}

#[derive(Debug, Clone)]
pub struct IpmiResponse {
    pub netfn: u8,
    pub cmd: u8,
    pub completion_code: u8,
    pub data: Vec<u8>,
    pub rs_addr: u8,
    pub rq_addr: u8,
    pub rq_seq: u8,
}

pub trait IpmiHandler: Send + Sync {
    fn handle(&self, request: &IpmiRequest) -> IpmiResponse;
}

#[derive(Debug, Clone)]
pub struct DefaultIpmiHandler {
    config: IpmiServerConfig,
}

impl DefaultIpmiHandler {
    pub fn new(config: IpmiServerConfig) -> Self {
        Self { config }
    }
}

impl IpmiHandler for DefaultIpmiHandler {
    fn handle(&self, request: &IpmiRequest) -> IpmiResponse {
        let mut response = IpmiResponse {
            netfn: request.netfn.wrapping_add(1),
            cmd: request.cmd,
            completion_code: 0x00,
            data: Vec::new(),
            rs_addr: 0x20,
            rq_addr: request.rq_addr,
            rq_seq: request.rq_seq,
        };
        match (request.netfn, request.cmd) {
            (NETFN_APP, CMD_GET_DEVICE_ID) => {
                response.data.extend_from_slice(&[
                    self.config.device_id,
                    self.config.device_revision,
                    self.config.firmware_major,
                    self.config.firmware_minor,
                    self.config.ipmi_version,
                    0x00,
                    self.config.manufacturer_id[0],
                    self.config.manufacturer_id[1],
                    self.config.manufacturer_id[2],
                ]);
                response.data.extend_from_slice(&self.config.product_id.to_le_bytes());
            }
            (NETFN_APP, CMD_GET_CHANNEL_AUTH_CAP) => {
                let channel = request.data.get(0).copied().unwrap_or(0x0E);
                response.data.extend_from_slice(&[
                    channel,
                    0x07,
                    0x00,
                    0x00,
                    0x00,
                ]);
            }
            _ => {
                response.completion_code = 0xC1;
            }
        }
        response
    }
}

pub struct IpmiServer {
    socket: UdpTransport,
    handler: Arc<dyn IpmiHandler>,
}

impl IpmiServer {
    pub fn bind(addr: SocketAddr, handler: Arc<dyn IpmiHandler>, config: IpmiServerConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind(addr)?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket, handler })
    }

    pub fn local_addr(&self) -> CoreResult<SocketAddr> {
        self.socket.try_clone()?.local_addr().map_err(CoreError::Io)
    }

    pub fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(2048)?;
            let socket = self.socket.clone();
            let handler = Arc::clone(&self.handler);
            thread::spawn(move || {
                let _ = handle_ipmi_request(socket, handler, &data, addr);
            });
        }
    }
}

pub struct AsyncIpmiServer {
    socket: AsyncUdpTransport,
    handler: Arc<dyn IpmiHandler>,
}

impl AsyncIpmiServer {
    pub async fn bind(addr: SocketAddr, handler: Arc<dyn IpmiHandler>) -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind(addr).await?;
        Ok(Self { socket, handler })
    }

    pub async fn serve(&self) -> CoreResult<()> {
        loop {
            let (data, addr) = self.socket.recv_from(2048).await?;
            let handler = Arc::clone(&self.handler);
            tokio::spawn(async move {
                let socket = match AsyncUdpTransport::bind_any().await {
                    Ok(socket) => socket,
                    Err(_) => return,
                };
                let _ = handle_ipmi_request_async(socket, handler, &data, addr).await;
            });
        }
    }
}

pub struct IpmiClient {
    socket: UdpTransport,
}

impl IpmiClient {
    pub fn connect(config: IpmiClientConfig) -> CoreResult<Self> {
        let socket = UdpTransport::bind_any()?;
        socket.set_read_timeout(Some(config.timeouts.read))?;
        Ok(Self { socket })
    }

    pub fn request(&self, addr: SocketAddr, netfn: u8, cmd: u8, data: &[u8]) -> CoreResult<IpmiResponse> {
        let msg = encode_ipmi_request(netfn, cmd, data, 0x81, 1);
        let packet = encode_rmcp_packet(&msg);
        self.socket.send_to(&packet, addr)?;
        let (resp, _) = self.socket.recv_from(2048)?;
        decode_ipmi_response(&resp)
    }

    pub fn get_device_id(&self, addr: SocketAddr) -> CoreResult<IpmiResponse> {
        self.request(addr, NETFN_APP, CMD_GET_DEVICE_ID, &[])
    }

    pub fn get_channel_auth_capabilities(&self, addr: SocketAddr, channel: u8) -> CoreResult<IpmiResponse> {
        self.request(addr, NETFN_APP, CMD_GET_CHANNEL_AUTH_CAP, &[channel, 0x00])
    }
}

pub struct AsyncIpmiClient {
    socket: AsyncUdpTransport,
}

impl AsyncIpmiClient {
    pub async fn connect() -> CoreResult<Self> {
        let socket = AsyncUdpTransport::bind_any().await?;
        Ok(Self { socket })
    }

    pub async fn request(&self, addr: SocketAddr, netfn: u8, cmd: u8, data: &[u8]) -> CoreResult<IpmiResponse> {
        let msg = encode_ipmi_request(netfn, cmd, data, 0x81, 1);
        let packet = encode_rmcp_packet(&msg);
        self.socket.send_to(&packet, addr).await?;
        let (resp, _) = self.socket.recv_from(2048).await?;
        decode_ipmi_response(&resp)
    }
}

fn handle_ipmi_request(
    socket: UdpTransport,
    handler: Arc<dyn IpmiHandler>,
    data: &[u8],
    addr: SocketAddr,
) -> CoreResult<()> {
    let request = decode_ipmi_request(data)?;
    let response = handler.handle(&request);
    let payload = encode_ipmi_response(&response);
    let packet = encode_rmcp_packet(&payload);
    socket.send_to(&packet, addr)?;
    Ok(())
}

async fn handle_ipmi_request_async(
    socket: AsyncUdpTransport,
    handler: Arc<dyn IpmiHandler>,
    data: &[u8],
    addr: SocketAddr,
) -> CoreResult<()> {
    let request = decode_ipmi_request(data)?;
    let response = handler.handle(&request);
    let payload = encode_ipmi_response(&response);
    let packet = encode_rmcp_packet(&payload);
    socket.send_to(&packet, addr).await?;
    Ok(())
}

fn encode_rmcp_packet(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push(RMCP_VERSION);
    out.push(0x00);
    out.push(0xFF);
    out.push(RMCP_CLASS_IPMI);
    out.extend_from_slice(payload);
    out
}

fn decode_rmcp_packet(data: &[u8]) -> CoreResult<&[u8]> {
    if data.len() < 4 {
        return Err(CoreError::Parse("rmcp packet too short".to_string()));
    }
    if data[0] != RMCP_VERSION || data[3] != RMCP_CLASS_IPMI {
        return Err(CoreError::Parse("rmcp header invalid".to_string()));
    }
    Ok(&data[4..])
}

fn encode_ipmi_request(netfn: u8, cmd: u8, data: &[u8], rq_addr: u8, rq_seq: u8) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(AUTH_TYPE_NONE);
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());

    let rs_addr = 0x20;
    let netfn_lun = (netfn << 2) | 0x00;
    let rq_seq_lun = (rq_seq << 2) | 0x00;

    msg.push(rs_addr);
    msg.push(netfn_lun);
    msg.push(checksum(&[rs_addr, netfn_lun]));
    msg.push(rq_addr);
    msg.push(rq_seq_lun);
    msg.push(cmd);
    msg.extend_from_slice(data);

    let checksum2 = checksum(&msg[12..]);
    msg.push(checksum2);
    msg
}

fn encode_ipmi_response(response: &IpmiResponse) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(AUTH_TYPE_NONE);
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());

    let netfn_lun = (response.netfn << 2) | 0x00;
    let rq_seq_lun = (response.rq_seq << 2) | 0x00;

    msg.push(response.rs_addr);
    msg.push(netfn_lun);
    msg.push(checksum(&[response.rs_addr, netfn_lun]));
    msg.push(response.rq_addr);
    msg.push(rq_seq_lun);
    msg.push(response.cmd);
    msg.push(response.completion_code);
    msg.extend_from_slice(&response.data);
    let checksum2 = checksum(&msg[12..]);
    msg.push(checksum2);
    msg
}

fn decode_ipmi_request(data: &[u8]) -> CoreResult<IpmiRequest> {
    let payload = decode_rmcp_packet(data)?;
    if payload.len() < 16 {
        return Err(CoreError::Parse("ipmi payload too short".to_string()));
    }
    let auth_type = payload[0];
    if auth_type != AUTH_TYPE_NONE {
        return Err(CoreError::Parse("ipmi auth not supported".to_string()));
    }
    let rs_addr = payload[9];
    let netfn_lun = payload[10];
    let chk1 = payload[11];
    if checksum(&[rs_addr, netfn_lun]) != chk1 {
        return Err(CoreError::Parse("ipmi checksum1 invalid".to_string()));
    }
    let rq_addr = payload[12];
    let rq_seq = payload[13] >> 2;
    let cmd = payload[14];
    let data_end = payload.len() - 1;
    let data_slice = &payload[15..data_end];
    let chk2 = payload[data_end];
    if checksum(&payload[12..data_end]) != chk2 {
        return Err(CoreError::Parse("ipmi checksum2 invalid".to_string()));
    }
    Ok(IpmiRequest {
        netfn: netfn_lun >> 2,
        cmd,
        data: data_slice.to_vec(),
        rq_addr,
        rq_seq,
    })
}

fn decode_ipmi_response(data: &[u8]) -> CoreResult<IpmiResponse> {
    let payload = decode_rmcp_packet(data)?;
    if payload.len() < 17 {
        return Err(CoreError::Parse("ipmi payload too short".to_string()));
    }
    let auth_type = payload[0];
    if auth_type != AUTH_TYPE_NONE {
        return Err(CoreError::Parse("ipmi auth not supported".to_string()));
    }
    let rs_addr = payload[9];
    let netfn_lun = payload[10];
    let chk1 = payload[11];
    if checksum(&[rs_addr, netfn_lun]) != chk1 {
        return Err(CoreError::Parse("ipmi checksum1 invalid".to_string()));
    }
    let rq_addr = payload[12];
    let rq_seq = payload[13] >> 2;
    let cmd = payload[14];
    let completion_code = payload[15];
    let data_end = payload.len() - 1;
    let data_slice = &payload[16..data_end];
    let chk2 = payload[data_end];
    if checksum(&payload[12..data_end]) != chk2 {
        return Err(CoreError::Parse("ipmi checksum2 invalid".to_string()));
    }
    Ok(IpmiResponse {
        netfn: netfn_lun >> 2,
        cmd,
        completion_code,
        data: data_slice.to_vec(),
        rs_addr,
        rq_addr,
        rq_seq,
    })
}

fn checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    (!sum).wrapping_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipmi_get_device_id() {
        let config = IpmiServerConfig::default();
        let handler = Arc::new(DefaultIpmiHandler::new(config.clone()));
        let server = IpmiServer::bind("127.0.0.1:0".parse().unwrap(), handler, config).unwrap();
        let addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || server.serve());

        let client = IpmiClient::connect(IpmiClientConfig::default()).unwrap();
        let resp = client.get_device_id(addr).unwrap();
        assert_eq!(resp.completion_code, 0x00);
        assert!(resp.data.len() >= 9);

        drop(handle);
    }
}
