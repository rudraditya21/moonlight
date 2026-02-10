use std::net::{Ipv4Addr, Ipv6Addr};

use corelib::error::CoreResult;

use crate::dns::{
    AsyncMdnsClient, AsyncMdnsServer, DnsFlags, DnsHeader, DnsMessage, DnsQuestion, DnsRecord,
    DnsRecordData, MdnsClient, MdnsServer,
};

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1;

pub const MDNS_PORT: u16 = 5353;
pub const MDNS_IPV4: &str = "224.0.0.251";
pub const MDNS_IPV6: &str = "ff02::fb";

#[derive(Debug, Clone)]
pub struct MdnsService {
    pub instance: String,
    pub service_type: String,
    pub host: String,
    pub port: u16,
    pub txt: Vec<(String, String)>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl MdnsService {
    pub fn instance_name(&self) -> String {
        normalize_name(&self.instance)
    }

    pub fn service_name(&self) -> String {
        normalize_name(&self.service_type)
    }

    pub fn host_name(&self) -> String {
        normalize_name(&self.host)
    }
}

pub fn build_query(service_type: &str) -> DnsMessage {
    let name = normalize_name(service_type);
    DnsMessage {
        header: DnsHeader {
            id: 0,
            flags: DnsFlags {
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: false,
                ra: false,
                rcode: 0,
            },
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        },
        questions: vec![DnsQuestion {
            name,
            qtype: TYPE_PTR,
            qclass: CLASS_IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

pub fn build_response(service: &MdnsService) -> DnsMessage {
    let service_name = service.service_name();
    let instance_name = service.instance_name();
    let host_name = service.host_name();

    let mut answers = Vec::new();
    let mut additionals = Vec::new();

    let ptr = DnsRecord {
        name: service_name.clone(),
        rtype: TYPE_PTR,
        class: CLASS_IN,
        ttl: 120,
        data: DnsRecordData::PTR(instance_name.clone()),
    };
    answers.push(ptr);

    let mut srv = DnsRecord {
        name: instance_name.clone(),
        rtype: TYPE_SRV,
        class: CLASS_IN,
        ttl: 120,
        data: DnsRecordData::SRV {
            priority: 0,
            weight: 0,
            port: service.port,
            target: host_name.clone(),
        },
    };
    srv.set_mdns_cache_flush(true);
    answers.push(srv);

    let mut txt_pairs = Vec::new();
    for (key, value) in &service.txt {
        txt_pairs.push(format!("{}={}", key, value));
    }
    let txt = DnsRecord {
        name: instance_name,
        rtype: TYPE_TXT,
        class: CLASS_IN,
        ttl: 120,
        data: DnsRecordData::TXT(txt_pairs.join("\n")),
    };
    answers.push(txt);

    if let Some(ip) = service.ipv4 {
        let mut record = DnsRecord {
            name: host_name.clone(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl: 120,
            data: DnsRecordData::A(ip),
        };
        record.set_mdns_cache_flush(true);
        additionals.push(record);
    }

    if let Some(ip) = service.ipv6 {
        let mut record = DnsRecord {
            name: host_name,
            rtype: TYPE_AAAA,
            class: CLASS_IN,
            ttl: 120,
            data: DnsRecordData::AAAA(ip),
        };
        record.set_mdns_cache_flush(true);
        additionals.push(record);
    }

    DnsMessage {
        header: DnsHeader {
            id: 0,
            flags: DnsFlags {
                qr: true,
                opcode: 0,
                aa: true,
                tc: false,
                rd: false,
                ra: false,
                rcode: 0,
            },
            qdcount: 0,
            ancount: answers.len() as u16,
            nscount: 0,
            arcount: additionals.len() as u16,
        },
        questions: Vec::new(),
        answers,
        authorities: Vec::new(),
        additionals,
    }
}

pub fn decode_message(bytes: &[u8]) -> CoreResult<DnsMessage> {
    DnsMessage::decode(bytes)
}

fn normalize_name(value: &str) -> String {
    value.trim_end_matches('.').to_string()
}

pub type MdnsSyncClient = MdnsClient;
pub type MdnsSyncServer = MdnsServer;
pub type MdnsAsyncClient = AsyncMdnsClient;
pub type MdnsAsyncServer = AsyncMdnsServer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdns_query_response_roundtrip() {
        let query = build_query("_moonlight._tcp.local");
        let encoded = query.encode().unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded.questions.len(), 1);

        let service = MdnsService {
            instance: "Moonlight".to_string(),
            service_type: "_moonlight._tcp.local".to_string(),
            host: "moonlight.local".to_string(),
            port: 1234,
            txt: vec![("version".to_string(), "1".to_string())],
            ipv4: Some(Ipv4Addr::new(127, 0, 0, 1)),
            ipv6: None,
        };
        let response = build_response(&service);
        let encoded = response.encode().unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded.answers.len(), 3);
    }
}
