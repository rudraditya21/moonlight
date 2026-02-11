use std::panic::{catch_unwind, AssertUnwindSafe};

use proto::*;

fn fuzz_bytes<F: FnMut(&[u8])>(iterations: usize, max_len: usize, seed: u64, mut f: F) {
    let mut state = seed;
    for _ in 0..iterations {
        let len = (next_u64(&mut state) as usize) % (max_len + 1);
        let mut buf = vec![0u8; len];
        fill_bytes(&mut state, &mut buf);
        let result = catch_unwind(AssertUnwindSafe(|| f(&buf)));
        assert!(result.is_ok(), "fuzz target panicked");
    }
}

fn fuzz_strings<F: FnMut(&str)>(iterations: usize, max_len: usize, seed: u64, mut f: F) {
    fuzz_bytes(iterations, max_len, seed, |data| {
        let text = String::from_utf8_lossy(data);
        f(&text);
    });
}

fn fill_bytes(state: &mut u64, out: &mut [u8]) {
    for chunk in out.chunks_mut(8) {
        let value = next_u64(state).to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&value[..len]);
    }
}

fn next_u64(state: &mut u64) -> u64 {
    let mut z = state.wrapping_add(0x9e3779b97f4a7c15);
    *state = z;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

#[test]
fn fuzz_acpp_decode() {
    assert!(acpp::Message::decode(&[], false).is_err());
    fuzz_bytes(128, 512, 0xAC11, |data| {
        let _ = acpp::Message::decode(data, false);
    });
}

#[test]
fn fuzz_adb_decode() {
    assert!(adb::AdbPacket::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xADB1, |data| {
        let _ = adb::AdbPacket::decode(data);
    });
}

#[test]
fn fuzz_addp_decode() {
    assert!(addp::AddpMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xADD1, |data| {
        let _ = addp::AddpMessage::decode(data);
    });
}

#[test]
fn fuzz_amqp_decode() {
    assert!(amqp::AmqpFrame::decode(&[]).is_err());
    assert!(amqp::AmqpMethod::decode(&[]).is_err());
    assert!(amqp::AmqpContentHeader::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xA1C1, |data| {
        let _ = amqp::AmqpFrame::decode(data);
        let _ = amqp::AmqpMethod::decode(data);
        let _ = amqp::AmqpContentHeader::decode(data);
    });
}

#[test]
fn fuzz_bcrypt_public_key_decode() {
    assert!(bcrypt_public_key::BcryptPublicKey::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xBEEF, |data| {
        let _ = bcrypt_public_key::BcryptPublicKey::decode(data);
    });
}

#[test]
fn fuzz_crypto_asn1_decode() {
    assert!(crypto_asn1::Asn1Value::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xA551, |data| {
        let _ = crypto_asn1::Asn1Value::decode(data);
    });
}

#[test]
fn fuzz_dcerpc_decode() {
    assert!(dcerpc::DceRpcHeader::decode(&[]).is_err());
    assert!(dcerpc::DceRpcPdu::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xDC12, |data| {
        let _ = dcerpc::DceRpcHeader::decode(data);
        let _ = dcerpc::DceRpcPdu::decode(data);
    });
}

#[test]
fn fuzz_dhcp_decode() {
    assert!(dhcp::DhcpPacket::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xD1C0, |data| {
        let _ = dhcp::DhcpPacket::decode(data);
    });
}

#[test]
fn fuzz_dns_decode() {
    assert!(dns::DnsMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xD15, |data| {
        let _ = dns::DnsMessage::decode(data);
    });
}

#[test]
fn fuzz_drda_decode() {
    assert!(drda::DrdaMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xD2DA, |data| {
        let _ = drda::DrdaMessage::decode(data);
    });
}

#[test]
fn fuzz_ftp_parse() {
    let _ = ftp::FtpCommand::parse("");
    fuzz_strings(128, 256, 0xF7F0, |text| {
        let _ = ftp::FtpCommand::parse(text);
    });
}

#[test]
fn fuzz_gss_decode() {
    assert!(gss::GssMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x655, |data| {
        let _ = gss::GssMessage::decode(data);
    });
}

#[test]
fn fuzz_iax2_decode() {
    assert!(iax2::IaxFrame::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x1A22, |data| {
        let _ = iax2::IaxFrame::decode(data);
    });
}

#[test]
fn fuzz_kerberos_decode() {
    assert!(kerberos::KerbFrame::decode(&[]).is_err());
    assert!(kerberos::KerbApRep::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x4B3B, |data| {
        let _ = kerberos::KerbFrame::decode(data);
        let _ = kerberos::KerbApRep::decode(data);
    });
}

#[test]
fn fuzz_ldap_decode() {
    assert!(ldap::LdapMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x1DA1, |data| {
        let _ = ldap::LdapMessage::decode(data);
    });
}

#[test]
fn fuzz_mdns_decode() {
    assert!(mdns::decode_message(&[]).is_err());
    fuzz_bytes(128, 512, 0x4D4E, |data| {
        let _ = mdns::decode_message(data);
    });
}

#[test]
fn fuzz_mms_decode() {
    assert!(mms::MmsFrame::decode(&[]).is_err());
    assert!(mms::MmsDescription::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x4D51, |data| {
        let _ = mms::MmsFrame::decode(data);
        let _ = mms::MmsDescription::decode(data);
    });
}

#[test]
fn fuzz_mqtt_decode() {
    assert!(mqtt::MqttPacket::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x4D77, |data| {
        let _ = mqtt::MqttPacket::decode(data);
    });
}

#[test]
fn fuzz_ms_adts_decode() {
    assert!(ms_adts::KeyCredentialStruct::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xAD75, |data| {
        let _ = ms_adts::KeyCredentialStruct::decode(data);
    });
}

#[test]
fn fuzz_ms_crtd_decode() {
    assert!(ms_crtd::CrtdMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xC12D, |data| {
        let _ = ms_crtd::CrtdMessage::decode(data);
    });
}

#[test]
fn fuzz_ms_dnsp_decode() {
    assert!(ms_dnsp::MsDnspMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x0D5E, |data| {
        let _ = ms_dnsp::MsDnspMessage::decode(data);
    });
}

#[test]
fn fuzz_ms_dtyp_decode() {
    assert!(ms_dtyp::Guid::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0xD7AF, |data| {
        let _ = ms_dtyp::Guid::decode(data);
    });
}

#[test]
fn fuzz_ms_nrtp_decode() {
    assert!(ms_nrtp::NrtpMessage::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x4E7F, |data| {
        let _ = ms_nrtp::NrtpMessage::decode(data);
    });
}

#[test]
fn fuzz_ms_tds_decode() {
    assert!(ms_tds::TdsHeader::decode(&[]).is_err());
    assert!(ms_tds::TdsPacket::decode(&[]).is_err());
    assert!(ms_tds::PreloginInfo::decode(&[]).is_err());
    assert!(ms_tds::Login7::decode(&[]).is_err());
    let _ = ms_tds::TdsResponse::decode(&[]);
    fuzz_bytes(128, 512, 0x7D52, |data| {
        let _ = ms_tds::TdsHeader::decode(data);
        let _ = ms_tds::TdsPacket::decode(data);
        let _ = ms_tds::PreloginInfo::decode(data);
        let _ = ms_tds::Login7::decode(data);
        let _ = ms_tds::TdsResponse::decode(data);
        let mut idx = 0usize;
        let _ = ms_tds::TdsToken::decode(data, &mut idx);
    });
}

#[test]
fn fuzz_natpmp_decode() {
    assert!(natpmp::NatPmpRequest::decode(&[]).is_err());
    assert!(natpmp::NatPmpResponse::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x6E41, |data| {
        let _ = natpmp::NatPmpRequest::decode(data);
        let _ = natpmp::NatPmpResponse::decode(data);
    });
}

#[test]
fn fuzz_ntlm_decode() {
    assert!(ntlm::NtlmMessage::decode(&[]).is_err());
    assert!(ntlm::decode_http_token("not-base64").is_err());
    fuzz_bytes(128, 512, 0x4711, |data| {
        let _ = ntlm::NtlmMessage::decode(data);
    });
    fuzz_strings(128, 256, 0x4712, |text| {
        let _ = ntlm::decode_http_token(text);
    });
}

#[test]
fn fuzz_ntp_decode() {
    assert!(ntp::NtpPacket::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x4700, |data| {
        let _ = ntp::NtpPacket::decode(data);
    });
}

#[test]
fn fuzz_nuuo_decode() {
    assert!(nuuo::NuuoFrame::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x4E00, |data| {
        let _ = nuuo::NuuoFrame::decode(data);
    });
}

#[test]
fn fuzz_pjl_parse() {
    assert!(pjl::PjlCommand::parse("").is_none());
    fuzz_strings(128, 256, 0x504A, |text| {
        let _ = pjl::PjlCommand::parse(text);
    });
}

#[test]
fn fuzz_rfb_decode() {
    assert!(rfb::RfbPixelFormat::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x5FB0, |data| {
        let _ = rfb::RfbPixelFormat::decode(data);
    });
}

#[test]
fn fuzz_rmi_decode() {
    assert!(rmi::RmiFrame::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x5A11, |data| {
        let _ = rmi::RmiFrame::decode(data);
    });
}

#[test]
fn fuzz_sasl_decode() {
    assert!(sasl::SaslFrame::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x5A51, |data| {
        let _ = sasl::SaslFrame::decode(data);
    });
}

#[test]
fn fuzz_secauthz_decode() {
    assert!(secauthz::SecAuthzFrame::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x5EC1, |data| {
        let _ = secauthz::SecAuthzFrame::decode(data);
    });
}

#[test]
fn fuzz_sip_parse() {
    assert!(sip::SipMethod::parse("").is_none());
    fuzz_strings(128, 256, 0x5190, |text| {
        let _ = sip::SipMethod::parse(text);
    });
}

#[test]
fn fuzz_smb_decode() {
    assert!(smb::Smb2Header::decode(&[]).is_err());
    assert!(smb::Smb2Packet::decode(&[]).is_err());
    fuzz_bytes(128, 512, 0x5AB0, |data| {
        let _ = smb::Smb2Header::decode(data);
        let _ = smb::Smb2Packet::decode(data);
    });
}

#[test]
fn fuzz_tftp_decode() {
    assert!(tftp::TftpPacket::decode(&[]).is_err());
    assert!(tftp::TftpMode::parse("").is_err());
    fuzz_bytes(128, 512, 0x7F70, |data| {
        let _ = tftp::TftpPacket::decode(data);
    });
    fuzz_strings(128, 256, 0x7F71, |text| {
        let _ = tftp::TftpMode::parse(text);
    });
}

#[test]
fn fuzz_x509_decode() {
    assert!(x509::parse_certificate(&[]).is_err());
    fuzz_bytes(128, 1024, 0x5509, |data| {
        let _ = x509::parse_certificate(data);
    });
}
