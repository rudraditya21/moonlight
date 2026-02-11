use proto::dns::DnsMessage;

#[test]
fn dns_query_golden() {
    let msg = DnsMessage::new_query(0x1a2b, "example.com", 1);
    let bytes = msg.encode().expect("encode");
    let expected: Vec<u8> = vec![
        0x1a, 0x2b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    assert_eq!(bytes, expected);
    let decoded = DnsMessage::decode(&bytes).expect("decode");
    assert_eq!(decoded.questions.len(), 1);
    let question = &decoded.questions[0];
    assert_eq!(question.name, "example.com");
    assert_eq!(question.qtype, 1);
}
