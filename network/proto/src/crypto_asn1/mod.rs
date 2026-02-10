use corelib::error::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Value {
    Boolean(bool),
    Integer(Vec<u8>),
    BitString { unused_bits: u8, data: Vec<u8> },
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u32>),
    Utf8String(String),
    PrintableString(String),
    Sequence(Vec<Asn1Value>),
    Set(Vec<Asn1Value>),
}

impl Asn1Value {
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        let (tag, content) = match self {
            Asn1Value::Boolean(value) => (0x01, vec![if *value { 0xFF } else { 0x00 }]),
            Asn1Value::Integer(bytes) => (0x02, encode_integer(bytes)),
            Asn1Value::BitString { unused_bits, data } => {
                let mut out = Vec::with_capacity(1 + data.len());
                out.push(*unused_bits);
                out.extend_from_slice(data);
                (0x03, out)
            }
            Asn1Value::OctetString(bytes) => (0x04, bytes.clone()),
            Asn1Value::Null => (0x05, Vec::new()),
            Asn1Value::ObjectIdentifier(oid) => (0x06, encode_oid(oid)?),
            Asn1Value::Utf8String(text) => (0x0C, text.as_bytes().to_vec()),
            Asn1Value::PrintableString(text) => (0x13, text.as_bytes().to_vec()),
            Asn1Value::Sequence(items) => (0x30, encode_constructed(items)?),
            Asn1Value::Set(items) => (0x31, encode_constructed(items)?),
        };
        let mut out = Vec::new();
        out.push(tag);
        encode_length(&mut out, content.len());
        out.extend_from_slice(&content);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> CoreResult<(Self, usize)> {
        decode_asn1(data, 0, 0)
    }
}

fn encode_constructed(items: &[Asn1Value]) -> CoreResult<Vec<u8>> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(&item.encode()?);
    }
    Ok(out)
}

fn encode_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
        return;
    }
    let mut buf = Vec::new();
    let mut value = len;
    while value > 0 {
        buf.push((value & 0xFF) as u8);
        value >>= 8;
    }
    buf.reverse();
    out.push(0x80 | buf.len() as u8);
    out.extend_from_slice(&buf);
}

fn decode_length(data: &[u8], idx: &mut usize) -> CoreResult<usize> {
    if *idx >= data.len() {
        return Err(CoreError::Parse("asn1 length out of bounds".to_string()));
    }
    let first = data[*idx];
    *idx += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = (first & 0x7F) as usize;
    if count == 0 || count > 4 {
        return Err(CoreError::Parse("asn1 length invalid".to_string()));
    }
    if *idx + count > data.len() {
        return Err(CoreError::Parse("asn1 length bounds".to_string()));
    }
    let mut value = 0usize;
    for _ in 0..count {
        value = (value << 8) | data[*idx] as usize;
        *idx += 1;
    }
    Ok(value)
}

fn encode_integer(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0];
    }
    let mut out = bytes.to_vec();
    while out.len() > 1 && out[0] == 0x00 && out[1] & 0x80 == 0 {
        out.remove(0);
    }
    while out.len() > 1 && out[0] == 0xFF && out[1] & 0x80 == 0x80 {
        out.remove(0);
    }
    out
}

fn encode_oid(oid: &[u32]) -> CoreResult<Vec<u8>> {
    if oid.len() < 2 {
        return Err(CoreError::Parse("asn1 oid too short".to_string()));
    }
    let first = oid[0];
    let second = oid[1];
    if first > 2 || second > 39 && first < 2 {
        return Err(CoreError::Parse("asn1 oid invalid".to_string()));
    }
    let mut out = Vec::new();
    out.push((first * 40 + second) as u8);
    for &component in &oid[2..] {
        out.extend_from_slice(&encode_base128(component));
    }
    Ok(out)
}

fn encode_base128(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.push((value & 0x7F) as u8);
    value >>= 7;
    while value > 0 {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.reverse();
    out
}

fn decode_oid(data: &[u8]) -> CoreResult<Vec<u32>> {
    if data.is_empty() {
        return Err(CoreError::Parse("asn1 oid empty".to_string()));
    }
    let first = data[0] / 40;
    let second = data[0] % 40;
    let mut out = vec![first as u32, second as u32];
    let mut value = 0u32;
    for &b in &data[1..] {
        value = (value << 7) | (b & 0x7F) as u32;
        if b & 0x80 == 0 {
            out.push(value);
            value = 0;
        }
    }
    Ok(out)
}

fn decode_asn1(data: &[u8], idx: usize, depth: usize) -> CoreResult<(Asn1Value, usize)> {
    if depth > 32 {
        return Err(CoreError::Parse("asn1 depth exceeded".to_string()));
    }
    if idx >= data.len() {
        return Err(CoreError::Parse("asn1 out of bounds".to_string()));
    }
    let tag = data[idx];
    let mut cursor = idx + 1;
    let len = decode_length(data, &mut cursor)?;
    if cursor + len > data.len() {
        return Err(CoreError::Parse("asn1 length bounds".to_string()));
    }
    let content = &data[cursor..cursor + len];
    let value = match tag {
        0x01 => {
            if content.len() != 1 {
                return Err(CoreError::Parse("asn1 bool len".to_string()));
            }
            Asn1Value::Boolean(content[0] != 0)
        }
        0x02 => Asn1Value::Integer(content.to_vec()),
        0x03 => {
            if content.is_empty() {
                return Err(CoreError::Parse("asn1 bitstring len".to_string()));
            }
            Asn1Value::BitString {
                unused_bits: content[0],
                data: content[1..].to_vec(),
            }
        }
        0x04 => Asn1Value::OctetString(content.to_vec()),
        0x05 => Asn1Value::Null,
        0x06 => Asn1Value::ObjectIdentifier(decode_oid(content)?),
        0x0C => Asn1Value::Utf8String(String::from_utf8_lossy(content).to_string()),
        0x13 => Asn1Value::PrintableString(String::from_utf8_lossy(content).to_string()),
        0x30 => Asn1Value::Sequence(decode_constructed(content, depth + 1)?),
        0x31 => Asn1Value::Set(decode_constructed(content, depth + 1)?),
        _ => return Err(CoreError::Parse("asn1 unsupported tag".to_string())),
    };
    Ok((value, cursor + len))
}

fn decode_constructed(data: &[u8], depth: usize) -> CoreResult<Vec<Asn1Value>> {
    let mut items = Vec::new();
    let mut idx = 0;
    while idx < data.len() {
        let (value, next) = decode_asn1(data, idx, depth)?;
        items.push(value);
        idx = next;
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn1_roundtrip_sequence() {
        let value = Asn1Value::Sequence(vec![
            Asn1Value::Integer(vec![0x01]),
            Asn1Value::OctetString(b"moon".to_vec()),
            Asn1Value::ObjectIdentifier(vec![1, 2, 840, 113549]),
        ]);
        let encoded = value.encode().unwrap();
        let (decoded, _) = Asn1Value::decode(&encoded).unwrap();
        assert_eq!(decoded, value);
    }
}
