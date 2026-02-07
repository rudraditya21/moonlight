use corelib::error::{CoreError, CoreResult};

use md5::Md5;

#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: String,
    pub qop: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DigestResponse {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: String,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
    pub opaque: Option<String>,
}

pub fn basic_auth(username: &str, password: &str) -> String {
    let token = format!("{}:{}", username, password);
    format!("Basic {}", base64_encode(token.as_bytes()))
}

pub fn bearer_auth(token: &str) -> String {
    format!("Bearer {}", token)
}

pub fn parse_digest_challenge(header: &str) -> CoreResult<DigestChallenge> {
    let header = header.trim();
    let value = header.strip_prefix("Digest ").unwrap_or(header);
    let params = parse_params(value);
    let realm = params
        .get("realm")
        .ok_or_else(|| CoreError::Parse("missing realm".to_string()))?
        .to_string();
    let nonce = params
        .get("nonce")
        .ok_or_else(|| CoreError::Parse("missing nonce".to_string()))?
        .to_string();
    let algorithm = params
        .get("algorithm")
        .cloned()
        .unwrap_or_else(|| "MD5".to_string());
    let qop = params.get("qop").cloned();
    let opaque = params.get("opaque").cloned();
    Ok(DigestChallenge {
        realm,
        nonce,
        opaque,
        algorithm,
        qop,
    })
}

pub fn digest_authorization(
    challenge: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> CoreResult<String> {
    digest_authorization_with_body(challenge, username, password, method, uri, &[])
}

pub fn digest_authorization_with_body(
    challenge: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    body: &[u8],
) -> CoreResult<String> {
    let qop = challenge
        .qop
        .as_deref()
        .unwrap_or("auth")
        .split(',')
        .map(|s| s.trim())
        .find(|&s| s == "auth" || s == "auth-int")
        .unwrap_or("auth");
    let cnonce = "moonlight";
    let nc = "00000001";

    let ha1 = md5_hex_bytes(format!("{}:{}:{}", username, challenge.realm, password).as_bytes());
    let ha2 = if qop == "auth-int" {
        let body_hash = md5_hex_bytes(body);
        md5_hex_bytes(format!("{}:{}:{}", method, uri, body_hash).as_bytes())
    } else {
        md5_hex_bytes(format!("{}:{}", method, uri).as_bytes())
    };

    let response = md5_hex_bytes(
        format!("{}:{}:{}:{}:{}:{}", ha1, challenge.nonce, nc, cnonce, qop, ha2).as_bytes(),
    );

    let resp = DigestResponse {
        username: username.to_string(),
        realm: challenge.realm.clone(),
        nonce: challenge.nonce.clone(),
        uri: uri.to_string(),
        response,
        algorithm: challenge.algorithm.clone(),
        qop: Some(qop.to_string()),
        nc: Some(nc.to_string()),
        cnonce: Some(cnonce.to_string()),
        opaque: challenge.opaque.clone(),
    };

    Ok(format!("Digest {}", format_digest_response(&resp)))
}

fn format_digest_response(resp: &DigestResponse) -> String {
    let mut parts = Vec::new();
    parts.push(format!("username=\"{}\"", resp.username));
    parts.push(format!("realm=\"{}\"", resp.realm));
    parts.push(format!("nonce=\"{}\"", resp.nonce));
    parts.push(format!("uri=\"{}\"", resp.uri));
    parts.push(format!("response=\"{}\"", resp.response));
    parts.push(format!("algorithm={}", resp.algorithm));
    if let Some(qop) = &resp.qop {
        parts.push(format!("qop={}", qop));
    }
    if let Some(nc) = &resp.nc {
        parts.push(format!("nc={}", nc));
    }
    if let Some(cnonce) = &resp.cnonce {
        parts.push(format!("cnonce=\"{}\"", cnonce));
    }
    if let Some(opaque) = &resp.opaque {
        parts.push(format!("opaque=\"{}\"", opaque));
    }
    parts.join(", ")
}

fn parse_params(input: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    let bytes = input.as_bytes();
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',') {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = input[start..i].trim().to_string();
        i += 1;
        if i >= bytes.len() {
            break;
        }
        let value = if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            let val = input[start..i].to_string();
            i += 1;
            val
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            input[start..i].trim().to_string()
        };
        if !key.is_empty() {
            map.insert(key, value);
        }
    }
    map
}

fn md5_hex_bytes(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if i + 1 < data.len() {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_header() {
        let header = basic_auth("Aladdin", "open sesame");
        assert_eq!(header, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn digest_auth_header() {
        let challenge = parse_digest_challenge(
            "Digest realm=\"test\", nonce=\"abc\", qop=\"auth\"",
        )
        .expect("parse");
        let header = digest_authorization(&challenge, "user", "pass", "GET", "/").unwrap();
        assert!(header.starts_with("Digest "));
        assert!(header.contains("username=\"user\""));
        assert!(header.contains("response="));
    }

    #[test]
    fn digest_auth_int_body() {
        let challenge = parse_digest_challenge(
            "Digest realm=\"test\", nonce=\"xyz\", qop=\"auth-int\"",
        )
        .expect("parse");
        let header = digest_authorization_with_body(&challenge, "user", "pass", "POST", "/upload", b"payload").unwrap();
        assert!(header.contains("qop=auth-int"));
        let response_pos = header.find("response=\"").expect("response");
        let response = &header[response_pos + "response=\"".len()..];
        let response = response.split('"').next().unwrap();

        let ha1 = md5_hex_bytes(b"user:test:pass");
        let body_hash = md5_hex_bytes(b"payload");
        let ha2 = md5_hex_bytes(format!("POST:/upload:{}", body_hash).as_bytes());
        let expected = md5_hex_bytes(format!("{}:{}:{}:{}:{}:{}", ha1, "xyz", "00000001", "moonlight", "auth-int", ha2).as_bytes());
        assert_eq!(response, expected);
    }
}
