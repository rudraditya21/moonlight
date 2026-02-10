use corelib::error::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCredentialEntry {
    pub identifier: u8,
    pub data: Vec<u8>,
}

impl KeyCredentialEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.data.len());
        let len = self.data.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.push(self.identifier);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<(Self, usize)> {
        if data.len() < 3 {
            return Err(CoreError::Parse("ms_adts entry too short".to_string()));
        }
        let len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if data.len() < 3 + len {
            return Err(CoreError::Parse("ms_adts entry length invalid".to_string()));
        }
        let identifier = data[2];
        let payload = data[3..3 + len].to_vec();
        Ok((
            KeyCredentialEntry {
                identifier,
                data: payload,
            },
            3 + len,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCredentialStruct {
    pub version: u32,
    pub entries: Vec<KeyCredentialEntry>,
}

impl KeyCredentialStruct {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.encode());
        }
        out
    }

    pub fn decode(data: &[u8]) -> CoreResult<Self> {
        if data.len() < 4 {
            return Err(CoreError::Parse("ms_adts struct too short".to_string()));
        }
        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut entries = Vec::new();
        let mut offset = 4;
        while offset < data.len() {
            let (entry, read) = KeyCredentialEntry::decode(&data[offset..])?;
            entries.push(entry);
            offset += read;
        }
        Ok(Self { version, entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_adts_roundtrip() {
        let entry = KeyCredentialEntry {
            identifier: 1,
            data: vec![1, 2, 3, 4],
        };
        let ks = KeyCredentialStruct {
            version: 2,
            entries: vec![entry.clone()],
        };
        let encoded = ks.encode();
        let decoded = KeyCredentialStruct::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.entries, vec![entry]);
    }
}
