use corelib::error::{CoreError, CoreResult};

#[derive(Debug, Clone)]
pub struct Frame {
    pub payload: Vec<u8>,
}

pub trait Framer {
    fn frame(&self, payload: &[u8]) -> CoreResult<Vec<u8>>;
    fn deframe(&self, buffer: &mut Vec<u8>) -> CoreResult<Option<Frame>>;
}

#[derive(Debug, Clone)]
pub struct LengthPrefixedFramer {
    len_bytes: usize,
    max_frame: usize,
}

impl LengthPrefixedFramer {
    pub fn new(len_bytes: usize, max_frame: usize) -> CoreResult<Self> {
        if len_bytes != 2 && len_bytes != 4 {
            return Err(CoreError::Parse(
                "length prefix must be 2 or 4 bytes".to_string(),
            ));
        }
        Ok(Self {
            len_bytes,
            max_frame,
        })
    }

    fn parse_len(&self, bytes: &[u8]) -> usize {
        match self.len_bytes {
            2 => u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
            4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            _ => 0,
        }
    }

    fn write_len(&self, len: usize) -> CoreResult<Vec<u8>> {
        match self.len_bytes {
            2 => {
                if len > u16::MAX as usize {
                    return Err(CoreError::Parse("frame too large for u16".to_string()));
                }
                Ok((len as u16).to_be_bytes().to_vec())
            }
            4 => {
                if len > u32::MAX as usize {
                    return Err(CoreError::Parse("frame too large for u32".to_string()));
                }
                Ok((len as u32).to_be_bytes().to_vec())
            }
            _ => Err(CoreError::Parse("invalid length prefix".to_string())),
        }
    }
}

impl Framer for LengthPrefixedFramer {
    fn frame(&self, payload: &[u8]) -> CoreResult<Vec<u8>> {
        if payload.len() > self.max_frame {
            return Err(CoreError::Parse("payload exceeds max frame".to_string()));
        }
        let mut out = self.write_len(payload.len())?;
        out.extend_from_slice(payload);
        Ok(out)
    }

    fn deframe(&self, buffer: &mut Vec<u8>) -> CoreResult<Option<Frame>> {
        if buffer.len() < self.len_bytes {
            return Ok(None);
        }
        let len = self.parse_len(&buffer[..self.len_bytes]);
        if len > self.max_frame {
            return Err(CoreError::Parse("frame exceeds max size".to_string()));
        }
        let total = self.len_bytes + len;
        if buffer.len() < total {
            return Ok(None);
        }
        let payload = buffer[self.len_bytes..total].to_vec();
        buffer.drain(..total);
        Ok(Some(Frame { payload }))
    }
}

#[derive(Debug, Clone)]
pub struct DelimiterFramer {
    delimiter: Vec<u8>,
    max_frame: usize,
}

impl DelimiterFramer {
    pub fn new(delimiter: &[u8], max_frame: usize) -> CoreResult<Self> {
        if delimiter.is_empty() {
            return Err(CoreError::Parse("delimiter cannot be empty".to_string()));
        }
        Ok(Self {
            delimiter: delimiter.to_vec(),
            max_frame,
        })
    }
}

impl Framer for DelimiterFramer {
    fn frame(&self, payload: &[u8]) -> CoreResult<Vec<u8>> {
        if payload.len() + self.delimiter.len() > self.max_frame {
            return Err(CoreError::Parse("payload exceeds max frame".to_string()));
        }
        let mut out = Vec::with_capacity(payload.len() + self.delimiter.len());
        out.extend_from_slice(payload);
        out.extend_from_slice(&self.delimiter);
        Ok(out)
    }

    fn deframe(&self, buffer: &mut Vec<u8>) -> CoreResult<Option<Frame>> {
        if buffer.len() > self.max_frame {
            return Err(CoreError::Parse("frame exceeds max size".to_string()));
        }
        if let Some(pos) = buffer
            .windows(self.delimiter.len())
            .position(|w| w == self.delimiter.as_slice())
        {
            let payload = buffer[..pos].to_vec();
            let drain_len = pos + self.delimiter.len();
            buffer.drain(..drain_len);
            return Ok(Some(Frame { payload }));
        }
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct FixedSizeFramer {
    size: usize,
}

impl FixedSizeFramer {
    pub fn new(size: usize) -> CoreResult<Self> {
        if size == 0 {
            return Err(CoreError::Parse("size must be > 0".to_string()));
        }
        Ok(Self { size })
    }
}

impl Framer for FixedSizeFramer {
    fn frame(&self, payload: &[u8]) -> CoreResult<Vec<u8>> {
        if payload.len() != self.size {
            return Err(CoreError::Parse("payload size mismatch".to_string()));
        }
        Ok(payload.to_vec())
    }

    fn deframe(&self, buffer: &mut Vec<u8>) -> CoreResult<Option<Frame>> {
        if buffer.len() < self.size {
            return Ok(None);
        }
        let payload = buffer[..self.size].to_vec();
        buffer.drain(..self.size);
        Ok(Some(Frame { payload }))
    }
}
