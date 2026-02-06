use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

#[derive(Debug, Clone)]
pub struct JsonError {
    pub message: String,
    pub offset: usize,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at offset {}", self.message, self.offset)
    }
}

impl std::error::Error for JsonError {}

pub fn parse_json(input: &str) -> Result<JsonValue, JsonError> {
    let mut parser = Parser::new(input);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if !parser.eof() {
        return Err(parser.error("trailing data"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Parser {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(self.error("unexpected character")),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn parse_literal(&mut self, literal: &[u8], value: JsonValue) -> Result<JsonValue, JsonError> {
        for &b in literal {
            let next = self
                .next()
                .ok_or_else(|| self.error("unexpected end of input"))?;
            if next != b {
                return Err(self.error("invalid literal"));
            }
        }
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        if self.next() != Some(b'\"') {
            return Err(self.error("expected '\"'"));
        }
        let mut out = String::new();
        while let Some(b) = self.next() {
            match b {
                b'"' => return Ok(out),
                b'\\' => out.push(self.parse_escape()?),
                b if b <= 0x1F => return Err(self.error("control character in string")),
                _ => out.push(b as char),
            }
        }
        Err(self.error("unterminated string"))
    }

    fn parse_escape(&mut self) -> Result<char, JsonError> {
        let esc = self
            .next()
            .ok_or_else(|| self.error("unterminated escape"))?;
        match esc {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.parse_unicode_escape(),
            _ => Err(self.error("invalid escape")),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let high = self.read_u16_hex()?;
        if (0xD800..=0xDBFF).contains(&high) {
            // Expect a low surrogate
            if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                return Err(self.error("invalid surrogate pair"));
            }
            let low = self.read_u16_hex()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(self.error("invalid surrogate pair"));
            }
            let codepoint = 0x10000 + (((high - 0xD800) as u32) << 10) + ((low - 0xDC00) as u32);
            std::char::from_u32(codepoint).ok_or_else(|| self.error("invalid codepoint"))
        } else {
            std::char::from_u32(high as u32).ok_or_else(|| self.error("invalid codepoint"))
        }
    }

    fn read_u16_hex(&mut self) -> Result<u16, JsonError> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let b = self
                .next()
                .ok_or_else(|| self.error("unterminated unicode escape"))?;
            value = (value << 4) | hex_value(b).ok_or_else(|| self.error("invalid hex"))? as u16;
        }
        Ok(value)
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        if self.next() != Some(b'[') {
            return Err(self.error("expected '['"));
        }
        let mut items = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b']') {
                self.next();
                break;
            }
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.next();
                }
                Some(b']') => {
                    self.next();
                    break;
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        if self.next() != Some(b'{') {
            return Err(self.error("expected '{'"));
        }
        let mut map = BTreeMap::new();
        loop {
            self.skip_whitespace();
            if self.peek() == Some(b'}') {
                self.next();
                break;
            }
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.next() != Some(b':') {
                return Err(self.error("expected ':'"));
            }
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.next();
                }
                Some(b'}') => {
                    self.next();
                    break;
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
        Ok(JsonValue::Object(map))
    }

    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.error("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let slice = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.error("invalid number"))?;
        let value = slice
            .parse::<f64>()
            .map_err(|_| self.error("invalid number"))?;
        Ok(JsonValue::Number(value))
    }

    fn error(&self, message: &str) -> JsonError {
        JsonError {
            message: message.to_string(),
            offset: self.pos,
        }
    }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_object() {
        let input = r#"{"name":"test","tags":["a","b"],"ok":true}"#;
        let value = parse_json(input).expect("parse");
        match value {
            JsonValue::Object(map) => {
                assert_eq!(
                    map.get("name"),
                    Some(&JsonValue::String("test".to_string()))
                );
            }
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn parse_unicode_escape() {
        let input = r#""hello \u263a""#;
        let value = parse_json(input).expect("parse");
        assert_eq!(value, JsonValue::String("hello ☺".to_string()));
    }
}
