//! Minimal, self-contained JSON parser and serializer for the AI agent APIs.

use std::fmt::Write;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn str(s: impl Into<String>) -> Self {
        JsonValue::Str(s.into())
    }

    pub fn obj(fields: impl IntoIterator<Item = (impl Into<String>, JsonValue)>) -> Self {
        JsonValue::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    pub fn arr(items: impl IntoIterator<Item = JsonValue>) -> Self {
        JsonValue::Array(items.into_iter().collect())
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64().and_then(|n| {
            if n >= 0.0 && n.is_finite() {
                Some(n as u64)
            } else {
                None
            }
        })
    }

    pub fn as_usize(&self) -> Option<usize> {
        self.as_u64().map(|n| n as usize)
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn to_json_string(&self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        out
    }

    fn write_to(&self, out: &mut String) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(true) => out.push_str("true"),
            JsonValue::Bool(false) => out.push_str("false"),
            JsonValue::Number(n) => {
                if n.is_finite() {
                    if n.fract() == 0.0 && n.abs() < (1i64 << 53) as f64 {
                        let _ = write!(out, "{}", *n as i64);
                    } else {
                        let _ = write!(out, "{n}");
                    }
                } else {
                    out.push_str("null");
                }
            }
            JsonValue::Str(s) => write_escaped_str(out, s),
            JsonValue::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_to(out);
                }
                out.push(']');
            }
            JsonValue::Object(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped_str(out, k);
                    out.push(':');
                    v.write_to(out);
                }
                out.push('}');
            }
        }
    }

    pub fn parse(input: &str) -> Result<JsonValue, String> {
        let mut parser = Parser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        let value = parser.parse_value(0)?;
        parser.skip_ws();
        if parser.pos < parser.bytes.len() {
            return Err(format!("unexpected trailing characters at byte {}", parser.pos));
        }
        Ok(value)
    }
}

fn write_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

const MAX_DEPTH: usize = 128;

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_DEPTH {
            return Err("JSON nesting too deep".to_owned());
        }
        self.skip_ws();
        let Some(b) = self.peek() else {
            return Err("unexpected end of JSON".to_owned());
        };
        match b {
            b'n' => self.parse_literal(b"null", JsonValue::Null),
            b't' => self.parse_literal(b"true", JsonValue::Bool(true)),
            b'f' => self.parse_literal(b"false", JsonValue::Bool(false)),
            b'"' => self.parse_string().map(JsonValue::Str),
            b'[' => self.parse_array(depth + 1),
            b'{' => self.parse_object(depth + 1),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(format!("unexpected byte '{}' at {}", b as char, self.pos)),
        }
    }

    fn parse_literal(&mut self, lit: &[u8], value: JsonValue) -> Result<JsonValue, String> {
        if self.bytes.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at {}", self.pos))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err(format!("expected '\"' at {}", self.pos));
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = *self
                    .bytes
                    .get(self.pos)
                    .ok_or_else(|| "unterminated escape".to_owned())?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{08}'),
                    b'f' => out.push('\u{0c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hi = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&hi) {
                            // High surrogate: check for following \uXXXX low surrogate.
                            if self.bytes.get(self.pos..self.pos + 2) == Some(b"\\u") {
                                self.pos += 2;
                                let lo = self.parse_hex4()?;
                                if (0xDC00..=0xDFFF).contains(&lo) {
                                    let cp = 0x10000
                                        + (((hi as u32 - 0xD800) << 10)
                                            | (lo as u32 - 0xDC00));
                                    if let Some(ch) = char::from_u32(cp) {
                                        out.push(ch);
                                        continue;
                                    }
                                }
                            }
                            out.push(char::REPLACEMENT_CHARACTER);
                        } else if let Some(ch) = char::from_u32(hi as u32) {
                            out.push(ch);
                        } else {
                            out.push(char::REPLACEMENT_CHARACTER);
                        }
                    }
                    other => out.push(other as char),
                }
            } else {
                // Consume a slice of unescaped UTF-8 bytes up to the next '"' or '\\'.
                let start = self.pos;
                while let Some(&c) = self.bytes.get(self.pos) {
                    if c == b'"' || c == b'\\' {
                        break;
                    }
                    self.pos += 1;
                }
                let s = std::str::from_utf8(&self.bytes[start..self.pos])
                    .map_err(|e| format!("invalid UTF-8 in JSON string: {e}"))?;
                out.push_str(s);
            }
        }
        Err("unterminated JSON string".to_owned())
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        let slice = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| "truncated \\u escape".to_owned())?;
        let s = std::str::from_utf8(slice).map_err(|_| "invalid \\u escape".to_owned())?;
        let val = u16::from_str_radix(s, 16).map_err(|_| "invalid hex in \\u escape".to_owned())?;
        self.pos += 4;
        Ok(val)
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        while let Some(&b) = self.bytes.get(self.pos) {
            if matches!(b, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number".to_owned())?;
        let n: f64 = s
            .parse()
            .map_err(|_| format!("invalid number '{s}' at {start}"))?;
        Ok(JsonValue::Number(n))
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, String> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            entries.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(entries));
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_nested_json_and_surrogates() {
        let value = JsonValue::obj([
            ("provider", JsonValue::str("grok")),
            ("enabled", JsonValue::Bool(true)),
            ("count", JsonValue::Number(42.0)),
            (
                "messages",
                JsonValue::arr([JsonValue::obj([
                    ("role", JsonValue::str("user")),
                    ("content", JsonValue::str("Line 1\n\"quoted\"\t🚀")),
                ])]),
            ),
        ]);
        let serialized = value.to_json_string();
        let parsed = JsonValue::parse(&serialized).unwrap();
        assert_eq!(parsed, value);

        let emoji = JsonValue::parse(r#"{"text": "hello \uD83D\uDE80 world"}"#).unwrap();
        assert_eq!(emoji.get("text").and_then(JsonValue::as_str), Some("hello 🚀 world"));
    }
}

