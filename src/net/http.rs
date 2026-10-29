//! Minimal HTTP/1.x message reading for the interception proxy.
//!
//! Messages are read fully into memory (the proxy re-originates each
//! request), which keeps framing simple and lets us capture bodies. Reading
//! is bounded so a hostile or runaway peer cannot exhaust memory.

use std::io::{self, BufRead, Read};

/// Maximum size of a request/response head (start line + headers).
const MAX_HEAD: usize = 256 * 1024;
/// Hard cap on a body we will buffer while proxying.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.remove(name);
        self.0.push((name.to_owned(), value.into()));
    }

    pub fn content_length(&self) -> Option<u64> {
        self.get("content-length")?.trim().parse().ok()
    }

    pub fn is_chunked(&self) -> bool {
        self.get("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    }
}

/// How a message body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyMode {
    /// A request or response with a known length.
    Length(u64),
    Chunked,
    /// A response body that runs until the connection closes.
    UntilClose,
    /// No body (e.g. GET request, 204/304 response).
    Empty,
}

fn read_head(reader: &mut impl BufRead) -> io::Result<Option<(String, Headers)>> {
    let mut head = Vec::new();
    loop {
        let before = head.len();
        let mut line = Vec::new();
        let n = reader
            .by_ref()
            .take((MAX_HEAD - before + 2) as u64)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return if head.is_empty() {
                Ok(None) // clean EOF between messages
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated head"))
            };
        }
        let is_blank = matches!(line.as_slice(), b"\r\n" | b"\n");
        head.extend_from_slice(&line);
        if is_blank {
            break;
        }
        if head.len() >= MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "header too large"));
        }
    }

    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let start_line = lines.next().unwrap_or("").to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    Ok(Some((start_line, Headers(headers))))
}

fn read_chunked(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut line = String::new();
        reader.by_ref().take(64).read_line(&mut line)?;
        let size_hex = line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            // Consume trailers up to the final blank line.
            loop {
                let mut trailer = String::new();
                let n = reader.by_ref().take(8192).read_line(&mut trailer)?;
                if n == 0 || matches!(trailer.as_str(), "\r\n" | "\n") {
                    break;
                }
            }
            return Ok(body);
        }
        if body.len() + size > MAX_BODY {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
}

fn read_body(reader: &mut impl BufRead, mode: BodyMode) -> io::Result<Vec<u8>> {
    match mode {
        BodyMode::Empty => Ok(Vec::new()),
        BodyMode::Length(len) => {
            if len > MAX_BODY as u64 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
            }
            let mut body = vec![0u8; len as usize];
            reader.read_exact(&mut body)?;
            Ok(body)
        }
        BodyMode::Chunked => read_chunked(reader),
        BodyMode::UntilClose => {
            let mut body = Vec::new();
            reader.by_ref().take(MAX_BODY as u64).read_to_end(&mut body)?;
            Ok(body)
        }
    }
}

/// A parsed request from the client.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Request {
    /// Reads one request, or `None` at a clean end of stream.
    pub fn read(reader: &mut impl BufRead) -> io::Result<Option<Request>> {
        let Some((start_line, headers)) = read_head(reader)? else {
            return Ok(None);
        };
        let mut parts = start_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let target = parts.next().unwrap_or_default().to_owned();
        let version = parts.next().unwrap_or("HTTP/1.1").to_owned();
        if method.is_empty() || target.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request line"));
        }
        let mode = if headers.is_chunked() {
            BodyMode::Chunked
        } else {
            match headers.content_length() {
                Some(len) => BodyMode::Length(len),
                None => BodyMode::Empty,
            }
        };
        let body = read_body(reader, mode)?;
        Ok(Some(Request {
            method,
            target,
            version,
            headers,
            body,
        }))
    }
}

/// A parsed response from the origin server.
#[derive(Debug, Clone)]
pub struct Response {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl Response {
    pub fn read(reader: &mut impl BufRead, request_method: &str) -> io::Result<Response> {
        let (start_line, headers) = read_head(reader)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no response"))?;
        let mut parts = start_line.splitn(3, ' ');
        let version = parts.next().unwrap_or("HTTP/1.1").to_owned();
        let status: u16 = parts
            .next()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status"))?;
        let reason = parts.next().unwrap_or("").trim().to_owned();

        // RFC 7230: HEAD and 1xx/204/304 never have a body.
        let bodyless = request_method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&status)
            || status == 204
            || status == 304;
        let mode = if bodyless {
            BodyMode::Empty
        } else if headers.is_chunked() {
            BodyMode::Chunked
        } else {
            match headers.content_length() {
                Some(len) => BodyMode::Length(len),
                None => BodyMode::UntilClose,
            }
        };
        let body = read_body(reader, mode)?;
        Ok(Response {
            version,
            status,
            reason,
            headers,
            body,
        })
    }
}

/// Serializes a head (start line + headers) followed by `\r\n`, with a
/// normalized `Content-Length` and no hop-by-hop framing headers.
pub fn serialize_head(
    start_line: &str,
    headers: &Headers,
    body_len: usize,
    keep_alive: bool,
) -> Vec<u8> {
    let mut out = format!("{start_line}\r\n");
    for (name, value) in &headers.0 {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "transfer-encoding" | "content-length" | "connection" | "proxy-connection"
        ) {
            continue;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {body_len}\r\n"));
    out.push_str(if keep_alive {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    out.into_bytes()
}

/// Decodes a body for display per `Content-Encoding` (gzip / deflate).
/// Returns the decoded bytes and the encoding name, or the original bytes.
pub fn decode_for_display(headers: &Headers, body: &[u8]) -> (Vec<u8>, Option<String>) {
    let Some(encoding) = headers.get("content-encoding") else {
        return (body.to_vec(), None);
    };
    let encoding = encoding.trim().to_ascii_lowercase();
    let decoded = match encoding.as_str() {
        "gzip" | "x-gzip" => inflate(flate2::read::GzDecoder::new(body)),
        "deflate" => inflate(flate2::read::ZlibDecoder::new(body))
            .or_else(|| inflate(flate2::read::DeflateDecoder::new(body))),
        _ => return (body.to_vec(), Some(encoding)),
    };
    match decoded {
        Some(bytes) => (bytes, Some(encoding)),
        None => (body.to_vec(), Some(format!("{encoding} (undecodable)"))),
    }
}

fn inflate(mut reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .by_ref()
        .take(MAX_BODY as u64)
        .read_to_end(&mut out)
        .ok()
        .map(|_| out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Write};

    fn request(bytes: &[u8]) -> Option<Request> {
        Request::read(&mut BufReader::new(bytes)).unwrap()
    }

    #[test]
    fn reads_request_with_length() {
        let r = request(b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap();
        assert_eq!((r.method.as_str(), r.target.as_str()), ("POST", "/api"));
        assert_eq!(r.headers.get("host"), Some("x"));
        assert_eq!(r.body, b"hello");
    }

    #[test]
    fn get_without_body_then_next_request() {
        let mut reader = BufReader::new(
            &b"GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: y\r\n\r\n"[..],
        );
        assert_eq!(Request::read(&mut reader).unwrap().unwrap().target, "/a");
        assert_eq!(Request::read(&mut reader).unwrap().unwrap().target, "/b");
        assert!(Request::read(&mut reader).unwrap().is_none());
    }

    #[test]
    fn reads_chunked_response() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                   5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = Response::read(&mut BufReader::new(raw.as_bytes()), "GET").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello world");
    }

    #[test]
    fn response_framing_rules() {
        // 204 has no body even with following bytes.
        let mut reader = BufReader::new(&b"HTTP/1.1 204 No Content\r\n\r\nNEXT"[..]);
        let r = Response::read(&mut reader, "GET").unwrap();
        assert!(r.body.is_empty());
        // HEAD response: headers only.
        let r = Response::read(
            &mut BufReader::new(&b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"[..]),
            "HEAD",
        )
        .unwrap();
        assert!(r.body.is_empty());
        // Until close.
        let r = Response::read(
            &mut BufReader::new(&b"HTTP/1.1 200 OK\r\n\r\nstreamed data"[..]),
            "GET",
        )
        .unwrap();
        assert_eq!(r.body, b"streamed data");
    }

    #[test]
    fn serialize_normalizes_framing() {
        let mut headers = Headers::default();
        headers.set("Transfer-Encoding", "chunked");
        headers.set("Host", "x");
        headers.set("Connection", "keep-alive");
        let head = serialize_head("GET /a HTTP/1.1", &headers, 3, false);
        let text = String::from_utf8(head).unwrap();
        assert!(text.contains("Host: x\r\n"));
        assert!(!text.to_lowercase().contains("transfer-encoding"));
        assert!(text.contains("Content-Length: 3\r\n"));
        assert!(text.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn decodes_gzip() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"decompressed!").unwrap();
        let gz = enc.finish().unwrap();
        let mut headers = Headers::default();
        headers.set("Content-Encoding", "gzip");
        let (body, enc) = decode_for_display(&headers, &gz);
        assert_eq!(body, b"decompressed!");
        assert_eq!(enc.as_deref(), Some("gzip"));
    }

    #[test]
    fn rejects_oversized_and_truncated() {
        assert!(
            Request::read(&mut BufReader::new(
                &b"POST / HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\n"[..]
            ))
            .is_err()
        );
        assert!(Request::read(&mut BufReader::new(&b"GET"[..])).is_err());
    }
}
