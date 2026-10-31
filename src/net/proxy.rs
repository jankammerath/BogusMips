//! The interception proxy (transparent + explicit).
//!
//! Outbound TCP connections from the emulator are transparently redirected to
//! this proxy via `iptables -t nat` (`DNAT`), so all apps — including
//! Dart/Flutter apps and native libraries that ignore Android's system proxy —
//! are intercepted alongside clients speaking explicit HTTP/CONNECT proxy
//! framing:
//! - **Transparent HTTPS**: starts directly with a TLS `ClientHello` record
//!   (`0x16`); the proxy terminates TLS using a dynamically generated leaf
//!   certificate for the `ClientHello` SNI hostname and reads origin-form HTTP
//!   requests inside the tunnel.
//! - **Transparent HTTP**: arrives in origin-form (`GET /path HTTP/1.1` with a
//!   `Host` header).
//! - **Explicit HTTP / CONNECT**: plain HTTP in absolute form
//!   (`GET http://host/path HTTP/1.1`) and HTTPS via `CONNECT host:443`.
//!
//! Every request is re-originated to the real server so the full response can
//! be captured.

use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use super::ca::{CertAuthority, SniResolver};
use super::capture::{Capture, RequestInfo, Scheme};
use super::http::{self, Request, Response};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Opens a connection to an origin server. Abstracted so the session loop can
/// be tested without real sockets.
pub trait OriginConnector: Send + Sync {
    fn connect(&self, scheme: Scheme, authority: &str) -> io::Result<Box<dyn ReadWrite>>;
}

pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Splits `host:port` (defaulting the port by scheme) and normalizes an
/// absolute-form target to its path.
fn authority_parts(authority: &str, scheme: Scheme) -> (String, String) {
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (host.to_owned(), authority.to_owned())
        }
        _ => {
            let port = if scheme == Scheme::Https { 443 } else { 80 };
            (authority.to_owned(), format!("{authority}:{port}"))
        }
    }
}

fn origin_form(target: &str) -> String {
    match target.split_once("://") {
        Some((_, rest)) => {
            let slash = rest.find('/').unwrap_or(rest.len());
            let path = &rest[slash..];
            if path.is_empty() { "/".to_owned() } else { path.to_owned() }
        }
        None => target.to_owned(),
    }
}

/// Authority for a request given in absolute form (`http://host/path` or
/// `https://host/path`).
fn authority_from_target(target: &str) -> Option<String> {
    let (scheme_prefix, rest) = target.split_once("://")?;
    let end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..end];
    if host.is_empty() {
        return None;
    }
    Some(if host.contains(':') {
        host.to_owned()
    } else if scheme_prefix.eq_ignore_ascii_case("https") {
        format!("{host}:443")
    } else {
        format!("{host}:80")
    })
}

/// Resolves the target `host:port` authority for `req` across transparent and
/// explicit proxy modes:
/// 1. Absolute-form request target (`GET http://host:port/path HTTP/1.1`).
/// 2. HTTP `Host` header (`Host: host` or `Host: host:port`), used by
///    transparent plain-HTTP and transparent TLS connections.
/// 3. `fixed_authority` from an explicit `CONNECT host:port` tunnel or the
///    TLS `ClientHello` SNI extension.
fn resolve_authority(
    scheme: Scheme,
    fixed_authority: Option<&str>,
    req: &Request,
) -> Option<String> {
    if let Some(auth) = authority_from_target(&req.target) {
        return Some(auth);
    }
    if let Some(host_hdr) = req
        .headers
        .get("Host")
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        let (hdr_host, normalized) = authority_parts(host_hdr, scheme);
        if !host_hdr.contains(':') {
            if let Some(fixed) = fixed_authority {
                let (fixed_host, _) = authority_parts(fixed, scheme);
                if fixed_host.eq_ignore_ascii_case(&hdr_host) {
                    return Some(fixed.to_owned());
                }
            }
        }
        return Some(normalized);
    }
    fixed_authority.map(ToOwned::to_owned)
}

/// Returns `true` when the first byte on an accepted TCP stream is a TLS
/// Handshake record (`0x16`), indicating a transparent TLS/HTTPS connection
/// without an HTTP `CONNECT` preface.
fn is_tls_client_hello(first_byte: u8) -> bool {
    first_byte == 0x16
}

fn send_simple(client: &mut impl Write, status: &str, message: &str) {
    let body = message.as_bytes();
    let _ = write!(
        client,
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = client.write_all(body);
    let _ = client.flush();
}

/// Forwards one request to the origin and returns the response.
fn forward(
    connector: &dyn OriginConnector,
    scheme: Scheme,
    authority: &str,
    req: &Request,
) -> io::Result<(Response, usize)> {
    let (host, _) = authority_parts(authority, scheme);
    let mut origin = connector.connect(scheme, authority)?;

    let mut headers = req.headers.clone();
    headers.set("Host", host);
    let path = origin_form(&req.target);
    let head = http::serialize_head(
        &format!("{} {path} HTTP/1.1", req.method),
        &headers,
        req.body.len(),
        false,
    );
    origin.write_all(&head)?;
    origin.write_all(&req.body)?;
    origin.flush()?;

    let mut reader = BufReader::new(origin);
    let resp = Response::read(&mut reader, &req.method)?;
    let wire = resp.body.len() + 256;
    Ok((resp, wire))
}

/// Reads requests from an accepted client connection and proxies each one,
/// keeping the connection alive. `fixed_authority` is set for MITM'd HTTPS
/// (from `CONNECT` or the TLS `ClientHello` SNI); transparent and explicit
/// HTTP (or SNI-less TLS) derive the authority from the request target or
/// `Host` header.
pub fn run_session<S: Read + Write>(
    stream: S,
    scheme: Scheme,
    fixed_authority: Option<String>,
    first: Option<Request>,
    connector: &dyn OriginConnector,
    capture: &Capture,
) {
    let mut reader = BufReader::new(stream);
    let mut pending = first;
    loop {
        let req = match pending.take() {
            Some(req) => req,
            None => match Request::read(&mut reader) {
                Ok(Some(req)) => req,
                Ok(None) => break,
                Err(_) => break,
            },
        };

        let Some(authority) = resolve_authority(scheme, fixed_authority.as_deref(), &req) else {
            send_simple(
                reader.get_mut(),
                "400 Bad Request",
                "Missing Host header or target authority",
            );
            break;
        };

        let info = RequestInfo::from_request(scheme, &authority, &req, req.body.len() + 256);
        let pending_flow = capture.start(&info);

        match forward(connector, scheme, &authority, &req) {
            Ok((resp, wire)) => {
                capture.finish_response(&pending_flow, &resp, wire);
                let head = http::serialize_head(
                    &format!("{} {} {}", resp.version, resp.status, resp.reason),
                    &resp.headers,
                    resp.body.len(),
                    true,
                );
                if reader.get_mut().write_all(&head).is_err()
                    || reader.get_mut().write_all(&resp.body).is_err()
                    || reader.get_mut().flush().is_err()
                {
                    break;
                }
            }
            Err(e) => {
                capture.finish_error(&pending_flow, e.to_string());
                send_simple(reader.get_mut(), "502 Bad Gateway", &format!("Proxy error: {e}"));
                break;
            }
        }
    }
}

/// Connects to real origin servers, using TLS (with the system/webpki roots)
/// for HTTPS.
struct NetConnector {
    client_config: Arc<ClientConfig>,
}

impl NetConnector {
    fn new() -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            client_config: Arc::new(config),
        }
    }
}

impl OriginConnector for NetConnector {
    fn connect(&self, scheme: Scheme, authority: &str) -> io::Result<Box<dyn ReadWrite>> {
        let (host, addr) = authority_parts(authority, scheme);
        let tcp = TcpStream::connect(&addr)?;
        tcp.set_read_timeout(Some(IO_TIMEOUT))?;
        tcp.set_write_timeout(Some(IO_TIMEOUT))?;
        match scheme {
            Scheme::Http => Ok(Box::new(tcp)),
            Scheme::Https => {
                let server_name = ServerName::try_from(host)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
                    .to_owned();
                let conn = ClientConnection::new(self.client_config.clone(), server_name)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                Ok(Box::new(StreamOwned::new(conn, tcp)))
            }
        }
    }
}

/// A running proxy. Dropping it (or calling [`Proxy::stop`]) stops accepting.
pub struct Proxy {
    addr: SocketAddr,
    running: Arc<AtomicBool>,
    capture: Arc<Capture>,
}

impl Proxy {
    /// Binds to `127.0.0.1` (reachable from the emulator as `10.0.2.2`) and
    /// starts accepting in a background thread.
    pub fn start(ca: Arc<CertAuthority>, capture: Arc<Capture>) -> io::Result<Proxy> {
        Self::start_with_connector(ca, capture, Arc::new(NetConnector::new()))
    }

    /// Like [`Proxy::start`] but with a custom origin connector (for tests).
    pub fn start_with_connector(
        ca: Arc<CertAuthority>,
        capture: Arc<Capture>,
        connector: Arc<dyn OriginConnector>,
    ) -> io::Result<Proxy> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver(ca)));
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_config = Arc::new(server_config);
        let running = Arc::new(AtomicBool::new(true));

        let ctx = Arc::new(ProxyThreads {
            server_config,
            connector,
            capture: capture.clone(),
            running: running.clone(),
            active: Mutex::new(0),
        });
        std::thread::spawn(move || accept_loop(listener, ctx));

        Ok(Proxy {
            addr,
            running,
            capture,
        })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn capture(&self) -> &Arc<Capture> {
        &self.capture
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ProxyThreads {
    server_config: Arc<ServerConfig>,
    connector: Arc<dyn OriginConnector>,
    capture: Arc<Capture>,
    running: Arc<AtomicBool>,
    active: Mutex<usize>,
}

fn accept_loop(listener: TcpListener, ctx: Arc<ProxyThreads>) {
    while ctx.running.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Bound the number of concurrent connections.
                {
                    let mut active = ctx.active.lock().unwrap();
                    if *active >= 256 {
                        continue;
                    }
                    *active += 1;
                }
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    // Accepted sockets inherit the listener's non-blocking
                    // flag on some platforms; restore blocking I/O.
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                    handle_connection(stream, &ctx);
                    *ctx.active.lock().unwrap() -= 1;
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(mut stream: TcpStream, ctx: &ProxyThreads) {
    let mut first_byte = [0u8; 1];
    match stream.peek(&mut first_byte) {
        Ok(1) if is_tls_client_hello(first_byte[0]) => {
            // Transparent TLS/HTTPS connection (e.g. Dart/Flutter or native
            // socket redirected via iptables DNAT without a CONNECT tunnel).
            let mut conn = match ServerConnection::new(ctx.server_config.clone()) {
                Ok(conn) => conn,
                Err(_) => return,
            };
            while conn.is_handshaking() {
                if conn.complete_io(&mut stream).is_err() {
                    return;
                }
            }
            let authority = conn.server_name().map(|host| format!("{host}:443"));
            let tls = StreamOwned::new(conn, stream);
            run_session(
                tls,
                Scheme::Https,
                authority,
                None,
                ctx.connector.as_ref(),
                &ctx.capture,
            );
            return;
        }
        Ok(1) => {}
        _ => return,
    }

    let mut reader = BufReader::new(stream);
    let first = match Request::read(&mut reader) {
        Ok(Some(req)) => req,
        _ => return,
    };

    if first.method.eq_ignore_ascii_case("CONNECT") {
        let authority = first.target.clone();
        if reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        let tcp = reader.into_inner();
        let conn = match ServerConnection::new(ctx.server_config.clone()) {
            Ok(conn) => conn,
            Err(_) => return,
        };
        let tls = StreamOwned::new(conn, tcp);
        run_session(
            tls,
            Scheme::Https,
            Some(authority),
            None,
            ctx.connector.as_ref(),
            &ctx.capture,
        );
    } else {
        let stream = reader.into_inner();
        run_session(
            stream,
            Scheme::Http,
            None,
            Some(first),
            ctx.connector.as_ref(),
            &ctx.capture,
        );
    }
}

/// Connects a TCP stream to `addr`, used when configuring the emulator.
pub fn probe(addr: SocketAddr) -> io::Result<()> {
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;

    type OriginLog = Arc<Mutex<Vec<(Scheme, String, Vec<u8>)>>>;

    /// A client stream: serves a fixed request buffer, collects the proxy's
    /// reply.
    struct MockClient {
        read: Cursor<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for MockClient {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read.read(buf)
        }
    }
    impl Write for MockClient {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// An origin that serves a canned response and logs the request bytes.
    struct OriginMock {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
        scheme: Scheme,
        authority: String,
        log: OriginLog,
    }
    impl Read for OriginMock {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read.read(buf)
        }
    }
    impl Write for OriginMock {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for OriginMock {
        fn drop(&mut self) {
            self.log
                .lock()
                .unwrap()
                .push((self.scheme, self.authority.clone(), std::mem::take(&mut self.written)));
        }
    }

    struct FakeConnector {
        response: Vec<u8>,
        fail: bool,
        log: OriginLog,
    }
    impl OriginConnector for FakeConnector {
        fn connect(&self, scheme: Scheme, authority: &str) -> io::Result<Box<dyn ReadWrite>> {
            if self.fail {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"));
            }
            Ok(Box::new(OriginMock {
                read: Cursor::new(self.response.clone()),
                written: Vec::new(),
                scheme,
                authority: authority.to_owned(),
                log: self.log.clone(),
            }))
        }
    }

    fn connector(response: &str) -> FakeConnector {
        FakeConnector {
            response: response.as_bytes().to_vec(),
            fail: false,
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn run(
        requests: &str,
        scheme: Scheme,
        fixed: Option<&str>,
        connector: &FakeConnector,
    ) -> (Capture, String) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let client = MockClient {
            read: Cursor::new(requests.as_bytes().to_vec()),
            written: written.clone(),
        };
        let capture = Capture::new();
        run_session(
            client,
            scheme,
            fixed.map(str::to_owned),
            None,
            connector,
            &capture,
        );
        let reply = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        (capture, reply)
    }

    #[test]
    fn proxies_plain_http_absolute_form() {
        let c = connector("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        let (capture, reply) = run(
            "GET http://api.test/a?b=1 HTTP/1.1\r\nHost: api.test\r\nUser-Agent: ua\r\n\r\n",
            Scheme::Http,
            None,
            &c,
        );
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.method, "GET");
        assert_eq!(flow.url(), "http://api.test/a?b=1");
        assert_eq!(flow.status, Some(200));
        assert_eq!(flow.resp_body, b"hi");
        assert!(reply.contains("200 OK") && reply.ends_with("hi"));
        // The origin received an origin-form request with the right Host.
        let (scheme, authority, bytes) = &c.log.lock().unwrap()[0];
        assert_eq!((*scheme, authority.as_str()), (Scheme::Http, "api.test:80"));
        let sent = String::from_utf8_lossy(bytes);
        assert!(sent.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(sent.contains("Host: api.test\r\n") && sent.contains("User-Agent: ua"));
    }

    #[test]
    fn proxies_mitm_https_origin_form() {
        let c = connector("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
        let (capture, reply) = run(
            "POST /login HTTP/1.1\r\nHost: api.test\r\nContent-Length: 4\r\n\r\nbody",
            Scheme::Https,
            Some("api.test:443"),
            &c,
        );
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.url(), "https://api.test/login");
        assert_eq!(flow.req_body, b"body");
        assert_eq!(flow.status, Some(201));
        assert!(reply.contains("201 Created"));
        let (scheme, authority, _) = &c.log.lock().unwrap()[0];
        assert_eq!((*scheme, authority.as_str()), (Scheme::Https, "api.test:443"));
    }

    #[test]
    fn keeps_connection_alive_for_multiple_requests() {
        let c = connector("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx");
        let (capture, reply) = run(
            "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n",
            Scheme::Https,
            Some("h:443"),
            &c,
        );
        let flows = capture.snapshot();
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].path, "/a");
        assert_eq!(flows[1].path, "/b");
        assert_eq!(reply.matches("200 OK").count(), 2);
        assert_eq!(c.log.lock().unwrap().len(), 2);
    }

    #[test]
    fn records_origin_errors_as_502() {
        let mut c = connector("");
        c.fail = true;
        let (capture, reply) = run(
            "GET /x HTTP/1.1\r\nHost: h\r\n\r\n",
            Scheme::Https,
            Some("h:443"),
            &c,
        );
        assert!(reply.contains("502 Bad Gateway"));
        assert!(capture.snapshot()[0].error.as_deref().unwrap().contains("refused"));
    }

    #[test]
    fn mitm_https_connect_is_decrypted() {
        use super::super::ca::CertAuthority;
        use rustls::pki_types::{CertificateDer, ServerName};
        use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
        use std::net::TcpStream;

        // Origin is faked, so the test is hermetic; the client<->proxy TLS is
        // real and must be decryptable with our CA.
        let ca = Arc::new(CertAuthority::new().unwrap());
        let capture = Arc::new(Capture::new());
        let connector = Arc::new(FakeConnector {
            response: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
                .to_vec(),
            fail: false,
            log: Arc::new(Mutex::new(Vec::new())),
        });
        let proxy =
            Proxy::start_with_connector(ca.clone(), capture.clone(), connector.clone()).unwrap();

        // Client trusts our CA.
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der().to_vec()))
            .unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let mut tcp = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // CONNECT to establish the tunnel.
        write!(tcp, "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 128];
        let n = tcp.read(&mut buf).unwrap();
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("200"),
            "no tunnel established"
        );

        // TLS over the tunnel, with SNI; the proxy presents a leaf for the host.
        let name = ServerName::try_from("api.example.com").unwrap();
        let conn = ClientConnection::new(client_config, name).unwrap();
        let mut tls = StreamOwned::new(conn, tcp);
        write!(tls, "GET /data HTTP/1.1\r\nHost: api.example.com\r\n\r\n").unwrap();
        let mut reply = Vec::new();
        let mut chunk = [0u8; 256];
        for _ in 0..10 {
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(k) => {
                    reply.extend_from_slice(&chunk[..k]);
                    if reply.windows(5).any(|w| w == b"hello") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let reply = String::from_utf8_lossy(&reply);
        assert!(reply.contains("200 OK") && reply.contains("hello"), "{reply}");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while capture.is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.scheme, Scheme::Https);
        assert_eq!(flow.url(), "https://api.example.com/data");
        assert_eq!(flow.status, Some(200));
        assert_eq!(flow.resp_body, b"hello");
    }

    #[test]
    fn end_to_end_plain_http_through_real_proxy() {
        use std::net::TcpStream;
        // A tiny origin server that replies once.
        let origin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = origin.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello",
                );
            }
        });

        let ca = Arc::new(CertAuthority::new().unwrap());
        let capture = Arc::new(Capture::new());
        let proxy = Proxy::start(ca, capture.clone()).unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{origin_port}/hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        let mut reply = Vec::new();
        // Read until the origin's keep-alive response arrives.
        let mut buf = [0u8; 512];
        for _ in 0..10 {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    reply.extend_from_slice(&buf[..n]);
                    if reply.windows(5).any(|w| w == b"hello") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let reply = String::from_utf8_lossy(&reply);
        assert!(reply.contains("200 OK") && reply.contains("hello"), "{reply}");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while capture.is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.status, Some(200));
        assert_eq!(flow.resp_headers.get("x-test"), Some("yes"));
        assert_eq!(flow.path, "/hello");
    }

    #[test]
    fn proxies_transparent_plain_http_origin_form_via_host_header() {
        let c = connector("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndart");
        let (capture, reply) = run(
            "GET /v1/flutter?x=1 HTTP/1.1\r\nHost: api.flutter.dev\r\nUser-Agent: Dart/3.5 (dart:io)\r\n\r\n",
            Scheme::Http,
            None,
            &c,
        );
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.method, "GET");
        assert_eq!(flow.url(), "http://api.flutter.dev/v1/flutter?x=1");
        assert_eq!(flow.status, Some(200));
        assert_eq!(flow.resp_body, b"dart");
        assert!(reply.contains("200 OK") && reply.ends_with("dart"));
        let (scheme, authority, bytes) = &c.log.lock().unwrap()[0];
        assert_eq!((*scheme, authority.as_str()), (Scheme::Http, "api.flutter.dev:80"));
        let sent = String::from_utf8_lossy(bytes);
        assert!(sent.starts_with("GET /v1/flutter?x=1 HTTP/1.1\r\n"));
        assert!(sent.contains("Host: api.flutter.dev\r\n"));
    }

    #[test]
    fn transparent_https_tls_without_connect_is_decrypted() {
        use super::super::ca::CertAuthority;
        use rustls::pki_types::{CertificateDer, ServerName};
        use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
        use std::net::TcpStream;

        let ca = Arc::new(CertAuthority::new().unwrap());
        let capture = Arc::new(Capture::new());
        let connector = Arc::new(FakeConnector {
            response: b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Type: text/plain\r\n\r\nflutter"
                .to_vec(),
            fail: false,
            log: Arc::new(Mutex::new(Vec::new())),
        });
        let proxy =
            Proxy::start_with_connector(ca.clone(), capture.clone(), connector.clone()).unwrap();

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der().to_vec()))
            .unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        // Connect directly and speak TLS (SNI = pub.dev) WITHOUT sending an
        // HTTP CONNECT preface — simulating a Dart/Flutter socket redirected
        // by iptables DNAT.
        let tcp = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let name = ServerName::try_from("pub.dev").unwrap();
        let conn = ClientConnection::new(client_config, name).unwrap();
        let mut tls = StreamOwned::new(conn, tcp);
        write!(
            tls,
            "GET /api/packages/http HTTP/1.1\r\nHost: pub.dev\r\nUser-Agent: Dart/3.5\r\n\r\n"
        )
        .unwrap();

        let mut reply = Vec::new();
        let mut chunk = [0u8; 256];
        for _ in 0..10 {
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(k) => {
                    reply.extend_from_slice(&chunk[..k]);
                    if reply.windows(7).any(|w| w == b"flutter") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let reply = String::from_utf8_lossy(&reply);
        assert!(reply.contains("200 OK") && reply.contains("flutter"), "{reply}");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while capture.is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.scheme, Scheme::Https);
        assert_eq!(flow.url(), "https://pub.dev/api/packages/http");
        assert_eq!(flow.status, Some(200));
        assert_eq!(flow.resp_body, b"flutter");
    }

    #[test]
    fn transparent_tls_handshake_and_sni_routing_works_in_memory() {
        use super::super::ca::CertAuthority;
        use rustls::pki_types::{CertificateDer, ServerName};
        use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

        let ca = Arc::new(CertAuthority::new().unwrap());
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniResolver(ca.clone())));
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_config = Arc::new(server_config);

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der().to_vec()))
            .unwrap();
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let name = ServerName::try_from("api.flutter.dev").unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), name).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();

        // First client flight starts with 0x16 (TLS Handshake ClientHello).
        let mut client_hello = Vec::new();
        client.write_tls(&mut client_hello).unwrap();
        assert!(is_tls_client_hello(client_hello[0]));

        server.read_tls(&mut client_hello.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        for _ in 0..20 {
            let mut s_buf = Vec::new();
            server.write_tls(&mut s_buf).unwrap();
            if !s_buf.is_empty() {
                client.read_tls(&mut s_buf.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }
            let mut c_buf = Vec::new();
            client.write_tls(&mut c_buf).unwrap();
            if !c_buf.is_empty() {
                server.read_tls(&mut c_buf.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }

        assert_eq!(server.server_name(), Some("api.flutter.dev"));
        assert_eq!(server.alpn_protocol(), Some(b"http/1.1".as_slice()));

        let sni_authority = server.server_name().map(|h| format!("{h}:443"));
        let c = connector("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let (capture, reply) = run(
            "GET /packages HTTP/1.1\r\nHost: api.flutter.dev\r\n\r\n",
            Scheme::Https,
            sni_authority.as_deref(),
            &c,
        );
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.scheme, Scheme::Https);
        assert_eq!(flow.url(), "https://api.flutter.dev/packages");
        assert_eq!(flow.status, Some(200));
        assert!(reply.contains("200 OK"));
    }

    #[test]
    fn helpers() {
        assert_eq!(origin_form("http://h/a/b"), "/a/b");
        assert_eq!(origin_form("http://h"), "/");
        assert_eq!(origin_form("/already"), "/already");
        assert_eq!(authority_from_target("https://h:8443/x").as_deref(), Some("h:8443"));
        assert_eq!(authority_from_target("http://h/x").as_deref(), Some("h:80"));
        assert_eq!(authority_from_target("/x"), None);
        assert_eq!(authority_parts("h:443", Scheme::Https), ("h".into(), "h:443".into()));
        assert_eq!(authority_parts("h", Scheme::Http), ("h".into(), "h:80".into()));
    }
}
