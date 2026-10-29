//! The data model for captured HTTP exchanges ("flows") and a thread-safe
//! store shared between the proxy threads and the UI.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use super::http::{Headers, Request, Response, decode_for_display};

/// Keep at most this many flows, dropping the oldest.
const MAX_FLOWS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// One request and its response (or an error), as captured by the proxy.
#[derive(Debug, Clone)]
pub struct Flow {
    pub id: u64,
    pub scheme: Scheme,
    pub method: String,
    /// `host:port`.
    pub authority: String,
    pub host: String,
    pub path: String,
    pub req_headers: Headers,
    pub req_body: Vec<u8>,
    pub status: Option<u16>,
    pub reason: String,
    pub resp_headers: Headers,
    pub resp_body: Vec<u8>,
    pub error: Option<String>,
    pub started_at: SystemTime,
    pub duration: Option<std::time::Duration>,
    pub req_wire_size: usize,
    pub resp_wire_size: usize,
}

impl Flow {
    pub fn url(&self) -> String {
        let default_port = matches!(
            (self.scheme, self.authority.rsplit(':').next()),
            (Scheme::Http, Some("80")) | (Scheme::Https, Some("443"))
        );
        let authority = if default_port {
            self.host.as_str()
        } else {
            self.authority.as_str()
        };
        format!("{}://{}{}", self.scheme.as_str(), authority, self.path)
    }

    /// The response body decoded for display (gunzipped, etc.).
    pub fn decoded_response(&self) -> (Vec<u8>, Option<String>) {
        decode_for_display(&self.resp_headers, &self.resp_body)
    }

    pub fn decoded_request(&self) -> (Vec<u8>, Option<String>) {
        decode_for_display(&self.req_headers, &self.req_body)
    }

    pub fn is_complete(&self) -> bool {
        self.status.is_some() || self.error.is_some()
    }
}

/// The request half of a flow, as the proxy observes it before contacting
/// the origin.
pub struct RequestInfo {
    pub scheme: Scheme,
    pub authority: String,
    pub method: String,
    pub path: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    pub wire_size: usize,
}

impl RequestInfo {
    pub fn from_request(scheme: Scheme, authority: &str, req: &Request, wire_size: usize) -> Self {
        // The target may be absolute-form (http://host/path) or origin-form.
        let path = match req.target.split_once("://") {
            Some((_, rest)) => {
                let slash = rest.find('/').unwrap_or(rest.len());
                rest[slash..].to_owned()
            }
            None => req.target.clone(),
        };
        let path = if path.is_empty() { "/".to_owned() } else { path };
        RequestInfo {
            scheme,
            authority: authority.to_owned(),
            method: req.method.clone(),
            path,
            headers: req.headers.clone(),
            body: req.body.clone(),
            wire_size,
        }
    }
}

/// A pending flow: holds the start time so `finish` can compute a duration.
pub struct Pending {
    id: u64,
    started: Instant,
}

#[derive(Default)]
pub struct Capture {
    flows: Mutex<Vec<Arc<Flow>>>,
    next_id: AtomicU64,
    /// Bumped on every change so the UI knows when to refresh.
    generation: AtomicU64,
}

impl Capture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Records the start of a flow and returns a handle to finish it.
    pub fn start(&self, info: &RequestInfo) -> Pending {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let host = info
            .authority
            .rsplit_once(':')
            .map_or(info.authority.as_str(), |(h, _)| h)
            .to_owned();
        let flow = Flow {
            id,
            scheme: info.scheme,
            method: info.method.clone(),
            authority: info.authority.clone(),
            host,
            path: info.path.clone(),
            req_headers: info.headers.clone(),
            req_body: info.body.clone(),
            status: None,
            reason: String::new(),
            resp_headers: Headers::default(),
            resp_body: Vec::new(),
            error: None,
            started_at: SystemTime::now(),
            duration: None,
            req_wire_size: info.wire_size,
            resp_wire_size: 0,
        };
        let mut flows = self.flows.lock().unwrap();
        flows.push(Arc::new(flow));
        if flows.len() > MAX_FLOWS {
            let excess = flows.len() - MAX_FLOWS;
            flows.drain(0..excess);
        }
        self.generation.fetch_add(1, Ordering::Relaxed);
        Pending {
            id,
            started: Instant::now(),
        }
    }

    fn replace(&self, id: u64, update: impl FnOnce(Flow) -> Flow) {
        let mut flows = self.flows.lock().unwrap();
        if let Some(slot) = flows.iter_mut().find(|f| f.id == id) {
            *slot = Arc::new(update(Flow::clone(slot)));
        }
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn finish_response(&self, pending: &Pending, resp: &Response, wire_size: usize) {
        let duration = pending.started.elapsed();
        self.replace(pending.id, |mut flow| {
            flow.status = Some(resp.status);
            flow.reason = resp.reason.clone();
            flow.resp_headers = resp.headers.clone();
            flow.resp_body = resp.body.clone();
            flow.resp_wire_size = wire_size;
            flow.duration = Some(duration);
            flow
        });
    }

    pub fn finish_error(&self, pending: &Pending, error: impl Into<String>) {
        let duration = pending.started.elapsed();
        let error = error.into();
        self.replace(pending.id, |mut flow| {
            flow.error = Some(error.clone());
            flow.duration = Some(duration);
            flow
        });
    }

    /// A cheap snapshot (Arc clones) for the UI.
    pub fn snapshot(&self) -> Vec<Arc<Flow>> {
        self.flows.lock().unwrap().clone()
    }

    pub fn get(&self, id: u64) -> Option<Arc<Flow>> {
        self.flows.lock().unwrap().iter().find(|f| f.id == id).cloned()
    }

    pub fn clear(&self) {
        self.flows.lock().unwrap().clear();
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.flows.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn req(raw: &[u8]) -> Request {
        Request::read(&mut BufReader::new(raw)).unwrap().unwrap()
    }

    #[test]
    fn records_request_then_response() {
        let capture = Capture::new();
        let request = req(b"POST /v1/users?q=1 HTTP/1.1\r\nHost: api.x\r\nContent-Length: 2\r\n\r\nhi");
        let info = RequestInfo::from_request(Scheme::Https, "api.x:443", &request, 60);
        let gen0 = capture.generation();
        let pending = capture.start(&info);
        assert!(capture.generation() > gen0);

        let flow = &capture.snapshot()[0];
        assert_eq!(flow.method, "POST");
        assert_eq!(flow.path, "/v1/users?q=1");
        assert_eq!(flow.host, "api.x");
        assert_eq!(flow.url(), "https://api.x/v1/users?q=1");
        assert!(!flow.is_complete());

        let response =
            Response::read(&mut BufReader::new(&b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"[..]), "POST").unwrap();
        capture.finish_response(&pending, &response, 40);
        let flow = capture.get(info_id(&capture)).unwrap();
        assert_eq!(flow.status, Some(201));
        assert_eq!(flow.resp_body, b"ok");
        assert!(flow.is_complete() && flow.duration.is_some());
    }

    fn info_id(capture: &Capture) -> u64 {
        capture.snapshot()[0].id
    }

    #[test]
    fn absolute_form_target_yields_path() {
        let request = req(b"GET http://host.example/a/b?x HTTP/1.1\r\nHost: host.example\r\n\r\n");
        let info = RequestInfo::from_request(Scheme::Http, "host.example:80", &request, 10);
        assert_eq!(info.path, "/a/b?x");
    }

    #[test]
    fn records_errors_and_url_hides_default_port() {
        let capture = Capture::new();
        let request = req(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        let info = RequestInfo::from_request(Scheme::Http, "x:80", &request, 10);
        let pending = capture.start(&info);
        capture.finish_error(&pending, "connection refused");
        let flow = &capture.snapshot()[0];
        assert_eq!(flow.error.as_deref(), Some("connection refused"));
        assert_eq!(flow.url(), "http://x/");
    }

    #[test]
    fn caps_flow_count() {
        let capture = Capture::new();
        let request = req(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        let info = RequestInfo::from_request(Scheme::Http, "x:80", &request, 1);
        for _ in 0..MAX_FLOWS + 50 {
            capture.start(&info);
        }
        assert_eq!(capture.len(), MAX_FLOWS);
    }
}
