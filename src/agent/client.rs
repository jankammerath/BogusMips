//! HTTP/TLS client and provider protocol adapters (Grok, Gemini, Claude,
//! OpenAI, and Custom OpenAI-compatible endpoints) with multi-step tool calling.

use std::io::{BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use super::config::{AgentConfig, Provider};
use super::json::JsonValue;
use super::tools::{AgentContext, ToolSpec, ToolTrace, build_system_prompt, execute_tool, tool_specs};
use crate::net::http::{Headers, Response, decode_for_display, serialize_head};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const IO_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_TOOL_ROUNDS: usize = 6;

/// Abstracted HTTP POST transport so provider protocols and agent loops can be
/// tested deterministically without real sockets.
pub trait HttpTransport: Send + Sync {
    fn post_json(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<(u16, String), String>;
}

pub struct TlsHttpTransport {
    tls_config: Arc<ClientConfig>,
}

impl Default for TlsHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsHttpTransport {
    pub fn new() -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls_config: Arc::new(config),
        }
    }
}

struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    path_and_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let trimmed = url.trim();
    let (https, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("URL must start with https:// or http://: {trimmed}"));
    };
    let slash = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash];
    let path_and_query = if slash < rest.len() {
        rest[slash..].to_owned()
    } else {
        "/".to_owned()
    };
    let default_port = if https { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = p.parse().map_err(|_| format!("invalid port in URL: {trimmed}"))?;
            (h.to_owned(), port)
        }
        _ => (authority.to_owned(), default_port),
    };
    if host.is_empty() {
        return Err(format!("missing host in URL: {trimmed}"));
    }
    Ok(ParsedUrl {
        https,
        host,
        port,
        path_and_query,
    })
}

impl HttpTransport for TlsHttpTransport {
    fn post_json(
        &self,
        url: &str,
        extra_headers: &[(&str, &str)],
        body: &str,
    ) -> Result<(u16, String), String> {
        let parsed = parse_url(url)?;
        let addr_str = format!("{}:{}", parsed.host, parsed.port);
        let addr = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("could not resolve {}: {e}", parsed.host))?
            .next()
            .ok_or_else(|| format!("could not resolve {}", parsed.host))?;

        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| format!("connection to {} failed: {e}", parsed.host))?;
        let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));

        let host_header = if (parsed.https && parsed.port == 443)
            || (!parsed.https && parsed.port == 80)
        {
            parsed.host.clone()
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };

        let mut headers = Headers::default();
        headers.set("Host", host_header);
        headers.set("User-Agent", "BogusMips/0.1");
        headers.set("Content-Type", "application/json");
        headers.set("Accept", "application/json");
        headers.set("Accept-Encoding", "gzip");
        for &(k, v) in extra_headers {
            headers.set(k, v);
        }

        let body_bytes = body.as_bytes();
        let head = serialize_head(
            &format!("POST {} HTTP/1.1", parsed.path_and_query),
            &headers,
            body_bytes.len(),
            false,
        );

        let resp = if parsed.https {
            let server_name = ServerName::try_from(parsed.host.clone())
                .map_err(|e| format!("invalid TLS host {}: {e}", parsed.host))?;
            let conn = ClientConnection::new(self.tls_config.clone(), server_name)
                .map_err(|e| format!("TLS error: {e}"))?;
            let mut stream = StreamOwned::new(conn, tcp);
            stream
                .write_all(&head)
                .and_then(|()| stream.write_all(body_bytes))
                .and_then(|()| stream.flush())
                .map_err(|e| format!("failed sending request: {e}"))?;
            let mut reader = BufReader::new(stream);
            Response::read(&mut reader, "POST")
                .map_err(|e| format!("failed reading response: {e}"))?
        } else {
            let mut stream = tcp;
            stream
                .write_all(&head)
                .and_then(|()| stream.write_all(body_bytes))
                .and_then(|()| stream.flush())
                .map_err(|e| format!("failed sending request: {e}"))?;
            let mut reader = BufReader::new(stream);
            Response::read(&mut reader, "POST")
                .map_err(|e| format!("failed reading response: {e}"))?
        };

        let (decoded, _) = decode_for_display(&resp.headers, &resp.body);
        let text = String::from_utf8_lossy(&decoded).into_owned();
        Ok((resp.status, text))
    }
}

/// Role in the conversation history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

#[derive(Debug, Clone)]
pub struct HistoryTurn {
    pub role: Role,
    pub text: String,
}

/// Runs one full user turn against the configured provider, executing any tool
/// calls in a loop until the model returns a final answer.
pub fn run_agent_turn(
    transport: &dyn HttpTransport,
    config: &AgentConfig,
    history: &[HistoryTurn],
    ctx: &AgentContext,
    cancel: &AtomicBool,
    on_status: &mut dyn FnMut(&str),
    on_trace: &mut dyn FnMut(ToolTrace),
) -> Result<String, String> {
    let provider = config.provider;
    let settings = config.active();
    let api_key = settings.effective_api_key(provider);
    if provider != Provider::Custom && api_key.is_empty() {
        let env_hint = provider.env_vars().join(" or ");
        return Err(format!(
            "No API key configured for {}. Open settings (⚙) in the Agent panel to enter a key, or set the {env_hint} environment variable.",
            provider.label()
        ));
    }

    let model = settings.effective_model(provider);
    let endpoint = settings.effective_endpoint(provider);
    let system_prompt = build_system_prompt(ctx);
    let specs = tool_specs(ctx);

    match provider {
        Provider::Grok | Provider::OpenAi | Provider::Custom => run_openai_compatible(
            transport,
            provider,
            endpoint,
            &api_key,
            model,
            &system_prompt,
            history,
            &specs,
            ctx,
            cancel,
            on_status,
            on_trace,
        ),
        Provider::Claude => run_anthropic(
            transport,
            endpoint,
            &api_key,
            model,
            &system_prompt,
            history,
            &specs,
            ctx,
            cancel,
            on_status,
            on_trace,
        ),
        Provider::Gemini => run_gemini(
            transport,
            endpoint,
            &api_key,
            model,
            &system_prompt,
            history,
            &specs,
            ctx,
            cancel,
            on_status,
            on_trace,
        ),
    }
}

fn extract_api_error(status: u16, body: &str) -> String {
    if let Ok(json) = JsonValue::parse(body) {
        if let Some(err) = json.get("error") {
            if let Some(msg) = err.get("message").and_then(JsonValue::as_str) {
                return format!("HTTP {status}: {msg}");
            }
            if let Some(msg) = err.as_str() {
                return format!("HTTP {status}: {msg}");
            }
        }
        if let Some(msg) = json.get("message").and_then(JsonValue::as_str) {
            return format!("HTTP {status}: {msg}");
        }
    }
    let snippet: String = body.trim().chars().take(240).collect();
    if snippet.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {snippet}")
    }
}

#[allow(clippy::too_many_arguments)]
fn run_openai_compatible(
    transport: &dyn HttpTransport,
    provider: Provider,
    endpoint: &str,
    api_key: &str,
    model: &str,
    system_prompt: &str,
    history: &[HistoryTurn],
    specs: &[ToolSpec],
    ctx: &AgentContext,
    cancel: &AtomicBool,
    on_status: &mut dyn FnMut(&str),
    on_trace: &mut dyn FnMut(ToolTrace),
) -> Result<String, String> {
    let mut messages = Vec::new();
    messages.push(JsonValue::obj([
        ("role", JsonValue::str("system")),
        ("content", JsonValue::str(system_prompt)),
    ]));
    for turn in history {
        let role = match turn.role {
            Role::User => "user",
            Role::Assistant => "assistant",
        };
        messages.push(JsonValue::obj([
            ("role", JsonValue::str(role)),
            ("content", JsonValue::str(&turn.text)),
        ]));
    }

    let tools_json: Vec<JsonValue> = specs
        .iter()
        .map(|s| {
            JsonValue::obj([
                ("type", JsonValue::str("function")),
                (
                    "function",
                    JsonValue::obj([
                        ("name", JsonValue::str(s.name)),
                        ("description", JsonValue::str(s.description)),
                        ("parameters", s.parameters_schema.clone()),
                    ]),
                ),
            ])
        })
        .collect();

    let mut use_tools = !tools_json.is_empty();
    let auth_header = format!("Bearer {api_key}");

    for round in 0..=MAX_TOOL_ROUNDS {
        if cancel.load(Ordering::Relaxed) {
            return Err("Cancelled.".to_owned());
        }
        on_status(&format!("Asking {} ({model})…", provider.short_label()));

        let mut fields = vec![
            ("model", JsonValue::str(model)),
            ("messages", JsonValue::Array(messages.clone())),
        ];
        if use_tools && round < MAX_TOOL_ROUNDS {
            fields.push(("tools", JsonValue::Array(tools_json.clone())));
        }
        let req_body = JsonValue::obj(fields).to_json_string();
        let headers: Vec<(&str, &str)> = if api_key.is_empty() {
            Vec::new()
        } else {
            vec![("Authorization", auth_header.as_str())]
        };

        let (status, resp_body) = transport.post_json(endpoint, &headers, &req_body)?;
        if !(200..300).contains(&status) {
            // If a custom/local model does not support tools, retry once without tools.
            if use_tools && round == 0 && (status == 400 || status == 422) {
                use_tools = false;
                continue;
            }
            return Err(extract_api_error(status, &resp_body));
        }

        let json = JsonValue::parse(&resp_body)
            .map_err(|e| format!("invalid JSON from {}: {e}", provider.short_label()))?;
        let choice = json
            .get("choices")
            .and_then(JsonValue::as_array)
            .and_then(|c| c.first())
            .ok_or_else(|| "response contained no choices".to_owned())?;
        let message = choice
            .get("message")
            .ok_or_else(|| "choice contained no message".to_owned())?;

        if let Some(tool_calls) = message
            .get("tool_calls")
            .and_then(JsonValue::as_array)
            .filter(|tc| !tc.is_empty())
        {
            messages.push(message.clone());
            for tc in tool_calls {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Cancelled.".to_owned());
                }
                let id = tc.get("id").and_then(JsonValue::as_str).unwrap_or("call_0");
                let func = tc.get("function");
                let name = func
                    .and_then(|f| f.get("name"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                let raw_args = func
                    .and_then(|f| f.get("arguments"))
                    .and_then(JsonValue::as_str)
                    .unwrap_or("{}");
                let args = JsonValue::parse(raw_args).unwrap_or(JsonValue::Object(Vec::new()));
                on_status(&format!("Running {name}…"));
                let (output, trace) = execute_tool(name, &args, ctx);
                on_trace(trace);
                messages.push(JsonValue::obj([
                    ("role", JsonValue::str("tool")),
                    ("tool_call_id", JsonValue::str(id)),
                    ("content", JsonValue::str(output)),
                ]));
            }
            continue;
        }

        let content = message
            .get("content")
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .trim()
            .to_owned();
        return Ok(if content.is_empty() {
            "(Empty response from model)".to_owned()
        } else {
            content
        });
    }

    Err("Agent reached maximum tool call steps.".to_owned())
}

#[allow(clippy::too_many_arguments)]
fn run_anthropic(
    transport: &dyn HttpTransport,
    endpoint: &str,
    api_key: &str,
    model: &str,
    system_prompt: &str,
    history: &[HistoryTurn],
    specs: &[ToolSpec],
    ctx: &AgentContext,
    cancel: &AtomicBool,
    on_status: &mut dyn FnMut(&str),
    on_trace: &mut dyn FnMut(ToolTrace),
) -> Result<String, String> {
    let mut messages: Vec<JsonValue> = history
        .iter()
        .map(|turn| {
            let role = match turn.role {
                Role::User => "user",
                Role::Assistant => "assistant",
            };
            JsonValue::obj([
                ("role", JsonValue::str(role)),
                ("content", JsonValue::str(&turn.text)),
            ])
        })
        .collect();

    let tools_json: Vec<JsonValue> = specs
        .iter()
        .map(|s| {
            JsonValue::obj([
                ("name", JsonValue::str(s.name)),
                ("description", JsonValue::str(s.description)),
                ("input_schema", s.parameters_schema.clone()),
            ])
        })
        .collect();

    let headers = [
        ("x-api-key", api_key),
        ("anthropic-version", "2023-06-01"),
    ];

    for round in 0..=MAX_TOOL_ROUNDS {
        if cancel.load(Ordering::Relaxed) {
            return Err("Cancelled.".to_owned());
        }
        on_status(&format!("Asking Claude ({model})…"));

        let mut fields = vec![
            ("model", JsonValue::str(model)),
            ("max_tokens", JsonValue::Number(4096.0)),
            ("system", JsonValue::str(system_prompt)),
            ("messages", JsonValue::Array(messages.clone())),
        ];
        if !tools_json.is_empty() && round < MAX_TOOL_ROUNDS {
            fields.push(("tools", JsonValue::Array(tools_json.clone())));
        }
        let req_body = JsonValue::obj(fields).to_json_string();
        let (status, resp_body) = transport.post_json(endpoint, &headers, &req_body)?;
        if !(200..300).contains(&status) {
            return Err(extract_api_error(status, &resp_body));
        }

        let json = JsonValue::parse(&resp_body)
            .map_err(|e| format!("invalid JSON from Claude: {e}"))?;
        let content_blocks = json
            .get("content")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "Claude response contained no content blocks".to_owned())?;

        let tool_uses: Vec<&JsonValue> = content_blocks
            .iter()
            .filter(|b| b.get("type").and_then(JsonValue::as_str) == Some("tool_use"))
            .collect();

        if !tool_uses.is_empty() {
            messages.push(JsonValue::obj([
                ("role", JsonValue::str("assistant")),
                ("content", JsonValue::Array(content_blocks.to_vec())),
            ]));
            let mut results = Vec::new();
            for tu in tool_uses {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Cancelled.".to_owned());
                }
                let id = tu.get("id").and_then(JsonValue::as_str).unwrap_or("tool_0");
                let name = tu.get("name").and_then(JsonValue::as_str).unwrap_or("");
                let input = tu
                    .get("input")
                    .cloned()
                    .unwrap_or(JsonValue::Object(Vec::new()));
                on_status(&format!("Running {name}…"));
                let (output, trace) = execute_tool(name, &input, ctx);
                on_trace(trace);
                results.push(JsonValue::obj([
                    ("type", JsonValue::str("tool_result")),
                    ("tool_use_id", JsonValue::str(id)),
                    ("content", JsonValue::str(output)),
                ]));
            }
            messages.push(JsonValue::obj([
                ("role", JsonValue::str("user")),
                ("content", JsonValue::Array(results)),
            ]));
            continue;
        }

        let mut text = String::new();
        for block in content_blocks {
            if block.get("type").and_then(JsonValue::as_str) == Some("text") {
                if let Some(t) = block.get("text").and_then(JsonValue::as_str) {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(t);
                }
            }
        }
        return Ok(if text.trim().is_empty() {
            "(Empty response from Claude)".to_owned()
        } else {
            text.trim().to_owned()
        });
    }

    Err("Agent reached maximum tool call steps.".to_owned())
}

fn gemini_endpoint_url(base: &str, model: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    if trimmed.contains(":generateContent") {
        trimmed.replace("{model}", model)
    } else if trimmed.ends_with(model) {
        format!("{trimmed}:generateContent")
    } else {
        format!("{trimmed}/{model}:generateContent")
    }
}

#[allow(clippy::too_many_arguments)]
fn run_gemini(
    transport: &dyn HttpTransport,
    endpoint: &str,
    api_key: &str,
    model: &str,
    system_prompt: &str,
    history: &[HistoryTurn],
    specs: &[ToolSpec],
    ctx: &AgentContext,
    cancel: &AtomicBool,
    on_status: &mut dyn FnMut(&str),
    on_trace: &mut dyn FnMut(ToolTrace),
) -> Result<String, String> {
    let url = gemini_endpoint_url(endpoint, model);
    let mut contents: Vec<JsonValue> = history
        .iter()
        .map(|turn| {
            let role = match turn.role {
                Role::User => "user",
                Role::Assistant => "model",
            };
            JsonValue::obj([
                ("role", JsonValue::str(role)),
                (
                    "parts",
                    JsonValue::arr([JsonValue::obj([("text", JsonValue::str(&turn.text))])]),
                ),
            ])
        })
        .collect();

    let func_decls: Vec<JsonValue> = specs
        .iter()
        .map(|s| {
            JsonValue::obj([
                ("name", JsonValue::str(s.name)),
                ("description", JsonValue::str(s.description)),
                ("parameters", s.parameters_schema.clone()),
            ])
        })
        .collect();

    let headers = [("x-goog-api-key", api_key)];

    for round in 0..=MAX_TOOL_ROUNDS {
        if cancel.load(Ordering::Relaxed) {
            return Err("Cancelled.".to_owned());
        }
        on_status(&format!("Asking Gemini ({model})…"));

        let mut fields = vec![
            (
                "systemInstruction",
                JsonValue::obj([(
                    "parts",
                    JsonValue::arr([JsonValue::obj([("text", JsonValue::str(system_prompt))])]),
                )]),
            ),
            ("contents", JsonValue::Array(contents.clone())),
        ];
        if !func_decls.is_empty() && round < MAX_TOOL_ROUNDS {
            fields.push((
                "tools",
                JsonValue::arr([JsonValue::obj([(
                    "functionDeclarations",
                    JsonValue::Array(func_decls.clone()),
                )])]),
            ));
        }
        let req_body = JsonValue::obj(fields).to_json_string();
        let (status, resp_body) = transport.post_json(&url, &headers, &req_body)?;
        if !(200..300).contains(&status) {
            return Err(extract_api_error(status, &resp_body));
        }

        let json = JsonValue::parse(&resp_body)
            .map_err(|e| format!("invalid JSON from Gemini: {e}"))?;
        let candidate = json
            .get("candidates")
            .and_then(JsonValue::as_array)
            .and_then(|c| c.first())
            .ok_or_else(|| "Gemini response contained no candidates".to_owned())?;
        let content_obj = candidate
            .get("content")
            .ok_or_else(|| "Gemini candidate contained no content".to_owned())?;
        let parts = content_obj
            .get("parts")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| "Gemini content contained no parts".to_owned())?;

        let calls: Vec<&JsonValue> = parts
            .iter()
            .filter_map(|p| p.get("functionCall"))
            .collect();

        if !calls.is_empty() {
            contents.push(content_obj.clone());
            let mut resp_parts = Vec::new();
            for call in calls {
                if cancel.load(Ordering::Relaxed) {
                    return Err("Cancelled.".to_owned());
                }
                let name = call.get("name").and_then(JsonValue::as_str).unwrap_or("");
                let args = call
                    .get("args")
                    .cloned()
                    .unwrap_or(JsonValue::Object(Vec::new()));
                on_status(&format!("Running {name}…"));
                let (output, trace) = execute_tool(name, &args, ctx);
                on_trace(trace);
                resp_parts.push(JsonValue::obj([(
                    "functionResponse",
                    JsonValue::obj([
                        ("name", JsonValue::str(name)),
                        (
                            "response",
                            JsonValue::obj([("result", JsonValue::str(output))]),
                        ),
                    ]),
                )]));
            }
            contents.push(JsonValue::obj([
                ("role", JsonValue::str("user")),
                ("parts", JsonValue::Array(resp_parts)),
            ]));
            continue;
        }

        let mut text = String::new();
        for part in parts {
            if let Some(t) = part.get("text").and_then(JsonValue::as_str) {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
        }
        return Ok(if text.trim().is_empty() {
            "(Empty response from Gemini)".to_owned()
        } else {
            text.trim().to_owned()
        });
    }

    Err("Agent reached maximum tool call steps.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    struct MockTransport {
        responses: Mutex<Vec<(u16, String)>>,
        requests: Mutex<Vec<(String, Vec<(String, String)>, String)>>,
    }

    impl MockTransport {
        fn new(responses: Vec<(u16, String)>) -> Self {
            Self {
                responses: Mutex::new(responses),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn post_json(
            &self,
            url: &str,
            headers: &[(&str, &str)],
            body: &str,
        ) -> Result<(u16, String), String> {
            self.requests.lock().unwrap().push((
                url.to_owned(),
                headers.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
                body.to_owned(),
            ));
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    fn test_ctx() -> AgentContext {
        let zip = crate::formats::zip::write_stored_zip(&[(
            "assets/secrets.txt",
            b"API_TOKEN=super_secret_value_123",
        )]);
        let pkg = Arc::new(
            crate::package::Package::from_bytes(Path::new("app.apk"), zip.into()).unwrap(),
        );
        AgentContext {
            package: Some(pkg),
            selected_node: None,
            capture: None,
            selected_flow: None,
            include_source: true,
            include_resources: true,
            include_network: true,
        }
    }

    #[test]
    fn grok_executes_tool_call_and_returns_final_answer() {
        let transport = MockTransport::new(vec![
            (
                200,
                r#"{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"search_package","arguments":"{\"query\":\"API_TOKEN\"}"}}]}}]}"#.to_owned(),
            ),
            (
                200,
                r#"{"choices":[{"message":{"role":"assistant","content":"Found API_TOKEN in assets/secrets.txt."}}]}"#.to_owned(),
            ),
        ]);
        let mut cfg = AgentConfig::default();
        cfg.provider = Provider::Grok;
        cfg.settings_mut(Provider::Grok).api_key = "xai-test".to_owned();

        let mut traces = Vec::new();
        let answer = run_agent_turn(
            &transport,
            &cfg,
            &[HistoryTurn {
                role: Role::User,
                text: "Find API_TOKEN".to_owned(),
            }],
            &test_ctx(),
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |t| traces.push(t),
        )
        .unwrap();

        assert_eq!(answer, "Found API_TOKEN in assets/secrets.txt.");
        assert_eq!(traces.len(), 1);
        assert!(traces[0].summary.contains("API_TOKEN"));
        let reqs = transport.requests.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].0.contains("api.x.ai"));
        assert!(reqs[1].2.contains("super_secret_value_123"));
    }

    #[test]
    fn gemini_executes_function_call_and_returns_answer() {
        let transport = MockTransport::new(vec![
            (
                200,
                r#"{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"read_node","args":{"target":"secrets.txt"}}}]}}]}"#.to_owned(),
            ),
            (
                200,
                r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"The secret is super_secret_value_123."}]}}]}"#.to_owned(),
            ),
        ]);
        let mut cfg = AgentConfig::default();
        cfg.provider = Provider::Gemini;
        cfg.settings_mut(Provider::Gemini).api_key = "gem-test".to_owned();

        let mut traces = Vec::new();
        let answer = run_agent_turn(
            &transport,
            &cfg,
            &[HistoryTurn {
                role: Role::User,
                text: "Read secrets.txt".to_owned(),
            }],
            &test_ctx(),
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |t| traces.push(t),
        )
        .unwrap();

        assert_eq!(answer, "The secret is super_secret_value_123.");
        assert_eq!(traces.len(), 1);
        let reqs = transport.requests.lock().unwrap();
        assert!(reqs[0].0.contains("generativelanguage.googleapis.com"));
        assert!(reqs[0].0.ends_with("gemini-2.5-flash:generateContent"));
        assert!(reqs[1].2.contains("super_secret_value_123"));
    }

    #[test]
    fn claude_executes_tool_use_and_returns_answer() {
        let transport = MockTransport::new(vec![
            (
                200,
                r#"{"content":[{"type":"tool_use","id":"toolu_1","name":"read_node","input":{"target":"secrets.txt"}}]}"#.to_owned(),
            ),
            (
                200,
                r#"{"content":[{"type":"text","text":"Claude found super_secret_value_123."}]}"#.to_owned(),
            ),
        ]);
        let mut cfg = AgentConfig::default();
        cfg.provider = Provider::Claude;
        cfg.settings_mut(Provider::Claude).api_key = "ant-test".to_owned();

        let mut traces = Vec::new();
        let answer = run_agent_turn(
            &transport,
            &cfg,
            &[HistoryTurn {
                role: Role::User,
                text: "Check secrets.txt".to_owned(),
            }],
            &test_ctx(),
            &AtomicBool::new(false),
            &mut |_| {},
            &mut |t| traces.push(t),
        )
        .unwrap();

        assert_eq!(answer, "Claude found super_secret_value_123.");
        assert_eq!(traces.len(), 1);
        let reqs = transport.requests.lock().unwrap();
        assert!(reqs[0].0.contains("api.anthropic.com"));
        assert!(reqs[1].2.contains("super_secret_value_123"));
    }
}
