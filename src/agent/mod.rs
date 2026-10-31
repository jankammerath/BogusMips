//! Built-in AI agent for querying disassembled source code, resource files,
//! and captured network traffic across configurable LLM providers (Grok,
//! Gemini, Claude, OpenAI, and custom OpenAI-compatible endpoints).

pub mod client;
pub mod config;
pub mod json;
pub mod tools;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use eframe::egui;

pub use client::{HistoryTurn, HttpTransport, Role, TlsHttpTransport, run_agent_turn};
pub use config::{AgentConfig, Provider, ProviderSettings};
pub use tools::{AgentContext, ToolTarget, ToolTrace};

/// One message in the agent chat history.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: Role,
    pub text: String,
    pub provider: Option<Provider>,
    pub model: Option<String>,
    pub traces: Vec<ToolTrace>,
    pub is_error: bool,
}

enum WorkerEvent {
    Status(String),
    Trace(ToolTrace),
    Done(Result<String, String>),
}

struct RunningJob {
    provider: Provider,
    model: String,
    status: String,
    traces: Vec<ToolTrace>,
    rx: Receiver<WorkerEvent>,
    cancel: Arc<AtomicBool>,
}

/// Manages the AI agent configuration, conversation history, and background
/// request execution.
pub struct AgentController {
    pub config: AgentConfig,
    pub messages: Vec<ChatMessage>,
    transport: Arc<dyn HttpTransport>,
    job: Option<RunningJob>,
}

impl Default for AgentController {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentController {
    pub fn new() -> Self {
        Self {
            config: AgentConfig::load(),
            messages: Vec::new(),
            transport: Arc::new(TlsHttpTransport::new()),
            job: None,
        }
    }

    pub fn with_transport(config: AgentConfig, transport: Arc<dyn HttpTransport>) -> Self {
        Self {
            config,
            messages: Vec::new(),
            transport,
            job: None,
        }
    }

    pub fn is_busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn current_status(&self) -> Option<&str> {
        self.job.as_ref().map(|j| j.status.as_str())
    }

    pub fn pending_traces(&self) -> &[ToolTrace] {
        self.job.as_ref().map_or(&[], |j| j.traces.as_slice())
    }

    pub fn cancel(&mut self) {
        if let Some(job) = self.job.take() {
            job.cancel.store(true, Ordering::Relaxed);
        }
    }

    pub fn clear(&mut self) {
        self.cancel();
        self.messages.clear();
    }

    /// Sends a user prompt to the currently configured AI provider in the
    /// background.
    pub fn send(&mut self, prompt: String, workspace_ctx: AgentContext, egui_ctx: &egui::Context) {
        let trimmed = prompt.trim();
        if trimmed.is_empty() || self.is_busy() {
            return;
        }
        self.messages.push(ChatMessage {
            role: Role::User,
            text: trimmed.to_owned(),
            provider: None,
            model: None,
            traces: Vec::new(),
            is_error: false,
        });

        let history: Vec<HistoryTurn> = self
            .messages
            .iter()
            .filter(|m| !m.is_error)
            .map(|m| HistoryTurn {
                role: m.role,
                text: m.text.clone(),
            })
            .collect();

        let config = self.config.clone();
        let provider = config.provider;
        let model = config.active().effective_model(provider).to_owned();
        let transport = self.transport.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let repaint = egui_ctx.clone();
        let (tx, rx) = channel();

        std::thread::spawn(move || {
            let mut on_status = |s: &str| {
                let _ = tx.send(WorkerEvent::Status(s.to_owned()));
                repaint.request_repaint();
            };
            let mut on_trace = |t: ToolTrace| {
                let _ = tx.send(WorkerEvent::Trace(t));
                repaint.request_repaint();
            };
            let result = run_agent_turn(
                &*transport,
                &config,
                &history,
                &workspace_ctx,
                &worker_cancel,
                &mut on_status,
                &mut on_trace,
            );
            let _ = tx.send(WorkerEvent::Done(result));
            repaint.request_repaint();
        });

        self.job = Some(RunningJob {
            provider,
            model,
            status: format!("Asking {}…", provider.short_label()),
            traces: Vec::new(),
            rx,
            cancel,
        });
    }

    /// Polls the running background request and updates the conversation.
    pub fn poll(&mut self) {
        let Some(job) = &mut self.job else {
            return;
        };
        loop {
            match job.rx.try_recv() {
                Ok(WorkerEvent::Status(s)) => {
                    job.status = s;
                }
                Ok(WorkerEvent::Trace(t)) => {
                    job.traces.push(t);
                }
                Ok(WorkerEvent::Done(result)) => {
                    let finished = self.job.take().unwrap();
                    match result {
                        Ok(answer) => {
                            self.messages.push(ChatMessage {
                                role: Role::Assistant,
                                text: answer,
                                provider: Some(finished.provider),
                                model: Some(finished.model),
                                traces: finished.traces,
                                is_error: false,
                            });
                        }
                        Err(err) => {
                            self.messages.push(ChatMessage {
                                role: Role::Assistant,
                                text: err,
                                provider: Some(finished.provider),
                                model: Some(finished.model),
                                traces: finished.traces,
                                is_error: true,
                            });
                        }
                    }
                    return;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    let finished = self.job.take().unwrap();
                    self.messages.push(ChatMessage {
                        role: Role::Assistant,
                        text: "Agent worker disconnected unexpectedly.".to_owned(),
                        provider: Some(finished.provider),
                        model: Some(finished.model),
                        traces: finished.traces,
                        is_error: true,
                    });
                    return;
                }
            }
        }
    }
}

