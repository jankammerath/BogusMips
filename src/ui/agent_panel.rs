//! Right-sidebar AI Agent panel: provider/model configuration (Grok, Gemini,
//! Claude, OpenAI, Custom), conversation history, tool traces, and prompt box.

use eframe::egui::{
    self, Color32, CornerRadius, Key, Margin, RichText, ScrollArea, Sense, Stroke, TextStyle,
    text::LayoutJob, vec2,
};

use super::highlight::{self, highlight_into};
use super::icons::{self, Icon};
use super::theme;
use crate::agent::{AgentController, ChatMessage, Provider, Role, ToolTarget, ToolTrace};
use crate::inspect::Syntax;
use crate::package::NodeId;

pub const PROMPT_INPUT_ID: &str = "agent_prompt_input";

/// UI state for the AI Agent panel.
#[derive(Default)]
pub struct AgentPanelState {
    pub prompt: String,
    pub show_settings: bool,
    pub show_api_key: bool,
}

/// Actions emitted by the AI Agent panel back to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPanelAction {
    /// Submit a prompt to the configured AI agent.
    SendPrompt(String),
    /// Jump to a package tree node in the editor.
    SelectNode(NodeId),
    /// Jump to a captured network flow in the editor.
    SelectFlow(u64),
}

/// Summary of the currently open document/selection shown in the context bar.
pub struct ContextSummary<'a> {
    pub has_package: bool,
    pub selected_label: Option<&'a str>,
    pub flow_count: usize,
    pub selected_flow: Option<u64>,
}

pub fn show(
    ui: &mut egui::Ui,
    agent: &mut AgentController,
    state: &mut AgentPanelState,
    ctx_summary: &ContextSummary<'_>,
) -> Option<AgentPanelAction> {
    let mut action = None;
    ui.set_max_width(ui.available_width());

    // Top provider & model bar.
    provider_bar(ui, agent, state);

    // Collapsible settings drawer (API key, endpoint, context toggles).
    if state.show_settings {
        ui.add_space(4.0);
        settings_drawer(ui, agent, state);
    } else if !agent.config.active().has_api_key(agent.config.provider) {
        ui.add_space(4.0);
        missing_key_banner(ui, agent.config.provider, state);
    }

    // Active workspace context indicator.
    ui.add_space(4.0);
    context_bar(ui, agent, ctx_summary);
    ui.add_space(4.0);
    ui.separator();

    // Reserve space at the bottom for the prompt input box (~86px), using the
    // remaining height for the scrollable message history.
    let available = ui.available_rect_before_wrap();
    let input_height = 84.0_f32.min((available.height() * 0.35).max(64.0));
    let history_height = (available.height() - input_height - 6.0).max(40.0);

    let history_rect = egui::Rect::from_min_size(
        available.min,
        vec2(available.width(), history_height),
    );
    let input_rect = egui::Rect::from_min_max(
        egui::pos2(available.left(), history_rect.bottom() + 6.0),
        available.max,
    );
    ui.allocate_rect(available, Sense::hover());

    let mut history_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(history_rect)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    if let Some(a) = message_history(&mut history_ui, agent, ctx_summary.has_package) {
        action = Some(a);
    }

    let mut input_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(input_rect)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    if let Some(a) = prompt_box(&mut input_ui, agent, state) {
        action = Some(a);
    }

    action
}

fn provider_bar(
    ui: &mut egui::Ui,
    agent: &mut AgentController,
    state: &mut AgentPanelState,
) {
    let mut changed = false;
    egui::Frame::NONE
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            let total_w = ui.max_rect().width();
            let combo_w = ((total_w - 8.0) * 0.45).max(70.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let current_provider = agent.config.provider;
                egui::ComboBox::from_id_salt("agent_provider")
                    .selected_text(current_provider.short_label())
                    .width(combo_w)
                    .show_ui(ui, |ui| {
                        for p in Provider::ALL {
                            if ui
                                .selectable_value(&mut agent.config.provider, p, p.label())
                                .changed()
                            {
                                changed = true;
                            }
                        }
                    });

                let provider = agent.config.provider;
                let presets = provider.preset_models();
                let model_w = (ui.available_width() - 4.0).max(60.0);
                let current_model = agent.config.active().effective_model(provider).to_owned();
                egui::ComboBox::from_id_salt(("agent_model_preset", provider.id()))
                    .selected_text(&current_model)
                    .width(model_w)
                    .show_ui(ui, |ui| {
                        for &preset in presets {
                            if ui
                                .selectable_value(
                                    &mut agent.config.active_mut().model,
                                    preset.to_owned(),
                                    preset,
                                )
                                .changed()
                            {
                                changed = true;
                            }
                        }
                        ui.separator();
                        if ui
                            .selectable_label(state.show_settings, "Custom model / API key…")
                            .clicked()
                        {
                            state.show_settings = true;
                        }
                    });
            });
        });
    if changed {
        let _ = agent.config.save();
    }
}

fn missing_key_banner(ui: &mut egui::Ui, provider: Provider, state: &mut AgentPanelState) {
    egui::Frame::NONE
        .fill(Color32::from_rgb(0x33, 0x2b, 0x1a))
        .stroke(Stroke::new(1.0, Color32::from_rgb(0x66, 0x52, 0x22)))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(8, 6))
        .outer_margin(Margin::symmetric(8, 0))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            let env_vars = provider.env_vars().join(" / ");
            let resp = ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "⚙ Click to configure {} API key (or set {env_vars})",
                        provider.short_label()
                    ))
                    .size(11.5)
                    .color(Color32::from_rgb(0xe8, 0xc5, 0x6b)),
                )
                .wrap()
                .sense(Sense::click()),
            );
            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                state.show_settings = true;
            }
        });
}

fn settings_drawer(
    ui: &mut egui::Ui,
    agent: &mut AgentController,
    state: &mut AgentPanelState,
) {
    let mut changed = false;
    let provider = agent.config.provider;
    egui::Frame::NONE
        .fill(theme::EDITOR)
        .stroke(Stroke::new(1.0, theme::SEPARATOR))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(8, 8))
        .outer_margin(Margin::symmetric(8, 0))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} CONFIGURATION", provider.short_label().to_uppercase()))
                        .size(11.0)
                        .family(theme::bold_family())
                        .color(theme::TEXT_DIM),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icons::button(ui, Icon::Close, 18.0, "Close settings").clicked() {
                        state.show_settings = false;
                    }
                });
            });
            ui.add_space(4.0);

            // API Key input.
            let env_detected = provider.env_api_key();
            let key_label = match &env_detected {
                Some((var, _)) if agent.config.active().api_key.trim().is_empty() => {
                    format!("API Key (using ${var})")
                }
                _ => "API Key".to_owned(),
            };
            ui.label(RichText::new(key_label).size(11.5).color(theme::TEXT_DIM));
            ui.horizontal(|ui| {
                let btn_w = 42.0;
                let edit_w = (ui.available_width() - btn_w - 6.0).max(60.0);
                let hint = provider
                    .env_vars()
                    .first()
                    .copied()
                    .unwrap_or("API key");
                changed |= ui
                    .add_sized(
                        vec2(edit_w, 22.0),
                        egui::TextEdit::singleline(&mut agent.config.active_mut().api_key)
                            .password(!state.show_api_key)
                            .hint_text(hint),
                    )
                    .changed();
                let toggle_label = if state.show_api_key { "Hide" } else { "Show" };
                if ui
                    .add_sized(vec2(btn_w, 22.0), egui::Button::new(RichText::new(toggle_label).size(11.0)))
                    .clicked()
                {
                    state.show_api_key = !state.show_api_key;
                }
            });
            ui.add_space(4.0);

            // Custom Model ID input.
            ui.label(RichText::new("Model").size(11.5).color(theme::TEXT_DIM));
            changed |= ui
                .add_sized(
                    vec2(ui.available_width(), 22.0),
                    egui::TextEdit::singleline(&mut agent.config.active_mut().model)
                        .hint_text(provider.default_model()),
                )
                .changed();
            ui.add_space(4.0);

            // Endpoint URL input.
            ui.horizontal(|ui| {
                ui.label(RichText::new("Endpoint URL").size(11.5).color(theme::TEXT_DIM));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if agent.config.active().endpoint != provider.default_endpoint()
                        && ui
                            .add(egui::Button::new(RichText::new("Reset").size(10.5)))
                            .clicked()
                    {
                        agent.config.active_mut().endpoint = provider.default_endpoint().to_owned();
                        changed = true;
                    }
                });
            });
            changed |= ui
                .add_sized(
                    vec2(ui.available_width(), 22.0),
                    egui::TextEdit::singleline(&mut agent.config.active_mut().endpoint)
                        .hint_text(provider.default_endpoint()),
                )
                .changed();
            ui.add_space(6.0);

            // Context toggles.
            ui.label(RichText::new("Context & Tools").size(11.5).color(theme::TEXT_DIM));
            ui.horizontal_wrapped(|ui| {
                changed |= ui
                    .checkbox(&mut agent.config.include_source, "Source code")
                    .changed();
                changed |= ui
                    .checkbox(&mut agent.config.include_resources, "Resources")
                    .changed();
                changed |= ui
                    .checkbox(&mut agent.config.include_network, "Network traffic")
                    .changed();
            });
        });

    if changed {
        let _ = agent.config.save();
    }
}

fn context_bar(
    ui: &mut egui::Ui,
    agent: &AgentController,
    summary: &ContextSummary<'_>,
) {
    egui::Frame::NONE
        .inner_margin(Margin::symmetric(8, 0))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            let mut parts = Vec::new();
            if summary.has_package {
                if let Some(sel) = summary.selected_label {
                    parts.push(format!("📄 {sel}"));
                } else {
                    parts.push("📦 Package open".to_owned());
                }
            } else {
                parts.push("No package open".to_owned());
            }
            if agent.config.include_network && summary.flow_count > 0 {
                if let Some(fid) = summary.selected_flow {
                    parts.push(format!("🌐 Flow #{fid} ({} total)", summary.flow_count));
                } else {
                    parts.push(format!("🌐 {} flows", summary.flow_count));
                }
            }
            let text = parts.join("  ·  ");
            ui.add(
                egui::Label::new(RichText::new(text).size(11.0).color(theme::TEXT_DIM)).truncate(),
            );
        });
}

fn message_history(
    ui: &mut egui::Ui,
    agent: &mut AgentController,
    has_package: bool,
) -> Option<AgentPanelAction> {
    let mut action = None;
    let mut cancel_clicked = false;
    ScrollArea::vertical()
        .id_salt("agent_chat_scroll")
        .auto_shrink(false)
        .stick_to_bottom(true)
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            egui::Frame::NONE
                .inner_margin(Margin {
                    left: 8,
                    right: 10,
                    top: 4,
                    bottom: 6,
                })
                .show(ui, |ui| {
                    ui.set_max_width(ui.available_width());
                    if agent.messages.is_empty() && !agent.is_busy() {
                        if let Some(prompt) = empty_welcome(ui, has_package) {
                            action = Some(AgentPanelAction::SendPrompt(prompt));
                        }
                        return;
                    }

                    for (i, msg) in agent.messages.iter().enumerate() {
                        if let Some(a) = render_message(ui, i, msg) {
                            action = Some(a);
                        }
                        ui.add_space(8.0);
                    }

                    if agent.is_busy() {
                        for trace in agent.pending_traces() {
                            if let Some(a) = render_trace_pill(ui, trace) {
                                action = Some(a);
                            }
                            ui.add_space(2.0);
                        }
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(13.0));
                            let status = agent.current_status().unwrap_or("Thinking…");
                            ui.add(
                                egui::Label::new(
                                    RichText::new(status).size(12.0).color(theme::TEXT_DIM),
                                )
                                .truncate(),
                            );
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui
                                    .add(egui::Button::new(RichText::new("Stop").size(11.0)))
                                    .clicked()
                                {
                                    cancel_clicked = true;
                                }
                            });
                        });
                    }
                });
        });

    if cancel_clicked {
        agent.cancel();
    }
    action
}

fn empty_welcome(ui: &mut egui::Ui, has_package: bool) -> Option<String> {
    let mut chosen = None;
    ui.add_space(6.0);
    ui.add(
        egui::Label::new(
            RichText::new(
                "Ask the AI agent about disassembled smali classes, decoded resource XMLs, \
                 or captured HTTP/HTTPS network traffic.",
            )
            .size(12.0)
            .color(theme::TEXT_DIM),
        )
        .wrap(),
    );
    ui.add_space(10.0);
    ui.label(
        RichText::new("SUGGESTED PROMPTS")
            .size(10.5)
            .family(theme::bold_family())
            .color(theme::TEXT_DIM),
    );
    ui.add_space(4.0);

    let prompts: &[(&str, &str)] = if has_package {
        &[
            (
                "Summarize app & permissions",
                "Summarize this app's purpose, main components, and requested permissions based on its manifest and package structure.",
            ),
            (
                "Explain selected item",
                "Explain what the currently selected class, resource file, or network request does and highlight anything noteworthy.",
            ),
            (
                "Find API keys, URLs & secrets",
                "Search the disassembled source code and resource files for hardcoded API keys, tokens, endpoints, or secrets.",
            ),
            (
                "Analyze network traffic",
                "Analyze the captured HTTP/HTTPS network traffic, authentication headers, and endpoints, and correlate them with the source code.",
            ),
        ]
    } else {
        &[
            (
                "What can you analyze?",
                "What kinds of Android reverse-engineering, resource inspection, and network traffic analyses can you help me perform?",
            ),
        ]
    };

    for &(label, full_prompt) in prompts {
        let resp = ui.add_sized(
            vec2(ui.available_width(), 26.0),
            egui::Button::new(RichText::new(label).size(12.0).color(theme::TEXT)),
        );
        if resp.on_hover_text(full_prompt).clicked() {
            chosen = Some(full_prompt.to_owned());
        }
        ui.add_space(3.0);
    }
    chosen
}

fn render_message(
    ui: &mut egui::Ui,
    index: usize,
    msg: &ChatMessage,
) -> Option<AgentPanelAction> {
    let mut action = None;
    match msg.role {
        Role::User => {
            egui::Frame::NONE
                .fill(theme::PILL)
                .corner_radius(CornerRadius::same(5))
                .inner_margin(Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.set_max_width(ui.available_width());
                    ui.add(
                        egui::Label::new(RichText::new(&msg.text).color(theme::TEXT_BRIGHT))
                            .wrap()
                            .selectable(true),
                    );
                });
        }
        Role::Assistant => {
            ui.horizontal(|ui| {
                let badge = match (msg.provider, msg.model.as_deref()) {
                    (Some(p), Some(m)) => format!("{} · {m}", p.short_label()),
                    (Some(p), None) => p.short_label().to_owned(),
                    _ => "Agent".to_owned(),
                };
                ui.label(
                    RichText::new(badge)
                        .size(11.0)
                        .family(theme::bold_family())
                        .color(theme::LINK),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icons::button(ui, Icon::Copy, 18.0, "Copy response").clicked() {
                        ui.ctx().copy_text(msg.text.clone());
                    }
                });
            });

            for trace in &msg.traces {
                if let Some(a) = render_trace_pill(ui, trace) {
                    action = Some(a);
                }
                ui.add_space(2.0);
            }

            if msg.is_error {
                egui::Frame::NONE
                    .fill(Color32::from_rgb(0x3a, 0x1d, 0x1d))
                    .stroke(Stroke::new(1.0, theme::ERROR))
                    .corner_radius(CornerRadius::same(4))
                    .inner_margin(Margin::symmetric(8, 6))
                    .show(ui, |ui| {
                        ui.set_max_width(ui.available_width());
                        ui.add(
                            egui::Label::new(RichText::new(&msg.text).color(theme::ERROR).size(12.0))
                                .wrap()
                                .selectable(true),
                        );
                    });
            } else {
                render_formatted_text(ui, index, &msg.text);
            }
        }
    }
    action
}

fn render_trace_pill(ui: &mut egui::Ui, trace: &ToolTrace) -> Option<AgentPanelAction> {
    let clickable = trace.target.is_some();
    let sense = if clickable { Sense::click() } else { Sense::hover() };
    let label = format!("⚡ {}", trace.summary);
    let resp = ui.add(
        egui::Label::new(
            RichText::new(label)
                .size(11.0)
                .color(if clickable { theme::LINK } else { theme::TEXT_DIM }),
        )
        .truncate()
        .sense(sense),
    );
    if clickable {
        let resp = resp
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text("Click to open in editor");
        if resp.clicked() {
            return match trace.target {
                Some(ToolTarget::Node(n)) => Some(AgentPanelAction::SelectNode(n)),
                Some(ToolTarget::Flow(f)) => Some(AgentPanelAction::SelectFlow(f)),
                None => None,
            };
        }
    }
    None
}

fn syntax_for_tag(tag: &str) -> Syntax {
    match tag.trim().to_ascii_lowercase().as_str() {
        "smali" | "dalvik" => Syntax::Smali,
        "xml" | "html" | "axml" => Syntax::Xml,
        "json" => Syntax::Json,
        "js" | "javascript" | "ts" | "java" | "kotlin" => Syntax::JavaScript,
        "css" => Syntax::Css,
        _ => Syntax::Plain,
    }
}

fn render_formatted_text(ui: &mut egui::Ui, msg_idx: usize, text: &str) {
    let mut in_code = false;
    let mut code_lang = String::new();
    let mut code_buf = String::new();
    let mut block_idx = 0usize;

    for line in text.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("```") {
            if in_code {
                render_code_block(ui, (msg_idx, block_idx), &code_lang, &code_buf);
                code_buf.clear();
                code_lang.clear();
                in_code = false;
                block_idx += 1;
            } else {
                code_lang = rest.trim().to_owned();
                in_code = true;
            }
            continue;
        }
        if in_code {
            if !code_buf.is_empty() {
                code_buf.push('\n');
            }
            code_buf.push_str(line);
        } else if line.trim().is_empty() {
            ui.add_space(4.0);
        } else {
            ui.add(
                egui::Label::new(RichText::new(line).color(theme::TEXT).size(12.5))
                    .wrap()
                    .selectable(true),
            );
        }
    }
    if in_code && !code_buf.is_empty() {
        render_code_block(ui, (msg_idx, block_idx), &code_lang, &code_buf);
    }
}

fn render_code_block(ui: &mut egui::Ui, id: (usize, usize), lang: &str, code: &str) {
    let syntax = syntax_for_tag(lang);
    let mono = TextStyle::Monospace.resolve(ui.style());
    egui::Frame::NONE
        .fill(theme::EDITOR)
        .stroke(Stroke::new(1.0, theme::CARD_BORDER))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            ScrollArea::horizontal()
                .id_salt(("agent_code", id.0, id.1))
                .show(ui, |ui| {
                    let mut job = LayoutJob::default();
                    for (i, line) in code.lines().enumerate() {
                        if i > 0 {
                            highlight::append(&mut job, "\n", theme::TEXT, &mono);
                        }
                        highlight_into(&mut job, line, syntax, &mono);
                    }
                    ui.add(egui::Label::new(job).extend().selectable(true));
                });
        });
}

fn prompt_box(
    ui: &mut egui::Ui,
    agent: &AgentController,
    state: &mut AgentPanelState,
) -> Option<AgentPanelAction> {
    let mut action = None;
    let busy = agent.is_busy();
    let focused = ui.memory(|m| m.has_focus(egui::Id::new(PROMPT_INPUT_ID)));

    egui::Frame::NONE
        .fill(theme::INPUT)
        .stroke(Stroke::new(
            1.0,
            if focused { theme::FOCUS } else { theme::SEPARATOR },
        ))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin {
            left: 8,
            right: 6,
            top: 6,
            bottom: 4,
        })
        .outer_margin(Margin::symmetric(8, 0))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            // Enter (without Shift) submits the prompt.
            let enter_pressed = focused
                && ui.input_mut(|i| {
                    if i.key_pressed(Key::Enter) && !i.modifiers.shift {
                        i.consume_key(egui::Modifiers::NONE, Key::Enter);
                        true
                    } else {
                        false
                    }
                });

            let edit = egui::TextEdit::multiline(&mut state.prompt)
                .id(egui::Id::new(PROMPT_INPUT_ID))
                .frame(false)
                .desired_rows(2)
                .desired_width((ui.available_width() - 4.0).max(40.0))
                .hint_text("Ask about source code, resources, or traffic…");
            ui.add(edit);

            ui.horizontal(|ui| {
                let provider = agent.config.provider;
                let model = agent.config.active().effective_model(provider);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("{} · {model}", provider.short_label()))
                            .size(10.5)
                            .color(theme::TEXT_DIM),
                    )
                    .truncate(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_send = !busy && !state.prompt.trim().is_empty();
                    let send_resp = ui.add_enabled(
                        can_send,
                        egui::Button::new(RichText::new("Ask ⏎").size(11.5).color(theme::TEXT_BRIGHT))
                            .fill(if can_send { theme::BUTTON } else { theme::PILL }),
                    );
                    if (send_resp.clicked() || enter_pressed) && can_send {
                        let text = std::mem::take(&mut state.prompt);
                        action = Some(AgentPanelAction::SendPrompt(text));
                    }
                });
            });
        });

    action
}
