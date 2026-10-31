//! Sidebar Network view: emulator controls, capture status and the live list
//! of captured requests.

use eframe::egui::{self, CornerRadius, Key, RichText, ScrollArea, Sense, Stroke, vec2};

use super::icons::{self, Icon};
use super::theme;
use crate::inspect::group_digits;
use crate::net::bypass::{FridaConfig, FridaScriptEntry, ScriptSource, parse_script_specs};
use crate::net::capture::Scheme;
use crate::net::controller::{NetworkController, Phase, ScriptState};
use crate::net::emulator::Avd;

const ROW_HEIGHT: f32 = 38.0;

pub const FRIDA_SCRIPT_INPUT_ID: &str = "frida_script_input";

#[derive(Default)]
pub struct NetworkViewState {
    pub avd: String,
    pub filter: String,
    pub log_expanded: bool,
    pub bypass_checks: bool,
    /// User-defined Frida scripts (CodeShare `owner/slug`, URL, or local `.js`
    /// file path) with individual enable/disable checkboxes.
    pub scripts: Vec<FridaScriptEntry>,
    /// Current text in the "Add Frida script" input field.
    pub script_input: String,
    /// Validation error from the last attempt to add a script.
    pub script_error: Option<String>,
    /// Whether changes to Frida settings should be persisted to disk.
    pub persist_config: bool,
}

impl NetworkViewState {
    pub fn from_config(cfg: &FridaConfig, persist_config: bool) -> Self {
        Self {
            bypass_checks: cfg.bypass_checks,
            scripts: cfg.scripts.clone(),
            persist_config,
            ..Self::default()
        }
    }

    pub fn to_config(&self) -> FridaConfig {
        FridaConfig {
            bypass_checks: self.bypass_checks,
            scripts: self.scripts.clone(),
        }
    }

    fn save_if_enabled(&self) {
        if self.persist_config {
            let _ = self.to_config().save();
        }
    }

    /// Parses and adds one or more Frida scripts (e.g. `"dzonerzy/aesinfo"`,
    /// `"frida --codeshare dzonerzy/aesinfo"`, a URL, or a `.js` file path) and
    /// enables them.
    pub fn add_script(&mut self, raw: &str) -> Result<(), String> {
        let parsed = match parse_script_specs(raw) {
            Ok(list) => list,
            Err(e) => {
                self.script_error = Some(e.clone());
                return Err(e);
            }
        };
        for source in parsed {
            let spec = source.spec();
            if let Some(existing) = self.scripts.iter_mut().find(|s| s.spec == spec) {
                existing.enabled = true;
            } else {
                self.scripts.push(FridaScriptEntry::new(spec, true));
            }
        }
        self.script_error = None;
        self.save_if_enabled();
        Ok(())
    }

    /// Adds the script currently typed into [`Self::script_input`], clearing the
    /// input field on success.
    pub fn add_input_script(&mut self) -> bool {
        let raw = self.script_input.trim().to_owned();
        if raw.is_empty() {
            return false;
        }
        if self.add_script(&raw).is_ok() {
            self.script_input.clear();
            true
        } else {
            false
        }
    }

    /// Removes the script at `index`.
    pub fn remove_script(&mut self, index: usize) {
        if index < self.scripts.len() {
            self.scripts.remove(index);
            self.save_if_enabled();
        }
    }

    /// Returns the specs of all currently enabled Frida scripts, in order.
    pub fn enabled_scripts(&self) -> Vec<String> {
        self.scripts
            .iter()
            .filter(|s| s.enabled)
            .map(|s| s.spec.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAction {
    StartStop,
    Clear,
    SelectFlow(u64),
    SaveCa,
    PickFile,
    PickFridaScript,
}

fn status_color(status: Option<u16>) -> egui::Color32 {
    match status {
        Some(200..=299) => egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
        Some(300..=399) => egui::Color32::from_rgb(0x56, 0x9c, 0xd6),
        Some(400..=499) => egui::Color32::from_rgb(0xcc, 0xa7, 0x00),
        Some(500..=599) => theme::ERROR,
        _ => theme::TEXT_DIM,
    }
}

fn method_color(method: &str) -> egui::Color32 {
    match method {
        "GET" => egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
        "POST" => egui::Color32::from_rgb(0xcc, 0xa7, 0x00),
        "PUT" | "PATCH" => egui::Color32::from_rgb(0x56, 0x9c, 0xd6),
        "DELETE" => theme::ERROR,
        _ => theme::TEXT,
    }
}

/// Shows the Network view. `doc` is `None` when no package is open.
pub fn show(
    ui: &mut egui::Ui,
    doc: Option<(&NetworkController, &[Avd], &mut NetworkViewState, Option<u64>)>,
) -> Option<NetworkAction> {
    theme::view_title(ui, "Network");
    let Some((controller, avds, state, selected)) = doc else {
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(RichText::new("Open a package to capture its traffic.").color(theme::TEXT_DIM));
        });
        ui.add_space(8.0);
        let mut action = None;
        egui::Frame::NONE
            .inner_margin(egui::Margin::symmetric(12, 0))
            .show(ui, |ui| {
                if theme::primary_button(ui, "Open APK or XAPK").clicked() {
                    action = Some(NetworkAction::PickFile);
                }
            });
        return action;
    };

    let mut action = None;
    let phase = controller.phase();
    let running = phase.is_active();

    egui::Frame::NONE
        .inner_margin(egui::Margin::symmetric(12, 0))
        .show(ui, |ui| {
            // Emulator picker.
            if state.avd.is_empty() {
                if let Some(first) = avds.iter().find(|a| a.rootable).or_else(|| avds.first()) {
                    state.avd = first.name.clone();
                }
            }
            ui.add_enabled_ui(!running, |ui| {
                egui::ComboBox::from_id_salt("avd")
                    .selected_text(if state.avd.is_empty() {
                        "Select an emulator".to_owned()
                    } else {
                        state.avd.clone()
                    })
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        for avd in avds {
                            let label = if avd.rootable {
                                avd.name.clone()
                            } else {
                                format!("{} (not rootable)", avd.name)
                            };
                            ui.add_enabled_ui(avd.rootable, |ui| {
                                ui.selectable_value(&mut state.avd, avd.name.clone(), label);
                            });
                        }
                    });
            });
            ui.add_space(6.0);

            ui.add_enabled_ui(!running, |ui| {
                if ui
                    .checkbox(&mut state.bypass_checks, "Bypass Play Services & root checks")
                    .on_hover_text(
                        "Inject a frida gadget that makes Google Play Services \
                         availability checks report success and neutralises common \
                         root-detection checks (RootBeer, test-keys, su), so apps \
                         that abort on a rooted/Play-Services-less emulator keep \
                         running. Downloads the gadget once (needs network and a \
                         rootable emulator). Cannot defeat server-side Play Integrity.",
                    )
                    .changed()
                {
                    state.save_if_enabled();
                }
            });

            ui.add_space(4.0);
            if let Some(a) = frida_scripts_block(ui, controller, state, running) {
                action = Some(a);
            }
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                let label = if running { "Stop" } else { "Start capture" };
                let enabled = running || !state.avd.is_empty();
                if ui
                    .add_enabled(enabled, egui::Button::new(label).min_size(vec2(110.0, 24.0)))
                    .clicked()
                {
                    action = Some(NetworkAction::StartStop);
                }
                if icons::button(ui, Icon::Trash, 24.0, "Clear captured requests").clicked() {
                    action = Some(NetworkAction::Clear);
                }
                if icons::button(ui, Icon::Download, 24.0, "Save the proxy CA certificate").clicked() {
                    action = Some(NetworkAction::SaveCa);
                }
            });
            ui.add_space(4.0);

            status_block(ui, controller, phase, state);
        });

    ui.add_space(4.0);
    filter_box(ui, state);
    ui.add_space(4.0);

    // The request list.
    let flows = controller.capture().snapshot();
    let needle = state.filter.trim().to_lowercase();
    let filtered: Vec<_> = flows
        .iter()
        .filter(|f| {
            needle.is_empty()
                || f.url().to_lowercase().contains(&needle)
                || f.method.to_lowercase().contains(&needle)
        })
        .rev()
        .collect();

    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        ScrollArea::vertical()
            .id_salt("net_flows")
            .auto_shrink(false)
            .show_rows(ui, ROW_HEIGHT, filtered.len(), |ui, range| {
                for flow in &filtered[range] {
                    if flow_row(ui, flow, selected == Some(flow.id)) {
                        action = Some(NetworkAction::SelectFlow(flow.id));
                    }
                }
            });
    });

    action
}

fn frida_scripts_block(
    ui: &mut egui::Ui,
    controller: &NetworkController,
    state: &mut NetworkViewState,
    running: bool,
) -> Option<NetworkAction> {
    let mut action = None;
    let enabled_count = state.scripts.iter().filter(|s| s.enabled).count();
    let runtime_states = controller.script_statuses();
    let header_text = if enabled_count > 0 {
        format!("Frida scripts ({enabled_count} active)")
    } else {
        "Frida scripts".to_owned()
    };
    ui.label(RichText::new(header_text).size(11.5).color(theme::TEXT_DIM));
    ui.add_space(2.0);

    // Input row: text field (CodeShare slug, `frida --codeshare ...`, URL, or .js file) + Add + Browse.
    let mut add_requested = false;
    ui.add_enabled_ui(!running, |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            let buttons_width = 66.0;
            let input_width = (ui.available_width() - buttons_width).max(60.0);
            let input_resp = egui::Frame::NONE
                .fill(theme::INPUT)
                .stroke(Stroke::new(1.0, theme::INPUT))
                .corner_radius(2)
                .inner_margin(egui::Margin {
                    left: 6,
                    right: 4,
                    top: 3,
                    bottom: 3,
                })
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut state.script_input)
                            .id(egui::Id::new(FRIDA_SCRIPT_INPUT_ID))
                            .frame(false)
                            .hint_text("dzonerzy/aesinfo or script.js")
                            .desired_width(input_width - 10.0),
                    )
                })
                .inner
                .on_hover_text(
                    "Add a Frida script by CodeShare slug (e.g. dzonerzy/aesinfo or \
                     frida --codeshare dzonerzy/aesinfo), https:// URL, or local .js path.",
                );

            if input_resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                add_requested = true;
            }
            if ui
                .add_enabled(
                    !state.script_input.trim().is_empty(),
                    egui::Button::new("Add").min_size(vec2(38.0, 22.0)),
                )
                .on_hover_text("Add Frida script")
                .clicked()
            {
                add_requested = true;
            }
            if icons::button(ui, Icon::Files, 22.0, "Browse for a local Frida script (.js)…")
                .clicked()
            {
                action = Some(NetworkAction::PickFridaScript);
            }
        });
    });

    if add_requested {
        state.add_input_script();
    }

    if let Some(err) = &state.script_error {
        ui.add(
            egui::Label::new(RichText::new(err).size(11.0).color(theme::ERROR)).wrap(),
        );
    }

    if !state.scripts.is_empty() {
        ui.add_space(2.0);
        let mut remove_idx = None;
        let mut toggled = false;
        ScrollArea::vertical()
            .id_salt("frida_scripts")
            .max_height(96.0)
            .show(ui, |ui| {
                for (idx, entry) in state.scripts.iter_mut().enumerate() {
                    let tooltip = ScriptSource::parse(&entry.spec)
                        .map(|s| s.description())
                        .unwrap_or_else(|_| entry.spec.clone());
                    let runtime = runtime_states
                        .iter()
                        .find(|(s, _)| s == &entry.spec)
                        .map(|(_, st)| st);
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(!running, |ui| {
                            if ui
                                .checkbox(&mut entry.enabled, &entry.spec)
                                .on_hover_text(tooltip)
                                .changed()
                            {
                                toggled = true;
                            }
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add_enabled_ui(!running, |ui| {
                                if icons::button(ui, Icon::Close, 18.0, "Remove script").clicked() {
                                    remove_idx = Some(idx);
                                }
                            });
                            if entry.enabled {
                                if let Some(st) = runtime {
                                    script_state_badge(ui, st);
                                }
                            }
                        });
                    });
                }
            });
        if toggled {
            state.save_if_enabled();
        }
        if let Some(idx) = remove_idx {
            state.remove_script(idx);
        }
    }

    action
}

fn script_state_badge(ui: &mut egui::Ui, state: &ScriptState) {
    let (label, color, tip) = match state {
        ScriptState::Loading => (
            "Loading…".to_owned(),
            egui::Color32::from_rgb(0xcc, 0xa7, 0x00),
            "Downloading or loading Frida script on the host…".to_owned(),
        ),
        ScriptState::Injected => (
            "Armed".to_owned(),
            egui::Color32::from_rgb(0x56, 0x9c, 0xd6),
            "Pushed to device with frida-gadget; waiting for app runtime to execute it…".to_owned(),
        ),
        ScriptState::Active { messages } => {
            let text = if *messages > 0 {
                format!("✔ Working ({messages})")
            } else {
                "✔ Working".to_owned()
            };
            (
                text,
                egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
                format!(
                    "Script is loaded and working inside the target app ({messages} log message(s) emitted)."
                ),
            )
        }
        ScriptState::Error(err) => (
            "✖ Error".to_owned(),
            theme::ERROR,
            format!("Script error: {err}"),
        ),
    };
    ui.add(egui::Label::new(RichText::new(label).size(10.5).color(color)).sense(Sense::hover()))
        .on_hover_text(tip);
}

fn status_block(
    ui: &mut egui::Ui,
    controller: &NetworkController,
    phase: Phase,
    state: &mut NetworkViewState,
) {
    let (_, error, log) = controller.status_snapshot();
    let script_states = controller.script_statuses();
    ui.horizontal(|ui| {
        if phase.is_active() && phase != Phase::Capturing {
            ui.add(egui::Spinner::new().size(12.0));
        }
        let color = match phase {
            Phase::Failed => theme::ERROR,
            Phase::Capturing => egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
            _ => theme::TEXT_DIM,
        };
        ui.label(RichText::new(phase.label()).size(12.0).color(color));
        let count = controller.capture().len();
        if count > 0 {
            ui.label(
                RichText::new(format!("· {} requests", group_digits(count)))
                    .size(12.0)
                    .color(theme::TEXT_DIM),
            );
        }
    });
    if let Some(error) = &error {
        ui.add(egui::Label::new(RichText::new(error).size(12.0).color(theme::ERROR)).wrap());
    }
    if !script_states.is_empty() {
        let total = script_states.len();
        let active = script_states
            .iter()
            .filter(|(_, s)| matches!(s, ScriptState::Active { .. }))
            .count();
        let messages: usize = script_states
            .iter()
            .map(|(_, s)| match s {
                ScriptState::Active { messages } => *messages,
                _ => 0,
            })
            .sum();
        let first_err = script_states.iter().find_map(|(spec, s)| match s {
            ScriptState::Error(e) => Some((spec.as_str(), e.as_str())),
            _ => None,
        });
        let (summary, color) = if let Some((spec, err)) = first_err {
            (
                format!("✖ Frida ({spec}): {err}"),
                theme::ERROR,
            )
        } else if active == total {
            let msg_suffix = if messages > 0 {
                format!(" ({messages} logs)")
            } else {
                String::new()
            };
            if total == 1 {
                (
                    format!("✔ Frida: {} loaded & working{msg_suffix}", script_states[0].0),
                    egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
                )
            } else {
                (
                    format!("✔ Frida: {active}/{total} scripts loaded & working{msg_suffix}"),
                    egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
                )
            }
        } else if script_states
            .iter()
            .any(|(_, s)| matches!(s, ScriptState::Injected))
        {
            (
                format!("⏳ Frida: {active}/{total} working (waiting for app runtime…)"),
                egui::Color32::from_rgb(0x56, 0x9c, 0xd6),
            )
        } else {
            (
                "⏳ Frida: loading script(s)…".to_owned(),
                theme::TEXT_DIM,
            )
        };
        ui.add(egui::Label::new(RichText::new(summary).size(11.5).color(color)).wrap());
    }
    // A collapsible log of the session steps and Frida script output.
    if !log.is_empty() {
        let header = if state.log_expanded { "▾ Log" } else { "▸ Log" };
        if ui
            .add(egui::Label::new(RichText::new(header).size(11.5).color(theme::TEXT_DIM)).sense(Sense::click()))
            .clicked()
        {
            state.log_expanded = !state.log_expanded;
        }
        if state.log_expanded {
            egui::Frame::NONE
                .fill(theme::EDITOR)
                .corner_radius(3)
                .inner_margin(egui::Margin::same(6))
                .show(ui, |ui| {
                    ScrollArea::vertical()
                        .id_salt("net_log")
                        .max_height(140.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &log {
                                let color = if line.starts_with("✔") {
                                    egui::Color32::from_rgb(0x4e, 0xc9, 0xb0)
                                } else if line.starts_with("✖") {
                                    theme::ERROR
                                } else if line.starts_with("[frida]") {
                                    egui::Color32::from_rgb(0x9c, 0xdc, 0xfe)
                                } else {
                                    theme::TEXT_DIM
                                };
                                ui.add(
                                    egui::Label::new(RichText::new(line).size(11.0).color(color))
                                        .wrap(),
                                );
                            }
                        });
                });
        }
    }
}

fn filter_box(ui: &mut egui::Ui, state: &mut NetworkViewState) {
    egui::Frame::NONE
        .fill(theme::INPUT)
        .stroke(Stroke::new(1.0, theme::INPUT))
        .corner_radius(2)
        .inner_margin(egui::Margin {
            left: 6,
            right: 2,
            top: 2,
            bottom: 2,
        })
        .outer_margin(egui::Margin::symmetric(12, 0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !state.filter.is_empty()
                        && icons::button(ui, Icon::Close, 18.0, "Clear filter").clicked()
                    {
                        state.filter.clear();
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut state.filter)
                            .frame(false)
                            .hint_text("Filter by URL or method")
                            .desired_width(ui.available_width()),
                    );
                });
            });
        });
}

fn flow_row(ui: &mut egui::Ui, flow: &crate::net::capture::Flow, selected: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), ROW_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    if selected {
        painter.rect_filled(rect, 0.0, theme::LIST_SELECTED);
    } else if response.hovered() {
        painter.rect_filled(rect, 0.0, theme::LIST_HOVER);
    }
    let left = rect.left() + 12.0;
    let top = rect.top() + 5.0;

    // First line: status, method, host.
    let status = flow
        .status
        .map(|s| s.to_string())
        .unwrap_or_else(|| if flow.error.is_some() { "ERR".into() } else { "…".into() });
    let small = egui::FontId::proportional(11.0);
    let body = egui::TextStyle::Body.resolve(ui.style());

    let status_galley = painter.layout_no_wrap(
        format!("{status:>3}"),
        body.clone(),
        if flow.error.is_some() { theme::ERROR } else { status_color(flow.status) },
    );
    painter.galley(egui::pos2(left, top), status_galley, theme::TEXT);
    let method_galley =
        painter.layout_no_wrap(flow.method.clone(), small.clone(), method_color(&flow.method));
    painter.galley(egui::pos2(left + 34.0, top + 1.0), method_galley, theme::TEXT);
    let host_galley = painter.layout_no_wrap(flow.host.clone(), small.clone(), theme::TEXT);
    painter.galley(egui::pos2(left + 84.0, top + 1.0), host_galley, theme::TEXT);
    if flow.scheme == Scheme::Https {
        let r = egui::Rect::from_min_size(egui::pos2(rect.right() - 20.0, top), vec2(12.0, 12.0));
        icons::paint(&painter, r, Icon::Lock, theme::TEXT_DIM);
    }

    // Second line: path, dimmed, clipped.
    let path_rect = egui::Rect::from_min_max(
        egui::pos2(left, rect.top() + 20.0),
        egui::pos2(rect.right() - 8.0, rect.bottom()),
    );
    let path_galley = painter.layout_no_wrap(flow.path.clone(), small, theme::TEXT_DIM);
    ui.painter_at(path_rect)
        .galley(path_rect.min, path_galley, theme::TEXT_DIM);

    painter.line_segment(
        [rect.left_bottom(), rect.right_bottom()],
        Stroke::new(1.0, egui::Color32::from_rgb(0x2a, 0x2a, 0x2a)),
    );
    let _ = CornerRadius::ZERO;
    response.on_hover_text(flow.url()).clicked()
}
