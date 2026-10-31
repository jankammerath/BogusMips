//! Right sidebar panel: houses the AI Agent prompt window and the collapsible
//! File / Request information sections.

use eframe::egui::{self, CornerRadius, RichText, ScrollArea, Sense, vec2};

use super::agent_panel::{self, AgentPanelAction, AgentPanelState, ContextSummary};
use super::icons::{self, Icon};
use super::theme;
use super::tree_view::paint_chevron;
use crate::agent::AgentController;
use crate::inspect::InfoSection;

/// Active tab of the right sidebar card.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum RightTab {
    #[default]
    Agent,
    Info,
}

pub struct RightPanelResponse {
    pub close: bool,
    pub agent_action: Option<AgentPanelAction>,
}

fn tab_pill(ui: &mut egui::Ui, active: bool, label: &str, tooltip: &str) -> bool {
    let font = egui::FontId::proportional(12.0);
    let text_color = if active {
        theme::TEXT_BRIGHT
    } else {
        theme::TEXT_DIM
    };
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, text_color);
    let (pill, response) =
        ui.allocate_exact_size(galley.size() + vec2(14.0, 8.0), Sense::click());
    if active {
        ui.painter()
            .rect_filled(pill, CornerRadius::same(4), theme::PILL);
    } else if response.hovered() {
        ui.painter()
            .rect_filled(pill, CornerRadius::same(4), theme::LIST_HOVER);
    }
    ui.painter()
        .galley(pill.center() - galley.size() / 2.0, galley, text_color);
    response.on_hover_text(tooltip).clicked()
}

/// Shows the right sidebar card with tabs for the AI Agent and File/Request
/// information.
pub fn show_right_panel(
    ui: &mut egui::Ui,
    tab: &mut RightTab,
    info_title: &str,
    sections: Option<&[InfoSection]>,
    agent: &mut AgentController,
    agent_state: &mut AgentPanelState,
    ctx_summary: &ContextSummary<'_>,
) -> RightPanelResponse {
    let full = ui.max_rect();
    ui.expand_to_include_rect(full);
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(full)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    let ui = &mut child;

    let mut close = false;
    let mut clear_chat = false;

    // Header: pill tabs ("AI Agent" and "File information") + action icons.
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.add_space(6.0);
        ui.spacing_mut().item_spacing.x = 4.0;
        if tab_pill(
            ui,
            *tab == RightTab::Agent,
            "AI Agent",
            "Ask the AI agent about source code, resources, and network traffic (⇧⌘A)",
        ) {
            *tab = RightTab::Agent;
        }
        if tab_pill(
            ui,
            *tab == RightTab::Info,
            info_title,
            "Show file or request details (⌘I)",
        ) {
            *tab = RightTab::Info;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(4.0);
            close = icons::button(ui, Icon::Close, 22.0, "Hide right sidebar (⌘I)").clicked();
            if *tab == RightTab::Agent {
                if !agent.messages.is_empty()
                    && icons::button(ui, Icon::Trash, 22.0, "Clear conversation").clicked()
                {
                    clear_chat = true;
                }
                if icons::button(
                    ui,
                    Icon::Settings,
                    22.0,
                    "Configure AI provider (Grok, Gemini, Claude, OpenAI…)",
                )
                .clicked()
                {
                    agent_state.show_settings = !agent_state.show_settings;
                }
            }
        });
    });
    if clear_chat {
        agent.clear();
    }
    ui.add_space(4.0);

    let agent_action = match *tab {
        RightTab::Agent => agent_panel::show(ui, agent, agent_state, ctx_summary),
        RightTab::Info => {
            show_info_sections(ui, sections);
            None
        }
    };

    RightPanelResponse {
        close,
        agent_action,
    }
}

pub fn show_info_sections(ui: &mut egui::Ui, sections: Option<&[InfoSection]>) {
    ScrollArea::vertical()
        .id_salt("info_scroll")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            egui::Frame::NONE
                .inner_margin(egui::Margin {
                    left: 8,
                    right: 10,
                    top: 0,
                    bottom: 8,
                })
                .show(ui, |ui| {
                    ui.set_max_width(ui.available_width());
                    let Some(sections) = sections else {
                        ui.label(
                            RichText::new("Select a file or class to see its details.")
                                .color(theme::TEXT_DIM),
                        );
                        return;
                    };
                    for (i, section) in sections.iter().enumerate() {
                        egui::CollapsingHeader::new(
                            RichText::new(section.title.to_uppercase())
                                .size(11.0)
                                .family(theme::bold_family()),
                        )
                        .id_salt(("info_section", i, &section.title))
                        .default_open(true)
                        .icon(|ui, openness, response| {
                            paint_chevron(ui.painter(), response.rect.center(), openness > 0.5);
                        })
                        .show(ui, |ui| {
                            for (key, value) in &section.rows {
                                if !key.is_empty() {
                                    ui.label(RichText::new(key).size(11.5).color(theme::TEXT_DIM));
                                }
                                let monospace = key.contains("SHA") || key == "Signature";
                                let text = if monospace {
                                    RichText::new(value).monospace()
                                } else {
                                    RichText::new(value)
                                };
                                ui.add(egui::Label::new(text).wrap());
                                ui.add_space(4.0);
                            }
                        });
                        ui.add_space(2.0);
                    }
                });
        });
}
