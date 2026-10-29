//! Right panel: details about the selected node.

use eframe::egui::{self, CornerRadius, RichText, ScrollArea, Sense, vec2};

use super::icons::{self, Icon};
use super::theme;
use super::tree_view::paint_chevron;
use crate::inspect::InfoSection;

/// Shows the panel. Returns `true` if the close button was clicked.
pub fn show(ui: &mut egui::Ui, title: &str, sections: Option<&[InfoSection]>) -> bool {
    let mut close = false;
    // Header: a label pill (like VS Code's "Chat") and a close button.
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.add_space(6.0);
        let font = egui::FontId::proportional(12.0);
        let galley = ui
            .painter()
            .layout_no_wrap(title.to_owned(), font, theme::TEXT);
        let (pill, _) = ui.allocate_exact_size(galley.size() + vec2(14.0, 8.0), Sense::hover());
        ui.painter()
            .rect_filled(pill, CornerRadius::same(4), theme::PILL);
        ui.painter()
            .galley(pill.center() - galley.size() / 2.0, galley, theme::TEXT);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(4.0);
            close = icons::button(ui, Icon::Close, 22.0, "Hide file information (⌘I)").clicked();
        });
    });
    ui.add_space(6.0);

    ScrollArea::vertical()
        .id_salt("info_scroll")
        .auto_shrink(false)
        .show(ui, |ui| {
            egui::Frame::NONE
                .inner_margin(egui::Margin {
                    left: 8,
                    right: 10,
                    top: 0,
                    bottom: 8,
                })
                .show(ui, |ui| {
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
    close
}
