//! Right panel: details about the selected node.

use eframe::egui::{self, RichText, ScrollArea};

use crate::inspect::Inspection;

pub fn show(ui: &mut egui::Ui, inspection: Option<&Inspection>) {
    ScrollArea::vertical()
        .id_salt("info_scroll")
        .auto_shrink(false)
        .show(ui, |ui| {
            let Some(inspection) = inspection else {
                ui.label(
                    RichText::new("Select a file or class to see its details.")
                        .color(ui.visuals().weak_text_color()),
                );
                return;
            };
            for (i, section) in inspection.sections.iter().enumerate() {
                egui::CollapsingHeader::new(
                    RichText::new(&section.title).family(super::theme::bold_family()),
                )
                .id_salt(("info_section", i, &section.title))
                .default_open(true)
                .show(ui, |ui| {
                    for (key, value) in &section.rows {
                        if !key.is_empty() {
                            ui.label(
                                RichText::new(key)
                                    .small()
                                    .color(ui.visuals().weak_text_color()),
                            );
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
                ui.add_space(4.0);
            }
        });
}
