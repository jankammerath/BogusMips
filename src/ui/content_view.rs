//! Center panel: shows the contents of the selected node.

use eframe::egui::{
    self, Align, Layout, RichText, ScrollArea, TextStyle, load::Bytes, text::LayoutJob,
};

use super::highlight::{GUTTER, TEXT, append, highlight_into};
use crate::inspect::{Content, Inspection, Syntax};

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ViewMode {
    #[default]
    Preview,
    Hex,
}

pub fn show(ui: &mut egui::Ui, inspection: &Inspection, mode: &mut ViewMode) {
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if inspection.raw.is_some() && !matches!(inspection.content, Content::Hex(_)) {
                ui.selectable_value(mode, ViewMode::Hex, "Hex");
                ui.selectable_value(mode, ViewMode::Preview, "Preview");
            }
            if let Content::Text { lines, .. } = &inspection.content {
                if *mode == ViewMode::Preview
                    && ui
                        .button("Copy")
                        .on_hover_text("Copy the full text")
                        .clicked()
                {
                    ui.ctx().copy_text(lines.join("\n"));
                }
            }
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                ui.add(egui::Label::new(RichText::new(&inspection.title).strong()).truncate());
            });
        });
    });
    ui.separator();

    let id = egui::Id::new(("content", inspection.node));
    match (&inspection.content, &inspection.raw, *mode) {
        (_, Some(raw), ViewMode::Hex) | (Content::Hex(raw), _, _) => hex_view(ui, id, raw),
        (Content::Text { lines, syntax }, _, _) => text_view(ui, id, lines, *syntax),
        (Content::Image { uri, bytes }, _, _) => {
            ScrollArea::both()
                .id_salt(id)
                .auto_shrink(false)
                .show(ui, |ui| {
                    ui.add_space(8.0);
                    ui.vertical_centered(|ui| {
                        ui.add(
                            egui::Image::from_bytes(uri.clone(), Bytes::Shared(bytes.clone()))
                                .fit_to_original_size(1.0),
                        );
                    });
                });
        }
        (Content::Message(msg), _, _) => {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new(msg).color(ui.visuals().weak_text_color()));
            });
        }
    }
}

fn monospace_rows(
    ui: &mut egui::Ui,
    id: egui::Id,
    count: usize,
    mut row: impl FnMut(usize, &egui::FontId) -> LayoutJob,
) {
    let font = TextStyle::Monospace.resolve(ui.style());
    let row_height = ui.fonts(|f| f.row_height(&font));
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        ScrollArea::both().id_salt(id).auto_shrink(false).show_rows(
            ui,
            row_height,
            count,
            |ui, range| {
                for i in range {
                    ui.add(egui::Label::new(row(i, &font)).extend());
                }
            },
        );
    });
}

fn text_view(ui: &mut egui::Ui, id: egui::Id, lines: &[String], syntax: Syntax) {
    let digits = lines.len().max(1).to_string().len();
    monospace_rows(ui, id, lines.len(), |i, font| {
        let mut job = LayoutJob::default();
        append(&mut job, &format!("{:>digits$}  ", i + 1), GUTTER, font);
        highlight_into(&mut job, &lines[i], syntax, font);
        job
    });
}

fn hex_view(ui: &mut egui::Ui, id: egui::Id, data: &[u8]) {
    const ASCII: egui::Color32 = egui::Color32::from_rgb(0xce, 0x91, 0x78);
    let rows = data.len().div_ceil(16);
    monospace_rows(ui, id.with("hex"), rows, |row, font| {
        let start = row * 16;
        let chunk = &data[start..(start + 16).min(data.len())];
        let mut hex = String::with_capacity(16 * 3 + 1);
        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let mut job = LayoutJob::default();
        append(&mut job, &format!("{start:08x}  "), GUTTER, font);
        append(&mut job, &format!("{hex:<50}"), TEXT, font);
        append(&mut job, &ascii, ASCII, font);
        job
    });
}
