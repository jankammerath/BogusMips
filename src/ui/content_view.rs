//! Center panel: shows the contents of the selected node.

use eframe::egui::{
    self, Align, Layout, RichText, ScrollArea, TextStyle, load::Bytes, text::LayoutJob,
};

use super::highlight::{GUTTER, TEXT, append, highlight_into};
use crate::inspect::{Content, Inspection, Syntax};

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ViewMode {
    /// Rendered / decoded / beautified content.
    #[default]
    Preview,
    /// The text as stored, for beautified files.
    Original,
    Hex,
}

pub fn show(ui: &mut egui::Ui, inspection: &Inspection, mode: &mut ViewMode) {
    if inspection.original.is_none() && *mode == ViewMode::Original {
        *mode = ViewMode::Preview;
    }
    let shown_text = match (&inspection.content, &inspection.original, *mode) {
        (Content::Text { .. }, Some(original), ViewMode::Original) => Some(original),
        (Content::Text { lines, .. }, _, ViewMode::Preview) => Some(lines),
        _ => None,
    };
    ui.horizontal(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if inspection.raw.is_some() && !matches!(inspection.content, Content::Hex(_)) {
                ui.selectable_value(mode, ViewMode::Hex, "Hex");
                if inspection.original.is_some() {
                    ui.selectable_value(mode, ViewMode::Original, "Original")
                        .on_hover_text("The text as stored in the package");
                    ui.selectable_value(mode, ViewMode::Preview, "Formatted")
                        .on_hover_text("Beautified; only whitespace differs from the original");
                } else {
                    ui.selectable_value(mode, ViewMode::Preview, "Preview");
                }
            }
            if let Some(lines) = shown_text {
                if ui
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
        (Content::Text { syntax, .. }, _, ViewMode::Original) if inspection.original.is_some() => {
            let original = inspection.original.as_deref().unwrap_or_default();
            text_view(ui, id.with("original"), original, *syntax)
        }
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

/// Shows `count` virtualized monospace rows. Each row has a gutter (line
/// number / offset) that sticks to the left edge while the content scrolls
/// horizontally underneath it.
fn monospace_rows(
    ui: &mut egui::Ui,
    id: egui::Id,
    count: usize,
    gutter_chars: usize,
    mut row: impl FnMut(usize, &egui::FontId) -> (String, LayoutJob),
) {
    let font = TextStyle::Monospace.resolve(ui.style());
    let row_height = ui.fonts(|f| f.row_height(&font));
    let char_width = ui.fonts(|f| f.glyph_width(&font, '0'));
    let gutter_width = gutter_chars as f32 * char_width + 2.0 * GUTTER_PADDING;
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        ScrollArea::both().id_salt(id).auto_shrink(false).show_rows(
            ui,
            row_height,
            count,
            |ui, range| {
                let viewport_left = ui.clip_rect().left();
                let background = ui.visuals().panel_fill;
                for i in range {
                    let (gutter, job) = row(i, &font);
                    let line = ui
                        .horizontal(|ui| {
                            ui.add_space(gutter_width);
                            ui.add(egui::Label::new(job).extend());
                        })
                        .response
                        .rect;
                    // Painted after the text, so scrolled text slides under it.
                    let rect = egui::Rect::from_min_size(
                        egui::pos2(viewport_left, line.top()),
                        egui::vec2(gutter_width, line.height().max(row_height)),
                    );
                    let painter = ui.painter();
                    painter.rect_filled(rect, 0.0, background);
                    painter.text(
                        egui::pos2(rect.right() - GUTTER_PADDING, rect.top()),
                        egui::Align2::RIGHT_TOP,
                        gutter,
                        font.clone(),
                        GUTTER,
                    );
                }
            },
        );
    });
}

const GUTTER_PADDING: f32 = 8.0;

fn text_view(ui: &mut egui::Ui, id: egui::Id, lines: &[String], syntax: Syntax) {
    let digits = lines.len().max(1).to_string().len();
    monospace_rows(ui, id, lines.len(), digits, |i, font| {
        let mut job = LayoutJob::default();
        highlight_into(&mut job, &lines[i], syntax, font);
        ((i + 1).to_string(), job)
    });
}

fn hex_view(ui: &mut egui::Ui, id: egui::Id, data: &[u8]) {
    const ASCII: egui::Color32 = egui::Color32::from_rgb(0xce, 0x91, 0x78);
    let rows = data.len().div_ceil(16);
    monospace_rows(ui, id.with("hex"), rows, 8, |row, font| {
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
        append(&mut job, &format!("{hex:<50}"), TEXT, font);
        append(&mut job, &ascii, ASCII, font);
        (format!("{start:08x}"), job)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::{Content, Inspection};

    fn texts(output: &egui::FullOutput) -> Vec<(egui::Pos2, String)> {
        output
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some((t.pos, t.galley.text().to_owned())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn line_numbers_stick_while_scrolling_horizontally() {
        let ctx = egui::Context::default();
        crate::ui::theme::install_fonts(&ctx);
        let inspection = Inspection {
            node: 0,
            title: "x".into(),
            content: Content::Text {
                lines: vec![format!("first {}", "x".repeat(2000)), "second".into()],
                syntax: Syntax::Plain,
            },
            raw: None,
            original: None,
            sections: Vec::new(),
        };
        let mut mode = ViewMode::Preview;
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0));
        let mut frame = |events: Vec<egui::Event>| {
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            let output = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| show(ui, &inspection, &mut mode));
            });
            texts(&output)
        };
        let find = |texts: &[(egui::Pos2, String)], pred: &dyn Fn(&str) -> bool| {
            texts
                .iter()
                .find(|(_, t)| pred(t))
                .map(|(p, _)| *p)
                .unwrap()
        };

        let before = frame(vec![]);
        let number = find(&before, &|t| t == "1");
        let code = find(&before, &|t| t.starts_with("first"));
        let pointer = egui::pos2(400.0, 300.0);
        frame(vec![egui::Event::PointerMoved(pointer)]);
        for _ in 0..5 {
            frame(vec![egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(-200.0, 0.0),
                modifiers: Default::default(),
            }]);
        }
        let after = frame(vec![]);
        let number_after = find(&after, &|t| t == "1");
        let code_after = find(&after, &|t| t.starts_with("first"));
        assert!(
            code_after.x < code.x - 100.0,
            "content did not scroll: {code:?} -> {code_after:?}"
        );
        assert_eq!(number, number_after, "line number moved");
        assert!(number.x < code.x);
    }
}
