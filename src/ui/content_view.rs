//! Editor card: a VS Code style tab bar with breadcrumbs, and the contents
//! of the selected node.

use std::ops::Range;

use eframe::egui::{
    self, CornerRadius, RichText, ScrollArea, Sense, TextStyle, load::Bytes, text::LayoutJob, vec2,
};

use super::highlight::{GUTTER, TEXT, append, highlight_into};
use super::icons::{self, Icon};
use super::theme;
use crate::inspect::{Content, Inspection, Syntax};

const TAB_BAR_HEIGHT: f32 = 35.0;
const BREADCRUMBS_HEIGHT: f32 = 22.0;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ViewMode {
    /// Rendered / decoded / beautified content.
    #[default]
    Preview,
    /// The text as stored, for beautified files.
    Original,
    Hex,
}

/// A location to show, e.g. a search match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Goto {
    pub line: usize,
    /// Byte range within the line to highlight.
    pub range: Range<usize>,
    /// Scroll there on the next frame.
    pub scroll: bool,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct EditorResponse {
    pub close: bool,
    pub toggle_info: bool,
}

/// A small text toggle in the tab bar (Formatted / Original / Hex).
fn mode_toggle(ui: &mut egui::Ui, mode: &mut ViewMode, value: ViewMode, label: &str, tip: &str) {
    let selected = *mode == value;
    let font = egui::FontId::proportional(12.0);
    let galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        font,
        if selected {
            theme::TEXT_BRIGHT
        } else {
            theme::TEXT_DIM
        },
    );
    let (rect, response) = ui.allocate_exact_size(galley.size() + vec2(12.0, 6.0), Sense::click());
    if selected {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(3), theme::PILL);
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(3), theme::LIST_HOVER);
    }
    ui.painter()
        .galley(rect.center() - galley.size() / 2.0, galley, theme::TEXT);
    if response.on_hover_text(tip).clicked() {
        *mode = value;
    }
}

/// Tab bar with a single tab for the open item, plus view actions.
fn tab_bar(
    ui: &mut egui::Ui,
    inspection: Option<&Inspection>,
    mode: &mut ViewMode,
    info_visible: bool,
    shown_text: Option<&Vec<String>>,
) -> EditorResponse {
    let mut response = EditorResponse::default();
    let (bar, _) =
        ui.allocate_exact_size(vec2(ui.available_width(), TAB_BAR_HEIGHT), Sense::hover());
    let radius = theme::CARD_RADIUS;
    ui.painter().rect_filled(
        bar,
        CornerRadius {
            nw: radius,
            ne: radius,
            sw: 0,
            se: 0,
        },
        theme::TAB_BAR,
    );
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(bar)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    let ui = &mut child;

    if let Some(inspection) = inspection {
        let name = inspection
            .title
            .rsplit(" / ")
            .next()
            .unwrap_or(&inspection.title)
            .to_owned();
        let font = egui::TextStyle::Body.resolve(ui.style());
        let galley = ui.painter().layout_no_wrap(name, font, theme::TEXT_BRIGHT);
        let tab_width = (galley.size().x + 52.0).max(120.0);
        let (tab, _) = ui.allocate_exact_size(vec2(tab_width, TAB_BAR_HEIGHT), Sense::hover());
        ui.painter().rect_filled(
            tab,
            CornerRadius {
                nw: radius,
                ne: 0,
                sw: 0,
                se: 0,
            },
            theme::EDITOR,
        );
        ui.painter().galley(
            egui::pos2(tab.left() + 14.0, tab.center().y - galley.size().y / 2.0),
            galley,
            theme::TEXT_BRIGHT,
        );
        let close_rect = egui::Rect::from_center_size(
            egui::pos2(tab.right() - 16.0, tab.center().y),
            vec2(20.0, 20.0),
        );
        let mut close_ui = ui.new_child(egui::UiBuilder::new().max_rect(close_rect));
        if icons::button(&mut close_ui, Icon::Close, 20.0, "Close").clicked() {
            response.close = true;
        }
    }

    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.add_space(8.0);
        let tip = if info_visible {
            "Hide file information (⌘I)"
        } else {
            "Show file information (⌘I)"
        };
        if icons::button(ui, Icon::PanelRight, 22.0, tip).clicked() {
            response.toggle_info = true;
        }
        if let Some(lines) = shown_text {
            if icons::button(ui, Icon::Copy, 22.0, "Copy the full text").clicked() {
                ui.ctx().copy_text(lines.join("\n"));
            }
        }
        if let Some(inspection) = inspection {
            if inspection.raw.is_some() && !matches!(inspection.content, Content::Hex(_)) {
                ui.add_space(6.0);
                mode_toggle(ui, mode, ViewMode::Hex, "Hex", "Hex dump of the file");
                if inspection.original.is_some() {
                    mode_toggle(
                        ui,
                        mode,
                        ViewMode::Original,
                        "Original",
                        "The text as stored in the package",
                    );
                    mode_toggle(
                        ui,
                        mode,
                        ViewMode::Preview,
                        "Formatted",
                        "Beautified; only whitespace differs from the original",
                    );
                } else {
                    mode_toggle(ui, mode, ViewMode::Preview, "Preview", "Decoded content");
                }
            }
        }
    });
    response
}

fn breadcrumbs(ui: &mut egui::Ui, title: &str) {
    let (rect, _) = ui.allocate_exact_size(
        vec2(ui.available_width(), BREADCRUMBS_HEIGHT),
        Sense::hover(),
    );
    let font = egui::FontId::proportional(12.0);
    let mut job = LayoutJob::default();
    let parts: Vec<&str> = title.split(" / ").collect();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            append(&mut job, "  ›  ", theme::TEXT_DIM, &font);
        }
        let color = if i + 1 == parts.len() {
            theme::TEXT
        } else {
            theme::TEXT_DIM
        };
        append(&mut job, part, color, &font);
    }
    let galley = ui.fonts(|f| f.layout_job(job));
    ui.painter_at(rect).galley(
        egui::pos2(rect.left() + 14.0, rect.center().y - galley.size().y / 2.0),
        galley,
        theme::TEXT,
    );
}

/// The editor card when no item is selected.
fn watermark(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space((ui.available_height() / 2.0 - 60.0).max(0.0));
        for (label, keys) in [
            ("Select a file or class in the Explorer", ""),
            ("Search file contents", "⇧⌘F"),
            ("Export the selected item", "⌘E"),
            ("Toggle file information", "⌘I"),
        ] {
            ui.label(RichText::new(format!("{label}   {keys}")).color(theme::TEXT_DIM));
            ui.add_space(6.0);
        }
    });
}

/// Shows the editor card's contents.
pub fn show(
    ui: &mut egui::Ui,
    inspection: Option<&Inspection>,
    mode: &mut ViewMode,
    goto: Option<&mut Goto>,
    info_visible: bool,
) -> EditorResponse {
    if inspection.is_none_or(|i| i.original.is_none()) && *mode == ViewMode::Original {
        *mode = ViewMode::Preview;
    }
    let shown_text = inspection.and_then(|i| match (&i.content, &i.original, *mode) {
        (Content::Text { .. }, Some(original), ViewMode::Original) => Some(original),
        (Content::Text { lines, .. }, _, ViewMode::Preview) => Some(lines),
        _ => None,
    });
    let response = tab_bar(ui, inspection, mode, info_visible, shown_text);
    let Some(inspection) = inspection else {
        watermark(ui);
        return response;
    };
    breadcrumbs(ui, &inspection.title);

    let id = egui::Id::new(("content", inspection.node));
    match (&inspection.content, &inspection.raw, *mode) {
        (_, Some(raw), ViewMode::Hex) | (Content::Hex(raw), _, _) => hex_view(ui, id, raw),
        (Content::Text { syntax, .. }, _, ViewMode::Original) if inspection.original.is_some() => {
            let original = inspection.original.as_deref().unwrap_or_default();
            text_view(ui, id.with("original"), original, *syntax, None)
        }
        (Content::Text { lines, syntax }, _, _) => text_view(ui, id, lines, *syntax, goto),
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
                ui.label(RichText::new(msg).color(theme::TEXT_DIM));
            });
        }
    }
    response
}

/// Gives `range` of the job's text a background color.
fn highlight_range(job: &mut LayoutJob, range: &Range<usize>, color: egui::Color32) {
    let mut sections = Vec::with_capacity(job.sections.len() + 2);
    for section in job.sections.drain(..) {
        let r = section.byte_range.clone();
        let cut_start = range.start.clamp(r.start, r.end);
        let cut_end = range.end.clamp(r.start, r.end);
        for (part, highlighted) in [
            (r.start..cut_start, false),
            (cut_start..cut_end, true),
            (cut_end..r.end, false),
        ] {
            if part.is_empty() {
                continue;
            }
            let mut s = section.clone();
            s.byte_range = part;
            if highlighted {
                s.format.background = color;
            }
            sections.push(s);
        }
    }
    job.sections = sections;
}

/// Shows `count` virtualized monospace rows. Each row has a gutter (line
/// number / offset) that sticks to the left edge while the content scrolls
/// horizontally underneath it. `goto` highlights (and once scrolls to) a line.
fn monospace_rows(
    ui: &mut egui::Ui,
    id: egui::Id,
    count: usize,
    gutter_chars: usize,
    goto: Option<&mut Goto>,
    mut row: impl FnMut(usize, &egui::FontId) -> (String, LayoutJob),
) {
    let font = TextStyle::Monospace.resolve(ui.style());
    let row_height = ui.fonts(|f| f.row_height(&font));
    let char_width = ui.fonts(|f| f.glyph_width(&font, '0'));
    let gutter_width = gutter_chars as f32 * char_width + 2.0 * GUTTER_PADDING;
    let target = goto.as_ref().map(|g| (g.line, g.range.clone()));
    let mut area = ScrollArea::both().id_salt(id).auto_shrink(false);
    if let Some(goto) = goto {
        if goto.scroll {
            goto.scroll = false;
            let top = goto.line as f32 * row_height - ui.available_height() / 3.0;
            area = area.vertical_scroll_offset(top.max(0.0));
            let column = goto.range.start as f32 * char_width;
            let left = column - (ui.available_width() - gutter_width) / 3.0;
            area = area.horizontal_scroll_offset(left.max(0.0));
        }
    }
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
        area.show_rows(ui, row_height, count, |ui, range| {
            let viewport = ui.clip_rect();
            for i in range {
                let (gutter, mut job) = row(i, &font);
                let target_range = target
                    .as_ref()
                    .filter(|(line, _)| *line == i)
                    .map(|(_, r)| r);
                if let Some(r) = target_range {
                    highlight_range(&mut job, r, theme::CURRENT_MATCH);
                }
                let background = ui.painter().add(egui::Shape::Noop);
                let line = ui
                    .horizontal(|ui| {
                        ui.add_space(gutter_width);
                        ui.add(egui::Label::new(job).extend());
                    })
                    .response
                    .rect;
                let full = egui::Rect::from_min_max(
                    egui::pos2(viewport.left(), line.top()),
                    egui::pos2(viewport.right(), line.top() + line.height().max(row_height)),
                );
                if target_range.is_some() {
                    ui.painter().set(
                        background,
                        egui::Shape::rect_filled(full, 0.0, theme::LINE_HIGHLIGHT),
                    );
                }
                // Painted after the text, so scrolled text slides under it.
                let gutter_rect =
                    egui::Rect::from_min_size(full.min, egui::vec2(gutter_width, full.height()));
                let painter = ui.painter();
                painter.rect_filled(gutter_rect, 0.0, theme::EDITOR);
                painter.text(
                    egui::pos2(gutter_rect.right() - GUTTER_PADDING, gutter_rect.top()),
                    egui::Align2::RIGHT_TOP,
                    gutter,
                    font.clone(),
                    if target_range.is_some() {
                        theme::TEXT
                    } else {
                        GUTTER
                    },
                );
            }
        });
    });
}

const GUTTER_PADDING: f32 = 8.0;

fn text_view(
    ui: &mut egui::Ui,
    id: egui::Id,
    lines: &[String],
    syntax: Syntax,
    goto: Option<&mut Goto>,
) {
    let digits = lines.len().max(1).to_string().len();
    monospace_rows(ui, id, lines.len(), digits, goto, |i, font| {
        let mut job = LayoutJob::default();
        highlight_into(&mut job, &lines[i], syntax, font);
        ((i + 1).to_string(), job)
    });
}

fn hex_view(ui: &mut egui::Ui, id: egui::Id, data: &[u8]) {
    const ASCII: egui::Color32 = egui::Color32::from_rgb(0xce, 0x91, 0x78);
    let rows = data.len().div_ceil(16);
    monospace_rows(ui, id.with("hex"), rows, 8, None, |row, font| {
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
                egui::CentralPanel::default()
                    .show(ctx, |ui| show(ui, Some(&inspection), &mut mode, None, true));
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
