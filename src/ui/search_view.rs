//! Sidebar search view: a query box with VS Code's option toggles and the
//! results grouped by file.

use std::collections::HashSet;
use std::ops::Range;

use eframe::egui::{
    self, Color32, CornerRadius, Key, Margin, RichText, ScrollArea, Sense, Stroke,
    text::{LayoutJob, TextFormat},
    vec2,
};

use super::theme;
use super::tree_view::{icon, paint_chevron};
use crate::inspect::group_digits;
use crate::package::{NodeId, Package};
use crate::search::{SearchController, Status};

pub const INPUT_ID: &str = "search_input";
const ROW_HEIGHT: f32 = 22.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchAction {
    /// Open a match in the editor.
    Open {
        node: NodeId,
        line: usize,
        range: Range<usize>,
    },
    PickFile,
}

#[derive(Default)]
pub struct SearchViewState {
    collapsed: HashSet<NodeId>,
    /// The match opened last: (node, line, match start).
    selected: Option<(NodeId, usize, usize)>,
}

/// An option toggle inside the search box (Aa, ab, .*).
fn toggle(ui: &mut egui::Ui, value: &mut bool, label: RichText, tooltip: &str) -> bool {
    let (rect, response) = ui.allocate_exact_size(vec2(22.0, 20.0), Sense::click());
    let painter = ui.painter();
    if *value {
        painter.rect(
            rect,
            CornerRadius::same(3),
            Color32::from_rgba_unmultiplied(0x24, 0x89, 0xdb, 0x51),
            Stroke::new(1.0, theme::ACCENT),
            egui::StrokeKind::Inside,
        );
    } else if response.hovered() {
        painter.rect_filled(
            rect,
            CornerRadius::same(3),
            Color32::from_rgba_unmultiplied(0x5a, 0x5d, 0x5e, 0x50),
        );
    }
    let galley = ui.painter().layout_no_wrap(
        label.text().to_owned(),
        egui::FontId::monospace(11.0),
        if *value {
            theme::TEXT_BRIGHT
        } else {
            theme::TEXT
        },
    );
    let pos = rect.center() - galley.size() / 2.0;
    if label.text() == "ab" {
        // "Match Whole Word" is drawn as an underlined "ab".
        let y = pos.y + galley.size().y + 0.5;
        ui.painter().line_segment(
            [egui::pos2(pos.x, y), egui::pos2(pos.x + galley.size().x, y)],
            Stroke::new(1.0, theme::TEXT),
        );
    }
    ui.painter().galley(pos, galley, theme::TEXT);
    let clicked = response.clicked();
    if clicked {
        *value = !*value;
    }
    response.on_hover_text(tooltip);
    clicked
}

fn search_box(ui: &mut egui::Ui, ctl: &mut SearchController) {
    let focused = ui.memory(|m| m.has_focus(egui::Id::new(INPUT_ID)));
    egui::Frame::NONE
        .fill(theme::INPUT)
        .stroke(Stroke::new(
            1.0,
            if focused { theme::FOCUS } else { theme::INPUT },
        ))
        .corner_radius(CornerRadius::same(2))
        .inner_margin(Margin {
            left: 6,
            right: 2,
            top: 2,
            bottom: 2,
        })
        .outer_margin(Margin::symmetric(12, 0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    let q = &mut ctl.query;
                    let mut changed = false;
                    changed |= toggle(
                        ui,
                        &mut q.regex,
                        RichText::new(".*"),
                        "Use Regular Expression",
                    );
                    changed |= toggle(
                        ui,
                        &mut q.whole_word,
                        RichText::new("ab"),
                        "Match Whole Word",
                    );
                    changed |= toggle(ui, &mut q.match_case, RichText::new("Aa"), "Match Case");
                    let edit = egui::TextEdit::singleline(&mut q.text)
                        .id(egui::Id::new(INPUT_ID))
                        .frame(false)
                        .hint_text("Search")
                        .desired_width(ui.available_width());
                    let response = ui.add(edit);
                    changed |= response.changed();
                    let enter = response.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    if enter {
                        ctl.search_now();
                    } else if changed {
                        ctl.query_changed();
                    }
                });
            });
        });
}

fn status_line(ui: &mut egui::Ui, ctl: &SearchController) {
    let (text, color) = if let Some(error) = &ctl.error {
        (error.clone(), ui.visuals().error_fg_color)
    } else {
        match ctl.status() {
            Status::Indexing { done, total } => (
                format!(
                    "Indexing {} of {} items…",
                    group_digits(done),
                    group_digits(total)
                ),
                theme::TEXT_DIM,
            ),
            Status::Searching => ("Searching…".to_owned(), theme::TEXT_DIM),
            Status::Idle => match &ctl.results {
                Some(_) if ctl.query.text.is_empty() => (String::new(), theme::TEXT_DIM),
                Some(r) if r.total_matches == 0 => {
                    ("No results found.".to_owned(), theme::TEXT_DIM)
                }
                Some(r) => {
                    let mut text = format!(
                        "{} {} in {} {}",
                        group_digits(r.total_matches),
                        if r.total_matches == 1 {
                            "result"
                        } else {
                            "results"
                        },
                        group_digits(r.files.len()),
                        if r.files.len() == 1 { "file" } else { "files" }
                    );
                    if r.truncated {
                        text.push_str(&format!(
                            " (showing the first {})",
                            group_digits(crate::search::MAX_MATCHES)
                        ));
                    }
                    (text, theme::TEXT_DIM)
                }
                None => (String::new(), theme::TEXT_DIM),
            },
        }
    };
    if !text.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.add(egui::Label::new(RichText::new(text).color(color).size(12.0)).wrap());
        });
    }
}

/// VS Code's thin indeterminate progress bar at the top of a view.
fn progress_bar(ui: &mut egui::Ui, active: bool) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 2.0), Sense::hover());
    if !active {
        return;
    }
    let t = ui.input(|i| i.time) as f32;
    let width = rect.width() * 0.3;
    let x = rect.left() + ((t * 0.8).fract() * (rect.width() + width)) - width;
    let bar = egui::Rect::from_min_max(
        egui::pos2(x.max(rect.left()), rect.top()),
        egui::pos2((x + width).min(rect.right()), rect.bottom()),
    );
    ui.painter().rect_filled(bar, 0.0, theme::ACCENT);
    ui.ctx().request_repaint();
}

enum Row {
    File(usize),
    Match(usize, usize),
}

fn file_row(
    ui: &mut egui::Ui,
    pkg: &Package,
    node: NodeId,
    count: usize,
    open: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), ROW_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    if response.hovered() {
        painter.rect_filled(rect, 0.0, theme::LIST_HOVER);
    }
    let y = rect.center().y;
    paint_chevron(&painter, egui::pos2(rect.left() + 16.0, y), open);
    let font = egui::TextStyle::Body.resolve(ui.style());
    let (glyph, color) = icon(pkg, node, false);
    let mut x = rect.left() + 26.0;
    let g = painter.layout_no_wrap(glyph.to_owned(), font.clone(), color);
    painter.galley(egui::pos2(x, y - g.size().y / 2.0), g.clone(), color);
    x += g.size().x + 6.0;
    let name = painter.layout_no_wrap(pkg.nodes[node].label.clone(), font.clone(), theme::TEXT);
    painter.galley(
        egui::pos2(x, y - name.size().y / 2.0),
        name.clone(),
        theme::TEXT,
    );
    x += name.size().x + 8.0;

    // Count badge on the right.
    let badge_text = painter.layout_no_wrap(
        group_digits(count),
        egui::FontId::proportional(11.0),
        theme::TEXT,
    );
    let badge = egui::Rect::from_center_size(
        egui::pos2(rect.right() - 12.0 - badge_text.size().x / 2.0 - 4.0, y),
        vec2(badge_text.size().x + 10.0, 16.0),
    );
    painter.rect_filled(
        badge,
        CornerRadius::same(8),
        Color32::from_rgb(0x4d, 0x4d, 0x4d),
    );
    painter.galley(
        badge.center() - badge_text.size() / 2.0,
        badge_text,
        theme::TEXT,
    );

    // Location (parent path), dimmed, between name and badge.
    let path = pkg.node_path(node);
    let parent = path
        .rsplit_once(" / ")
        .map_or("", |(p, _)| p)
        .split(" / ")
        .skip(1)
        .collect::<Vec<_>>()
        .join("/");
    let room = badge.left() - 8.0 - x;
    if room > 20.0 && !parent.is_empty() {
        let loc = painter.layout_no_wrap(parent, egui::FontId::proportional(11.5), theme::TEXT_DIM);
        let clip = egui::Rect::from_min_max(
            egui::pos2(x, rect.top()),
            egui::pos2(x + room, rect.bottom()),
        );
        ui.painter_at(clip)
            .galley(egui::pos2(x, y - loc.size().y / 2.0), loc, theme::TEXT_DIM);
    }
    response.on_hover_text(path)
}

fn match_row(
    ui: &mut egui::Ui,
    preview: &str,
    range: &Range<usize>,
    selected: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), ROW_HEIGHT), Sense::click());
    let painter = ui.painter_at(rect);
    if selected {
        painter.rect_filled(rect, 0.0, theme::LIST_SELECTED);
    } else if response.hovered() {
        painter.rect_filled(rect, 0.0, theme::LIST_HOVER);
    }
    let font = egui::TextStyle::Body.resolve(ui.style());
    let plain = TextFormat::simple(font.clone(), theme::TEXT);
    let mut job = LayoutJob::default();
    let safe = |i: usize| {
        (0..=i.min(preview.len()))
            .rev()
            .find(|&i| preview.is_char_boundary(i))
            .unwrap_or(0)
    };
    let (start, end) = (safe(range.start), safe(range.end));
    job.append(&preview[..start], 0.0, plain.clone());
    job.append(
        &preview[start..end],
        0.0,
        TextFormat {
            background: theme::MATCH,
            color: theme::TEXT_BRIGHT,
            ..plain.clone()
        },
    );
    job.append(&preview[end..], 0.0, plain);
    let galley = ui.fonts(|f| f.layout_job(job));
    painter.galley(
        egui::pos2(rect.left() + 40.0, rect.center().y - galley.size().y / 2.0),
        galley,
        theme::TEXT,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Shows the search view. `doc` is `None` when no package is open.
pub fn show(
    ui: &mut egui::Ui,
    doc: Option<(&Package, &mut SearchController, &mut SearchViewState)>,
) -> Option<SearchAction> {
    let busy = doc.as_ref().is_some_and(|(_, c, _)| c.is_busy());
    progress_bar(ui, busy);
    theme::view_title(ui, "Search");
    let Some((pkg, ctl, state)) = doc else {
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(
                RichText::new("Open a package to search its contents.").color(theme::TEXT_DIM),
            );
        });
        ui.add_space(8.0);
        let mut action = None;
        egui::Frame::NONE
            .inner_margin(Margin::symmetric(12, 0))
            .show(ui, |ui| {
                if theme::primary_button(ui, "Open APK or XAPK").clicked() {
                    action = Some(SearchAction::PickFile);
                }
            });
        return action;
    };

    search_box(ui, ctl);
    ui.add_space(6.0);
    status_line(ui, ctl);
    ui.add_space(4.0);

    let results = ctl.results.clone()?;
    let mut rows = Vec::new();
    for (fi, file) in results.files.iter().enumerate() {
        rows.push(Row::File(fi));
        if !state.collapsed.contains(&file.node) {
            rows.extend((0..file.matches.len()).map(|mi| Row::Match(fi, mi)));
        }
    }

    let mut action = None;
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        ScrollArea::vertical()
            .id_salt("search_results")
            .auto_shrink(false)
            .show_rows(ui, ROW_HEIGHT, rows.len(), |ui, range| {
                for row in &rows[range] {
                    match *row {
                        Row::File(fi) => {
                            let file = &results.files[fi];
                            let open = !state.collapsed.contains(&file.node);
                            if file_row(ui, pkg, file.node, file.matches.len(), open).clicked()
                                && !state.collapsed.remove(&file.node)
                            {
                                state.collapsed.insert(file.node);
                            }
                        }
                        Row::Match(fi, mi) => {
                            let file = &results.files[fi];
                            let m = &file.matches[mi];
                            let key = (file.node, m.line, m.range.start);
                            let response = match_row(
                                ui,
                                &m.preview,
                                &m.preview_range,
                                state.selected == Some(key),
                            )
                            .on_hover_text(format!("Line {}", m.line + 1));
                            if response.clicked() {
                                state.selected = Some(key);
                                action = Some(SearchAction::Open {
                                    node: file.node,
                                    line: m.line,
                                    range: m.range.clone(),
                                });
                            }
                        }
                    }
                }
            });
    });
    action
}
