//! Left panel: virtualized tree of the package (source code and files).

use std::collections::HashSet;

use eframe::egui::{self, Color32, Key, ScrollArea, Sense, Shape, Stroke, pos2, vec2};

use crate::export::{self, ExportKind};
use crate::package::{NodeId, NodeKind, Package};

/// Row metrics and colors modelled on the VS Code explorer.
const ROW_HEIGHT: f32 = 22.0;
const INDENT: f32 = 12.0;
const CHEVRON_WIDTH: f32 = 16.0;
const LEFT_PADDING: f32 = 4.0;
const SELECTED: Color32 = Color32::from_rgb(0x37, 0x37, 0x3d);
const HOVERED: Color32 = Color32::from_rgb(0x2a, 0x2d, 0x2e);
const GUIDE: Color32 = Color32::from_rgb(0x40, 0x40, 0x40);
const CHEVRON: Color32 = Color32::from_rgb(0xc5, 0xc5, 0xc5);
pub const FILTER_ID: &str = "tree_filter";

pub struct TreeState {
    pub expanded: HashSet<NodeId>,
    pub filter: String,
    filter_cache: Option<(String, Vec<bool>, usize)>,
    scroll_offset: f32,
    view_height: f32,
}

impl TreeState {
    pub fn new(pkg: &Package) -> Self {
        let root = pkg.root();
        let mut expanded = HashSet::from([root]);
        expanded.extend(pkg.nodes[root].children.iter().copied());
        Self {
            expanded,
            filter: String::new(),
            filter_cache: None,
            scroll_offset: 0.0,
            view_height: 0.0,
        }
    }

    /// Expands all ancestors of `node` so it becomes visible.
    pub fn reveal(&mut self, pkg: &Package, node: NodeId) {
        let mut current = pkg.nodes[node].parent;
        while let Some(id) = current {
            self.expanded.insert(id);
            current = pkg.nodes[id].parent;
        }
    }

    /// Visibility mask for the current filter: matching nodes plus ancestors.
    fn visible_mask(&mut self, pkg: &Package) -> Option<(&[bool], usize)> {
        let needle = self.filter.trim().to_lowercase();
        if needle.is_empty() {
            return None;
        }
        let stale = self
            .filter_cache
            .as_ref()
            .is_none_or(|(cached, _, _)| *cached != needle);
        if stale {
            let mut mask = vec![false; pkg.nodes.len()];
            let mut matches = 0;
            for (id, node) in pkg.nodes.iter().enumerate() {
                if node.parent.is_some() && node.label.to_lowercase().contains(&needle) {
                    matches += 1;
                    let mut current = Some(id);
                    while let Some(c) = current {
                        if mask[c] {
                            break;
                        }
                        mask[c] = true;
                        current = pkg.nodes[c].parent;
                    }
                }
            }
            mask[pkg.root()] = true;
            self.filter_cache = Some((needle, mask, matches));
        }
        self.filter_cache
            .as_ref()
            .map(|(_, mask, matches)| (mask.as_slice(), *matches))
    }
}

fn flatten(
    pkg: &Package,
    expanded: &HashSet<NodeId>,
    mask: Option<&[bool]>,
) -> Vec<(NodeId, usize)> {
    let mut rows = Vec::new();
    let mut stack = vec![(pkg.root(), 0usize)];
    while let Some((id, depth)) = stack.pop() {
        if mask.is_some_and(|m| !m[id]) {
            continue;
        }
        rows.push((id, depth));
        if mask.is_some() || expanded.contains(&id) {
            for &child in pkg.nodes[id].children.iter().rev() {
                stack.push((child, depth + 1));
            }
        }
    }
    rows
}

fn icon(pkg: &Package, id: NodeId, open: bool) -> (&'static str, Color32) {
    const FOLDER: Color32 = Color32::from_rgb(0xdc, 0xb6, 0x7a);
    const CODE: Color32 = Color32::from_rgb(0x4e, 0xc9, 0xb0);
    const GRAY: Color32 = Color32::from_rgb(0xa0, 0xa0, 0xa0);
    match &pkg.nodes[id].kind {
        NodeKind::Archive(_) => ("📦", Color32::from_rgb(0xc5, 0x86, 0xc0)),
        NodeKind::SourceRoot(_) => ("☕", CODE),
        NodeKind::ResourcesRoot(_) => ("🎨", Color32::from_rgb(0xce, 0x91, 0x78)),
        NodeKind::ResourceDir(..) if open => ("📂", FOLDER),
        NodeKind::ResourceDir(..) => ("📁", FOLDER),
        NodeKind::ResourceFile(..) => ("📝", Color32::from_rgb(0xdc, 0xdc, 0xaa)),
        NodeKind::FilesRoot(_) => ("🗄", FOLDER),
        NodeKind::Folder(_) if open => ("📂", FOLDER),
        NodeKind::Folder(_) => ("📁", FOLDER),
        NodeKind::JavaPackage(_) => ("🗀", Color32::from_rgb(0x56, 0x9c, 0xd6)),
        NodeKind::Class(_) => ("©", CODE),
        NodeKind::File(f) => {
            let name = pkg.files[*f].path.to_ascii_lowercase();
            let ext = name.rsplit('.').next().unwrap_or("");
            match ext {
                "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" => {
                    ("🖼", Color32::from_rgb(0x9c, 0xdc, 0xfe))
                }
                "dex" | "so" | "odex" | "vdex" | "oat" => {
                    ("⚙", Color32::from_rgb(0xce, 0x91, 0x78))
                }
                "xml" => ("📝", Color32::from_rgb(0xdc, 0xdc, 0xaa)),
                "apk" | "jar" | "zip" => ("📦", Color32::from_rgb(0xc5, 0x86, 0xc0)),
                "txt" | "json" | "properties" | "mf" | "sf" | "version" | "kotlin_builtins" => {
                    ("📃", GRAY)
                }
                _ => ("📄", GRAY),
            }
        }
    }
}

/// Draws a `›` (closed) or `⌄` (open) chevron centered at `center`.
fn paint_chevron(painter: &egui::Painter, center: egui::Pos2, open: bool) {
    let points = if open {
        vec![
            center + vec2(-4.0, -2.0),
            center + vec2(0.0, 2.0),
            center + vec2(4.0, -2.0),
        ]
    } else {
        vec![
            center + vec2(-2.0, -4.0),
            center + vec2(2.0, 0.0),
            center + vec2(-2.0, 4.0),
        ]
    };
    painter.add(Shape::line(points, Stroke::new(1.3, CHEVRON)));
}

/// Paints one explorer row (highlight, indent guides, chevron, icon, label)
/// spanning the full width of the tree.
fn paint_row(
    ui: &mut egui::Ui,
    pkg: &Package,
    id: NodeId,
    depth: usize,
    open: bool,
    selected: bool,
) -> egui::Response {
    let node = &pkg.nodes[id];
    let is_root = node.parent.is_none();
    let body = egui::TextStyle::Body.resolve(ui.style());
    let text_color = ui.visuals().text_color();

    let (label, label_font) = if is_root {
        (
            node.label.to_uppercase(),
            super::theme::bold(body.size - 1.0),
        )
    } else {
        (node.label.clone(), body.clone())
    };
    let painter = ui.painter().clone();
    let label_galley = painter.layout_no_wrap(label, label_font, text_color);
    let icon_galley = (!is_root).then(|| {
        let (glyph, color) = icon(pkg, id, open);
        painter.layout_no_wrap(glyph.to_owned(), body.clone(), color)
    });

    let left = ui.max_rect().left();
    let chevron_x = left + LEFT_PADDING + depth as f32 * INDENT;
    let icon_x = chevron_x + CHEVRON_WIDTH;
    let text_x = icon_x + icon_galley.as_ref().map_or(0.0, |g| g.size().x + 6.0);
    let width = (text_x + label_galley.size().x + 8.0 - left).max(ui.available_width());

    let (rect, response) = ui.allocate_exact_size(vec2(width, ROW_HEIGHT), Sense::click());
    if !ui.is_rect_visible(rect) {
        return response;
    }
    if selected {
        painter.rect_filled(rect, 0.0, SELECTED);
    } else if response.hovered() {
        painter.rect_filled(rect, 0.0, HOVERED);
    }
    for level in 1..depth {
        let x = left + LEFT_PADDING + level as f32 * INDENT + CHEVRON_WIDTH / 2.0;
        painter.line_segment(
            [pos2(x, rect.top()), pos2(x, rect.bottom())],
            Stroke::new(1.0, GUIDE),
        );
    }
    if node.kind.is_container() && !node.children.is_empty() {
        paint_chevron(
            &painter,
            pos2(chevron_x + CHEVRON_WIDTH / 2.0, rect.center().y),
            open,
        );
    }
    let center_y = rect.center().y;
    if let Some(g) = icon_galley {
        let pos = pos2(icon_x, center_y - g.size().y / 2.0);
        painter.galley(pos, g, text_color);
    }
    let pos = pos2(text_x, center_y - label_galley.size().y / 2.0);
    painter.galley(pos, label_galley, text_color);
    response
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct TreeResponse {
    /// The newly selected node, if the selection changed.
    pub selected: Option<NodeId>,
    /// Export chosen from a row's context menu.
    pub export: Option<(NodeId, ExportKind)>,
}

/// Shows the tree.
pub fn show(
    ui: &mut egui::Ui,
    pkg: &Package,
    state: &mut TreeState,
    selected: Option<NodeId>,
) -> TreeResponse {
    let mut new_selection = None;
    let mut export_request = None;

    ui.label(
        egui::RichText::new("PACKAGE")
            .small()
            .family(super::theme::bold_family())
            .color(ui.visuals().weak_text_color()),
    );
    ui.add_space(2.0);
    // Right-to-left, so the text field only takes the width that is left after
    // the clear button; sizing it from the full width would push the panel
    // wider on every frame. The surrounding `horizontal` limits the layout to
    // a single row (on its own it would fill the panel's whole height).
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add_enabled(
                    !state.filter.is_empty(),
                    egui::Button::new("✖").frame(false),
                )
                .on_hover_text("Clear filter")
                .clicked()
            {
                state.filter.clear();
            }
            let edit = egui::TextEdit::singleline(&mut state.filter)
                .id(egui::Id::new(FILTER_ID))
                .hint_text("🔍 Filter (⌘F)")
                .desired_width(ui.available_width());
            ui.add(edit);
        });
    });

    let expanded_snapshot = std::mem::take(&mut state.expanded);
    let (rows, matches) = match state.visible_mask(pkg) {
        Some((mask, matches)) => (flatten(pkg, &expanded_snapshot, Some(mask)), Some(matches)),
        None => (flatten(pkg, &expanded_snapshot, None), None),
    };
    state.expanded = expanded_snapshot;
    if let Some(matches) = matches {
        ui.label(
            egui::RichText::new(format!("{matches} matches"))
                .small()
                .color(ui.visuals().weak_text_color()),
        );
    }
    ui.add_space(2.0);

    let row_height = ROW_HEIGHT;
    let selected_row = selected.and_then(|s| rows.iter().position(|(id, _)| *id == s));

    // Keyboard navigation while no text field has focus.
    let mut scroll_to: Option<usize> = None;
    if !ui.ctx().wants_keyboard_input() {
        let (up, down, left, right) = ui.input(|i| {
            (
                i.key_pressed(Key::ArrowUp),
                i.key_pressed(Key::ArrowDown),
                i.key_pressed(Key::ArrowLeft),
                i.key_pressed(Key::ArrowRight),
            )
        });
        if let Some(row) = selected_row {
            let id = rows[row].0;
            let node = &pkg.nodes[id];
            if down && row + 1 < rows.len() {
                new_selection = Some(rows[row + 1].0);
                scroll_to = Some(row + 1);
            } else if up && row > 0 {
                new_selection = Some(rows[row - 1].0);
                scroll_to = Some(row - 1);
            } else if right && !node.children.is_empty() {
                state.expanded.insert(id);
            } else if left && !state.expanded.remove(&id) {
                if let Some(parent) = node.parent {
                    new_selection = Some(parent);
                    scroll_to = rows.iter().position(|(r, _)| *r == parent);
                }
            }
        } else if (down || up) && !rows.is_empty() {
            new_selection = Some(rows[0].0);
            scroll_to = Some(0);
        }
    }

    let mut area = ScrollArea::both().id_salt("tree_scroll").auto_shrink(false);
    if let Some(row) = scroll_to {
        let top = row as f32 * row_height;
        let bottom = top + row_height;
        if top < state.scroll_offset {
            area = area.vertical_scroll_offset(top);
        } else if bottom > state.scroll_offset + state.view_height {
            area = area.vertical_scroll_offset(bottom - state.view_height);
        }
    }

    let output = ui
        .scope(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            area.show_rows(ui, row_height, rows.len(), |ui, range| {
                for &(id, depth) in &rows[range] {
                    let open = matches.is_some() || state.expanded.contains(&id);
                    let row = paint_row(ui, pkg, id, depth, open, selected == Some(id));
                    if row.clicked() {
                        new_selection = Some(id);
                        if pkg.nodes[id].kind.is_container() && !state.expanded.remove(&id) {
                            state.expanded.insert(id);
                        }
                    }
                    if row.secondary_clicked() {
                        new_selection = Some(id);
                    }
                    row.context_menu(|ui| {
                        let options = export::options(pkg, id);
                        if options.is_empty() {
                            ui.add_enabled(false, egui::Button::new("Nothing to export"));
                        }
                        for option in options {
                            if ui.button(option.label).clicked() {
                                export_request = Some((id, option.kind));
                                ui.close();
                            }
                        }
                    });
                }
            })
        })
        .inner;
    state.scroll_offset = output.state.offset.y;
    state.view_height = output.inner_rect.height();

    TreeResponse {
        selected: new_selection.filter(|&n| Some(n) != selected),
        export: export_request,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_respects_expansion() {
        let mut pkg_nodes = Vec::new();
        let mk = |label: &str, parent: Option<usize>, kind: NodeKind| crate::package::Node {
            label: label.into(),
            kind,
            parent,
            children: Vec::new(),
        };
        pkg_nodes.push(mk("root", None, NodeKind::Folder("/".into())));
        pkg_nodes.push(mk("a", Some(0), NodeKind::Folder("a/".into())));
        pkg_nodes.push(mk("b", Some(1), NodeKind::File(0)));
        pkg_nodes[0].children = vec![1];
        pkg_nodes[1].children = vec![2];
        let expanded = HashSet::from([0]);
        let pkg = test_package(pkg_nodes);
        assert_eq!(flatten(&pkg, &expanded, None), vec![(0, 0), (1, 1)]);
        let mask = [true, true, true];
        assert_eq!(flatten(&pkg, &expanded, Some(&mask)).len(), 3);
    }

    fn test_package(nodes: Vec<crate::package::Node>) -> Package {
        Package {
            path: Default::default(),
            kind: crate::package::PackageKind::Apk,
            archives: Vec::new(),
            files: Vec::new(),
            dex_files: Vec::new(),
            nodes,
        }
    }
}
