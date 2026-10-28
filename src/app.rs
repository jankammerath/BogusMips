use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use eframe::egui::{self, Key, KeyboardShortcut, Modifiers, RichText};

use crate::export::{self, ExportKind};
use crate::inspect::{Content, Inspection, format_size, group_digits, inspect};
use crate::package::{NodeId, Package, PackageKind};
use crate::ui::content_view::{self, ViewMode};
use crate::ui::tree_view::{self, TreeState};
use crate::ui::{info_panel, theme};

const OPEN: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::O);
const CLOSE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::W);
const TOGGLE_INFO: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::I);
const FIND: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::F);
const EXPORT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::E);

/// Asks where to save an export, given the suggested file name.
type SaveDialog = Box<dyn Fn(&str) -> Option<PathBuf>>;

fn native_save_dialog(file_name: &str) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Export")
        .set_file_name(file_name)
        .save_file()
}

struct Loading {
    path: PathBuf,
    rx: Receiver<Result<Package, String>>,
}

struct Document {
    package: Package,
    tree: TreeState,
    selected: Option<NodeId>,
    inspection: Option<Inspection>,
    view_mode: ViewMode,
}

pub struct BogusMipsApp {
    document: Option<Document>,
    loading: Option<Loading>,
    pending_open: Option<PathBuf>,
    pending_export: Option<(NodeId, ExportKind)>,
    /// Title and message of an error dialog.
    error: Option<(&'static str, String)>,
    /// Confirmation shown in the status bar (e.g. after an export).
    notice: Option<String>,
    save_dialog: SaveDialog,
    show_info: bool,
    native_theme_applied: bool,
    window_title: String,
}

impl BogusMipsApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial_file: Option<PathBuf>) -> Self {
        Self::with_context(&cc.egui_ctx, initial_file)
    }

    pub fn with_context(ctx: &egui::Context, initial_file: Option<PathBuf>) -> Self {
        theme::install_fonts(ctx);
        theme::apply_dark(ctx);
        egui_extras::install_image_loaders(ctx);
        Self {
            document: None,
            loading: None,
            pending_open: initial_file,
            pending_export: None,
            error: None,
            notice: None,
            save_dialog: Box::new(native_save_dialog),
            show_info: true,
            native_theme_applied: false,
            window_title: "BogusMips".to_owned(),
        }
    }

    fn pick_file(&mut self) {
        let picked = rfd::FileDialog::new()
            .set_title("Open Android package")
            .add_filter("Android package (*.apk, *.xapk)", &["apk", "xapk"])
            .pick_file();
        if let Some(path) = picked {
            self.pending_open = Some(path);
        }
    }

    fn start_loading(&mut self, ctx: &egui::Context, path: PathBuf) {
        self.close(ctx);
        let (tx, rx) = channel();
        let worker_path = path.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Package::open(&worker_path));
            repaint.request_repaint();
        });
        self.loading = Some(Loading { path, rx });
    }

    fn poll_loading(&mut self, ctx: &egui::Context) {
        let Some(loading) = &self.loading else { return };
        match loading.rx.try_recv() {
            Ok(Ok(package)) => {
                let tree = TreeState::new(&package);
                let root = package.root();
                let title = format!("{} — BogusMips", package.archives[0].name);
                self.set_title(ctx, title);
                let mut doc = Document {
                    package,
                    tree,
                    selected: None,
                    inspection: None,
                    view_mode: ViewMode::default(),
                };
                select(ctx, &mut doc, root);
                self.document = Some(doc);
                self.loading = None;
            }
            Ok(Err(e)) => {
                self.error = Some(("Could not open file", e));
                self.loading = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.error = Some((
                    "Could not open file",
                    format!("Loading {} failed unexpectedly.", loading.path.display()),
                ));
                self.loading = None;
            }
        }
    }

    fn close(&mut self, ctx: &egui::Context) {
        if self.document.take().is_some() {
            ctx.forget_all_images();
            self.set_title(ctx, "BogusMips".to_owned());
        }
    }

    /// The selected node and its primary export, if it can be exported.
    fn primary_export(&self) -> Option<(NodeId, ExportKind)> {
        let doc = self.document.as_ref()?;
        let node = doc.selected?;
        export::options(&doc.package, node)
            .first()
            .map(|o| (node, o.kind))
    }

    fn request_primary_export(&mut self) {
        if let Some(request) = self.primary_export() {
            self.pending_export = Some(request);
        }
    }

    fn run_export(&mut self, node: NodeId, kind: ExportKind) {
        let Some(doc) = &self.document else {
            return;
        };
        let options = export::options(&doc.package, node);
        let Some(option) = options.iter().find(|o| o.kind == kind) else {
            return;
        };
        let Some(path) = (self.save_dialog)(&option.file_name) else {
            return;
        };
        let written = export::export_bytes(&doc.package, node, kind).and_then(|bytes| {
            std::fs::write(&path, &bytes)
                .map(|()| bytes.len())
                .map_err(|e| format!("{}: {e}", path.display()))
        });
        match written {
            Ok(len) => {
                self.notice = Some(format!(
                    "Exported {} to {}",
                    format_size(len as u64),
                    path.display()
                ));
            }
            Err(e) => self.error = Some(("Could not export", e)),
        }
    }

    fn set_title(&mut self, ctx: &egui::Context, title: String) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
        self.window_title = title;
    }

    /// macOS: the black strip behind the traffic lights, showing the window
    /// title and acting as the drag handle (the native title bar is hidden).
    fn title_bar(&self, ctx: &egui::Context) {
        let fullscreen = ctx.input(|i| i.viewport().fullscreen.unwrap_or(false));
        if !cfg!(target_os = "macos") || fullscreen {
            return;
        }
        egui::TopBottomPanel::top("title_bar")
            .exact_height(theme::MACOS_TITLE_BAR_HEIGHT)
            .show_separator_line(false)
            .frame(egui::Frame::NONE.fill(theme::BACKGROUND))
            .show(ctx, |ui| {
                let rect = ui.max_rect();
                let response =
                    ui.interact(rect, ui.id().with("drag"), egui::Sense::click_and_drag());
                if response.drag_started() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
                if response.double_clicked() {
                    let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
                }
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    &self.window_title,
                    egui::FontId::proportional(13.0),
                    egui::Color32::from_rgb(0xcc, 0xcc, 0xcc),
                );
            });
    }

    fn handle_input(&mut self, ctx: &egui::Context) {
        let (open, close, toggle_info, find, export, dropped) = ctx.input_mut(|i| {
            (
                i.consume_shortcut(&OPEN),
                i.consume_shortcut(&CLOSE),
                i.consume_shortcut(&TOGGLE_INFO),
                i.consume_shortcut(&FIND),
                i.consume_shortcut(&EXPORT),
                i.raw.dropped_files.iter().find_map(|f| f.path.clone()),
            )
        });
        if open {
            self.pick_file();
        }
        if close {
            self.close(ctx);
        }
        if toggle_info {
            self.show_info = !self.show_info;
        }
        if find {
            ctx.memory_mut(|m| m.request_focus(egui::Id::new(tree_view::FILTER_ID)));
        }
        if export {
            self.request_primary_export();
        }
        if let Some(path) = dropped {
            self.pending_open = Some(path);
        }
    }

    fn menu_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui
                        .add(egui::Button::new("Open…").shortcut_text(ctx.format_shortcut(&OPEN)))
                        .clicked()
                    {
                        self.pick_file();
                    }
                    let can_export = self.primary_export().is_some();
                    if ui
                        .add_enabled(
                            can_export,
                            egui::Button::new("Export…").shortcut_text(ctx.format_shortcut(&EXPORT)),
                        )
                        .on_hover_text("Export the selected item (also available by right-clicking it in the tree)")
                        .clicked()
                    {
                        self.request_primary_export();
                    }
                    if ui
                        .add_enabled(
                            self.document.is_some(),
                            egui::Button::new("Close").shortcut_text(ctx.format_shortcut(&CLOSE)),
                        )
                        .clicked()
                    {
                        self.close(ctx);
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("View", |ui| {
                    let label = if self.show_info {
                        "Hide file information"
                    } else {
                        "Show file information"
                    };
                    if ui
                        .add(
                            egui::Button::new(label)
                                .shortcut_text(ctx.format_shortcut(&TOGGLE_INFO)),
                        )
                        .clicked()
                    {
                        self.show_info = !self.show_info;
                    }
                });
            });
        });
    }

    fn status_bar(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(loading) = &self.loading {
                    ui.spinner();
                    ui.label(format!("Opening {}…", loading.path.display()));
                } else if let Some(doc) = &self.document {
                    let pkg = &doc.package;
                    let kind = match pkg.kind {
                        PackageKind::Apk => "APK",
                        PackageKind::Xapk => "XAPK",
                    };
                    let classes: usize = pkg.dex_files.iter().map(|d| d.dex.class_defs.len()).sum();
                    let warnings: usize =
                        pkg.archives.iter().map(|a| a.warnings.len()).sum::<usize>()
                            + pkg
                                .dex_files
                                .iter()
                                .map(|d| d.dex.warnings.len())
                                .sum::<usize>();
                    ui.label(format!(
                        "{kind} · {} files · {} DEX · {} classes",
                        group_digits(pkg.files.len()),
                        pkg.dex_files.len(),
                        group_digits(classes)
                    ));
                    if warnings > 0 {
                        ui.label(
                            RichText::new(format!("⚠ {warnings} warnings"))
                                .color(ui.visuals().warn_fg_color),
                        )
                        .on_hover_text("Select the package root to see the warnings");
                    }
                } else {
                    ui.label("No file open");
                }
                if let Some(notice) = &self.notice {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("✔ {notice}"))
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .truncate(),
                        );
                    });
                }
            });
        });
    }

    fn info_panel(&mut self, ctx: &egui::Context) {
        let inspection = self.document.as_ref().and_then(|d| d.inspection.as_ref());
        let mut toggle = false;
        let expanded = egui::SidePanel::right("info_panel")
            .resizable(true)
            .default_width(300.0)
            .min_width(220.0);
        let collapsed = egui::SidePanel::right("info_panel_collapsed")
            .resizable(false)
            .exact_width(28.0);
        egui::SidePanel::show_animated_between(
            ctx,
            self.show_info,
            collapsed,
            expanded,
            |ui, how_expanded| {
                if how_expanded < 0.5 {
                    ui.vertical_centered(|ui| {
                        if ui
                            .add(egui::Button::new("«").frame(false))
                            .on_hover_text("Show file information (⌘I)")
                            .clicked()
                        {
                            toggle = true;
                        }
                    });
                    return;
                }
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("FILE INFORMATION")
                            .small()
                            .family(theme::bold_family())
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(egui::Button::new("»").frame(false))
                            .on_hover_text("Hide file information (⌘I)")
                            .clicked()
                        {
                            toggle = true;
                        }
                    });
                });
                ui.separator();
                info_panel::show(ui, inspection);
            },
        );
        if toggle {
            self.show_info = !self.show_info;
        }
    }

    fn welcome(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space((ui.available_height() / 2.0 - 90.0).max(0.0));
            if let Some(loading) = &self.loading {
                ui.spinner();
                ui.label(format!("Opening {}…", file_name(&loading.path)));
                return;
            }
            ui.heading(RichText::new("BogusMips").size(32.0));
            ui.add_space(4.0);
            ui.label(
                RichText::new("See how far your Android app can be disassembled.")
                    .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(16.0);
            if ui
                .add(egui::Button::new(
                    RichText::new("Open APK or XAPK…").size(16.0),
                ))
                .clicked()
            {
                self.pick_file();
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new("or drop a file onto this window")
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        });
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn select(ctx: &egui::Context, doc: &mut Document, node: NodeId) {
    if let Some(Inspection {
        content: Content::Image { uri, .. },
        ..
    }) = &doc.inspection
    {
        ctx.forget_image(uri);
    }
    doc.selected = Some(node);
    doc.tree.reveal(&doc.package, node);
    // Parsers are hardened against hostile input; this is a last line of
    // defense so a missed edge case cannot take down the whole app.
    let package = &doc.package;
    let inspection =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inspect(package, node)))
            .unwrap_or_else(|_| Inspection {
                node,
                title: package.node_path(node),
                content: Content::Message("Internal error while decoding this item.".to_owned()),
                raw: None,
                original: None,
                sections: Vec::new(),
            });
    doc.inspection = Some(inspection);
    doc.view_mode = ViewMode::Preview;
}

impl eframe::App for BogusMipsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(target_os = "windows")]
        if !self.native_theme_applied {
            theme::apply_black_window_frame(_frame);
        }
        self.ui(ctx);
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme::BACKGROUND.to_normalized_gamma_f32()
    }
}

impl BogusMipsApp {
    pub fn ui(&mut self, ctx: &egui::Context) {
        if !self.native_theme_applied {
            theme::apply_dark_window_frame(ctx);
            self.native_theme_applied = true;
        }

        self.handle_input(ctx);
        if let Some(path) = self.pending_open.take() {
            self.start_loading(ctx, path);
        }
        self.poll_loading(ctx);

        self.title_bar(ctx);
        self.menu_bar(ctx);
        self.status_bar(ctx);

        if let Some(doc) = &mut self.document {
            egui::SidePanel::left("tree_panel")
                .resizable(true)
                .default_width(320.0)
                .min_width(200.0)
                .show(ctx, |ui| {
                    let response = tree_view::show(ui, &doc.package, &mut doc.tree, doc.selected);
                    if let Some(node) = response.selected {
                        select(ctx, doc, node);
                    }
                    if response.export.is_some() {
                        self.pending_export = response.export;
                    }
                });
        }
        if self.document.is_some() {
            self.info_panel(ctx);
        }

        egui::CentralPanel::default().show(ctx, |ui| match &mut self.document {
            Some(Document {
                inspection: Some(inspection),
                view_mode,
                ..
            }) => content_view::show(ui, inspection, view_mode),
            Some(_) => {}
            None => self.welcome(ui),
        });

        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop_overlay"),
            ));
            let rect = ctx.screen_rect();
            painter.rect_filled(rect, 0.0, egui::Color32::from_black_alpha(160));
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Drop to open",
                egui::FontId::proportional(24.0),
                egui::Color32::WHITE,
            );
        }

        if let Some((node, kind)) = self.pending_export.take() {
            self.run_export(node, kind);
        }

        if let Some((title, error)) = self.error.clone() {
            let modal = egui::Modal::new(egui::Id::new("error_modal")).show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.heading(title);
                ui.add_space(8.0);
                ui.label(error);
                ui.add_space(12.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.button("OK").clicked()
                })
                .inner
            });
            if modal.inner || modal.should_close() {
                self.error = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn frame(ctx: &egui::Context, app: &mut BogusMipsApp) {
        let _ = ctx.run(egui::RawInput::default(), |ctx| app.ui(ctx));
    }

    #[test]
    fn uses_pitch_black_background() {
        let ctx = egui::Context::default();
        let _app = BogusMipsApp::with_context(&ctx, None);
        let visuals = ctx.style().visuals.clone();
        let expected = egui::Color32::BLACK;
        assert_eq!(visuals.panel_fill, expected);
        assert_eq!(visuals.window_fill, expected);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn draws_title_in_black_macos_title_bar() {
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            ..Default::default()
        };
        let output = ctx.run(input, |ctx| app.ui(ctx));
        let texts: Vec<(egui::Pos2, String)> = output
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some((t.pos, t.galley.text().to_owned())),
                _ => None,
            })
            .collect();
        let bar = theme::MACOS_TITLE_BAR_HEIGHT;
        let (title_pos, _) = texts.iter().find(|(_, t)| t == "BogusMips").expect("title");
        assert!(title_pos.y < bar && title_pos.x > 500.0, "{title_pos:?}");
        let (file_pos, _) = texts.iter().find(|(_, t)| t == "File").expect("menu");
        assert!(
            file_pos.y >= bar,
            "menu bar overlaps the title bar: {file_pos:?}"
        );
    }

    #[test]
    fn renders_welcome_screen() {
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        frame(&ctx, &mut app);
        frame(&ctx, &mut app);
        assert!(app.document.is_none());
    }

    #[test]
    fn reports_open_errors() {
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, Some(PathBuf::from("/nonexistent.apk")));
        let deadline = Instant::now() + Duration::from_secs(10);
        while app.error.is_none() && Instant::now() < deadline {
            frame(&ctx, &mut app);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.error.is_some());
        frame(&ctx, &mut app);
    }

    #[test]
    fn panels_keep_their_width_while_the_pointer_moves() {
        let zip = crate::formats::zip::write_stored_zip(&[
            ("AndroidManifest.xml", b"x"),
            (
                "res/layout/a_rather_long_file_name_for_testing.xml",
                b"<a/>",
            ),
            ("assets/readme.txt", b"hello"),
        ]);
        let package = Package::from_bytes(Path::new("test.apk"), zip.into()).unwrap();
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let tree = TreeState::new(&package);
        let mut doc = Document {
            package,
            tree,
            selected: None,
            inspection: None,
            view_mode: ViewMode::default(),
        };
        select(&ctx, &mut doc, 0);
        app.document = Some(doc);

        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0));
        let width = |ctx: &egui::Context, id: &str| {
            egui::containers::panel::PanelState::load(ctx, egui::Id::new(id))
                .map(|s| s.rect.width())
        };
        let mut widths = Vec::new();
        let mut texts: Vec<(egui::Pos2, String)> = Vec::new();
        for i in 0..60 {
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events: vec![egui::Event::PointerMoved(egui::pos2(
                    (i * 20) as f32,
                    (i * 13 % 800) as f32,
                ))],
                ..Default::default()
            };
            let output = ctx.run(input, |ctx| app.ui(ctx));
            widths.push((width(&ctx, "tree_panel"), width(&ctx, "info_panel")));
            texts = output
                .shapes
                .iter()
                .filter_map(|c| match &c.shape {
                    egui::Shape::Text(t) => Some((t.pos, t.galley.text().to_owned())),
                    _ => None,
                })
                .collect();
        }
        // The tree rows must be visible in the left panel.
        for label in ["TEST.APK", "Source code", "Files"] {
            assert!(
                texts
                    .iter()
                    .any(|(pos, t)| t.contains(label) && pos.x < 320.0 && pos.y < 200.0),
                "{label} not drawn: {texts:?}"
            );
        }
        assert!(widths[5..].iter().all(|w| *w == widths[5]), "{widths:?}");
        // The filter row must sit at the top, leaving the space below for the tree.
        let filter = ctx
            .read_response(egui::Id::new(crate::ui::tree_view::FILTER_ID))
            .expect("filter rendered");
        assert!(filter.rect.top() < 80.0, "filter at {:?}", filter.rect);
        assert!(filter.rect.height() < 40.0, "filter at {:?}", filter.rect);
    }

    #[test]
    fn clicking_a_folder_row_selects_and_toggles_it() {
        let zip = crate::formats::zip::write_stored_zip(&[("assets/readme.txt", b"hello")]);
        let package = Package::from_bytes(Path::new("test.apk"), zip.into()).unwrap();
        let files = package
            .nodes
            .iter()
            .position(|n| n.label == "Files")
            .unwrap();
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let tree = TreeState::new(&package);
        let mut doc = Document {
            package,
            tree,
            selected: None,
            inspection: None,
            view_mode: ViewMode::default(),
        };
        select(&ctx, &mut doc, 0);
        app.document = Some(doc);
        assert!(
            app.document
                .as_ref()
                .unwrap()
                .tree
                .expanded
                .contains(&files)
        );

        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0));
        let run = |app: &mut BogusMipsApp, events: Vec<egui::Event>| {
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            ctx.run(input, |ctx| app.ui(ctx))
        };
        let output = run(&mut app, vec![]);
        let pos = output
            .shapes
            .iter()
            .find_map(|c| match &c.shape {
                egui::Shape::Text(t) if t.galley.text() == "Files" => {
                    Some(t.pos + egui::vec2(4.0, 4.0))
                }
                _ => None,
            })
            .expect("Files row drawn");
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        run(&mut app, vec![egui::Event::PointerMoved(pos), button(true)]);
        run(&mut app, vec![button(false)]);

        let doc = app.document.as_ref().unwrap();
        assert_eq!(doc.selected, Some(files));
        assert!(!doc.tree.expanded.contains(&files));
    }

    #[test]
    fn beautifies_minified_assets_with_original_toggle() {
        let js = "function a(b){return b?1:2}".repeat(20);
        let zip = crate::formats::zip::write_stored_zip(&[
            ("assets/app.min.js", js.as_bytes()),
            ("assets/config.json", br#"{"a":[1,2],"b":{"c":true}}"#),
        ]);
        let package = Package::from_bytes(Path::new("test.apk"), zip.into()).unwrap();
        let node = |name: &str| package.nodes.iter().position(|n| n.label == name).unwrap();
        let (js_node, json_node) = (node("app.min.js"), node("config.json"));
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let tree = TreeState::new(&package);
        app.document = Some(Document {
            package,
            tree,
            selected: None,
            inspection: None,
            view_mode: ViewMode::default(),
        });
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0));
        let frame = |app: &mut BogusMipsApp| {
            let input = egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            };
            let output = ctx.run(input, |ctx| app.ui(ctx));
            output
                .shapes
                .iter()
                .filter_map(|c| match &c.shape {
                    egui::Shape::Text(t) => Some(t.galley.text().to_owned()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        for (node, expected) in [(json_node, "\"a\": ["), (js_node, "function a(b) {")] {
            let doc = app.document.as_mut().unwrap();
            select(&ctx, doc, node);
            let inspection = doc.inspection.as_ref().unwrap();
            assert_eq!(inspection.original.as_ref().map(Vec::len), Some(1));
            let Content::Text { lines, .. } = &inspection.content else {
                panic!("expected text");
            };
            assert!(
                lines.len() > 3 && lines.iter().any(|l| l.contains(expected)),
                "{lines:?}"
            );

            let texts = frame(&mut app);
            assert!(
                texts.iter().any(|t| t == "Formatted") && texts.iter().any(|t| t == "Original")
            );
            assert!(
                texts.iter().any(|t| t.contains(expected)),
                "formatted text not drawn"
            );

            app.document.as_mut().unwrap().view_mode = ViewMode::Original;
            let texts = frame(&mut app);
            assert!(
                !texts.iter().any(|t| t.contains(expected)),
                "original should be shown"
            );
        }
    }

    #[test]
    fn right_click_exports_the_file() {
        let zip = crate::formats::zip::write_stored_zip(&[
            ("assets/config.json", br#"{"a":1}"#),
            ("assets/z.txt", b"other"),
        ]);
        let package = Package::from_bytes(Path::new("test.apk"), zip.into()).unwrap();
        let target = node_named(&package, "config.json");
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-export");
        std::fs::create_dir_all(&out_dir).unwrap();
        let asked = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let (dir, log) = (out_dir.clone(), asked.clone());
        app.save_dialog = Box::new(move |name| {
            log.borrow_mut().push(name.to_owned());
            Some(dir.join(name))
        });
        let mut tree = TreeState::new(&package);
        tree.reveal(&package, target);
        app.document = Some(Document {
            package,
            tree,
            selected: None,
            inspection: None,
            view_mode: ViewMode::default(),
        });

        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1280.0, 800.0));
        let run = |app: &mut BogusMipsApp, events: Vec<egui::Event>| {
            let input = egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            };
            let output = ctx.run(input, |ctx| app.ui(ctx));
            output
                .shapes
                .iter()
                .filter_map(|c| match &c.shape {
                    egui::Shape::Text(t) => Some((t.pos, t.galley.text().to_owned())),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let click = |pos: egui::Pos2, button| {
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed: true,
                    modifiers: Default::default(),
                },
                egui::Event::PointerButton {
                    pos,
                    button,
                    pressed: false,
                    modifiers: Default::default(),
                },
            ]
        };
        let find = |texts: &[(egui::Pos2, String)], label: &str| {
            texts
                .iter()
                .find(|(_, t)| t == label)
                .map(|(p, _)| *p + egui::vec2(4.0, 4.0))
        };

        let texts = run(&mut app, vec![]);
        let row = find(&texts, "config.json").expect("row drawn");
        run(&mut app, click(row, egui::PointerButton::Secondary));
        let texts = run(&mut app, vec![]);
        assert_eq!(app.document.as_ref().unwrap().selected, Some(target));
        assert!(find(&texts, "Export…").is_some(), "context menu not shown");
        let item = find(&texts, "Export as shown…").expect("as-shown option");
        run(&mut app, click(item, egui::PointerButton::Primary));
        run(&mut app, vec![]);

        assert_eq!(asked.borrow().as_slice(), ["config.json"]);
        let written = std::fs::read_to_string(out_dir.join("config.json")).unwrap();
        assert_eq!(written, "{\n  \"a\": 1\n}\n");
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|n| n.contains("config.json"))
        );
        assert!(app.error.is_none());

        // File → Export… / ⌘E exports the selection's primary (raw) form.
        app.request_primary_export();
        run(&mut app, vec![]);
        let raw = std::fs::read_to_string(out_dir.join("config.json")).unwrap();
        assert_eq!(raw, r#"{"a":1}"#);
        std::fs::remove_dir_all(&out_dir).unwrap();
    }

    fn node_named(package: &Package, label: &str) -> NodeId {
        package.nodes.iter().position(|n| n.label == label).unwrap()
    }

    /// Renders every node of a real package headlessly. Opt-in, as no APK
    /// ships with the repository: `BOGUSMIPS_TEST_APK=app.apk cargo test`.
    #[test]
    fn renders_every_node_of_real_package() {
        let Some(path) = std::env::var_os("BOGUSMIPS_TEST_APK") else {
            return;
        };
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, Some(PathBuf::from(path)));
        let deadline = Instant::now() + Duration::from_secs(60);
        while app.document.is_none() && app.error.is_none() && Instant::now() < deadline {
            frame(&ctx, &mut app);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(app.error.is_none(), "{:?}", app.error);
        let nodes = app.document.as_ref().expect("loaded").package.nodes.len();
        for node in 0..nodes {
            let doc = app.document.as_mut().expect("loaded");
            select(&ctx, doc, node);
            frame(&ctx, &mut app);
            let doc = app.document.as_mut().expect("loaded");
            if doc.inspection.as_ref().is_some_and(|i| i.raw.is_some()) {
                doc.view_mode = ViewMode::Hex;
                frame(&ctx, &mut app);
            }
        }
        app.show_info = false;
        frame(&ctx, &mut app);
        app.document.as_mut().expect("loaded").tree.filter = "main".to_owned();
        frame(&ctx, &mut app);
    }
}
