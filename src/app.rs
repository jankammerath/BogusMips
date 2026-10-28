use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use eframe::egui::{self, Key, KeyboardShortcut, Modifiers, RichText};

use crate::inspect::{Content, Inspection, group_digits, inspect};
use crate::package::{NodeId, Package, PackageKind};
use crate::ui::content_view::{self, ViewMode};
use crate::ui::tree_view::{self, TreeState};
use crate::ui::{info_panel, theme};

const OPEN: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::O);
const CLOSE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::W);
const TOGGLE_INFO: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::I);
const FIND: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::F);

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
    error: Option<String>,
    show_info: bool,
    native_theme_applied: bool,
}

impl BogusMipsApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial_file: Option<PathBuf>) -> Self {
        Self::with_context(&cc.egui_ctx, initial_file)
    }

    pub fn with_context(ctx: &egui::Context, initial_file: Option<PathBuf>) -> Self {
        theme::apply_dark(ctx);
        egui_extras::install_image_loaders(ctx);
        Self {
            document: None,
            loading: None,
            pending_open: initial_file,
            error: None,
            show_info: true,
            native_theme_applied: false,
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
                ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
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
                self.error = Some(e);
                self.loading = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.error = Some(format!(
                    "Loading {} failed unexpectedly.",
                    loading.path.display()
                ));
                self.loading = None;
            }
        }
    }

    fn close(&mut self, ctx: &egui::Context) {
        if self.document.take().is_some() {
            ctx.forget_all_images();
            ctx.send_viewport_cmd(egui::ViewportCommand::Title("BogusMips".to_owned()));
        }
    }

    fn handle_input(&mut self, ctx: &egui::Context) {
        let (open, close, toggle_info, find, dropped) = ctx.input_mut(|i| {
            (
                i.consume_shortcut(&OPEN),
                i.consume_shortcut(&CLOSE),
                i.consume_shortcut(&TOGGLE_INFO),
                i.consume_shortcut(&FIND),
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
                    ui.strong("File information");
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
                sections: Vec::new(),
            });
    doc.inspection = Some(inspection);
    doc.view_mode = ViewMode::Preview;
}

impl eframe::App for BogusMipsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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

        self.menu_bar(ctx);
        self.status_bar(ctx);

        if let Some(doc) = &mut self.document {
            egui::SidePanel::left("tree_panel")
                .resizable(true)
                .default_width(320.0)
                .min_width(200.0)
                .show(ctx, |ui| {
                    if let Some(node) =
                        tree_view::show(ui, &doc.package, &mut doc.tree, doc.selected)
                    {
                        select(ctx, doc, node);
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

        if let Some(error) = self.error.clone() {
            let modal = egui::Modal::new(egui::Id::new("error_modal")).show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.heading("Could not open file");
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
    fn uses_macos_dark_background() {
        let ctx = egui::Context::default();
        let _app = BogusMipsApp::with_context(&ctx, None);
        let visuals = ctx.style().visuals.clone();
        let expected = egui::Color32::from_rgb(0x2f, 0x31, 0x33);
        assert_eq!(visuals.panel_fill, expected);
        assert_eq!(visuals.window_fill, expected);
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
        for label in ["test.apk", "Source code", "Files"] {
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
