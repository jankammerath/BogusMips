use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use eframe::egui::{self, Key, KeyboardShortcut, Modifiers, RichText};

use crate::export::{self, ExportKind};
use crate::inspect::{Content, Inspection, format_size, group_digits, inspect};
use crate::package::{NodeId, Package, PackageKind};
use crate::search::SearchController;
use crate::ui::content_view::{self, Goto, ViewMode};
use crate::ui::icons::{self, Icon};
use crate::ui::search_view::{self, SearchAction, SearchViewState};
use crate::ui::tree_view::{self, TreeState};
use crate::ui::{MenuAction, info_panel, theme};

const OPEN: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::O);
const CLOSE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::W);
const TOGGLE_INFO: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::I);
const FIND: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::F);
const EXPORT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::E);
const SHOW_EXPLORER: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::E);
const SHOW_SEARCH: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::F);
const ACTIVITY_BAR_WIDTH: f32 = 48.0;

/// The views of the left sidebar, selected in the activity bar.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SideView {
    Explorer,
    Search,
}

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
    package: Arc<Package>,
    tree: TreeState,
    selected: Option<NodeId>,
    inspection: Option<Inspection>,
    view_mode: ViewMode,
    /// Location to highlight in the editor (e.g. a search match).
    goto: Option<Goto>,
    search: SearchController,
    search_view: SearchViewState,
}

impl Document {
    fn new(package: Package) -> Self {
        Self {
            tree: TreeState::new(&package),
            package: Arc::new(package),
            selected: None,
            inspection: None,
            view_mode: ViewMode::default(),
            goto: None,
            search: SearchController::new(),
            search_view: SearchViewState::default(),
        }
    }
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
    show_sidebar: bool,
    sidebar_view: SideView,
    /// Where the activity bar icons were drawn (for tests).
    activity_icons: Vec<(SideView, egui::Rect)>,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    native_menu: Option<crate::ui::native_menu::NativeMenu>,
    native_theme_applied: bool,
    window_title: String,
}

impl BogusMipsApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial_file: Option<PathBuf>) -> Self {
        #[allow(unused_mut)]
        let mut app = Self::with_context(&cc.egui_ctx, initial_file);
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            app.native_menu = crate::ui::native_menu::NativeMenu::install(cc);
        }
        app
    }

    fn has_native_menu(&self) -> bool {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.native_menu.is_some()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    /// Handles native menu selections and keeps the menu's state current.
    fn sync_native_menu(&mut self, ctx: &egui::Context) {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            let state = (
                self.primary_export().is_some(),
                self.document.is_some(),
                self.show_info,
            );
            let Some(menu) = &mut self.native_menu else {
                return;
            };
            menu.update(state.0, state.1, state.2);
            for action in menu.poll() {
                self.perform(ctx, action);
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = ctx;
    }

    fn perform(&mut self, ctx: &egui::Context, action: MenuAction) {
        match action {
            MenuAction::Open => self.pick_file(),
            MenuAction::Export => self.request_primary_export(),
            MenuAction::Close => self.close(ctx),
            MenuAction::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            MenuAction::ShowExplorer => self.show_view(ctx, SideView::Explorer),
            MenuAction::ShowSearch => self.show_view(ctx, SideView::Search),
            MenuAction::ToggleInfo => self.show_info = !self.show_info,
        }
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
            show_sidebar: true,
            sidebar_view: SideView::Explorer,
            activity_icons: Vec::new(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            native_menu: None,
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
                let root = package.root();
                let title = format!("{} — BogusMips", package.archives[0].name);
                self.set_title(ctx, title);
                let mut doc = Document::new(package);
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

    /// Opens a sidebar view, or hides the sidebar if that view is showing
    /// (like clicking an activity bar icon in VS Code).
    fn toggle_view(&mut self, ctx: &egui::Context, view: SideView) {
        if self.show_sidebar && self.sidebar_view == view {
            self.show_sidebar = false;
        } else {
            self.show_view(ctx, view);
        }
    }

    fn show_view(&mut self, ctx: &egui::Context, view: SideView) {
        self.show_sidebar = true;
        self.sidebar_view = view;
        let focus = match view {
            SideView::Explorer => tree_view::FILTER_ID,
            SideView::Search => search_view::INPUT_ID,
        };
        if view == SideView::Search {
            ctx.memory_mut(|m| m.request_focus(egui::Id::new(focus)));
        }
    }

    /// macOS: the title bar area behind the traffic lights (the native title
    /// bar is hidden). Shows the title in VS Code's command center box,
    /// which opens the search view, and acts as the window's drag handle.
    fn title_bar(&mut self, ctx: &egui::Context) {
        let fullscreen = ctx.input(|i| i.viewport().fullscreen.unwrap_or(false));
        if !cfg!(target_os = "macos") || fullscreen {
            // Small gap above the cards under the native title bar.
            egui::TopBottomPanel::top("top_gap")
                .exact_height(4.0)
                .show_separator_line(false)
                .frame(egui::Frame::NONE.fill(theme::WINDOW))
                .show(ctx, |_| {});
            return;
        }
        let mut open_search = false;
        egui::TopBottomPanel::top("title_bar")
            .exact_height(theme::MACOS_TITLE_BAR_HEIGHT)
            .show_separator_line(false)
            .frame(egui::Frame::NONE.fill(theme::WINDOW))
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
                let width = (rect.width() * 0.4).clamp(200.0, 500.0);
                let center = egui::Rect::from_center_size(rect.center(), egui::vec2(width, 24.0));
                let center_response = ui
                    .interact(center, ui.id().with("command_center"), egui::Sense::click())
                    .on_hover_text("Search file contents (⇧⌘F)");
                let fill = if center_response.hovered() {
                    egui::Color32::from_rgb(0x50, 0x50, 0x50)
                } else {
                    theme::COMMAND_CENTER
                };
                ui.painter().rect(
                    center,
                    6.0,
                    fill,
                    egui::Stroke::new(1.0, theme::COMMAND_CENTER_BORDER),
                    egui::StrokeKind::Inside,
                );
                icons::paint(
                    ui.painter(),
                    egui::Rect::from_center_size(
                        egui::pos2(center.left() + 16.0, center.center().y),
                        egui::vec2(14.0, 14.0),
                    ),
                    Icon::Search,
                    theme::TEXT_DIM,
                );
                ui.painter_at(center.shrink2(egui::vec2(28.0, 0.0))).text(
                    center.center(),
                    egui::Align2::CENTER_CENTER,
                    &self.window_title,
                    egui::FontId::proportional(12.0),
                    theme::TEXT,
                );
                open_search = center_response.clicked();
            });
        if open_search {
            self.show_view(ctx, SideView::Search);
        }
    }

    fn handle_input(&mut self, ctx: &egui::Context) {
        // Shift variants first: shortcuts without Shift also match with it.
        let (show_explorer, show_search) = ctx.input_mut(|i| {
            (
                i.consume_shortcut(&SHOW_EXPLORER),
                i.consume_shortcut(&SHOW_SEARCH),
            )
        });
        if show_explorer {
            self.show_view(ctx, SideView::Explorer);
        }
        if show_search {
            self.show_view(ctx, SideView::Search);
        }
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
            self.show_view(ctx, SideView::Explorer);
            ctx.memory_mut(|m| m.request_focus(egui::Id::new(tree_view::FILTER_ID)));
        }
        if export {
            self.request_primary_export();
        }
        if let Some(path) = dropped {
            self.pending_open = Some(path);
        }
    }

    /// The in-app menu, used where no native menu is available.
    fn app_menu(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let mut action = None;
        let mut entry = |ui: &mut egui::Ui,
                         label: &str,
                         enabled: bool,
                         shortcut: Option<&KeyboardShortcut>,
                         a: MenuAction| {
            let mut button = egui::Button::new(label);
            if let Some(shortcut) = shortcut {
                button = button.shortcut_text(ctx.format_shortcut(shortcut));
            }
            if ui.add_enabled(enabled, button).clicked() {
                action = Some(a);
                ui.close();
            }
        };
        let can_export = self.primary_export().is_some();
        let has_document = self.document.is_some();
        let info_label = if self.show_info {
            "Hide File Information"
        } else {
            "Show File Information"
        };
        ui.menu_button("File", |ui| {
            entry(ui, "Open…", true, Some(&OPEN), MenuAction::Open);
            entry(ui, "Export…", can_export, Some(&EXPORT), MenuAction::Export);
            ui.separator();
            entry(ui, "Close", has_document, Some(&CLOSE), MenuAction::Close);
            ui.separator();
            entry(ui, "Exit", true, None, MenuAction::Quit);
        });
        ui.menu_button("View", |ui| {
            entry(
                ui,
                "Explorer",
                true,
                Some(&SHOW_EXPLORER),
                MenuAction::ShowExplorer,
            );
            entry(
                ui,
                "Search",
                true,
                Some(&SHOW_SEARCH),
                MenuAction::ShowSearch,
            );
            ui.separator();
            entry(
                ui,
                info_label,
                true,
                Some(&TOGGLE_INFO),
                MenuAction::ToggleInfo,
            );
        });
        if let Some(action) = action {
            self.perform(ctx, action);
        }
    }

    /// Menu bar at the top of the window when there is no native menu.
    fn menu_bar(&mut self, ctx: &egui::Context) {
        if self.has_native_menu() {
            return;
        }
        egui::TopBottomPanel::top("menu_bar")
            .show_separator_line(false)
            .frame(
                egui::Frame::NONE
                    .fill(theme::WINDOW)
                    .inner_margin(egui::Margin::symmetric(6, 2)),
            )
            .show(ctx, |ui| {
                egui::MenuBar::new().ui(ui, |ui| self.app_menu(ui, ctx));
            });
    }

    /// The icon column at the left edge of the sidebar card.
    fn activity_items(&mut self, ui: &mut egui::Ui) -> Option<SideView> {
        let mut clicked = None;
        self.activity_icons.clear();
        ui.add_space(4.0);
        for (view, icon, tooltip) in [
            (SideView::Explorer, Icon::Files, "Explorer (⇧⌘E)"),
            (SideView::Search, Icon::Search, "Search (⇧⌘F)"),
        ] {
            let active = self.show_sidebar && self.sidebar_view == view;
            let (rect, response) = ui
                .allocate_exact_size(egui::vec2(ui.available_width(), 44.0), egui::Sense::click());
            let square = egui::Rect::from_center_size(rect.center(), egui::vec2(36.0, 36.0));
            if active {
                ui.painter().rect_filled(square, 6.0, theme::PILL);
            }
            let color = if active || response.hovered() {
                theme::ICON_ACTIVE
            } else {
                theme::ICON_INACTIVE
            };
            icons::paint(
                ui.painter(),
                egui::Rect::from_center_size(rect.center(), egui::vec2(22.0, 22.0)),
                icon,
                color,
            );
            self.activity_icons.push((view, rect));
            if response.on_hover_text(tooltip).clicked() {
                clicked = Some(view);
            }
        }
        clicked
    }

    fn status_bar(&self, ctx: &egui::Context) {
        let text = |s: String| RichText::new(s).color(theme::TEXT_BRIGHT).size(12.0);
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(22.0)
            .show_separator_line(false)
            .frame(
                egui::Frame::NONE
                    .fill(theme::STATUS_BAR)
                    .inner_margin(egui::Margin::symmetric(10, 0)),
            )
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    if let Some(loading) = &self.loading {
                        ui.add(egui::Spinner::new().size(12.0).color(theme::TEXT_BRIGHT));
                        ui.label(text(format!("Opening {}…", file_name(&loading.path))));
                    } else if let Some(doc) = &self.document {
                        let pkg = &doc.package;
                        let kind = match pkg.kind {
                            PackageKind::Apk => "APK",
                            PackageKind::Xapk => "XAPK",
                        };
                        let classes: usize =
                            pkg.dex_files.iter().map(|d| d.dex.class_defs.len()).sum();
                        let warnings: usize =
                            pkg.archives.iter().map(|a| a.warnings.len()).sum::<usize>()
                                + pkg
                                    .dex_files
                                    .iter()
                                    .map(|d| d.dex.warnings.len())
                                    .sum::<usize>();
                        ui.label(text(format!(
                            "{kind}  {} files  {} DEX  {} classes",
                            group_digits(pkg.files.len()),
                            pkg.dex_files.len(),
                            group_digits(classes)
                        )));
                        if warnings > 0 {
                            ui.label(text(format!("⚠ {warnings}")))
                                .on_hover_text("Warnings: select the package root to see them");
                        }
                    } else {
                        ui.label(text("No package open".to_owned()));
                    }
                    if let Some(notice) = &self.notice {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add(egui::Label::new(text(format!("✔ {notice}"))).truncate());
                        });
                    }
                });
            });
    }

    fn info_panel(&mut self, ctx: &egui::Context) {
        let inspection = self.document.as_ref().and_then(|d| d.inspection.as_ref());
        let mut close = false;
        egui::SidePanel::right("info_panel")
            .resizable(true)
            .default_width(300.0)
            .min_width(220.0)
            .show_separator_line(false)
            .frame(theme::card(theme::SIDEBAR))
            .show(ctx, |ui| {
                close = info_panel::show(ui, inspection);
            });
        if close {
            self.show_info = false;
        }
    }

    /// The left card: activity icons, plus the Explorer or Search view
    /// when the sidebar is shown.
    fn sidebar(&mut self, ctx: &egui::Context) {
        let mut pick = false;
        let mut search_action = None;
        let mut toggle = None;
        let panel = if self.show_sidebar {
            egui::SidePanel::left("sidebar")
                .resizable(true)
                .default_width(ACTIVITY_BAR_WIDTH + 300.0)
                .min_width(ACTIVITY_BAR_WIDTH + 200.0)
        } else {
            egui::SidePanel::left("activity_only")
                .resizable(false)
                .exact_width(ACTIVITY_BAR_WIDTH + 2.0)
        };
        panel
            .show_separator_line(false)
            .frame(theme::card(theme::SIDEBAR))
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.expand_to_include_rect(full);
                let bar = egui::Rect::from_min_size(
                    full.min,
                    egui::vec2(ACTIVITY_BAR_WIDTH.min(full.width()), full.height()),
                );
                let mut bar_ui = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(bar)
                        .layout(egui::Layout::top_down(egui::Align::Center)),
                );
                bar_ui.spacing_mut().item_spacing.y = 0.0;
                toggle = self.activity_items(&mut bar_ui);
                if !self.show_sidebar {
                    return;
                }
                ui.painter().vline(
                    bar.right(),
                    full.y_range(),
                    egui::Stroke::new(1.0, theme::CARD_BORDER),
                );
                let content =
                    egui::Rect::from_min_max(egui::pos2(bar.right() + 1.0, full.top()), full.max);
                let mut ui = ui.new_child(
                    egui::UiBuilder::new()
                        .max_rect(content)
                        .layout(egui::Layout::top_down(egui::Align::Min)),
                );
                let ui = &mut ui;
                match (self.sidebar_view, &mut self.document) {
                    (SideView::Explorer, Some(doc)) => {
                        let response =
                            tree_view::show(ui, &doc.package, &mut doc.tree, doc.selected);
                        if let Some(node) = response.selected {
                            select(ctx, doc, node);
                        }
                        if response.export.is_some() {
                            self.pending_export = response.export;
                        }
                    }
                    (SideView::Explorer, None) => pick = tree_view::show_empty(ui),
                    (SideView::Search, doc) => {
                        let doc = doc
                            .as_mut()
                            .map(|d| (&*d.package, &mut d.search, &mut d.search_view));
                        search_action = search_view::show(ui, doc);
                    }
                }
            });
        if let Some(view) = toggle {
            self.toggle_view(ctx, view);
        }
        match search_action {
            Some(SearchAction::Open { node, line, range }) => {
                if let Some(doc) = &mut self.document {
                    select(ctx, doc, node);
                    doc.goto = Some(Goto {
                        line,
                        range,
                        scroll: true,
                    });
                }
            }
            Some(SearchAction::PickFile) => pick = true,
            None => {}
        }
        if pick {
            self.pick_file();
        }
    }

    fn editor(&mut self, ctx: &egui::Context) {
        let mut toggle_info = false;
        egui::CentralPanel::default()
            .frame(theme::card(theme::EDITOR))
            .show(ctx, |ui| match &mut self.document {
                Some(doc) => {
                    let response = content_view::show(
                        ui,
                        doc.inspection.as_ref(),
                        &mut doc.view_mode,
                        doc.goto.as_mut(),
                        self.show_info,
                    );
                    if response.close {
                        deselect(ctx, doc);
                    }
                    toggle_info = response.toggle_info;
                }
                None => self.welcome(ui),
            });
        if toggle_info {
            self.show_info = !self.show_info;
        }
    }

    /// The editor card without a package: VS Code's welcome page.
    fn welcome(&mut self, ui: &mut egui::Ui) {
        if let Some(loading) = &self.loading {
            ui.centered_and_justified(|ui| {
                ui.horizontal_centered(|ui| {
                    ui.spinner();
                    ui.label(format!("Opening {}…", file_name(&loading.path)));
                });
            });
            return;
        }
        let link = |ui: &mut egui::Ui, icon: Icon, text: &str| {
            let response = ui
                .horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                    icons::paint(ui.painter(), rect, icon, theme::LINK);
                    ui.add(
                        egui::Label::new(RichText::new(text).color(theme::LINK))
                            .sense(egui::Sense::click()),
                    )
                })
                .inner;
            response.on_hover_cursor(egui::CursorIcon::PointingHand)
        };
        let width = ui.available_width().min(560.0);
        ui.add_space((ui.available_height() * 0.18).max(24.0));
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - width) / 2.0).max(24.0));
            ui.vertical(|ui| {
                ui.set_max_width(width);
                ui.label(
                    RichText::new("BogusMips")
                        .size(28.0)
                        .color(theme::TEXT_BRIGHT),
                );
                ui.label(
                    RichText::new("See how far your Android app can be disassembled.")
                        .color(theme::TEXT_DIM),
                );
                ui.add_space(28.0);
                ui.label(RichText::new("Start").size(17.0).color(theme::TEXT));
                ui.add_space(8.0);
                if link(ui, Icon::Files, "Open APK or XAPK…").clicked() {
                    self.pick_file();
                }
                ui.add_space(28.0);
                ui.label(RichText::new("Tips").size(17.0).color(theme::TEXT));
                ui.add_space(8.0);
                for tip in [
                    "Drop an .apk or .xapk file onto this window to open it.",
                    "Search the contents of all classes and files with ⇧⌘F.",
                    "Right-click an item in the Explorer to export it.",
                    "Toggle the file information panel with ⌘I.",
                ] {
                    ui.label(RichText::new(tip).color(theme::TEXT_DIM));
                    ui.add_space(4.0);
                }
            });
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
    doc.goto = None;
}

/// Closes the editor tab (nothing selected).
fn deselect(ctx: &egui::Context, doc: &mut Document) {
    if let Some(Inspection {
        content: Content::Image { uri, .. },
        ..
    }) = &doc.inspection
    {
        ctx.forget_image(uri);
    }
    doc.selected = None;
    doc.inspection = None;
    doc.goto = None;
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
        if let Some(doc) = &mut self.document {
            doc.search.poll(&doc.package, ctx);
        }

        // Panel order matters: full-width bars first, then the columns.
        self.sync_native_menu(ctx);
        self.title_bar(ctx);
        self.menu_bar(ctx);
        self.status_bar(ctx);
        self.sidebar(ctx);
        if self.document.is_some() && self.show_info {
            self.info_panel(ctx);
        }
        self.editor(ctx);

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

    fn texts_of(output: &egui::FullOutput) -> Vec<(egui::Pos2, String)> {
        output
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Text(t) => Some((t.pos, t.galley.text().to_owned())),
                _ => None,
            })
            .collect()
    }

    fn input(events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            events,
            ..Default::default()
        }
    }

    fn click(pos: egui::Pos2) -> Vec<egui::Event> {
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        vec![egui::Event::PointerMoved(pos), button(true), button(false)]
    }

    #[test]
    fn uses_vscode_dark_palette() {
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let visuals = ctx.style().visuals.clone();
        assert_eq!(
            visuals.panel_fill,
            egui::Color32::from_rgb(0x3c, 0x3c, 0x3c)
        );
        assert_eq!(visuals.extreme_bg_color, theme::INPUT);
        assert_eq!(visuals.override_text_color, Some(theme::TEXT));

        let output = ctx.run(input(vec![]), |ctx| app.ui(ctx));
        let fills: Vec<egui::Color32> = output
            .shapes
            .iter()
            .filter_map(|c| match &c.shape {
                egui::Shape::Rect(r) => Some(r.fill),
                _ => None,
            })
            .collect();
        for color in [
            theme::SIDEBAR,
            theme::EDITOR,
            theme::STATUS_BAR,
            theme::BUTTON,
        ] {
            assert!(fills.contains(&color), "{color:?} not painted");
        }
        // Welcome views as in VS Code: explorer button and editor start page.
        let texts = texts_of(&output);
        for label in ["Explorer", "Open APK or XAPK", "Start", "Open APK or XAPK…"] {
            assert!(texts.iter().any(|(_, t)| t == label), "{label} missing");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn draws_title_in_command_center() {
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let texts = texts_of(&ctx.run(input(vec![]), |ctx| app.ui(ctx)));
        let bar = theme::MACOS_TITLE_BAR_HEIGHT;
        let (title_pos, _) = texts.iter().find(|(_, t)| t == "BogusMips").expect("title");
        assert!(title_pos.y < bar && title_pos.x > 500.0, "{title_pos:?}");
        // Clicking the command center opens the search view.
        app.show_sidebar = false;
        let _ = ctx.run(input(click(egui::pos2(640.0, bar / 2.0))), |ctx| {
            app.ui(ctx)
        });
        assert!(app.show_sidebar && app.sidebar_view == SideView::Search);
    }

    fn icon_pos(app: &BogusMipsApp, view: SideView) -> egui::Pos2 {
        app.activity_icons
            .iter()
            .find(|(v, _)| *v == view)
            .map(|(_, r)| r.center())
            .expect("activity icon drawn")
    }

    #[test]
    fn activity_bar_switches_and_hides_views() {
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let _ = ctx.run(input(vec![]), |ctx| app.ui(ctx));
        let sidebar_width = |ctx: &egui::Context, id: &str| {
            egui::containers::panel::PanelState::load(ctx, egui::Id::new(id)).map(|s| s.rect)
        };

        // The icons live inside the sidebar card, at its left edge.
        let card = sidebar_width(&ctx, "sidebar").expect("sidebar card");
        let search = icon_pos(&app, SideView::Search);
        assert!(card.contains(search) && search.x < card.left() + ACTIVITY_BAR_WIDTH);

        let _ = ctx.run(input(click(search)), |ctx| app.ui(ctx));
        assert_eq!(app.sidebar_view, SideView::Search);
        let texts = texts_of(&ctx.run(input(vec![]), |ctx| app.ui(ctx)));
        assert!(texts.iter().any(|(_, t)| t == "Search"));

        // Clicking the active view's icon collapses the card to the icons.
        let _ = ctx.run(input(click(icon_pos(&app, SideView::Search))), |ctx| {
            app.ui(ctx)
        });
        assert!(!app.show_sidebar);
        let _ = ctx.run(input(vec![]), |ctx| app.ui(ctx));
        let collapsed = sidebar_width(&ctx, "activity_only").expect("collapsed card");
        assert!(
            collapsed.width() < ACTIVITY_BAR_WIDTH + 12.0,
            "{collapsed:?}"
        );
        let explorer = icon_pos(&app, SideView::Explorer);
        assert!(collapsed.contains(explorer));
        let _ = ctx.run(input(click(explorer)), |ctx| app.ui(ctx));
        assert!(app.show_sidebar && app.sidebar_view == SideView::Explorer);
    }

    #[test]
    fn fallback_menu_bar_without_native_menu() {
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        let texts = texts_of(&ctx.run(input(vec![]), |ctx| app.ui(ctx)));
        let (file, _) = texts.iter().find(|(_, t)| t == "File").expect("File menu");
        assert!(texts.iter().any(|(_, t)| t == "View"));
        // Open the View menu and toggle the file information panel.
        let (view, _) = texts.iter().find(|(_, t)| t == "View").unwrap();
        let _ = ctx.run(input(click(*view + egui::vec2(4.0, 4.0))), |ctx| {
            app.ui(ctx)
        });
        let texts = texts_of(&ctx.run(input(vec![]), |ctx| app.ui(ctx)));
        let (item, _) = texts
            .iter()
            .find(|(_, t)| t == "Hide File Information")
            .expect("menu opened");
        let _ = ctx.run(input(click(*item + egui::vec2(4.0, 4.0))), |ctx| {
            app.ui(ctx)
        });
        assert!(!app.show_info);
        let _ = file;
    }

    #[test]
    fn search_opens_match_in_editor() {
        let lines: Vec<String> = (0..200).map(|i| format!("line {i}")).collect();
        let mut text = lines.join("\n");
        text.push_str("\n    the secret_token is here\n");
        let zip = crate::formats::zip::write_stored_zip(&[
            ("assets/notes.txt", text.as_bytes()),
            ("assets/other.txt", b"nothing to see"),
        ]);
        let package = Package::from_bytes(Path::new("test.apk"), zip.into()).unwrap();
        let notes = node_named(&package, "notes.txt");
        let ctx = egui::Context::default();
        let mut app = BogusMipsApp::with_context(&ctx, None);
        app.document = Some(Document::new(package));
        app.show_view(&ctx, SideView::Search);

        // Type into the focused search box.
        let _ = ctx.run(input(vec![]), |ctx| app.ui(ctx));
        let _ = ctx.run(
            input(vec![egui::Event::Text("SECRET_token".into())]),
            |ctx| app.ui(ctx),
        );
        assert_eq!(
            app.document.as_ref().unwrap().search.query.text,
            "SECRET_token"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while app.document.as_ref().unwrap().search.results.is_none()
            && std::time::Instant::now() < deadline
        {
            let _ = ctx.run(input(vec![]), |ctx| app.ui(ctx));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let texts = texts_of(&ctx.run(input(vec![]), |ctx| app.ui(ctx)));
        assert!(
            texts.iter().any(|(_, t)| t == "1 result in 1 file"),
            "{texts:?}"
        );
        let (pos, _) = texts
            .iter()
            .find(|(_, t)| t == "the secret_token is here")
            .unwrap_or_else(|| panic!("match preview not drawn: {texts:?}"));
        let _ = ctx.run(input(click(*pos + egui::vec2(4.0, 4.0))), |ctx| app.ui(ctx));

        let doc = app.document.as_ref().unwrap();
        assert_eq!(doc.selected, Some(notes));
        assert_eq!(
            doc.goto.as_ref().map(|g| (g.line, g.range.clone())),
            Some((200, 8..20))
        );
        // The editor scrolls to the match and shows the highlighted line.
        let texts = texts_of(&ctx.run(input(vec![]), |ctx| app.ui(ctx)));
        let texts = if texts.iter().any(|(_, t)| t.contains("secret_token")) {
            texts
        } else {
            texts_of(&ctx.run(input(vec![]), |ctx| app.ui(ctx)))
        };
        assert!(
            texts.iter().any(|(_, t)| t == "201"),
            "line number not visible"
        );
        assert!(
            texts
                .iter()
                .any(|(_, t)| t.contains("    the secret_token is here"))
        );
        assert!(!app.document.as_ref().unwrap().goto.as_ref().unwrap().scroll);
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
        let mut doc = Document::new(package);
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
            widths.push((width(&ctx, "sidebar"), width(&ctx, "info_panel")));
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
        assert!(
            widths[5].0.is_some() && widths[5].1.is_some(),
            "panels not found"
        );
        assert!(widths[5..].iter().all(|w| *w == widths[5]), "{widths:?}");
        // The filter row must sit at the top, leaving the space below for the tree.
        let filter = ctx
            .read_response(egui::Id::new(crate::ui::tree_view::FILTER_ID))
            .expect("filter rendered");
        // At the top under the title/menu bar, not centered in the panel.
        assert!(filter.rect.top() < 130.0, "filter at {:?}", filter.rect);
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
        let mut doc = Document::new(package);
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
        app.document = Some(Document::new(package));
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
        let mut doc = Document::new(package);
        doc.tree.reveal(&doc.package, target);
        app.document = Some(doc);

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
