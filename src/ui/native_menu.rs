//! The application menu: native on macOS (the system menu bar) and Windows
//! (the window's menu bar), built with `muda`.

use std::sync::mpsc::{Receiver, channel};

use muda::accelerator::{Accelerator, CMD_OR_CTRL, Code, Modifiers};
use muda::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};

use super::MenuAction;

pub struct NativeMenu {
    // Keeps the menu alive; dropping it would remove it.
    _menu: Menu,
    export: MenuItem,
    close: MenuItem,
    toggle_info: MenuItem,
    actions: Vec<(MenuId, MenuAction)>,
    rx: Receiver<MenuEvent>,
    state: Option<(bool, bool, bool)>,
}

impl NativeMenu {
    /// Builds the menu and attaches it to the application (macOS) or the
    /// window (Windows). Returns `None` if that fails.
    pub fn install(cc: &eframe::CreationContext<'_>) -> Option<Self> {
        let menu = Menu::new();
        let mut actions = Vec::new();
        let mut item = |text: &str, action: MenuAction, accelerator: Option<Accelerator>| {
            let item = MenuItem::new(text, true, accelerator);
            actions.push((item.id().clone(), action));
            item
        };
        let shortcut = |key: Code| Some(Accelerator::new(Some(CMD_OR_CTRL), key));
        let shift_shortcut =
            |key: Code| Some(Accelerator::new(Some(CMD_OR_CTRL | Modifiers::SHIFT), key));

        let open = item("Open…", MenuAction::Open, shortcut(Code::KeyO));
        let export = item("Export…", MenuAction::Export, shortcut(Code::KeyE));
        let close = item("Close", MenuAction::Close, shortcut(Code::KeyW));
        let explorer = item(
            "Explorer",
            MenuAction::ShowExplorer,
            shift_shortcut(Code::KeyE),
        );
        let search = item("Search", MenuAction::ShowSearch, shift_shortcut(Code::KeyF));
        let network = item("Network", MenuAction::ShowNetwork, shift_shortcut(Code::KeyN));
        let agent = item("AI Agent", MenuAction::ShowAgent, shift_shortcut(Code::KeyA));
        let toggle_info = item(
            "Hide File Information",
            MenuAction::ToggleInfo,
            shortcut(Code::KeyI),
        );
        let separator = PredefinedMenuItem::separator;

        let file = Submenu::new("&File", true);
        let view = Submenu::new("&View", true);
        if cfg!(target_os = "macos") {
            // The first submenu becomes the application menu.
            let app = Submenu::new("BogusMips", true);
            app.append_items(&[
                &PredefinedMenuItem::about(Some("About BogusMips"), None),
                &separator(),
                &PredefinedMenuItem::hide(None),
                &PredefinedMenuItem::hide_others(None),
                &PredefinedMenuItem::show_all(None),
                &separator(),
                &PredefinedMenuItem::quit(None),
            ])
            .ok()?;
            menu.append(&app).ok()?;
            file.append_items(&[&open, &export, &separator(), &close])
                .ok()?;
        } else {
            let quit = item("E&xit", MenuAction::Quit, None);
            file.append_items(&[&open, &export, &separator(), &close, &separator(), &quit])
                .ok()?;
        }
        view.append_items(&[
            &explorer,
            &search,
            &network,
            &separator(),
            &agent,
            &toggle_info,
        ])
        .ok()?;
        menu.append_items(&[&file, &view]).ok()?;
        if cfg!(target_os = "macos") {
            let window = Submenu::new("Window", true);
            window
                .append_items(&[
                    &PredefinedMenuItem::minimize(None),
                    &PredefinedMenuItem::maximize(None),
                    &separator(),
                    &PredefinedMenuItem::fullscreen(None),
                ])
                .ok()?;
            menu.append(&window).ok()?;
            #[cfg(target_os = "macos")]
            window.set_as_windows_menu_for_nsapp();
        }

        attach(&menu, cc)?;

        // Menu events arrive outside of egui's frame loop: forward them and
        // wake the UI.
        let (tx, rx) = channel();
        let ctx = cc.egui_ctx.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let _ = tx.send(event);
            ctx.request_repaint();
        }));

        Some(Self {
            _menu: menu,
            export,
            close,
            toggle_info,
            actions,
            rx,
            state: None,
        })
    }

    /// Actions chosen in the menu since the last call.
    pub fn poll(&self) -> Vec<MenuAction> {
        self.rx
            .try_iter()
            .filter_map(|event| {
                self.actions
                    .iter()
                    .find(|(id, _)| *id == event.id)
                    .map(|(_, action)| *action)
            })
            .collect()
    }

    /// Keeps item states in sync with the app (only touching changed ones).
    pub fn update(&mut self, can_export: bool, has_document: bool, info_visible: bool) {
        let state = (can_export, has_document, info_visible);
        if self.state == Some(state) {
            return;
        }
        self.state = Some(state);
        self.export.set_enabled(can_export);
        self.close.set_enabled(has_document);
        self.toggle_info.set_text(if info_visible {
            "Hide File Information"
        } else {
            "Show File Information"
        });
    }
}

#[cfg(target_os = "macos")]
fn attach(menu: &Menu, _cc: &eframe::CreationContext<'_>) -> Option<()> {
    menu.init_for_nsapp();
    Some(())
}

#[cfg(target_os = "windows")]
fn attach(menu: &Menu, cc: &eframe::CreationContext<'_>) -> Option<()> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let RawWindowHandle::Win32(handle) = cc.window_handle().ok()?.as_raw() else {
        return None;
    };
    // SAFETY: the handle is eframe's live main window.
    unsafe {
        menu.init_for_hwnd_with_theme(handle.hwnd.get(), muda::MenuTheme::Dark)
            .ok()
    }
}
