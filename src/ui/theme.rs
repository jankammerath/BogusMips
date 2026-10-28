use eframe::egui::{self, Color32};

/// Pitch black window and panel background.
pub const BACKGROUND: Color32 = Color32::BLACK;
pub const TEXT: Color32 = Color32::from_rgb(0xd4, 0xd4, 0xd4);

pub fn apply_dark(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        let v = &mut style.visuals;
        v.panel_fill = BACKGROUND;
        v.window_fill = BACKGROUND;
        v.faint_bg_color = Color32::from_rgb(0x0c, 0x0c, 0x0c);
        // Inputs (e.g. the tree filter) stay slightly lifted off the black.
        v.extreme_bg_color = Color32::from_rgb(0x1a, 0x1a, 0x1a);
        // Panel separators.
        v.widgets.noninteractive.bg_stroke.color = Color32::from_rgb(0x26, 0x26, 0x26);
        v.override_text_color = Some(TEXT);
    });
}

/// Forces the native window decorations (title bar / frame) into dark mode,
/// independent of the OS appearance setting. Uses `NSAppearance` (darkAqua) on
/// macOS and DWM immersive dark mode on Windows 10 1809+ / Windows 11.
pub fn apply_dark_window_frame(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(egui::SystemTheme::Dark));
}
