use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke,
};

// VS Code "Dark+" colors, as used by its floating-card layout.
/// Window frame: title bar and the gaps between the cards.
pub const WINDOW: Color32 = Color32::from_rgb(0x3c, 0x3c, 0x3c);
pub const BACKGROUND: Color32 = WINDOW;
pub const ICON_ACTIVE: Color32 = Color32::WHITE;
pub const ICON_INACTIVE: Color32 = Color32::from_rgb(0x85, 0x85, 0x85);
pub const SIDEBAR: Color32 = Color32::from_rgb(0x25, 0x25, 0x26);
pub const EDITOR: Color32 = Color32::from_rgb(0x1e, 0x1e, 0x1e);
pub const TAB_BAR: Color32 = Color32::from_rgb(0x25, 0x25, 0x26);
pub const CARD_BORDER: Color32 = Color32::from_rgb(0x2b, 0x2b, 0x2c);
pub const SEPARATOR: Color32 = Color32::from_rgb(0x3e, 0x3e, 0x3f);
pub const TEXT: Color32 = Color32::from_rgb(0xcc, 0xcc, 0xcc);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x9d, 0x9d, 0x9d);
pub const TEXT_BRIGHT: Color32 = Color32::WHITE;
pub const LINK: Color32 = Color32::from_rgb(0x37, 0x94, 0xff);
pub const ACCENT: Color32 = Color32::from_rgb(0x00, 0x7a, 0xcc);
pub const ERROR: Color32 = Color32::from_rgb(0xf4, 0x87, 0x71);
pub const FOCUS: Color32 = Color32::from_rgb(0x00, 0x7f, 0xd4);
pub const BUTTON: Color32 = Color32::from_rgb(0x0e, 0x63, 0x9c);
pub const BUTTON_HOVER: Color32 = Color32::from_rgb(0x11, 0x77, 0xbb);
pub const INPUT: Color32 = Color32::from_rgb(0x3c, 0x3c, 0x3c);
pub const LIST_HOVER: Color32 = Color32::from_rgb(0x2a, 0x2d, 0x2e);
pub const LIST_SELECTED: Color32 = Color32::from_rgb(0x04, 0x39, 0x5e);
pub const PILL: Color32 = Color32::from_rgb(0x37, 0x37, 0x3d);
pub const STATUS_BAR: Color32 = Color32::from_rgb(0x00, 0x7a, 0xcc);
pub const COMMAND_CENTER: Color32 = Color32::from_rgb(0x46, 0x46, 0x46);
pub const COMMAND_CENTER_BORDER: Color32 = Color32::from_rgb(0x4b, 0x4b, 0x4b);
/// Search match in result lists (`editor.findMatchHighlightBackground`).
pub const MATCH: Color32 = Color32::from_rgba_premultiplied(0x4e, 0x1f, 0x00, 0x55);
/// The match jumped to (`editor.findMatchBackground`).
pub const CURRENT_MATCH: Color32 = Color32::from_rgb(0x51, 0x5c, 0x6a);
pub const LINE_HIGHLIGHT: Color32 = Color32::from_rgb(0x2a, 0x2d, 0x2e);
pub const CARD_RADIUS: u8 = 6;
/// Gap between the cards.
pub const GAP: i8 = 2;

/// A rounded card (sidebar, editor, panel) on the window background.
pub fn card(fill: Color32) -> egui::Frame {
    egui::Frame::NONE
        .fill(fill)
        .stroke(Stroke::new(1.0, CARD_BORDER))
        .corner_radius(CornerRadius::same(CARD_RADIUS))
        // Keeps content off the border and out of the rounded corners.
        .inner_margin(Margin {
            left: 1,
            right: 1,
            top: 1,
            bottom: 4,
        })
        .outer_margin(Margin {
            left: GAP,
            right: GAP,
            top: 0,
            bottom: 2 * GAP,
        })
}

const HACK_REGULAR: &[u8] = include_bytes!("../../media/fonts/Hack-Regular.ttf");
const HACK_BOLD: &[u8] = include_bytes!("../../media/fonts/Hack-Bold.ttf");
const BOLD_FAMILY: &str = "Hack Bold";

/// Installs the bundled Hack font for all text. egui's default fonts stay
/// as fallbacks for glyphs Hack lacks (e.g. the emoji used as tree icons).
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "Hack".to_owned(),
        Arc::new(FontData::from_static(HACK_REGULAR)),
    );
    fonts.font_data.insert(
        "Hack-Bold".to_owned(),
        Arc::new(FontData::from_static(HACK_BOLD)),
    );

    let fallbacks = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .insert(0, "Hack".to_owned());
    }
    let mut bold = vec!["Hack-Bold".to_owned()];
    bold.extend(fallbacks);
    fonts
        .families
        .insert(FontFamily::Name(BOLD_FAMILY.into()), bold);
    ctx.set_fonts(fonts);
}

/// The bundled bold face, for headings.
pub fn bold_family() -> FontFamily {
    FontFamily::Name(BOLD_FAMILY.into())
}

pub fn bold(size: f32) -> FontId {
    FontId::new(size, bold_family())
}

pub fn apply_dark(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        style.spacing.button_padding = egui::vec2(8.0, 3.0);
        style.spacing.menu_margin = Margin::same(4);
        let v = &mut style.visuals;
        v.override_text_color = Some(TEXT);
        v.panel_fill = WINDOW;
        // Menus, popups and dialogs.
        v.window_fill = SIDEBAR;
        v.window_stroke = Stroke::new(1.0, Color32::from_rgb(0x45, 0x45, 0x45));
        v.window_corner_radius = CornerRadius::same(CARD_RADIUS);
        v.menu_corner_radius = CornerRadius::same(5);
        v.faint_bg_color = Color32::from_rgb(0x2a, 0x2a, 0x2a);
        v.extreme_bg_color = INPUT;
        v.code_bg_color = EDITOR;
        v.hyperlink_color = LINK;
        v.warn_fg_color = Color32::from_rgb(0xcc, 0xa7, 0x00);
        v.error_fg_color = Color32::from_rgb(0xf4, 0x87, 0x71);
        v.selection.bg_fill = Color32::from_rgb(0x26, 0x4f, 0x78);
        // Focus outline of text fields.
        v.selection.stroke = Stroke::new(1.0, FOCUS);

        let radius = CornerRadius::same(2);
        let w = &mut v.widgets;
        w.noninteractive.bg_stroke = Stroke::new(1.0, SEPARATOR);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.weak_bg_fill = Color32::from_rgb(0x3a, 0x3d, 0x41);
        w.inactive.bg_fill = Color32::from_rgb(0x3a, 0x3d, 0x41);
        w.inactive.bg_stroke = Stroke::new(1.0, INPUT);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.corner_radius = radius;
        w.hovered.weak_bg_fill = Color32::from_rgb(0x45, 0x49, 0x4e);
        w.hovered.bg_fill = Color32::from_rgb(0x45, 0x49, 0x4e);
        w.hovered.bg_stroke = Stroke::NONE;
        w.hovered.fg_stroke = Stroke::new(1.0, TEXT_BRIGHT);
        w.hovered.corner_radius = radius;
        w.hovered.expansion = 0.0;
        w.active.weak_bg_fill = LIST_SELECTED;
        w.active.bg_fill = LIST_SELECTED;
        w.active.bg_stroke = Stroke::NONE;
        w.active.fg_stroke = Stroke::new(1.0, TEXT_BRIGHT);
        w.active.corner_radius = radius;
        w.active.expansion = 0.0;
        w.open.weak_bg_fill = LIST_SELECTED;
        w.open.corner_radius = radius;
    });
}

/// A primary (blue) button as in VS Code's welcome views.
pub fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let height = 26.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    let fill = if response.hovered() {
        BUTTON_HOVER
    } else {
        BUTTON
    };
    ui.painter().rect_filled(rect, CornerRadius::same(2), fill);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        egui::TextStyle::Body.resolve(ui.style()),
        TEXT_BRIGHT,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A small uppercase-free view title such as "Explorer", dimmed.
pub fn view_title(ui: &mut egui::Ui, title: &str) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        ui.label(egui::RichText::new(title).color(TEXT).size(12.0));
    });
    ui.add_space(4.0);
}

/// Height of the area behind the macOS traffic lights, which the app paints
/// itself (see [`window_options`]).
pub const MACOS_TITLE_BAR_HEIGHT: f32 = 35.0;

/// Native window options for a pitch black frame. On macOS the title bar is
/// made transparent and the content extends behind it, because the system
/// dark title bar is grey; the app then draws the title itself.
pub fn window_options(builder: egui::ViewportBuilder) -> egui::ViewportBuilder {
    if cfg!(target_os = "macos") {
        builder
            .with_fullsize_content_view(true)
            .with_titlebar_shown(false)
            .with_title_shown(false)
    } else {
        builder
    }
}

/// Windows 11: paints the caption (title bar) and border in the title bar
/// color. Earlier Windows versions keep the system dark frame.
#[cfg(target_os = "windows")]
pub fn apply_black_window_frame(frame: &eframe::Frame) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Dwm::{
        DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DwmSetWindowAttribute,
    };

    let Ok(handle) = frame.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return;
    };
    let hwnd = win32.hwnd.get() as HWND;
    // COLORREF is 0x00BBGGRR.
    let [r, g, b, _] = WINDOW.to_array();
    let color: u32 = u32::from(r) | (u32::from(g) << 8) | (u32::from(b) << 16);
    for attribute in [DWMWA_CAPTION_COLOR, DWMWA_BORDER_COLOR] {
        // SAFETY: `hwnd` is the live window owned by eframe, and the pointer
        // refers to a 4-byte COLORREF as the attributes require.
        unsafe {
            DwmSetWindowAttribute(
                hwnd,
                attribute as u32,
                (&color as *const u32).cast(),
                std::mem::size_of::<u32>() as u32,
            );
        }
    }
}

/// Forces the native window decorations (title bar / frame) into dark mode,
/// independent of the OS appearance setting. Uses `NSAppearance` (darkAqua) on
/// macOS and DWM immersive dark mode on Windows 10 1809+ / Windows 11.
pub fn apply_dark_window_frame(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(egui::SystemTheme::Dark));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hack_is_used_for_all_text() {
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let _ = ctx.run(Default::default(), |_| {});
        ctx.fonts(|f| {
            // Hack is monospaced; egui's default proportional font is not.
            for font in [
                FontId::proportional(14.0),
                FontId::monospace(14.0),
                bold(14.0),
            ] {
                assert_eq!(
                    f.glyph_width(&font, 'i'),
                    f.glyph_width(&font, 'W'),
                    "{font:?}"
                );
            }
            // Emoji fallbacks for the tree icons are still available.
            assert!(f.has_glyph(&FontId::proportional(14.0), '📦'));
            assert!(f.has_glyph(&bold(14.0), '📦'));
        });
    }
}
