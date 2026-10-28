use std::sync::Arc;

use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, FontId};

/// Pitch black window and panel background.
pub const BACKGROUND: Color32 = Color32::BLACK;
pub const TEXT: Color32 = Color32::from_rgb(0xd4, 0xd4, 0xd4);

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

/// Height of the area behind the macOS traffic lights, which the app paints
/// itself (see [`window_options`]).
pub const MACOS_TITLE_BAR_HEIGHT: f32 = 28.0;

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

/// Windows 11: paints the caption (title bar) and border black. Earlier
/// Windows versions do not support these attributes and keep the dark frame.
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
    let black: u32 = 0x0000_0000;
    for attribute in [DWMWA_CAPTION_COLOR, DWMWA_BORDER_COLOR] {
        // SAFETY: `hwnd` is the live window owned by eframe, and the pointer
        // refers to a 4-byte COLORREF as the attributes require.
        unsafe {
            DwmSetWindowAttribute(
                hwnd,
                attribute as u32,
                (&black as *const u32).cast(),
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
