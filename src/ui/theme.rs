use eframe::egui::{self, Color32};

pub fn apply_dark(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.style_mut_of(egui::Theme::Dark, |style| {
        let bg = Color32::from_rgb(0x1e, 0x1e, 0x22);
        style.visuals.panel_fill = bg;
        style.visuals.window_fill = bg;
        style.visuals.override_text_color = Some(Color32::from_rgb(0xe6, 0xe6, 0xe6));
    });
}
