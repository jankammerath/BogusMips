use eframe::egui;

use crate::ui::theme;

#[derive(Default)]
pub struct BogusMipsApp {
    native_theme_applied: bool,
}

impl BogusMipsApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply_dark(&cc.egui_ctx);
        Self::default()
    }
}

impl eframe::App for BogusMipsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.native_theme_applied {
            theme::apply_dark_window_frame(ctx);
            self.native_theme_applied = true;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.centered_and_justified(|ui| {
                ui.heading("Hello, World!");
            });
        });
    }
}
