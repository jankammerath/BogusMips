use eframe::egui;

use crate::ui::theme;

#[derive(Default)]
pub struct BogusMipsApp;

impl BogusMipsApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply_dark(&cc.egui_ctx);
        Self
    }
}

impl eframe::App for BogusMipsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.centered_and_justified(|ui| {
                ui.heading("Hello, World!");
            });
        });
    }
}
