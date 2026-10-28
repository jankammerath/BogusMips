mod app;
mod ui;

use app::BogusMipsApp;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("BogusMips")
            .with_inner_size([1024.0, 720.0])
            .with_min_inner_size([640.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BogusMips",
        options,
        Box::new(|cc| Ok(Box::new(BogusMipsApp::new(cc)))),
    )
}
