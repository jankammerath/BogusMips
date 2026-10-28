use bogusmips::app::BogusMipsApp;

fn main() -> eframe::Result {
    let initial_file = std::env::args_os().nth(1).map(std::path::PathBuf::from);

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("BogusMips")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([800.0, 480.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "BogusMips",
        options,
        Box::new(|cc| Ok(Box::new(BogusMipsApp::new(cc, initial_file)))),
    )
}
