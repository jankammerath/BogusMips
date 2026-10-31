//! Writes the composed macOS squircle application icon as a 1024×1024 PNG file.

use std::path::PathBuf;

fn main() {
    let out = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("AppIcon-1024.png"));
    let icon = bogusmips::ui::icon::compose(1024);
    icon.save(&out).expect("failed to write composed icon PNG");
}

