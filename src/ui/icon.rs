//! Application icon, composed the way `media/AppIcon/AppIconMac.icon`
//! describes it: the artwork on a solid black fill, scaled to 0.9 and moved
//! down by 51.2 of 1024 points, clipped to the macOS app icon shape.

use eframe::egui::IconData;
use image::{ImageFormat, Rgba, RgbaImage, imageops};

const ARTWORK: &[u8] = include_bytes!("../../media/AppIcon/BogusMipsAppIcon.png");
const ICON_SIZE: u32 = 512;

/// macOS icon grid (of 1024): the shape is 824 wide with a 100 margin.
const SHAPE: f32 = 824.0 / 1024.0;
const CORNER_RADIUS: f32 = 185.4 / 824.0;
/// Layer placement from `icon.json`.
const ART_SCALE: f32 = 0.9;
const ART_OFFSET_Y: f32 = 51.2 / 1024.0;

pub fn app_icon() -> IconData {
    let image = compose(ICON_SIZE);
    IconData {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    }
}

/// Signed distance from `(x, y)` to a rounded square of side `size` at the
/// origin; negative inside.
fn rounded_square_distance(x: f32, y: f32, size: f32, radius: f32) -> f32 {
    let half = size / 2.0;
    let qx = (x - half).abs() - (half - radius);
    let qy = (y - half).abs() - (half - radius);
    let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
    outside + qx.max(qy).min(0.0) - radius
}

pub fn compose(size: u32) -> RgbaImage {
    let shape = (size as f32 * SHAPE).round();
    let margin = ((size as f32 - shape) / 2.0).round() as u32;
    let shape_px = shape as u32;

    let artwork = image::load_from_memory_with_format(ARTWORK, ImageFormat::Png)
        .expect("bundled app icon is a valid PNG")
        .to_rgba8();
    let art_px = (shape * ART_SCALE).round() as u32;
    let art = imageops::resize(&artwork, art_px, art_px, imageops::FilterType::Triangle);

    let mut layer = RgbaImage::from_pixel(shape_px, shape_px, Rgba([0, 0, 0, 255]));
    let art_x = i64::from((shape_px - art_px) / 2);
    let art_y = i64::from((shape_px - art_px) / 2) + (shape * ART_OFFSET_Y).round() as i64;
    imageops::overlay(&mut layer, &art, art_x, art_y);

    let radius = shape * CORNER_RADIUS;
    let mut icon = RgbaImage::new(size, size);
    for (x, y, pixel) in layer.enumerate_pixels() {
        let d = rounded_square_distance(x as f32 + 0.5, y as f32 + 0.5, shape, radius);
        let coverage = (0.5 - d).clamp(0.0, 1.0);
        if coverage > 0.0 {
            let mut p = *pixel;
            p[3] = (f32::from(p[3]) * coverage).round() as u8;
            icon.put_pixel(x + margin, y + margin, p);
        }
    }
    icon
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_icon_like_icon_composer() {
        let icon = compose(256);
        assert_eq!(icon.dimensions(), (256, 256));
        // Transparent margin and rounded corners.
        assert_eq!(icon.get_pixel(0, 0)[3], 0);
        assert_eq!(icon.get_pixel(30, 30)[3], 0);
        // Opaque black fill inside the shape.
        let p = icon.get_pixel(40, 128);
        assert_eq!((p[0], p[1], p[2], p[3]), (0, 0, 0, 255));
        // The white line artwork is present.
        assert!(icon.pixels().any(|p| p[0] > 200 && p[3] == 255));
    }

    #[test]
    fn provides_icon_data() {
        let data = app_icon();
        assert_eq!((data.width, data.height), (ICON_SIZE, ICON_SIZE));
        assert_eq!(data.rgba.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
    }
}
