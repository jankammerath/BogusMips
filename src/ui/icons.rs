//! Small line icons in the style of VS Code's codicons, drawn as vector
//! shapes (egui's fonts do not contain codicons).

use eframe::egui::{Color32, Painter, Pos2, Rect, Shape, Stroke, vec2};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Menu,
    Files,
    Search,
    Close,
    PanelRight,
    Copy,
    Network,
    Lock,
    Trash,
    Download,
}

fn line(painter: &Painter, points: Vec<Pos2>, stroke: Stroke) {
    painter.add(Shape::line(points, stroke));
}

/// Paints `icon` centered in `rect` (designed for a 16×16 area, scaled).
pub fn paint(painter: &Painter, rect: Rect, icon: Icon, color: Color32) {
    let s = rect.width().min(rect.height()) / 16.0;
    let o = rect.center() - vec2(8.0, 8.0) * s;
    let p = |x: f32, y: f32| o + vec2(x, y) * s;
    let stroke = Stroke::new(1.2 * s.max(1.0), color);
    match icon {
        Icon::Menu => {
            for y in [4.0, 8.0, 12.0] {
                line(painter, vec![p(2.5, y), p(13.5, y)], stroke);
            }
        }
        Icon::Files => {
            // Back document.
            line(
                painter,
                vec![
                    p(5.0, 3.5),
                    p(5.0, 1.5),
                    p(10.5, 1.5),
                    p(14.0, 5.0),
                    p(14.0, 12.5),
                    p(12.0, 12.5),
                ],
                stroke,
            );
            // Front document with folded corner.
            line(
                painter,
                vec![
                    p(2.0, 3.5),
                    p(8.5, 3.5),
                    p(12.0, 7.0),
                    p(12.0, 15.0),
                    p(2.0, 15.0),
                    p(2.0, 3.5),
                ],
                stroke,
            );
            line(
                painter,
                vec![p(8.5, 3.5), p(8.5, 7.0), p(12.0, 7.0)],
                stroke,
            );
        }
        Icon::Search => {
            painter.circle_stroke(p(9.5, 6.5), 4.5 * s, stroke);
            line(
                painter,
                vec![p(6.3, 9.7), p(1.8, 14.2)],
                Stroke::new(stroke.width * 1.3, color),
            );
        }
        Icon::Close => {
            line(painter, vec![p(4.0, 4.0), p(12.0, 12.0)], stroke);
            line(painter, vec![p(12.0, 4.0), p(4.0, 12.0)], stroke);
        }
        Icon::PanelRight => {
            let r = Rect::from_min_max(p(1.5, 2.5), p(14.5, 13.5));
            painter.rect_stroke(r, 1.0, stroke, eframe::egui::StrokeKind::Middle);
            painter.rect_filled(Rect::from_min_max(p(10.0, 2.5), p(14.5, 13.5)), 0.0, color);
        }
        Icon::Copy => {
            painter.rect_stroke(
                Rect::from_min_max(p(5.0, 5.0), p(14.0, 14.5)),
                1.0,
                stroke,
                eframe::egui::StrokeKind::Middle,
            );
            line(
                painter,
                vec![
                    p(3.0, 11.0),
                    p(2.0, 11.0),
                    p(2.0, 1.5),
                    p(11.0, 1.5),
                    p(11.0, 3.0),
                ],
                stroke,
            );
        }
        Icon::Network => {
            // Chevrons with three dots: < · · · >
            line(painter, vec![p(4.5, 4.0), p(1.0, 8.0), p(4.5, 12.0)], stroke);
            line(painter, vec![p(11.5, 4.0), p(15.0, 8.0), p(11.5, 12.0)], stroke);
            for x in [5.6, 8.0, 10.4] {
                painter.circle_filled(p(x, 8.0), 0.95 * s, color);
            }
        }
        Icon::Lock => {
            painter.rect_stroke(
                Rect::from_min_max(p(3.5, 7.0), p(12.5, 14.5)),
                1.0,
                stroke,
                eframe::egui::StrokeKind::Middle,
            );
            // Shackle.
            line(
                painter,
                vec![p(5.0, 7.0), p(5.0, 5.0), p(5.5, 3.5), p(7.0, 2.5), p(9.0, 2.5), p(10.5, 3.5), p(11.0, 5.0), p(11.0, 7.0)],
                stroke,
            );
        }
        Icon::Trash => {
            line(painter, vec![p(2.5, 3.5), p(13.5, 3.5)], stroke);
            line(painter, vec![p(6.0, 3.5), p(6.5, 2.0), p(9.5, 2.0), p(10.0, 3.5)], stroke);
            line(
                painter,
                vec![p(3.5, 3.5), p(4.5, 14.0), p(11.5, 14.0), p(12.5, 3.5)],
                stroke,
            );
            for x in [6.5, 8.0, 9.5] {
                line(painter, vec![p(x, 5.5), p(x, 12.0)], stroke);
            }
        }
        Icon::Download => {
            line(painter, vec![p(8.0, 2.0), p(8.0, 10.5)], stroke);
            line(painter, vec![p(4.0, 7.0), p(8.0, 10.5), p(12.0, 7.0)], stroke);
            line(painter, vec![p(2.5, 13.5), p(13.5, 13.5)], stroke);
        }
    }
}

/// A frameless icon button with VS Code's hover background.
pub fn button(
    ui: &mut eframe::egui::Ui,
    icon: Icon,
    size: f32,
    tooltip: &str,
) -> eframe::egui::Response {
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), eframe::egui::Sense::click());
    let color = if response.hovered() {
        ui.painter().rect_filled(
            rect,
            4.0,
            Color32::from_rgba_unmultiplied(0x5a, 0x5d, 0x5e, 0x50),
        );
        super::theme::TEXT_BRIGHT
    } else {
        super::theme::TEXT
    };
    paint(ui.painter(), rect.shrink(size * 0.2), icon, color);
    response.on_hover_text(tooltip)
}
