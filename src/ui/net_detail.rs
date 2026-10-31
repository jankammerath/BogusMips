//! Editor content for a captured network flow: an overview, the request and
//! the response, with header tables and decoded bodies.

use eframe::egui::{
    self, Color32, ColorImage, RichText, ScrollArea, Sense, TextStyle, TextureHandle,
    TextureOptions, text::LayoutJob, vec2,
};

use super::content_view::EditorResponse;
use super::highlight::{self, TEXT};
use super::icons::{self, Icon};
use super::svg;
use super::theme;
use crate::beautify;
use crate::inspect::{InfoSection, Syntax, format_size, group_digits};
use crate::net::capture::{Flow, Scheme};
use crate::net::http::Headers;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum FlowTab {
    #[default]
    Overview,
    Request,
    Response,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum BodyView {
    /// Formatted text for text bodies, or rendered image preview for raster/SVG images.
    #[default]
    Pretty,
    /// Formatted XML source view for SVG images.
    Source,
    Raw,
    Hex,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImageKind {
    Raster(&'static str),
    Svg,
}

#[derive(Default)]
pub struct FlowDetailState {
    pub tab: FlowTab,
    pub body: BodyView,
}

/// Color for an HTTP status code, by class.
fn status_color(status: u16) -> egui::Color32 {
    match status {
        200..=299 => egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
        300..=399 => egui::Color32::from_rgb(0x56, 0x9c, 0xd6),
        400..=499 => egui::Color32::from_rgb(0xcc, 0xa7, 0x00),
        500..=599 => theme::ERROR,
        _ => theme::TEXT_DIM,
    }
}

fn method_color(method: &str) -> egui::Color32 {
    match method {
        "GET" => egui::Color32::from_rgb(0x4e, 0xc9, 0xb0),
        "POST" => egui::Color32::from_rgb(0xcc, 0xa7, 0x00),
        "PUT" | "PATCH" => egui::Color32::from_rgb(0x56, 0x9c, 0xd6),
        "DELETE" => theme::ERROR,
        _ => theme::TEXT,
    }
}

fn content_type(headers: &Headers) -> Option<String> {
    headers
        .get("content-type")
        .map(|v| v.split(';').next().unwrap_or(v).trim().to_owned())
}

/// Detects whether a decoded HTTP message body is a raster or SVG image.
pub fn detect_body_image(headers: &Headers, decoded: &[u8]) -> Option<ImageKind> {
    if decoded.is_empty() {
        return None;
    }
    if decoded.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(ImageKind::Raster("PNG"));
    }
    if decoded.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some(ImageKind::Raster("JPEG"));
    }
    if decoded.starts_with(b"GIF87a") || decoded.starts_with(b"GIF89a") {
        return Some(ImageKind::Raster("GIF"));
    }
    if decoded.len() >= 12 && &decoded[0..4] == b"RIFF" && &decoded[8..12] == b"WEBP" {
        return Some(ImageKind::Raster("WebP"));
    }
    let ctype = content_type(headers).unwrap_or_default();
    let ctype_lower = ctype.to_ascii_lowercase();
    if decoded.starts_with(b"BM")
        && decoded.len() > 26
        && (ctype_lower == "image/bmp"
            || ctype_lower == "image/x-bmp"
            || ctype_lower == "image/x-ms-bmp"
            || matches!(image::guess_format(decoded), Ok(image::ImageFormat::Bmp)))
    {
        return Some(ImageKind::Raster("BMP"));
    }
    if svg::is_svg( (!ctype.is_empty()).then_some(ctype.as_str()), decoded) {
        return Some(ImageKind::Svg);
    }
    if ctype_lower.starts_with("image/") {
        if let Ok(fmt) = image::guess_format(decoded) {
            let label = match fmt {
                image::ImageFormat::Png => "PNG",
                image::ImageFormat::Jpeg => "JPEG",
                image::ImageFormat::Gif => "GIF",
                image::ImageFormat::WebP => "WebP",
                image::ImageFormat::Bmp => "BMP",
                _ => "Image",
            };
            return Some(ImageKind::Raster(label));
        }
    }
    None
}

/// Formats the HTTP request (request line, headers, and decoded/formatted body) for clipboard copy.
pub fn format_request(flow: &Flow, view: BodyView) -> String {
    let mut out = format!("{} {} HTTP/1.1\n", flow.method, flow.path);
    for (name, value) in &flow.req_headers.0 {
        out.push_str(&format!("{name}: {value}\n"));
    }
    if !flow.req_body.is_empty() {
        out.push('\n');
        out.push_str(&format_body_for_copy(&flow.req_headers, &flow.req_body, view));
    }
    out
}

/// Formats the HTTP response (status line, headers, and decoded/formatted body) for clipboard copy.
pub fn format_response(flow: &Flow, view: BodyView) -> String {
    let Some(status) = flow.status else {
        return flow
            .error
            .as_ref()
            .map_or_else(|| "Waiting for the response…".to_owned(), |e| format!("Error: {e}"));
    };
    let mut out = format!("HTTP/1.1 {status} {}\n", flow.reason);
    for (name, value) in &flow.resp_headers.0 {
        out.push_str(&format!("{name}: {value}\n"));
    }
    if !flow.resp_body.is_empty() {
        out.push('\n');
        out.push_str(&format_body_for_copy(&flow.resp_headers, &flow.resp_body, view));
    }
    out
}

/// Formats both the HTTP request and response for clipboard copy.
pub fn format_flow(flow: &Flow, view: BodyView) -> String {
    let mut out = format_request(flow, view);
    if flow.status.is_some() || flow.error.is_some() {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&format_response(flow, view));
    }
    out
}

fn format_body_for_copy(headers: &Headers, body: &[u8], view: BodyView) -> String {
    if view == BodyView::Hex {
        return format_hex_string(body);
    }
    let (decoded, _) = crate::net::http::decode_for_display(headers, body);
    let shown = &decoded[..decoded.len().min(MAX_SHOWN)];
    match std::str::from_utf8(shown) {
        Ok(text) => {
            let ctype = content_type(headers).unwrap_or_default();
            if matches!(view, BodyView::Pretty | BodyView::Source) {
                pretty(&ctype, text).0
            } else {
                text.to_owned()
            }
        }
        Err(_) => format_hex_string(body),
    }
}

fn format_hex_string(data: &[u8]) -> String {
    let shown = &data[..data.len().min(MAX_SHOWN)];
    let mut out = String::new();
    for (row, chunk) in shown.chunks(16).enumerate() {
        let mut hex = String::new();
        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        out.push_str(&format!("{:08x}  {hex:<50}{ascii}\n", row * 16));
    }
    out
}

fn tab_button(ui: &mut egui::Ui, state: &mut FlowTab, value: FlowTab, label: &str) {
    let selected = *state == value;
    let (rect, response) = ui.allocate_exact_size(
        vec2(ui.painter().layout_no_wrap(label.into(), font(ui), theme::TEXT).size().x + 20.0, 28.0),
        Sense::click(),
    );
    if selected {
        ui.painter().line_segment(
            [rect.left_bottom() + vec2(4.0, -1.0), rect.right_bottom() + vec2(-4.0, -1.0)],
            egui::Stroke::new(2.0, theme::ACCENT),
        );
    } else if response.hovered() {
        ui.painter().rect_filled(rect, 0.0, theme::LIST_HOVER);
    }
    let color = if selected { theme::TEXT_BRIGHT } else { theme::TEXT_DIM };
    let galley = ui.painter().layout_no_wrap(label.into(), font(ui), color);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, color);
    if response.clicked() {
        *state = value;
    }
}

fn font(ui: &egui::Ui) -> egui::FontId {
    TextStyle::Body.resolve(ui.style())
}

pub fn show(ui: &mut egui::Ui, flow: &Flow, state: &mut FlowDetailState, info_visible: bool) -> EditorResponse {
    let mut response = EditorResponse::default();

    // Header: method, URL, status, duration.
    egui::Frame::NONE
        .inner_margin(egui::Margin {
            left: 12,
            right: 8,
            top: 8,
            bottom: 4,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&flow.method).strong().color(method_color(&flow.method)));
                if flow.scheme == Scheme::Https {
                    let (rect, _) = ui.allocate_exact_size(vec2(14.0, 14.0), Sense::hover());
                    icons::paint(ui.painter(), rect, Icon::Lock, theme::TEXT_DIM);
                }
                ui.add(egui::Label::new(RichText::new(flow.url()).color(theme::TEXT)).truncate());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    response.close |= icons::button(ui, Icon::Close, 20.0, "Close").clicked();
                    let tip = if info_visible {
                        "Hide file information (⌘I)"
                    } else {
                        "Show file information (⌘I)"
                    };
                    response.toggle_info |= icons::button(ui, Icon::PanelRight, 20.0, tip).clicked();
                    let copy_tip = match state.tab {
                        FlowTab::Overview => "Copy request & response to clipboard",
                        FlowTab::Request => "Copy request to clipboard",
                        FlowTab::Response => "Copy response to clipboard",
                    };
                    if icons::button(ui, Icon::Copy, 20.0, copy_tip).clicked() {
                        let copied = match state.tab {
                            FlowTab::Overview => format_flow(flow, state.body),
                            FlowTab::Request => format_request(flow, state.body),
                            FlowTab::Response => format_response(flow, state.body),
                        };
                        ui.ctx().copy_text(copied);
                    }
                });
            });
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                match (flow.status, &flow.error) {
                    (Some(status), _) => {
                        ui.label(
                            RichText::new(format!("{status} {}", flow.reason))
                                .color(status_color(status)),
                        );
                    }
                    (None, Some(error)) => {
                        ui.label(RichText::new(format!("✖ {error}")).color(theme::ERROR));
                    }
                    (None, None) => {
                        ui.label(RichText::new("pending…").color(theme::TEXT_DIM));
                    }
                }
                if let Some(duration) = flow.duration {
                    ui.label(
                        RichText::new(format!("· {} ms", duration.as_millis())).color(theme::TEXT_DIM),
                    );
                }
            });
        });

    // Tabs.
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        tab_button(ui, &mut state.tab, FlowTab::Overview, "Overview");
        tab_button(ui, &mut state.tab, FlowTab::Request, "Request");
        tab_button(ui, &mut state.tab, FlowTab::Response, "Response");
    });
    ui.separator();

    match state.tab {
        FlowTab::Overview => overview(ui, flow),
        FlowTab::Request => {
            body_toolbar(ui, state, flow, &flow.req_headers, &flow.req_body, "req");
            message(ui, flow.id, "req", &flow.req_headers, &flow.req_body, state.body);
        }
        FlowTab::Response => {
            if flow.status.is_none() {
                ui.centered_and_justified(|ui| {
                    let text = flow.error.as_deref().unwrap_or("Waiting for the response…");
                    ui.label(RichText::new(text).color(theme::TEXT_DIM));
                });
            } else {
                body_toolbar(ui, state, flow, &flow.resp_headers, &flow.resp_body, "resp");
                message(ui, flow.id, "resp", &flow.resp_headers, &flow.resp_body, state.body);
            }
        }
    }
    response
}

fn overview(ui: &mut egui::Ui, flow: &Flow) {
    ScrollArea::vertical()
        .id_salt(("flow_overview", flow.id))
        .auto_shrink(false)
        .show(ui, |ui| {
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    for section in flow_sections(flow) {
                        ui.label(
                            RichText::new(section.title.to_uppercase())
                                .size(11.0)
                                .family(theme::bold_family())
                                .color(theme::TEXT_DIM),
                        );
                        ui.add_space(2.0);
                        for (key, value) in &section.rows {
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    vec2(120.0, 18.0),
                                    egui::Label::new(RichText::new(key).color(theme::TEXT_DIM))
                                        .halign(egui::Align::LEFT),
                                );
                                ui.add(egui::Label::new(value).wrap());
                            });
                        }
                        ui.add_space(10.0);
                    }
                });
        });
}

fn body_toolbar(
    ui: &mut egui::Ui,
    state: &mut FlowDetailState,
    flow: &Flow,
    headers: &Headers,
    body: &[u8],
    tag: &str,
) {
    let (decoded, _) = crate::net::http::decode_for_display(headers, body);
    let img_kind = detect_body_image(headers, &decoded);

    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.label(RichText::new("Body").size(12.0).color(theme::TEXT_DIM));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            let copy_tip = if tag == "req" {
                "Copy request to clipboard"
            } else {
                "Copy response to clipboard"
            };
            if icons::button(ui, Icon::Copy, 20.0, copy_tip).clicked() {
                let text = if tag == "req" {
                    format_request(flow, state.body)
                } else {
                    format_response(flow, state.body)
                };
                ui.ctx().copy_text(text);
            }
            ui.add_space(4.0);

            match img_kind {
                Some(ImageKind::Svg) => {
                    for (value, label) in [
                        (BodyView::Hex, "Hex"),
                        (BodyView::Raw, "Raw"),
                        (BodyView::Source, "Source"),
                        (BodyView::Pretty, "Image"),
                    ] {
                        let selected = state.body == value;
                        if view_pill(ui, label, selected).clicked() {
                            state.body = value;
                        }
                    }
                }
                Some(ImageKind::Raster(_)) => {
                    for (value, label, selected) in [
                        (BodyView::Hex, "Hex", state.body == BodyView::Hex),
                        (BodyView::Pretty, "Image", state.body != BodyView::Hex),
                    ] {
                        if view_pill(ui, label, selected).clicked() {
                            state.body = value;
                        }
                    }
                }
                None => {
                    for (value, label, selected) in [
                        (BodyView::Hex, "Hex", state.body == BodyView::Hex),
                        (BodyView::Raw, "Raw", state.body == BodyView::Raw),
                        (
                            BodyView::Pretty,
                            "Pretty",
                            matches!(state.body, BodyView::Pretty | BodyView::Source),
                        ),
                    ] {
                        if view_pill(ui, label, selected).clicked() {
                            state.body = value;
                        }
                    }
                }
            }
        });
    });
}

fn view_pill(ui: &mut egui::Ui, label: &str, selected: bool) -> egui::Response {
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .size(12.0)
                .color(if selected { theme::TEXT_BRIGHT } else { theme::TEXT_DIM }),
        )
        .fill(if selected { theme::PILL } else { egui::Color32::TRANSPARENT }),
    )
}

fn message(ui: &mut egui::Ui, id: u64, tag: &str, headers: &Headers, body: &[u8], view: BodyView) {
    ScrollArea::both()
        .id_salt(("flow_msg", id, tag))
        .auto_shrink(false)
        .show(ui, |ui| {
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(12, 6))
                .show(ui, |ui| {
                    // Header table.
                    for (name, value) in &headers.0 {
                        let mut job = LayoutJob::default();
                        let mono = TextStyle::Monospace.resolve(ui.style());
                        highlight::append(&mut job, name, theme::LINK, &mono);
                        highlight::append(&mut job, ": ", theme::TEXT_DIM, &mono);
                        highlight::append(&mut job, value, TEXT, &mono);
                        ui.add(egui::Label::new(job).wrap());
                    }
                    if body.is_empty() {
                        ui.add_space(6.0);
                        ui.label(RichText::new("(no body)").color(theme::TEXT_DIM));
                        return;
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(4.0);
                    body_contents(ui, id, tag, headers, body, view);
                });
        });
}

/// Largest body rendered inline; more is truncated with a note.
const MAX_SHOWN: usize = 512 * 1024;

fn body_contents(
    ui: &mut egui::Ui,
    id: u64,
    tag: &str,
    headers: &Headers,
    body: &[u8],
    view: BodyView,
) {
    let mono = TextStyle::Monospace.resolve(ui.style());
    if view == BodyView::Hex {
        hex_dump(ui, body, &mono);
        return;
    }
    let (decoded, _enc) = crate::net::http::decode_for_display(headers, body);
    let img_kind = detect_body_image(headers, &decoded);

    match img_kind {
        Some(ImageKind::Raster(fmt)) => {
            if render_raster_body(ui, id, tag, fmt, &decoded, body.len()) {
                return;
            }
        }
        Some(ImageKind::Svg) if view == BodyView::Pretty => {
            if let Ok(svg_text) = std::str::from_utf8(&decoded) {
                if render_svg_body(ui, id, tag, svg_text, body.len()) {
                    return;
                }
            }
        }
        _ => {}
    }

    let shown = &decoded[..decoded.len().min(MAX_SHOWN)];
    let text = match std::str::from_utf8(shown) {
        Ok(text) => text.to_owned(),
        Err(_) => {
            ui.label(
                RichText::new(format!("Binary body ({}). Use the Hex view.", format_size(body.len() as u64)))
                    .color(theme::TEXT_DIM),
            );
            return;
        }
    };

    let ctype = content_type(headers).unwrap_or_default();
    let (display, syntax) = if matches!(view, BodyView::Pretty | BodyView::Source) {
        pretty(&ctype, &text)
    } else {
        (text, Syntax::Plain)
    };
    for line in display.lines() {
        let mut job = LayoutJob::default();
        highlight::highlight_into(&mut job, &line.replace('\t', "    "), syntax, &mono);
        ui.add(egui::Label::new(job).extend());
    }
    if decoded.len() > MAX_SHOWN {
        ui.add_space(4.0);
        ui.label(
            RichText::new(format!("… truncated ({} total)", format_size(decoded.len() as u64)))
                .color(theme::TEXT_DIM),
        );
    }
}

#[derive(Clone)]
struct CachedFlowImage {
    len: usize,
    texture: TextureHandle,
    display_size: (f32, f32),
    pixel_size: (u32, u32),
}

fn render_raster_body(
    ui: &mut egui::Ui,
    id: u64,
    tag: &str,
    fmt: &str,
    decoded: &[u8],
    raw_len: usize,
) -> bool {
    let cache_id = egui::Id::new(("flow_raster_tex", id, tag));
    let cached: Option<CachedFlowImage> =
        ui.ctx().data_mut(|d| d.get_temp::<CachedFlowImage>(cache_id));
    let entry = match cached.filter(|c| c.len == decoded.len()) {
        Some(c) => c,
        None => {
            let Ok(dyn_img) = image::load_from_memory(decoded) else {
                return false;
            };
            let rgba = dyn_img.to_rgba8();
            let (w, h) = rgba.dimensions();
            let color_image =
                ColorImage::from_rgba_unmultiplied([w as usize, h as usize], rgba.as_raw());
            let texture = ui.ctx().load_texture(
                format!("flow_{id}_{tag}_raster"),
                color_image,
                TextureOptions::LINEAR,
            );
            let entry = CachedFlowImage {
                len: decoded.len(),
                texture,
                display_size: (w as f32, h as f32),
                pixel_size: (w, h),
            };
            ui.ctx()
                .data_mut(|d| d.insert_temp(cache_id, entry.clone()));
            entry
        }
    };

    let (pw, ph) = entry.pixel_size;
    ui.label(
        RichText::new(format!(
            "{fmt} image · {pw} × {ph} px · {}",
            format_size(raw_len as u64)
        ))
        .size(12.0)
        .color(theme::TEXT_DIM),
    );
    ui.add_space(6.0);
    paint_image_preview(ui, &entry.texture, entry.display_size);
    true
}

fn render_svg_body(
    ui: &mut egui::Ui,
    id: u64,
    tag: &str,
    svg_text: &str,
    raw_len: usize,
) -> bool {
    let cache_id = egui::Id::new(("flow_svg_tex", id, tag));
    let cached: Option<CachedFlowImage> =
        ui.ctx().data_mut(|d| d.get_temp::<CachedFlowImage>(cache_id));
    let entry = match cached.filter(|c| c.len == svg_text.len()) {
        Some(c) => c,
        None => {
            let Some(rendered) = svg::render_svg(svg_text, 512) else {
                return false;
            };
            let (dw, dh) = rendered.display_size;
            let texture = ui.ctx().load_texture(
                format!("flow_{id}_{tag}_svg"),
                rendered.image,
                TextureOptions::LINEAR,
            );
            let entry = CachedFlowImage {
                len: svg_text.len(),
                texture,
                display_size: (dw, dh),
                pixel_size: (dw.round() as u32, dh.round() as u32),
            };
            ui.ctx()
                .data_mut(|d| d.insert_temp(cache_id, entry.clone()));
            entry
        }
    };

    let (pw, ph) = entry.pixel_size;
    ui.label(
        RichText::new(format!(
            "SVG image · {pw} × {ph} px · {}",
            format_size(raw_len as u64)
        ))
        .size(12.0)
        .color(theme::TEXT_DIM),
    );
    ui.add_space(6.0);
    paint_image_preview(ui, &entry.texture, entry.display_size);
    true
}

fn paint_image_preview(ui: &mut egui::Ui, texture: &TextureHandle, (mut w, mut h): (f32, f32)) {
    let max_w = (ui.available_width() - 16.0).max(64.0);
    let max_h = 480.0f32;
    if w > max_w {
        let s = max_w / w;
        w *= s;
        h *= s;
    }
    if h > max_h {
        let s = max_h / h;
        w *= s;
        h *= s;
    }
    let size = vec2(w.max(1.0), h.max(1.0));
    let pad = vec2(8.0, 8.0);
    let (outer, _) = ui.allocate_exact_size(size + pad * 2.0, Sense::hover());
    let inner = outer.shrink2(pad);

    // Subtle checkerboard backdrop so both dark-on-transparent and white-on-transparent
    // images remain clearly visible.
    let painter = ui.painter_at(outer);
    let c_dark = Color32::from_rgb(0x26, 0x26, 0x26);
    let c_light = Color32::from_rgb(0x32, 0x32, 0x32);
    painter.rect_filled(outer, 4.0, c_dark);
    let tile = 8.0f32;
    let cols = (outer.width() / tile).ceil() as i32;
    let rows = (outer.height() / tile).ceil() as i32;
    for r in 0..rows {
        for c in 0..cols {
            if (r + c) % 2 == 1 {
                let min = outer.min + vec2(c as f32 * tile, r as f32 * tile);
                let max = (min + vec2(tile, tile)).min(outer.max);
                if max.x > min.x && max.y > min.y {
                    painter.rect_filled(egui::Rect::from_min_max(min, max), 0.0, c_light);
                }
            }
        }
    }
    painter.rect_stroke(
        outer,
        4.0,
        egui::Stroke::new(1.0, theme::CARD_BORDER),
        egui::StrokeKind::Inside,
    );
    painter.image(
        texture.id(),
        inner,
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        Color32::WHITE,
    );
}

fn pretty(content_type: &str, text: &str) -> (String, Syntax) {
    let path = match content_type_to_path(content_type) {
        "body" if svg::looks_like_svg_str(text) => "body.svg",
        other => other,
    };
    let format = beautify::detect(path, text);
    match format {
        Some(f) => {
            let out = beautify::beautify(f, text).unwrap_or_else(|| text.to_owned());
            (out, syntax_of(Some(f)))
        }
        None => (text.to_owned(), Syntax::Plain),
    }
}

fn content_type_to_path(content_type: &str) -> &'static str {
    let ct = content_type.to_ascii_lowercase();
    match ct.as_str() {
        "application/json" | "text/json" => "body.json",
        "application/xml" | "text/xml" | "image/svg+xml" | "image/svg" => "body.xml",
        "text/html" => "body.html",
        "text/css" => "body.css",
        "application/javascript" | "text/javascript" => "body.js",
        _ if ct.ends_with("+json") => "body.json",
        _ if ct.ends_with("+xml") => "body.xml",
        _ => "body",
    }
}

fn syntax_of(format: Option<beautify::Format>) -> Syntax {
    match format {
        Some(beautify::Format::Json) => Syntax::Json,
        Some(beautify::Format::Xml | beautify::Format::Html) => Syntax::Xml,
        Some(beautify::Format::Css) => Syntax::Css,
        Some(beautify::Format::JavaScript) => Syntax::JavaScript,
        None => Syntax::Plain,
    }
}

fn hex_dump(ui: &mut egui::Ui, data: &[u8], font: &egui::FontId) {
    let shown = &data[..data.len().min(MAX_SHOWN)];
    for (row, chunk) in shown.chunks(16).enumerate() {
        let mut hex = String::new();
        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        let mut job = LayoutJob::default();
        highlight::append(&mut job, &format!("{:08x}  ", row * 16), theme::TEXT_DIM, font);
        highlight::append(&mut job, &format!("{hex:<50}"), TEXT, font);
        highlight::append(&mut job, &ascii, egui::Color32::from_rgb(0xce, 0x91, 0x78), font);
        ui.add(egui::Label::new(job).extend());
    }
    if data.len() > MAX_SHOWN {
        ui.label(RichText::new("… truncated").color(theme::TEXT_DIM));
    }
}

/// Info-panel sections for a flow.
pub fn flow_sections(flow: &Flow) -> Vec<InfoSection> {
    let mut general = InfoSection::new("General");
    general.row("Method", flow.method.clone());
    general.row("URL", flow.url());
    general.row("Host", flow.host.clone());
    general.row("Scheme", flow.scheme.as_str().to_uppercase());
    match (flow.status, &flow.error) {
        (Some(status), _) => {
            general.row("Status", format!("{status} {}", flow.reason));
        }
        (None, Some(error)) => {
            general.row("Error", error.clone());
        }
        (None, None) => {
            general.row("Status", "pending".to_owned());
        }
    }
    if let Some(duration) = flow.duration {
        general.row("Duration", format!("{} ms", duration.as_millis()));
    }

    let mut sizes = InfoSection::new("Sizes");
    sizes.row("Request body", format_size(flow.req_body.len() as u64));
    sizes.row("Response body", format_size(flow.resp_body.len() as u64));

    let mut content = InfoSection::new("Content");
    if let Some(ct) = content_type(&flow.req_headers) {
        content.row("Request type", ct);
    }
    if let Some(ct) = content_type(&flow.resp_headers) {
        content.row("Response type", ct);
    }
    if let Some(enc) = flow.resp_headers.get("content-encoding") {
        content.row("Response encoding", enc.to_owned());
    }
    content.row(
        "Request headers",
        group_digits(flow.req_headers.0.len()),
    );
    content.row(
        "Response headers",
        group_digits(flow.resp_headers.0.len()),
    );

    let mut sections = vec![general, sizes];
    if !content.rows.is_empty() {
        sections.push(content);
    }
    sections
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::capture::{Capture, RequestInfo};
    use crate::net::http::{Request, Response};
    use std::io::{BufReader, Cursor};

    fn sample_flow() -> std::sync::Arc<Flow> {
        let capture = Capture::new();
        let request = Request::read(&mut BufReader::new(
            &b"POST /api HTTP/1.1\r\nHost: api.x\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"[..],
        ))
        .unwrap()
        .unwrap();
        let info = RequestInfo::from_request(Scheme::Https, "api.x:443", &request, 80);
        let pending = capture.start(&info);
        let response = Response::read(
            &mut BufReader::new(&b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{\"ok\":1}\n"[..]),
            "POST",
        )
        .unwrap();
        capture.finish_response(&pending, &response, 50);
        capture.snapshot()[0].clone()
    }

    fn flow_with_response(content_type: &str, body: &[u8]) -> std::sync::Arc<Flow> {
        let capture = Capture::new();
        let request = Request::read(&mut BufReader::new(
            &b"GET /asset HTTP/1.1\r\nHost: cdn.x\r\n\r\n"[..],
        ))
        .unwrap()
        .unwrap();
        let info = RequestInfo::from_request(Scheme::Https, "cdn.x:443", &request, 40);
        let pending = capture.start(&info);
        let mut raw_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw_resp.extend_from_slice(body);
        let response = Response::read(&mut BufReader::new(&raw_resp[..]), "GET").unwrap();
        capture.finish_response(&pending, &response, 64);
        capture.snapshot()[0].clone()
    }

    #[test]
    fn builds_overview_sections() {
        let flow = sample_flow();
        let sections = flow_sections(&flow);
        let general = &sections[0];
        assert_eq!(general.title, "General");
        assert!(general.rows.iter().any(|(k, v)| k == "Status" && v == "200 OK"));
        assert!(general.rows.iter().any(|(k, v)| k == "URL" && v == "https://api.x/api"));
        assert!(sections.iter().any(|s| s.title == "Content"));
    }

    #[test]
    fn pretty_prints_json_bodies() {
        let (out, syntax) = pretty("application/json", "{\"a\":1,\"b\":2}");
        assert!(out.contains("\n  \"a\": 1"));
        assert_eq!(syntax, Syntax::Json);
        // Unknown types are left alone.
        let (out, syntax) = pretty("text/plain", "hello");
        assert_eq!((out.as_str(), syntax), ("hello", Syntax::Plain));
    }

    #[test]
    fn pretty_prints_svg_xml_bodies() {
        let (out, syntax) = pretty(
            "image/svg+xml",
            "<svg viewBox=\"0 0 10 10\"><rect width=\"10\" height=\"10\"/></svg>",
        );
        assert!(out.contains("<svg"));
        assert!(out.contains("\n    <rect"));
        assert_eq!(syntax, Syntax::Xml);
    }

    #[test]
    fn formats_request_and_response_for_clipboard() {
        let flow = sample_flow();
        let req_text = format_request(&flow, BodyView::Pretty);
        assert!(req_text.starts_with("POST /api HTTP/1.1\n"));
        assert!(req_text.contains("Host: api.x\n"));
        assert!(req_text.contains("\"a\": 1"));

        let resp_text = format_response(&flow, BodyView::Pretty);
        assert!(resp_text.starts_with("HTTP/1.1 200 OK\n"));
        assert!(resp_text.contains("Content-Type: application/json\n"));
        assert!(resp_text.contains("\"ok\": 1"));

        let full = format_flow(&flow, BodyView::Raw);
        assert!(full.contains("POST /api HTTP/1.1"));
        assert!(full.contains("HTTP/1.1 200 OK"));
    }

    #[test]
    fn renders_raster_image_instead_of_hex_prompt() {
        let mut png_bytes = Vec::new();
        let img = image::RgbaImage::from_pixel(12, 8, image::Rgba([40, 180, 240, 255]));
        img.write_to(&mut Cursor::new(&mut png_bytes), image::ImageFormat::Png)
            .unwrap();
        let flow = flow_with_response("image/png", &png_bytes);
        let mut state = FlowDetailState {
            tab: FlowTab::Response,
            body: BodyView::Pretty,
        };
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                show(ui, &flow, &mut state, true);
            });
        });
        let cached = ctx.data_mut(|d| {
            d.get_temp::<CachedFlowImage>(egui::Id::new(("flow_raster_tex", flow.id, "resp")))
        });
        assert!(cached.is_some(), "raster image texture should be loaded");
        assert_eq!(cached.unwrap().pixel_size, (12, 8));
    }

    #[test]
    fn renders_svg_image_and_switches_to_source() {
        let svg_body = br##"<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32"><circle cx="16" cy="16" r="12" fill="#4ec9b0"/></svg>"##;
        let flow = flow_with_response("image/svg+xml", svg_body);
        let mut state = FlowDetailState {
            tab: FlowTab::Response,
            body: BodyView::Pretty,
        };
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                show(ui, &flow, &mut state, true);
            });
        });
        let cached = ctx.data_mut(|d| {
            d.get_temp::<CachedFlowImage>(egui::Id::new(("flow_svg_tex", flow.id, "resp")))
        });
        assert!(cached.is_some(), "SVG image texture should be rendered in Image mode");
        assert_eq!(cached.unwrap().pixel_size, (32, 32));

        // Switching to Source mode renders the formatted XML source.
        state.body = BodyView::Source;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                show(ui, &flow, &mut state, true);
            });
        });
        let copied = format_response(&flow, state.body);
        assert!(copied.contains("<circle cx=\"16\""));
    }

    #[test]
    fn colors_by_status_and_method() {
        assert_eq!(status_color(204), egui::Color32::from_rgb(0x4e, 0xc9, 0xb0));
        assert_eq!(status_color(404), egui::Color32::from_rgb(0xcc, 0xa7, 0x00));
        assert_ne!(method_color("DELETE"), method_color("GET"));
    }
}
