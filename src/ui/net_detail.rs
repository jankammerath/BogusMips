//! Editor content for a captured network flow: an overview, the request and
//! the response, with header tables and decoded bodies.

use eframe::egui::{self, RichText, ScrollArea, Sense, TextStyle, text::LayoutJob, vec2};

use super::content_view::EditorResponse;
use super::highlight::{self, TEXT};
use super::icons::{self, Icon};
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
    #[default]
    Pretty,
    Raw,
    Hex,
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
            body_toolbar(ui, state, &flow.req_headers, flow.id, "req");
            message(ui, flow.id, "req", &flow.req_headers, &flow.req_body, state.body);
        }
        FlowTab::Response => {
            if flow.status.is_none() {
                ui.centered_and_justified(|ui| {
                    let text = flow.error.as_deref().unwrap_or("Waiting for the response…");
                    ui.label(RichText::new(text).color(theme::TEXT_DIM));
                });
            } else {
                body_toolbar(ui, state, &flow.resp_headers, flow.id, "resp");
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

fn body_toolbar(ui: &mut egui::Ui, state: &mut FlowDetailState, headers: &Headers, id: u64, _tag: &str) {
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.label(RichText::new("Body").size(12.0).color(theme::TEXT_DIM));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(8.0);
            for (value, label) in [
                (BodyView::Hex, "Hex"),
                (BodyView::Raw, "Raw"),
                (BodyView::Pretty, "Pretty"),
            ] {
                let selected = state.body == value;
                if ui
                    .add(egui::Button::new(
                        RichText::new(label)
                            .size(12.0)
                            .color(if selected { theme::TEXT_BRIGHT } else { theme::TEXT_DIM }),
                    ).fill(if selected { theme::PILL } else { egui::Color32::TRANSPARENT }))
                    .clicked()
                {
                    state.body = value;
                }
            }
            let _ = (headers, id);
        });
    });
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
                    body_contents(ui, headers, body, view);
                });
        });
}

/// Largest body rendered inline; more is truncated with a note.
const MAX_SHOWN: usize = 512 * 1024;

fn body_contents(ui: &mut egui::Ui, headers: &Headers, body: &[u8], view: BodyView) {
    let mono = TextStyle::Monospace.resolve(ui.style());
    if view == BodyView::Hex {
        hex_dump(ui, body, &mono);
        return;
    }
    let (decoded, _enc) = crate::net::http::decode_for_display(headers, body);
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
    let (display, syntax) = if view == BodyView::Pretty {
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

fn pretty(content_type: &str, text: &str) -> (String, Syntax) {
    let format = beautify::detect(content_type_to_path(content_type), text);
    match format {
        Some(f) => {
            let out = beautify::beautify(f, text).unwrap_or_else(|| text.to_owned());
            (out, syntax_of(Some(f)))
        }
        None => (text.to_owned(), Syntax::Plain),
    }
}

fn content_type_to_path(content_type: &str) -> &'static str {
    match content_type {
        "application/json" | "text/json" => "body.json",
        "application/xml" | "text/xml" => "body.xml",
        "text/html" => "body.html",
        "text/css" => "body.css",
        "application/javascript" | "text/javascript" => "body.js",
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
    use std::io::BufReader;

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
    fn colors_by_status_and_method() {
        assert_eq!(status_color(204), egui::Color32::from_rgb(0x4e, 0xc9, 0xb0));
        assert_eq!(status_color(404), egui::Color32::from_rgb(0xcc, 0xa7, 0x00));
        assert_ne!(method_color("DELETE"), method_color("GET"));
    }
}
