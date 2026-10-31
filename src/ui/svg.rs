//! Lightweight, self-contained SVG parser and anti-aliased rasterizer for
//! previewing `image/svg+xml` network responses and resources.

use std::collections::HashMap;
use eframe::egui::{Color32, ColorImage};

#[derive(Clone, Debug)]
pub struct RenderedSvg {
    pub image: ColorImage,
    /// Intrinsic display dimensions in logical points `(width, height)`.
    pub display_size: (f32, f32),
}

/// Returns `true` if `content_type` or `data` indicates an SVG document.
pub fn is_svg(content_type: Option<&str>, data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    if let Some(ct) = content_type {
        let mime = ct.split(';').next().unwrap_or(ct).trim();
        if mime.eq_ignore_ascii_case("image/svg+xml") || mime.eq_ignore_ascii_case("image/svg") {
            return looks_like_svg_str(text) || text.contains("<svg");
        }
    }
    looks_like_svg_str(text)
}

pub fn looks_like_svg_str(text: &str) -> bool {
    let mut s = text.trim_start_matches('\u{feff}').trim_start();
    loop {
        if s.starts_with("<?") {
            if let Some(end) = s.find("?>") {
                s = s[end + 2..].trim_start();
                continue;
            }
            return false;
        }
        if s.starts_with("<!--") {
            if let Some(end) = s.find("-->") {
                s = s[end + 3..].trim_start();
                continue;
            }
            return false;
        }
        if s.len() >= 9 && s[..9].eq_ignore_ascii_case("<!doctype") {
            if let Some(end) = s.find('>') {
                s = s[end + 1..].trim_start();
                continue;
            }
            return false;
        }
        break;
    }
    if s.len() < 4 {
        return false;
    }
    let prefix = &s[..4];
    prefix.eq_ignore_ascii_case("<svg")
        && s.as_bytes()
            .get(4)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/' || *b == b':')
}

#[derive(Clone, Copy, Debug)]
struct Transform([f32; 6]); // [a, b, c, d, e, f]

impl Default for Transform {
    fn default() -> Self {
        Self([1.0, 0.0, 0.0, 1.0, 0.0, 0.0])
    }
}

impl Transform {
    fn multiply(self, other: Self) -> Self {
        let [a1, b1, c1, d1, e1, f1] = self.0;
        let [a2, b2, c2, d2, e2, f2] = other.0;
        Self([
            a1 * a2 + c1 * b2,
            b1 * a2 + d1 * b2,
            a1 * c2 + c1 * d2,
            b1 * c2 + d1 * d2,
            a1 * e2 + c1 * f2 + e1,
            b1 * e2 + d1 * f2 + f1,
        ])
    }

    fn apply(self, x: f32, y: f32) -> (f32, f32) {
        let [a, b, c, d, e, f] = self.0;
        (a * x + c * y + e, b * x + d * y + f)
    }

    fn scale_factor(self) -> f32 {
        let [a, b, c, d, _, _] = self.0;
        let sx = (a * a + b * b).sqrt();
        let sy = (c * c + d * d).sqrt();
        (sx + sy) * 0.5
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FillRule {
    NonZero,
    EvenOdd,
}

#[derive(Clone, Copy, Debug)]
enum Paint {
    None,
    Solid([u8; 4]),
    CurrentColor,
}

#[derive(Clone, Debug)]
struct Style {
    fill: Paint,
    stroke: Paint,
    stroke_width: f32,
    opacity: f32,
    fill_opacity: f32,
    stroke_opacity: f32,
    fill_rule: FillRule,
    color: [u8; 4],
    transform: Transform,
    hidden: bool,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            fill: Paint::Solid([0, 0, 0, 255]),
            stroke: Paint::None,
            stroke_width: 1.0,
            opacity: 1.0,
            fill_opacity: 1.0,
            stroke_opacity: 1.0,
            fill_rule: FillRule::NonZero,
            color: [212, 212, 212, 255],
            transform: Transform::default(),
            hidden: false,
        }
    }
}

#[derive(Clone, Debug)]
struct XmlNode {
    tag: String,
    attrs: Vec<(String, String)>,
    text: String,
    children: Vec<XmlNode>,
}

impl XmlNode {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| {
                k.eq_ignore_ascii_case(name)
                    || k.rsplit_once(':')
                        .is_some_and(|(_, local)| local.eq_ignore_ascii_case(name))
            })
            .map(|(_, v)| v.as_str())
    }
}

/// Renders an SVG document into an anti-aliased [`RenderedSvg`].
pub fn render_svg(svg_text: &str, max_side: u32) -> Option<RenderedSvg> {
    let root = parse_xml(svg_text)?;
    let svg = find_svg_node(&root)?;

    let mut defs_gradients: HashMap<String, [u8; 4]> = HashMap::new();
    let mut defs_nodes: HashMap<String, XmlNode> = HashMap::new();
    let mut css_rules: HashMap<String, Vec<(String, String)>> = HashMap::new();
    collect_defs(svg, &mut defs_gradients, &mut defs_nodes, &mut css_rules);

    let view_box = svg.attr("viewBox").and_then(parse_view_box);
    let attr_w = svg.attr("width").and_then(parse_length);
    let attr_h = svg.attr("height").and_then(parse_length);

    let mut draw_commands = Vec::new();
    let root_style = apply_node_style(
        &Style::default(),
        svg,
        &defs_gradients,
        &css_rules,
        true,
    );
    collect_shapes(
        svg,
        &root_style,
        &defs_gradients,
        &defs_nodes,
        &css_rules,
        0,
        &mut draw_commands,
    );

    let (vb_x, vb_y, vb_w, vb_h) = match view_box {
        Some((x, y, w, h)) if w > 0.0 && h > 0.0 => (x, y, w, h),
        _ => match (attr_w, attr_h) {
            (Some(w), Some(h)) if w > 0.0 && h > 0.0 => (0.0, 0.0, w, h),
            _ => compute_bounds(&draw_commands).unwrap_or((0.0, 0.0, 100.0, 100.0)),
        },
    };

    let (mut disp_w, mut disp_h) = match (attr_w, attr_h) {
        (Some(w), Some(h)) if w > 0.0 && h > 0.0 => (w, h),
        (Some(w), None) if w > 0.0 => (w, w * (vb_h / vb_w.max(1e-4))),
        (None, Some(h)) if h > 0.0 => (h * (vb_w / vb_h.max(1e-4)), h),
        _ => {
            // Scale small viewBox icons (e.g. 24x24) up to a comfortable preview size.
            let scale = if vb_w.max(vb_h) < 64.0 {
                (96.0 / vb_w.max(vb_h).max(1.0)).clamp(1.0, 8.0)
            } else {
                1.0
            };
            (vb_w * scale, vb_h * scale)
        }
    };

    let max_f = max_side.max(64) as f32;
    if disp_w > max_f || disp_h > max_f {
        let ratio = (max_f / disp_w).min(max_f / disp_h);
        disp_w *= ratio;
        disp_h *= ratio;
    }

    // Rasterize at up to 2x resolution for crisp rendering on Retina/HiDPI displays.
    let raster_scale = ((max_f / disp_w.max(disp_h)).min(2.0)).max(1.0);
    let out_w = (disp_w * raster_scale).round().clamp(1.0, max_f) as u32;
    let out_h = (disp_h * raster_scale).round().clamp(1.0, max_f) as u32;

    let sx = out_w as f32 / vb_w.max(1e-4);
    let sy = out_h as f32 / vb_h.max(1e-4);
    let view_transform = Transform([sx, 0.0, 0.0, sy, -vb_x * sx, -vb_y * sy]);

    let mut pixels = vec![[0u8; 4]; (out_w * out_h) as usize];
    for cmd in &draw_commands {
        let xf = view_transform.multiply(cmd.style.transform);
        let subpaths: Vec<Vec<(f32, f32)>> = cmd
            .subpaths
            .iter()
            .map(|sp| sp.points.iter().map(|&(x, y)| xf.apply(x, y)).collect())
            .collect();

        if let Some(color) = resolve_paint(cmd.style.fill, cmd.style.color, cmd.style.opacity * cmd.style.fill_opacity) {
            rasterize_fill(&mut pixels, out_w, out_h, &subpaths, cmd.style.fill_rule, color);
        }
        if let Some(color) = resolve_paint(cmd.style.stroke, cmd.style.color, cmd.style.opacity * cmd.style.stroke_opacity) {
            let width = (cmd.style.stroke_width * xf.scale_factor()).max(0.75);
            for (sp, orig) in subpaths.iter().zip(cmd.subpaths.iter()) {
                rasterize_stroke(&mut pixels, out_w, out_h, sp, orig.closed, width, color);
            }
        }
    }

    let color_pixels: Vec<Color32> = pixels
        .into_iter()
        .map(|[r, g, b, a]| Color32::from_rgba_unmultiplied(r, g, b, a))
        .collect();

    Some(RenderedSvg {
        image: ColorImage {
            size: [out_w as usize, out_h as usize],
            source_size: eframe::egui::vec2(disp_w.round().max(1.0), disp_h.round().max(1.0)),
            pixels: color_pixels,
        },
        display_size: (disp_w.round().max(1.0), disp_h.round().max(1.0)),
    })
}

fn resolve_paint(paint: Paint, current_color: [u8; 4], alpha_scale: f32) -> Option<[u8; 4]> {
    let mut rgba = match paint {
        Paint::None => return None,
        Paint::Solid(c) => c,
        Paint::CurrentColor => current_color,
    };
    let a = (f32::from(rgba[3]) * alpha_scale.clamp(0.0, 1.0)).round() as u8;
    if a == 0 {
        return None;
    }
    rgba[3] = a;
    Some(rgba)
}

#[derive(Clone, Debug)]
struct Subpath {
    points: Vec<(f32, f32)>,
    closed: bool,
}

#[derive(Clone, Debug)]
struct DrawCmd {
    subpaths: Vec<Subpath>,
    style: Style,
}

fn find_svg_node(node: &XmlNode) -> Option<&XmlNode> {
    if node.tag.eq_ignore_ascii_case("svg")
        || node
            .tag
            .rsplit_once(':')
            .is_some_and(|(_, local)| local.eq_ignore_ascii_case("svg"))
    {
        return Some(node);
    }
    for child in &node.children {
        if let Some(found) = find_svg_node(child) {
            return Some(found);
        }
    }
    None
}

fn collect_defs(
    node: &XmlNode,
    gradients: &mut HashMap<String, [u8; 4]>,
    defs_nodes: &mut HashMap<String, XmlNode>,
    css_rules: &mut HashMap<String, Vec<(String, String)>>,
) {
    let tag = local_tag(&node.tag);
    if tag.eq_ignore_ascii_case("style") {
        parse_css_stylesheet(&node.text, css_rules);
    }
    if tag.eq_ignore_ascii_case("lineargradient") || tag.eq_ignore_ascii_case("radialgradient") {
        if let Some(id) = node.attr("id") {
            let mut stop_colors = Vec::new();
            for child in &node.children {
                if local_tag(&child.tag).eq_ignore_ascii_case("stop") {
                    let mut stop_color = child.attr("stop-color").and_then(parse_color);
                    let mut stop_opacity = child
                        .attr("stop-opacity")
                        .and_then(parse_number)
                        .unwrap_or(1.0);
                    if let Some(style) = child.attr("style") {
                        for (k, v) in parse_inline_style(style) {
                            if k.eq_ignore_ascii_case("stop-color") {
                                stop_color = parse_color(&v);
                            } else if k.eq_ignore_ascii_case("stop-opacity") {
                                if let Some(op) = parse_number(&v) {
                                    stop_opacity = op;
                                }
                            }
                        }
                    }
                    if let Some(mut c) = stop_color {
                        c[3] = (f32::from(c[3]) * stop_opacity.clamp(0.0, 1.0)).round() as u8;
                        if c[3] > 0 {
                            stop_colors.push(c);
                        }
                    }
                }
            }
            if !stop_colors.is_empty() {
                let n = stop_colors.len() as u32;
                let r = stop_colors.iter().map(|c| u32::from(c[0])).sum::<u32>() / n;
                let g = stop_colors.iter().map(|c| u32::from(c[1])).sum::<u32>() / n;
                let b = stop_colors.iter().map(|c| u32::from(c[2])).sum::<u32>() / n;
                let a = stop_colors.iter().map(|c| u32::from(c[3])).sum::<u32>() / n;
                gradients.insert(id.to_owned(), [r as u8, g as u8, b as u8, a as u8]);
            }
        }
    }
    if let Some(id) = node.attr("id") {
        defs_nodes.insert(id.to_owned(), node.clone());
    }
    for child in &node.children {
        collect_defs(child, gradients, defs_nodes, css_rules);
    }
}

fn parse_css_stylesheet(css: &str, rules: &mut HashMap<String, Vec<(String, String)>>) {
    for block in css.split('}') {
        let Some((selectors, body)) = block.split_once('{') else {
            continue;
        };
        let props = parse_inline_style(body);
        if props.is_empty() {
            continue;
        }
        for sel in selectors.split(',') {
            let sel = sel.trim();
            if !sel.is_empty() {
                rules.entry(sel.to_owned()).or_default().extend(props.clone());
            }
        }
    }
}

fn local_tag(tag: &str) -> &str {
    tag.rsplit_once(':').map_or(tag, |(_, local)| local)
}

fn collect_shapes(
    node: &XmlNode,
    parent_style: &Style,
    gradients: &HashMap<String, [u8; 4]>,
    defs_nodes: &HashMap<String, XmlNode>,
    css_rules: &HashMap<String, Vec<(String, String)>>,
    depth: usize,
    out: &mut Vec<DrawCmd>,
) {
    if depth > 32 {
        return;
    }
    let tag = local_tag(&node.tag).to_ascii_lowercase();
    if matches!(
        tag.as_str(),
        "defs" | "clippath" | "mask" | "marker" | "pattern" | "lineargradient"
            | "radialgradient" | "stop" | "style" | "title" | "desc" | "metadata"
            | "script" | "filter" | "symbol"
    ) {
        return;
    }

    let style = apply_node_style(parent_style, node, gradients, css_rules, false);
    if style.hidden {
        return;
    }

    match tag.as_str() {
        "g" | "svg" | "a" | "switch" => {
            for child in &node.children {
                collect_shapes(child, &style, gradients, defs_nodes, css_rules, depth + 1, out);
            }
        }
        "use" => {
            let href = node
                .attr("href")
                .or_else(|| node.attr("xlink:href"))
                .unwrap_or("");
            if let Some(id) = href.strip_prefix('#') {
                if let Some(target) = defs_nodes.get(id) {
                    let dx = node.attr("x").and_then(parse_length).unwrap_or(0.0);
                    let dy = node.attr("y").and_then(parse_length).unwrap_or(0.0);
                    let mut use_style = style.clone();
                    if dx != 0.0 || dy != 0.0 {
                        use_style.transform = use_style
                            .transform
                            .multiply(Transform([1.0, 0.0, 0.0, 1.0, dx, dy]));
                    }
                    if local_tag(&target.tag).eq_ignore_ascii_case("symbol") {
                        for child in &target.children {
                            collect_shapes(
                                child,
                                &use_style,
                                gradients,
                                defs_nodes,
                                css_rules,
                                depth + 1,
                                out,
                            );
                        }
                    } else {
                        collect_shapes(
                            target,
                            &use_style,
                            gradients,
                            defs_nodes,
                            css_rules,
                            depth + 1,
                            out,
                        );
                    }
                }
            }
        }
        "path" => {
            if let Some(d) = node.attr("d") {
                let subpaths = parse_path(d);
                if !subpaths.is_empty() {
                    out.push(DrawCmd { subpaths, style });
                }
            }
        }
        "rect" => {
            let x = node.attr("x").and_then(parse_length).unwrap_or(0.0);
            let y = node.attr("y").and_then(parse_length).unwrap_or(0.0);
            let w = node.attr("width").and_then(parse_length).unwrap_or(0.0);
            let h = node.attr("height").and_then(parse_length).unwrap_or(0.0);
            if w > 0.0 && h > 0.0 {
                let rx = node.attr("rx").and_then(parse_length);
                let ry = node.attr("ry").and_then(parse_length);
                let (rx, ry) = match (rx, ry) {
                    (Some(rx), Some(ry)) => (rx, ry),
                    (Some(r), None) | (None, Some(r)) => (r, r),
                    (None, None) => (0.0, 0.0),
                };
                let subpaths = vec![rect_subpath(x, y, w, h, rx.min(w * 0.5), ry.min(h * 0.5))];
                out.push(DrawCmd { subpaths, style });
            }
        }
        "circle" => {
            let cx = node.attr("cx").and_then(parse_length).unwrap_or(0.0);
            let cy = node.attr("cy").and_then(parse_length).unwrap_or(0.0);
            let r = node.attr("r").and_then(parse_length).unwrap_or(0.0);
            if r > 0.0 {
                out.push(DrawCmd {
                    subpaths: vec![ellipse_subpath(cx, cy, r, r)],
                    style,
                });
            }
        }
        "ellipse" => {
            let cx = node.attr("cx").and_then(parse_length).unwrap_or(0.0);
            let cy = node.attr("cy").and_then(parse_length).unwrap_or(0.0);
            let rx = node.attr("rx").and_then(parse_length).unwrap_or(0.0);
            let ry = node.attr("ry").and_then(parse_length).unwrap_or(0.0);
            if rx > 0.0 && ry > 0.0 {
                out.push(DrawCmd {
                    subpaths: vec![ellipse_subpath(cx, cy, rx, ry)],
                    style,
                });
            }
        }
        "line" => {
            let x1 = node.attr("x1").and_then(parse_length).unwrap_or(0.0);
            let y1 = node.attr("y1").and_then(parse_length).unwrap_or(0.0);
            let x2 = node.attr("x2").and_then(parse_length).unwrap_or(0.0);
            let y2 = node.attr("y2").and_then(parse_length).unwrap_or(0.0);
            let mut line_style = style;
            line_style.fill = Paint::None;
            out.push(DrawCmd {
                subpaths: vec![Subpath {
                    points: vec![(x1, y1), (x2, y2)],
                    closed: false,
                }],
                style: line_style,
            });
        }
        "polyline" | "polygon" => {
            if let Some(pts_str) = node.attr("points") {
                let pts = parse_points(pts_str);
                if pts.len() >= 2 {
                    let closed = tag == "polygon";
                    out.push(DrawCmd {
                        subpaths: vec![Subpath { points: pts, closed }],
                        style,
                    });
                }
            }
        }
        _ => {
            for child in &node.children {
                collect_shapes(child, &style, gradients, defs_nodes, css_rules, depth + 1, out);
            }
        }
    }
}

fn apply_node_style(
    parent: &Style,
    node: &XmlNode,
    gradients: &HashMap<String, [u8; 4]>,
    css_rules: &HashMap<String, Vec<(String, String)>>,
    is_root: bool,
) -> Style {
    let mut s = parent.clone();
    if !is_root {
        // Opacity on a node is non-accumulating unless multiplied into parent.
        s.opacity = parent.opacity;
    }

    let mut pairs: Vec<(String, String)> = Vec::new();
    let tag = local_tag(&node.tag);
    if let Some(rule) = css_rules.get(tag) {
        pairs.extend(rule.clone());
    }
    if let Some(classes) = node.attr("class") {
        for cls in classes.split_whitespace() {
            if let Some(rule) = css_rules.get(&format!(".{cls}")) {
                pairs.extend(rule.clone());
            }
        }
    }
    if let Some(id) = node.attr("id") {
        if let Some(rule) = css_rules.get(&format!("#{id}")) {
            pairs.extend(rule.clone());
        }
    }
    for (k, v) in &node.attrs {
        if !k.eq_ignore_ascii_case("style") {
            pairs.push((k.clone(), v.clone()));
        }
    }
    if let Some(inline) = node.attr("style") {
        pairs.extend(parse_inline_style(inline));
    }

    for (k, v) in pairs {
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("fill") {
            if let Some(p) = parse_paint(v, gradients) {
                s.fill = p;
            }
        } else if k.eq_ignore_ascii_case("stroke") {
            if let Some(p) = parse_paint(v, gradients) {
                s.stroke = p;
            }
        } else if k.eq_ignore_ascii_case("stroke-width") {
            if let Some(w) = parse_length(v) {
                s.stroke_width = w.max(0.0);
            }
        } else if k.eq_ignore_ascii_case("opacity") {
            if let Some(op) = parse_number(v) {
                s.opacity = parent.opacity * op.clamp(0.0, 1.0);
            }
        } else if k.eq_ignore_ascii_case("fill-opacity") {
            if let Some(op) = parse_number(v) {
                s.fill_opacity = op.clamp(0.0, 1.0);
            }
        } else if k.eq_ignore_ascii_case("stroke-opacity") {
            if let Some(op) = parse_number(v) {
                s.stroke_opacity = op.clamp(0.0, 1.0);
            }
        } else if k.eq_ignore_ascii_case("fill-rule") {
            if v.eq_ignore_ascii_case("evenodd") {
                s.fill_rule = FillRule::EvenOdd;
            } else if v.eq_ignore_ascii_case("nonzero") {
                s.fill_rule = FillRule::NonZero;
            }
        } else if k.eq_ignore_ascii_case("color") {
            if let Some(c) = parse_color(v) {
                s.color = c;
            }
        } else if k.eq_ignore_ascii_case("display") && v.eq_ignore_ascii_case("none") {
            s.hidden = true;
        } else if k.eq_ignore_ascii_case("visibility")
            && (v.eq_ignore_ascii_case("hidden") || v.eq_ignore_ascii_case("collapse"))
        {
            s.hidden = true;
        } else if k.eq_ignore_ascii_case("transform") {
            s.transform = s.transform.multiply(parse_transform(v));
        }
    }
    s
}

fn parse_inline_style(style: &str) -> Vec<(String, String)> {
    style
        .split(';')
        .filter_map(|decl| {
            let (k, v) = decl.split_once(':')?;
            let k = k.trim();
            let v = v.trim().trim_end_matches("!important").trim();
            (!k.is_empty() && !v.is_empty()).then(|| (k.to_owned(), v.to_owned()))
        })
        .collect()
}

fn parse_paint(val: &str, gradients: &HashMap<String, [u8; 4]>) -> Option<Paint> {
    let v = val.trim();
    if v.eq_ignore_ascii_case("none") || v.eq_ignore_ascii_case("transparent") {
        return Some(Paint::None);
    }
    if v.eq_ignore_ascii_case("currentcolor") {
        return Some(Paint::CurrentColor);
    }
    if let Some(rest) = v.strip_prefix("url(") {
        if let Some(end) = rest.find(')') {
            let id = rest[..end]
                .trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .strip_prefix('#')
                .unwrap_or("");
            if let Some(&c) = gradients.get(id) {
                return Some(Paint::Solid(c));
            }
        }
    }
    parse_color(v).map(Paint::Solid)
}

fn parse_color(val: &str) -> Option<[u8; 4]> {
    let v = val.trim();
    if let Some(hex) = v.strip_prefix('#') {
        let bytes = hex.as_bytes();
        return match bytes.len() {
            3 => {
                let r = hex_nibble(bytes[0])?;
                let g = hex_nibble(bytes[1])?;
                let b = hex_nibble(bytes[2])?;
                Some([r * 17, g * 17, b * 17, 255])
            }
            4 => {
                let r = hex_nibble(bytes[0])?;
                let g = hex_nibble(bytes[1])?;
                let b = hex_nibble(bytes[2])?;
                let a = hex_nibble(bytes[3])?;
                Some([r * 17, g * 17, b * 17, a * 17])
            }
            6 => {
                let r = hex_byte(bytes[0], bytes[1])?;
                let g = hex_byte(bytes[2], bytes[3])?;
                let b = hex_byte(bytes[4], bytes[5])?;
                Some([r, g, b, 255])
            }
            8 => {
                let r = hex_byte(bytes[0], bytes[1])?;
                let g = hex_byte(bytes[2], bytes[3])?;
                let b = hex_byte(bytes[4], bytes[5])?;
                let a = hex_byte(bytes[6], bytes[7])?;
                Some([r, g, b, a])
            }
            _ => None,
        };
    }
    let lower = v.to_ascii_lowercase();
    if let Some(inner) = lower
        .strip_prefix("rgba(")
        .or_else(|| lower.strip_prefix("rgb("))
        .and_then(|s| s.strip_suffix(')'))
    {
        let parts: Vec<&str> = inner
            .split(|c: char| c == ',' || c.is_ascii_whitespace() || c == '/')
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() >= 3 {
            let r = parse_channel(parts[0])?;
            let g = parse_channel(parts[1])?;
            let b = parse_channel(parts[2])?;
            let a = if parts.len() >= 4 {
                if let Some(pct) = parts[3].strip_suffix('%') {
                    (pct.parse::<f32>().ok()?.clamp(0.0, 100.0) * 2.55).round() as u8
                } else {
                    let f = parts[3].parse::<f32>().ok()?;
                    if f <= 1.0 {
                        (f.clamp(0.0, 1.0) * 255.0).round() as u8
                    } else {
                        f.clamp(0.0, 255.0).round() as u8
                    }
                }
            } else {
                255
            };
            return Some([r, g, b, a]);
        }
    }
    match lower.as_str() {
        "black" => Some([0, 0, 0, 255]),
        "white" => Some([255, 255, 255, 255]),
        "red" => Some([255, 0, 0, 255]),
        "green" => Some([0, 128, 0, 255]),
        "lime" => Some([0, 255, 0, 255]),
        "blue" => Some([0, 0, 255, 255]),
        "yellow" => Some([255, 255, 0, 255]),
        "cyan" | "aqua" => Some([0, 255, 255, 255]),
        "magenta" | "fuchsia" => Some([255, 0, 255, 255]),
        "gray" | "grey" => Some([128, 128, 128, 255]),
        "lightgray" | "lightgrey" => Some([211, 211, 211, 255]),
        "darkgray" | "darkgrey" => Some([169, 169, 169, 255]),
        "silver" => Some([192, 192, 192, 255]),
        "maroon" => Some([128, 0, 0, 255]),
        "olive" => Some([128, 128, 0, 255]),
        "purple" => Some([128, 0, 128, 255]),
        "teal" => Some([0, 128, 128, 255]),
        "navy" => Some([0, 0, 128, 255]),
        "orange" => Some([255, 165, 0, 255]),
        "gold" => Some([255, 215, 0, 255]),
        "pink" => Some([255, 192, 203, 255]),
        "coral" => Some([255, 127, 80, 255]),
        "tomato" => Some([255, 99, 71, 255]),
        "dodgerblue" => Some([30, 144, 255, 255]),
        "steelblue" => Some([70, 130, 180, 255]),
        "cornflowerblue" => Some([100, 149, 237, 255]),
        "indigo" => Some([75, 0, 130, 255]),
        "violet" => Some([238, 130, 238, 255]),
        "transparent" | "none" => Some([0, 0, 0, 0]),
        _ => None,
    }
}

fn parse_channel(s: &str) -> Option<u8> {
    if let Some(pct) = s.strip_suffix('%') {
        Some((pct.parse::<f32>().ok()?.clamp(0.0, 100.0) * 2.55).round() as u8)
    } else {
        Some(s.parse::<f32>().ok()?.clamp(0.0, 255.0).round() as u8)
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_nibble(hi)? << 4) | hex_nibble(lo)?)
}

fn parse_number(s: &str) -> Option<f32> {
    s.trim().parse::<f32>().ok()
}

fn parse_length(s: &str) -> Option<f32> {
    let s = s.trim();
    if s.ends_with('%') {
        return None;
    }
    let trimmed = s
        .trim_end_matches("px")
        .trim_end_matches("pt")
        .trim_end_matches("em")
        .trim_end_matches("rem")
        .trim_end_matches("mm")
        .trim_end_matches("cm")
        .trim_end_matches("in")
        .trim();
    trimmed.parse::<f32>().ok()
}

fn parse_view_box(s: &str) -> Option<(f32, f32, f32, f32)> {
    let nums = lex_numbers(s);
    if nums.len() >= 4 {
        Some((nums[0], nums[1], nums[2], nums[3]))
    } else {
        None
    }
}

fn parse_transform(s: &str) -> Transform {
    let mut out = Transform::default();
    let mut rest = s.trim();
    while let Some(open) = rest.find('(') {
        let name = rest[..open].trim();
        let Some(close) = rest[open + 1..].find(')') else {
            break;
        };
        let args = lex_numbers(&rest[open + 1..open + 1 + close]);
        rest = rest[open + 1 + close + 1..].trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
        let xf = match name {
            "translate" => {
                let tx = args.first().copied().unwrap_or(0.0);
                let ty = args.get(1).copied().unwrap_or(0.0);
                Transform([1.0, 0.0, 0.0, 1.0, tx, ty])
            }
            "scale" => {
                let sx = args.first().copied().unwrap_or(1.0);
                let sy = args.get(1).copied().unwrap_or(sx);
                Transform([sx, 0.0, 0.0, sy, 0.0, 0.0])
            }
            "rotate" => {
                let deg = args.first().copied().unwrap_or(0.0);
                let rad = deg.to_radians();
                let (sin, cos) = rad.sin_cos();
                let rot = Transform([cos, sin, -sin, cos, 0.0, 0.0]);
                if args.len() >= 3 {
                    let (cx, cy) = (args[1], args[2]);
                    Transform([1.0, 0.0, 0.0, 1.0, cx, cy])
                        .multiply(rot)
                        .multiply(Transform([1.0, 0.0, 0.0, 1.0, -cx, -cy]))
                } else {
                    rot
                }
            }
            "skewX" => {
                let deg = args.first().copied().unwrap_or(0.0);
                Transform([1.0, 0.0, deg.to_radians().tan(), 1.0, 0.0, 0.0])
            }
            "skewY" => {
                let deg = args.first().copied().unwrap_or(0.0);
                Transform([1.0, deg.to_radians().tan(), 0.0, 1.0, 0.0, 0.0])
            }
            "matrix" if args.len() >= 6 => {
                Transform([args[0], args[1], args[2], args[3], args[4], args[5]])
            }
            _ => Transform::default(),
        };
        out = out.multiply(xf);
    }
    out
}

fn parse_points(s: &str) -> Vec<(f32, f32)> {
    let nums = lex_numbers(s);
    nums.chunks_exact(2).map(|c| (c[0], c[1])).collect()
}

fn lex_numbers(s: &str) -> Vec<f32> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        if bytes[i] == b'+' || bytes[i] == b'-' {
            i += 1;
        }
        let mut seen_dot = false;
        let mut seen_digit = false;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                seen_digit = true;
                i += 1;
            } else if bytes[i] == b'.' && !seen_dot {
                seen_dot = true;
                i += 1;
            } else {
                break;
            }
        }
        if !seen_digit {
            i = start + 1;
            continue;
        }
        if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
            i += 1;
            if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                i += 1;
            }
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        if let Ok(v) = s[start..i].parse::<f32>() {
            out.push(v);
        }
    }
    out
}

#[derive(Clone, Debug)]
enum PathToken {
    Cmd(char),
    Num(f32),
}

fn tokenize_path(d: &str) -> Vec<PathToken> {
    let mut tokens = Vec::new();
    let bytes = d.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() || b == b',' {
            i += 1;
            continue;
        }
        if b.is_ascii_alphabetic() {
            tokens.push(PathToken::Cmd(b as char));
            i += 1;
            continue;
        }
        let start = i;
        if b == b'+' || b == b'-' {
            i += 1;
        }
        let mut seen_dot = false;
        let mut seen_digit = false;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                seen_digit = true;
                i += 1;
            } else if bytes[i] == b'.' && !seen_dot {
                seen_dot = true;
                i += 1;
            } else {
                break;
            }
        }
        if !seen_digit {
            i = start + 1;
            continue;
        }
        if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
            i += 1;
            if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                i += 1;
            }
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        if let Ok(v) = d[start..i].parse::<f32>() {
            tokens.push(PathToken::Num(v));
        }
    }
    tokens
}

fn parse_path(d: &str) -> Vec<Subpath> {
    let tokens = tokenize_path(d);
    let mut out = Vec::new();
    let mut current: Vec<(f32, f32)> = Vec::new();
    let (mut cx, mut cy) = (0.0f32, 0.0f32);
    let (mut sx, mut sy) = (0.0f32, 0.0f32);
    let mut last_cubic_ctrl: Option<(f32, f32)> = None;
    let mut last_quad_ctrl: Option<(f32, f32)> = None;
    let mut cmd = 'M';
    let mut idx = 0;

    let next_num = |idx: &mut usize| -> Option<f32> {
        match tokens.get(*idx) {
            Some(PathToken::Num(n)) => {
                *idx += 1;
                Some(*n)
            }
            _ => None,
        }
    };

    while idx < tokens.len() {
        if let PathToken::Cmd(c) = tokens[idx] {
            cmd = c;
            idx += 1;
            if cmd == 'Z' || cmd == 'z' {
                if !current.is_empty() {
                    current.push((sx, sy));
                    out.push(Subpath {
                        points: std::mem::take(&mut current),
                        closed: true,
                    });
                }
                cx = sx;
                cy = sy;
                last_cubic_ctrl = None;
                last_quad_ctrl = None;
                continue;
            }
        }

        let rel = cmd.is_ascii_lowercase();
        match cmd.to_ascii_uppercase() {
            'M' => {
                let (Some(mut x), Some(mut y)) = (next_num(&mut idx), next_num(&mut idx)) else {
                    break;
                };
                if rel {
                    x += cx;
                    y += cy;
                }
                if !current.is_empty() {
                    out.push(Subpath {
                        points: std::mem::take(&mut current),
                        closed: false,
                    });
                }
                cx = x;
                cy = y;
                sx = x;
                sy = y;
                current.push((cx, cy));
                cmd = if rel { 'l' } else { 'L' };
                last_cubic_ctrl = None;
                last_quad_ctrl = None;
            }
            'L' => {
                let (Some(mut x), Some(mut y)) = (next_num(&mut idx), next_num(&mut idx)) else {
                    break;
                };
                if rel {
                    x += cx;
                    y += cy;
                }
                if current.is_empty() {
                    current.push((cx, cy));
                }
                cx = x;
                cy = y;
                current.push((cx, cy));
                last_cubic_ctrl = None;
                last_quad_ctrl = None;
            }
            'H' => {
                let Some(mut x) = next_num(&mut idx) else {
                    break;
                };
                if rel {
                    x += cx;
                }
                if current.is_empty() {
                    current.push((cx, cy));
                }
                cx = x;
                current.push((cx, cy));
                last_cubic_ctrl = None;
                last_quad_ctrl = None;
            }
            'V' => {
                let Some(mut y) = next_num(&mut idx) else {
                    break;
                };
                if rel {
                    y += cy;
                }
                if current.is_empty() {
                    current.push((cx, cy));
                }
                cy = y;
                current.push((cx, cy));
                last_cubic_ctrl = None;
                last_quad_ctrl = None;
            }
            'C' => {
                let (Some(mut x1), Some(mut y1), Some(mut x2), Some(mut y2), Some(mut x), Some(mut y)) = (
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                ) else {
                    break;
                };
                if rel {
                    x1 += cx;
                    y1 += cy;
                    x2 += cx;
                    y2 += cy;
                    x += cx;
                    y += cy;
                }
                if current.is_empty() {
                    current.push((cx, cy));
                }
                flatten_cubic(&mut current, (cx, cy), (x1, y1), (x2, y2), (x, y));
                last_cubic_ctrl = Some((x2, y2));
                last_quad_ctrl = None;
                cx = x;
                cy = y;
            }
            'S' => {
                let (Some(mut x2), Some(mut y2), Some(mut x), Some(mut y)) = (
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                ) else {
                    break;
                };
                if rel {
                    x2 += cx;
                    y2 += cy;
                    x += cx;
                    y += cy;
                }
                let (x1, y1) = match last_cubic_ctrl {
                    Some((px, py)) => (2.0 * cx - px, 2.0 * cy - py),
                    None => (cx, cy),
                };
                if current.is_empty() {
                    current.push((cx, cy));
                }
                flatten_cubic(&mut current, (cx, cy), (x1, y1), (x2, y2), (x, y));
                last_cubic_ctrl = Some((x2, y2));
                last_quad_ctrl = None;
                cx = x;
                cy = y;
            }
            'Q' => {
                let (Some(mut x1), Some(mut y1), Some(mut x), Some(mut y)) = (
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                ) else {
                    break;
                };
                if rel {
                    x1 += cx;
                    y1 += cy;
                    x += cx;
                    y += cy;
                }
                if current.is_empty() {
                    current.push((cx, cy));
                }
                flatten_quad(&mut current, (cx, cy), (x1, y1), (x, y));
                last_quad_ctrl = Some((x1, y1));
                last_cubic_ctrl = None;
                cx = x;
                cy = y;
            }
            'T' => {
                let (Some(mut x), Some(mut y)) = (next_num(&mut idx), next_num(&mut idx)) else {
                    break;
                };
                if rel {
                    x += cx;
                    y += cy;
                }
                let (x1, y1) = match last_quad_ctrl {
                    Some((px, py)) => (2.0 * cx - px, 2.0 * cy - py),
                    None => (cx, cy),
                };
                if current.is_empty() {
                    current.push((cx, cy));
                }
                flatten_quad(&mut current, (cx, cy), (x1, y1), (x, y));
                last_quad_ctrl = Some((x1, y1));
                last_cubic_ctrl = None;
                cx = x;
                cy = y;
            }
            'A' => {
                let (
                    Some(rx),
                    Some(ry),
                    Some(x_rot),
                    Some(large_arc),
                    Some(sweep),
                    Some(mut x),
                    Some(mut y),
                ) = (
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                    next_num(&mut idx),
                )
                else {
                    break;
                };
                if rel {
                    x += cx;
                    y += cy;
                }
                if current.is_empty() {
                    current.push((cx, cy));
                }
                flatten_arc(
                    &mut current,
                    (cx, cy),
                    (rx, ry),
                    x_rot,
                    large_arc != 0.0,
                    sweep != 0.0,
                    (x, y),
                );
                last_cubic_ctrl = None;
                last_quad_ctrl = None;
                cx = x;
                cy = y;
            }
            _ => break,
        }
    }
    if !current.is_empty() {
        out.push(Subpath {
            points: current,
            closed: false,
        });
    }
    out
}

fn flatten_cubic(
    out: &mut Vec<(f32, f32)>,
    p0: (f32, f32),
    p1: (f32, f32),
    p2: (f32, f32),
    p3: (f32, f32),
) {
    let steps = 16;
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        let u = 1.0 - t;
        let x = u * u * u * p0.0
            + 3.0 * u * u * t * p1.0
            + 3.0 * u * t * t * p2.0
            + t * t * t * p3.0;
        let y = u * u * u * p0.1
            + 3.0 * u * u * t * p1.1
            + 3.0 * u * t * t * p2.1
            + t * t * t * p3.1;
        out.push((x, y));
    }
}

fn flatten_quad(out: &mut Vec<(f32, f32)>, p0: (f32, f32), p1: (f32, f32), p2: (f32, f32)) {
    let steps = 12;
    for i in 1..=steps {
        let t = i as f32 / steps as f32;
        let u = 1.0 - t;
        let x = u * u * p0.0 + 2.0 * u * t * p1.0 + t * t * p2.0;
        let y = u * u * p0.1 + 2.0 * u * t * p1.1 + t * t * p2.1;
        out.push((x, y));
    }
}

fn flatten_arc(
    out: &mut Vec<(f32, f32)>,
    (x1, y1): (f32, f32),
    (mut rx, mut ry): (f32, f32),
    x_axis_rotation: f32,
    large_arc: bool,
    sweep: bool,
    (x2, y2): (f32, f32),
) {
    rx = rx.abs();
    ry = ry.abs();
    if rx < 1e-5 || ry < 1e-5 || ((x1 - x2).abs() < 1e-5 && (y1 - y2).abs() < 1e-5) {
        out.push((x2, y2));
        return;
    }
    let phi = x_axis_rotation.to_radians();
    let (sin_phi, cos_phi) = phi.sin_cos();
    let dx2 = (x1 - x2) * 0.5;
    let dy2 = (y1 - y2) * 0.5;
    let x1p = cos_phi * dx2 + sin_phi * dy2;
    let y1p = -sin_phi * dx2 + cos_phi * dy2;

    let lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
    if lambda > 1.0 {
        let s = lambda.sqrt();
        rx *= s;
        ry *= s;
    }

    let rx_sq = rx * rx;
    let ry_sq = ry * ry;
    let x1p_sq = x1p * x1p;
    let y1p_sq = y1p * y1p;
    let denom = rx_sq * y1p_sq + ry_sq * x1p_sq;
    let numer = (rx_sq * ry_sq - denom).max(0.0);
    let mut factor = (numer / denom.max(1e-7)).sqrt();
    if large_arc == sweep {
        factor = -factor;
    }
    let cxp = factor * (rx * y1p / ry);
    let cyp = factor * (-ry * x1p / rx);
    let cx = cos_phi * cxp - sin_phi * cyp + (x1 + x2) * 0.5;
    let cy = sin_phi * cxp + cos_phi * cyp + (y1 + y2) * 0.5;

    let vec_angle = |ux: f32, uy: f32, vx: f32, vy: f32| -> f32 {
        let dot = ux * vx + uy * vy;
        let len = ((ux * ux + uy * uy) * (vx * vx + vy * vy)).sqrt().max(1e-7);
        let ang = (dot / len).clamp(-1.0, 1.0).acos();
        if ux * vy - uy * vx < 0.0 { -ang } else { ang }
    };

    let theta1 = vec_angle(1.0, 0.0, (x1p - cxp) / rx, (y1p - cyp) / ry);
    let mut dtheta = vec_angle(
        (x1p - cxp) / rx,
        (y1p - cyp) / ry,
        (-x1p - cxp) / rx,
        (-y1p - cyp) / ry,
    );
    if !sweep && dtheta > 0.0 {
        dtheta -= std::f32::consts::TAU;
    } else if sweep && dtheta < 0.0 {
        dtheta += std::f32::consts::TAU;
    }

    let steps = ((dtheta.abs() / (std::f32::consts::PI / 12.0)).ceil() as usize).clamp(4, 48);
    for i in 1..=steps {
        let t = theta1 + dtheta * (i as f32 / steps as f32);
        let (st, ct) = t.sin_cos();
        let x = cos_phi * rx * ct - sin_phi * ry * st + cx;
        let y = sin_phi * rx * ct + cos_phi * ry * st + cy;
        out.push((x, y));
    }
}

fn rect_subpath(x: f32, y: f32, w: f32, h: f32, rx: f32, ry: f32) -> Subpath {
    if rx <= 0.0 || ry <= 0.0 {
        return Subpath {
            points: vec![(x, y), (x + w, y), (x + w, y + h), (x, y + h), (x, y)],
            closed: true,
        };
    }
    let mut pts = Vec::new();
    pts.push((x + rx, y));
    pts.push((x + w - rx, y));
    flatten_arc(&mut pts, (x + w - rx, y), (rx, ry), 0.0, false, true, (x + w, y + ry));
    pts.push((x + w, y + h - ry));
    flatten_arc(&mut pts, (x + w, y + h - ry), (rx, ry), 0.0, false, true, (x + w - rx, y + h));
    pts.push((x + rx, y + h));
    flatten_arc(&mut pts, (x + rx, y + h), (rx, ry), 0.0, false, true, (x, y + h - ry));
    pts.push((x, y + ry));
    flatten_arc(&mut pts, (x, y + ry), (rx, ry), 0.0, false, true, (x + rx, y));
    Subpath {
        points: pts,
        closed: true,
    }
}

fn ellipse_subpath(cx: f32, cy: f32, rx: f32, ry: f32) -> Subpath {
    let steps = 36;
    let mut pts = Vec::with_capacity(steps + 1);
    for i in 0..=steps {
        let a = (i as f32 / steps as f32) * std::f32::consts::TAU;
        pts.push((cx + rx * a.cos(), cy + ry * a.sin()));
    }
    Subpath {
        points: pts,
        closed: true,
    }
}

fn compute_bounds(cmds: &[DrawCmd]) -> Option<(f32, f32, f32, f32)> {
    let (mut min_x, mut min_y) = (f32::INFINITY, f32::INFINITY);
    let (mut max_x, mut max_y) = (f32::NEG_INFINITY, f32::NEG_INFINITY);
    for cmd in cmds {
        for sp in &cmd.subpaths {
            for &(x, y) in &sp.points {
                let (tx, ty) = cmd.style.transform.apply(x, y);
                min_x = min_x.min(tx);
                min_y = min_y.min(ty);
                max_x = max_x.max(tx);
                max_y = max_y.max(ty);
            }
        }
    }
    if min_x.is_finite() && max_x > min_x && max_y > min_y {
        Some((min_x, min_y, max_x - min_x, max_y - min_y))
    } else {
        None
    }
}

fn blend_pixel(dst: &mut [u8; 4], src: [u8; 4], coverage: f32) {
    let sa = (f32::from(src[3]) / 255.0) * coverage.clamp(0.0, 1.0);
    if sa <= 0.0 {
        return;
    }
    let da = f32::from(dst[3]) / 255.0;
    let out_a = sa + da * (1.0 - sa);
    if out_a <= 0.0 {
        return;
    }
    for i in 0..3 {
        let sc = f32::from(src[i]) / 255.0;
        let dc = f32::from(dst[i]) / 255.0;
        let out_c = (sc * sa + dc * da * (1.0 - sa)) / out_a;
        dst[i] = (out_c * 255.0).round().clamp(0.0, 255.0) as u8;
    }
    dst[3] = (out_a * 255.0).round().clamp(0.0, 255.0) as u8;
}

fn rasterize_fill(
    pixels: &mut [[u8; 4]],
    width: u32,
    height: u32,
    subpaths: &[Vec<(f32, f32)>],
    rule: FillRule,
    color: [u8; 4],
) {
    let mut edges: Vec<(f32, f32, f32, f32)> = Vec::new();
    let (mut min_y, mut max_y) = (f32::INFINITY, f32::NEG_INFINITY);
    for sp in subpaths {
        if sp.len() < 2 {
            continue;
        }
        for pair in sp.windows(2) {
            let (x0, y0) = pair[0];
            let (x1, y1) = pair[1];
            if (y0 - y1).abs() > 1e-5 {
                edges.push((x0, y0, x1, y1));
                min_y = min_y.min(y0.min(y1));
                max_y = max_y.max(y0.max(y1));
            }
        }
        let (fx, fy) = sp[0];
        let (lx, ly) = sp[sp.len() - 1];
        if (fy - ly).abs() > 1e-5 {
            edges.push((lx, ly, fx, fy));
            min_y = min_y.min(fy.min(ly));
            max_y = max_y.max(fy.max(ly));
        }
    }
    if edges.is_empty() {
        return;
    }
    let y_start = (min_y.floor() as i32).max(0) as u32;
    let y_end = (max_y.ceil() as i32).min(height as i32) as u32;
    if y_start >= y_end {
        return;
    }

    const SUB: usize = 4;
    let mut coverage_row = vec![0u8; width as usize];
    let mut crossings: Vec<(f32, i32)> = Vec::new();

    for py in y_start..y_end {
        coverage_row.fill(0);
        for sy in 0..SUB {
            let scan_y = py as f32 + (sy as f32 + 0.5) / SUB as f32;
            crossings.clear();
            for &(x0, y0, x1, y1) in &edges {
                let (ymin, ymax, dir) = if y0 < y1 {
                    (y0, y1, 1)
                } else {
                    (y1, y0, -1)
                };
                if scan_y >= ymin && scan_y < ymax {
                    let t = (scan_y - y0) / (y1 - y0);
                    let x = x0 + t * (x1 - x0);
                    crossings.push((x, dir));
                }
            }
            if crossings.len() < 2 {
                continue;
            }
            crossings.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
            let mut winding = 0i32;
            let mut prev_x = 0.0f32;
            for &(x, dir) in &crossings {
                let inside = match rule {
                    FillRule::NonZero => winding != 0,
                    FillRule::EvenOdd => (winding & 1) != 0,
                };
                if inside {
                    let x0 = prev_x.max(0.0).min(width as f32);
                    let x1 = x.max(0.0).min(width as f32);
                    if x1 > x0 {
                        let px_start = x0.floor() as u32;
                        let px_end = (x1.ceil() as u32).min(width);
                        for px in px_start..px_end {
                            for sx in 0..SUB {
                                let sample_x = px as f32 + (sx as f32 + 0.5) / SUB as f32;
                                if sample_x >= x0 && sample_x < x1 {
                                    coverage_row[px as usize] += 1;
                                }
                            }
                        }
                    }
                }
                winding += dir;
                prev_x = x;
            }
        }
        let row_offset = (py * width) as usize;
        for (px, &cov) in coverage_row.iter().enumerate() {
            if cov > 0 {
                let frac = f32::from(cov) / (SUB * SUB) as f32;
                blend_pixel(&mut pixels[row_offset + px], color, frac);
            }
        }
    }
}

fn rasterize_stroke(
    pixels: &mut [[u8; 4]],
    width: u32,
    height: u32,
    points: &[(f32, f32)],
    closed: bool,
    stroke_width: f32,
    color: [u8; 4],
) {
    if points.len() < 2 {
        return;
    }
    let half = stroke_width * 0.5;
    let mut min_x = f32::INFINITY;
    let mut min_y = f32::INFINITY;
    let mut max_x = f32::NEG_INFINITY;
    let mut max_y = f32::NEG_INFINITY;
    for &(x, y) in points {
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    }
    let pad = half + 1.5;
    let x0 = ((min_x - pad).floor() as i32).max(0) as u32;
    let y0 = ((min_y - pad).floor() as i32).max(0) as u32;
    let x1 = ((max_x + pad).ceil() as i32).min(width as i32).max(0) as u32;
    let y1 = ((max_y + pad).ceil() as i32).min(height as i32).max(0) as u32;

    for py in y0..y1 {
        let cy = py as f32 + 0.5;
        for px in x0..x1 {
            let cx = px as f32 + 0.5;
            let mut min_dist = f32::INFINITY;
            for pair in points.windows(2) {
                let d = dist_to_segment((cx, cy), pair[0], pair[1]);
                if d < min_dist {
                    min_dist = d;
                }
            }
            if closed && points.len() > 2 {
                let d = dist_to_segment((cx, cy), points[points.len() - 1], points[0]);
                if d < min_dist {
                    min_dist = d;
                }
            }
            let coverage = (half + 0.5 - min_dist).clamp(0.0, 1.0);
            if coverage > 0.0 {
                blend_pixel(&mut pixels[(py * width + px) as usize], color, coverage);
            }
        }
    }
}

fn dist_to_segment((px, py): (f32, f32), (ax, ay): (f32, f32), (bx, by): (f32, f32)) -> f32 {
    let dx = bx - ax;
    let dy = by - ay;
    let len_sq = dx * dx + dy * dy;
    if len_sq <= 1e-6 {
        return ((px - ax).powi(2) + (py - ay).powi(2)).sqrt();
    }
    let t = (((px - ax) * dx + (py - ay) * dy) / len_sq).clamp(0.0, 1.0);
    let proj_x = ax + t * dx;
    let proj_y = ay + t * dy;
    ((px - proj_x).powi(2) + (py - proj_y).powi(2)).sqrt()
}

fn parse_xml(input: &str) -> Option<XmlNode> {
    let mut root = XmlNode {
        tag: "root".to_owned(),
        attrs: Vec::new(),
        text: String::new(),
        children: Vec::new(),
    };
    let mut stack: Vec<XmlNode> = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let Some(rel_lt) = input[i..].find('<') else {
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&input[i..]);
            }
            break;
        };
        let lt = i + rel_lt;
        if lt > i {
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&input[i..lt]);
            }
        }
        let rest = &input[lt..];
        if rest.starts_with("<!--") {
            let end = rest.find("-->").map_or(rest.len(), |p| p + 3);
            i = lt + end;
            continue;
        }
        if rest.starts_with("<![CDATA[") {
            let end = rest.find("]]>").map_or(rest.len(), |p| {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&rest[9..p]);
                }
                p + 3
            });
            i = lt + end;
            continue;
        }
        if rest.starts_with("<?") {
            let end = rest.find("?>").map_or(rest.len(), |p| p + 2);
            i = lt + end;
            continue;
        }
        if rest.starts_with("<!") {
            let end = skip_doctype(rest);
            i = lt + end;
            continue;
        }
        let Some(tag_len) = find_tag_end(rest) else {
            break;
        };
        let tag_content = rest[1..tag_len - 1].trim();
        i = lt + tag_len;

        if let Some(close_name) = tag_content.strip_prefix('/') {
            let close_name = close_name.trim();
            if let Some(node) = stack.pop() {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root.children.push(node);
                }
            }
            let _ = close_name;
            continue;
        }

        let self_closing = tag_content.ends_with('/');
        let inner = if self_closing {
            tag_content[..tag_content.len() - 1].trim()
        } else {
            tag_content
        };
        let (tag_name, attrs) = parse_tag_and_attrs(inner);
        if tag_name.is_empty() {
            continue;
        }
        let node = XmlNode {
            tag: tag_name,
            attrs,
            text: String::new(),
            children: Vec::new(),
        };
        if self_closing {
            if let Some(parent) = stack.last_mut() {
                parent.children.push(node);
            } else {
                root.children.push(node);
            }
        } else {
            stack.push(node);
        }
    }

    while let Some(node) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(node);
        } else {
            root.children.push(node);
        }
    }

    (!root.children.is_empty()).then_some(root)
}

fn skip_doctype(s: &str) -> usize {
    let mut depth = 0i32;
    let mut in_quote: Option<u8> = None;
    for (idx, b) in s.bytes().enumerate() {
        if let Some(q) = in_quote {
            if b == q {
                in_quote = None;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => in_quote = Some(b),
            b'[' => depth += 1,
            b']' => depth -= 1,
            b'>' if depth <= 0 => return idx + 1,
            _ => {}
        }
    }
    s.len()
}

fn find_tag_end(s: &str) -> Option<usize> {
    let mut in_quote: Option<u8> = None;
    for (idx, b) in s.bytes().enumerate().skip(1) {
        if let Some(q) = in_quote {
            if b == q {
                in_quote = None;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => in_quote = Some(b),
            b'>' => return Some(idx + 1),
            _ => {}
        }
    }
    None
}

fn parse_tag_and_attrs(s: &str) -> (String, Vec<(String, String)>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let tag = s[..i].to_owned();
    let mut attrs = Vec::new();
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let k_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'=' {
            i += 1;
        }
        let key = s[k_start..i].trim().to_owned();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let quote = bytes[i];
        let val = if quote == b'"' || quote == b'\'' {
            i += 1;
            let v_start = i;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            let raw = &s[v_start..i];
            if i < bytes.len() {
                i += 1;
            }
            unescape_xml(raw)
        } else {
            let v_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            unescape_xml(&s[v_start..i])
        };
        if !key.is_empty() {
            attrs.push((key, val));
        }
    }
    (tag, attrs)
}

fn unescape_xml(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_svg_by_mime_and_content() {
        let svg = b"<?xml version=\"1.0\"?>\n<svg viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"10\"/></svg>";
        assert!(is_svg(Some("image/svg+xml; charset=utf-8"), svg));
        assert!(is_svg(Some("text/plain"), svg));
        assert!(!is_svg(Some("text/html"), b"<html><body>hello</body></html>"));
        assert!(!is_svg(Some("image/png"), b"\x89PNG\r\n\x1a\n"));
    }

    #[test]
    fn renders_svg_shapes_and_paths() {
        let svg = r##"
            <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
                <rect x="0" y="0" width="64" height="64" fill="#ff0000"/>
                <circle cx="32" cy="32" r="16" fill="#00ff00"/>
                <path d="M 16 32 L 48 32" stroke="#0000ff" stroke-width="4"/>
            </svg>
        "##;
        let rendered = render_svg(svg, 256).expect("SVG should render");
        assert!(rendered.image.width() >= 64);
        assert!(rendered.image.height() >= 64);
        assert_eq!(rendered.display_size, (64.0, 64.0));

        // Corner pixel should be red (#ff0000).
        let corner = rendered.image[(4, 4)];
        assert_eq!((corner.r(), corner.g(), corner.b(), corner.a()), (255, 0, 0, 255));

        // Center pixel should be blue from the horizontal path over the green circle.
        let cx = rendered.image.width() / 2;
        let cy = rendered.image.height() / 2;
        let center = rendered.image[(cx, cy)];
        assert_eq!((center.r(), center.g(), center.b(), center.a()), (0, 0, 255, 255));
    }
}
