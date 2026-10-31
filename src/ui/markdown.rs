//! Markdown parser and egui renderer for AI agent responses.
//!
//! Supports headings, paragraphs, bold/italic/strikethrough, inline code,
//! links, unordered/ordered/task lists (including multi-line items and
//! nesting), blockquotes, horizontal rules, tables, and syntax-highlighted
//! fenced code blocks.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, RichText, ScrollArea, Stroke,
    TextStyle,
    text::{LayoutJob, TextFormat},
    vec2,
};

use super::highlight::{self, highlight_into};
use super::icons::{self, Icon};
use super::theme;
use crate::inspect::Syntax;

const INLINE_CODE_BG: Color32 = Color32::from_rgb(0x33, 0x33, 0x37);
const INLINE_CODE_FG: Color32 = Color32::from_rgb(0xce, 0x91, 0x78);
const QUOTE_BAR: Color32 = Color32::from_rgb(0x4d, 0x55, 0x62);

/// Parsed block-level Markdown element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Heading {
        level: u8,
        text: String,
    },
    Paragraph(String),
    CodeBlock {
        lang: String,
        code: String,
    },
    List(Vec<ListItem>),
    Quote(Vec<Block>),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Rule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub indent: usize,
    pub marker: ListMarker,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListMarker {
    Bullet,
    Ordered(String),
    Task(bool),
}

/// Inline span style state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InlineStyle {
    pub bold: bool,
    pub italic: bool,
    pub strike: bool,
    pub code: bool,
    pub link: bool,
}

/// Parses a Markdown document into block-level elements.
pub fn parse_blocks(input: &str) -> Vec<Block> {
    let lines: Vec<&str> = input.lines().collect();
    parse_slice(&lines)
}

fn parse_slice(lines: &[&str]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // 1. Blank line.
        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // 2. Fenced code block (``` or ~~~).
        if let Some((fence, lang)) = parse_fence_open(trimmed) {
            i += 1;
            let mut code = String::new();
            while i < lines.len() {
                let l = lines[i];
                if l.trim_start().starts_with(fence) && l.trim().chars().all(|c| c == fence.as_bytes()[0] as char) {
                    i += 1;
                    break;
                }
                if !code.is_empty() {
                    code.push('\n');
                }
                code.push_str(l);
                i += 1;
            }
            blocks.push(Block::CodeBlock { lang, code });
            continue;
        }

        // 3. Horizontal rule (---, ***, ___).
        if is_horizontal_rule(trimmed) {
            blocks.push(Block::Rule);
            i += 1;
            continue;
        }

        // 4. ATX Heading (# .. ######).
        if let Some((level, text)) = parse_heading(trimmed) {
            blocks.push(Block::Heading { level, text });
            i += 1;
            continue;
        }

        // 5. Blockquote (> ...).
        if trimmed.starts_with('>') {
            let mut quote_lines = Vec::new();
            while i < lines.len() {
                let t = lines[i].trim_start();
                if let Some(rest) = t.strip_prefix('>') {
                    quote_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
                    i += 1;
                } else {
                    break;
                }
            }
            blocks.push(Block::Quote(parse_slice(&quote_lines)));
            continue;
        }

        // 6. Table (| header | ... followed by | --- | ...).
        if i + 1 < lines.len()
            && is_table_row(trimmed)
            && is_table_delimiter(lines[i + 1].trim())
        {
            let headers = split_table_cells(trimmed);
            i += 2;
            let mut rows = Vec::new();
            while i < lines.len() && is_table_row(lines[i].trim()) {
                rows.push(split_table_cells(lines[i].trim()));
                i += 1;
            }
            blocks.push(Block::Table { headers, rows });
            continue;
        }

        // 7. List (unordered or ordered).
        if let Some((indent, marker, text)) = parse_list_line(line) {
            let mut items = vec![ListItem {
                indent,
                marker,
                text,
            }];
            i += 1;
            while i < lines.len() {
                let next = lines[i];
                let next_trimmed = next.trim();
                if next_trimmed.is_empty() {
                    // A single blank line between list items continues the list.
                    if i + 1 < lines.len() && parse_list_line(lines[i + 1]).is_some() {
                        i += 1;
                        continue;
                    }
                    break;
                }
                if parse_fence_open(next_trimmed).is_some()
                    || is_horizontal_rule(next_trimmed)
                    || parse_heading(next_trimmed).is_some()
                    || next_trimmed.starts_with('>')
                {
                    break;
                }
                if let Some((ind, m, txt)) = parse_list_line(next) {
                    items.push(ListItem {
                        indent: ind,
                        marker: m,
                        text: txt,
                    });
                    i += 1;
                } else {
                    // Continuation line of the current list item.
                    if let Some(last) = items.last_mut() {
                        if !last.text.is_empty() {
                            last.text.push(' ');
                        }
                        last.text.push_str(next_trimmed);
                    }
                    i += 1;
                }
            }
            blocks.push(Block::List(items));
            continue;
        }

        // 8. Paragraph: collect consecutive prose lines.
        let mut para = String::new();
        while i < lines.len() {
            let l = lines[i];
            let t = l.trim();
            if t.is_empty()
                || parse_fence_open(t).is_some()
                || is_horizontal_rule(t)
                || parse_heading(t).is_some()
                || t.starts_with('>')
                || parse_list_line(l).is_some()
                || (i + 1 < lines.len()
                    && is_table_row(t)
                    && is_table_delimiter(lines[i + 1].trim()))
            {
                break;
            }
            let hard_break = l.ends_with("  ") || l.ends_with('\\');
            let clean = t.strip_suffix('\\').unwrap_or(t).trim_end();
            if !para.is_empty() && !para.ends_with('\n') {
                para.push(' ');
            }
            para.push_str(clean);
            if hard_break {
                para.push('\n');
            }
            i += 1;
        }
        if !para.is_empty() {
            blocks.push(Block::Paragraph(para));
        }
    }

    blocks
}

fn parse_fence_open(trimmed: &str) -> Option<(&'static str, String)> {
    if let Some(rest) = trimmed.strip_prefix("```") {
        let lang = rest.trim_start_matches('`').trim().to_owned();
        Some(("```", lang))
    } else if let Some(rest) = trimmed.strip_prefix("~~~") {
        let lang = rest.trim_start_matches('~').trim().to_owned();
        Some(("~~~", lang))
    } else {
        None
    }
}

fn is_horizontal_rule(trimmed: &str) -> bool {
    if trimmed.len() < 3 {
        return false;
    }
    for marker in ['-', '*', '_'] {
        let count = trimmed.chars().filter(|&c| c == marker).count();
        if count >= 3 && trimmed.chars().all(|c| c == marker || c == ' ') {
            return true;
        }
    }
    false
}

fn parse_heading(trimmed: &str) -> Option<(u8, String)> {
    let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
    if (1..=6).contains(&hashes) {
        let rest = &trimmed[hashes..];
        if rest.is_empty() || rest.starts_with(' ') {
            let text = rest.trim().trim_end_matches('#').trim().to_owned();
            return Some((hashes as u8, text));
        }
    }
    None
}

fn parse_list_line(line: &str) -> Option<(usize, ListMarker, String)> {
    let indent: usize = line
        .chars()
        .take_while(|&c| c == ' ' || c == '\t')
        .map(|c| if c == '\t' { 2 } else { 1 })
        .sum();
    let trimmed = line.trim_start();

    // Unordered list: "- ", "* ", "+ "
    for prefix in ["- ", "* ", "+ "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let rest = rest.trim_start();
            if let Some(task) = rest
                .strip_prefix("[ ] ")
                .or_else(|| rest.strip_prefix("[] "))
            {
                return Some((indent / 2, ListMarker::Task(false), task.to_owned()));
            }
            if let Some(task) = rest
                .strip_prefix("[x] ")
                .or_else(|| rest.strip_prefix("[X] "))
            {
                return Some((indent / 2, ListMarker::Task(true), task.to_owned()));
            }
            return Some((indent / 2, ListMarker::Bullet, rest.to_owned()));
        }
    }

    // Ordered list: "1. ", "2) "
    let digits = trimmed.bytes().take_while(|b| b.is_ascii_digit()).count();
    if (1..=4).contains(&digits) {
        let after = &trimmed[digits..];
        if let Some(rest) = after.strip_prefix(". ").or_else(|| after.strip_prefix(") ")) {
            let num = format!("{}.", &trimmed[..digits]);
            return Some((indent / 2, ListMarker::Ordered(num), rest.trim_start().to_owned()));
        }
    }

    None
}

fn is_table_row(trimmed: &str) -> bool {
    trimmed.contains('|') && trimmed.len() >= 3
}

fn is_table_delimiter(trimmed: &str) -> bool {
    if !trimmed.contains('|') || !trimmed.contains('-') {
        return false;
    }
    let cells = split_table_cells(trimmed);
    !cells.is_empty()
        && cells.iter().all(|c| {
            let t = c.trim();
            !t.is_empty() && t.chars().all(|ch| matches!(ch, '-' | ':' | ' '))
        })
}

fn split_table_cells(trimmed: &str) -> Vec<String> {
    let inner = trimmed
        .strip_prefix('|')
        .unwrap_or(trimmed)
        .strip_suffix('|')
        .unwrap_or(trimmed);
    inner.split('|').map(|c| c.trim().to_owned()).collect()
}

/// Parses inline Markdown spans (`**bold**`, `*italic*`, `` `code` ``,
/// `~~strike~~`, `[text](url)`) into `(text, InlineStyle)` segments.
pub fn parse_inline(input: &str) -> Vec<(String, InlineStyle)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut style = InlineStyle::default();
    let bytes = input.as_bytes();
    let mut i = 0;

    let flush = |buf: &mut String, style: InlineStyle, out: &mut Vec<(String, InlineStyle)>| {
        if !buf.is_empty() {
            out.push((std::mem::take(buf), style));
        }
    };

    while i < bytes.len() {
        // 1. Escape sequence: \* \_ \` \~ \[ \\
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if matches!(
                next,
                b'*' | b'_' | b'`' | b'~' | b'[' | b']' | b'(' | b')' | b'\\' | b'#'
            ) {
                buf.push(next as char);
                i += 2;
                continue;
            }
        }

        // 2. Inline code: ``...`` or `...`
        if bytes[i] == b'`' {
            let ticks = bytes[i..].iter().take_while(|&&b| b == b'`').count();
            let marker = &input[i..i + ticks];
            let content_start = i + ticks;
            if let Some(rel_end) = input[content_start..].find(marker) {
                flush(&mut buf, style, &mut out);
                let code_slice = &input[content_start..content_start + rel_end];
                let trimmed = if code_slice.len() >= 2
                    && code_slice.starts_with(' ')
                    && code_slice.ends_with(' ')
                {
                    &code_slice[1..code_slice.len() - 1]
                } else {
                    code_slice
                };
                out.push((
                    trimmed.to_owned(),
                    InlineStyle {
                        code: true,
                        ..style
                    },
                ));
                i = content_start + rel_end + ticks;
                continue;
            }
        }

        // 3. Link: [label](url)
        if bytes[i] == b'[' {
            if let Some((label, _url, consumed)) = try_parse_link(&input[i..]) {
                flush(&mut buf, style, &mut out);
                out.push((
                    label.to_owned(),
                    InlineStyle {
                        link: true,
                        ..style
                    },
                ));
                i += consumed;
                continue;
            }
        }

        // 4. Bold + Italic: *** or ___
        if input[i..].starts_with("***") || input[i..].starts_with("___") {
            flush(&mut buf, style, &mut out);
            style.bold = !style.bold;
            style.italic = !style.italic;
            i += 3;
            continue;
        }

        // 5. Bold: ** or __
        if input[i..].starts_with("**") || input[i..].starts_with("__") {
            flush(&mut buf, style, &mut out);
            style.bold = !style.bold;
            i += 2;
            continue;
        }

        // 6. Strikethrough: ~~
        if input[i..].starts_with("~~") {
            flush(&mut buf, style, &mut out);
            style.strike = !style.strike;
            i += 2;
            continue;
        }

        // 7. Italic: * or _ (for '_', require word boundary so snake_case_identifiers stay intact!)
        if bytes[i] == b'*' {
            // Only treat '*' as italic if we are closing italic OR there is a matching '*' ahead.
            if style.italic || input[i + 1..].contains('*') {
                flush(&mut buf, style, &mut out);
                style.italic = !style.italic;
                i += 1;
                continue;
            }
        } else if bytes[i] == b'_' {
            let prev_alnum = i > 0 && (bytes[i - 1] as char).is_ascii_alphanumeric();
            let next_alnum = i + 1 < bytes.len() && (bytes[i + 1] as char).is_ascii_alphanumeric();
            let is_intraword = prev_alnum && next_alnum;
            if !is_intraword && (style.italic || input[i + 1..].contains('_')) {
                flush(&mut buf, style, &mut out);
                style.italic = !style.italic;
                i += 1;
                continue;
            }
        }

        let ch = input[i..].chars().next().unwrap();
        buf.push(ch);
        i += ch.len_utf8();
    }

    flush(&mut buf, style, &mut out);
    out
}

fn try_parse_link(s: &str) -> Option<(&str, &str, usize)> {
    let close_bracket = s.find("](")?;
    let label = &s[1..close_bracket];
    if label.is_empty() || label.contains('\n') {
        return None;
    }
    let after = &s[close_bracket + 2..];
    let close_paren = after.find(')')?;
    let url = &after[..close_paren];
    if url.contains('\n') {
        return None;
    }
    Some((label, url, close_bracket + 2 + close_paren + 1))
}

/// Builds an egui [`LayoutJob`] from inline Markdown text.
pub fn inline_layout_job(text: &str, base_size: f32, base_color: Color32, force_bold: bool) -> LayoutJob {
    let mut job = LayoutJob::default();
    for (segment, style) in parse_inline(text) {
        if style.code {
            let format = TextFormat {
                font_id: FontId::new((base_size - 0.5).max(10.5), FontFamily::Monospace),
                color: INLINE_CODE_FG,
                background: INLINE_CODE_BG,
                ..Default::default()
            };
            job.append(&format!(" {segment} "), 0.0, format);
        } else {
            let family = if style.bold || force_bold {
                theme::bold_family()
            } else {
                FontFamily::Proportional
            };
            let color = if style.link {
                theme::LINK
            } else if style.bold || force_bold {
                theme::TEXT_BRIGHT
            } else {
                base_color
            };
            let format = TextFormat {
                font_id: FontId::new(base_size, family),
                color,
                italics: style.italic,
                strikethrough: if style.strike {
                    Stroke::new(1.0, theme::TEXT_DIM)
                } else {
                    Stroke::NONE
                },
                underline: if style.link {
                    Stroke::new(1.0, theme::LINK)
                } else {
                    Stroke::NONE
                },
                ..Default::default()
            };
            job.append(&segment, 0.0, format);
        }
    }
    job
}

fn syntax_for_tag(tag: &str) -> Syntax {
    match tag.trim().to_ascii_lowercase().as_str() {
        "smali" | "dalvik" => Syntax::Smali,
        "xml" | "html" | "axml" => Syntax::Xml,
        "json" | "jsonc" => Syntax::Json,
        "js" | "javascript" | "ts" | "typescript" | "java" | "kotlin" | "kt" | "c" | "cpp"
        | "rust" | "rs" => Syntax::JavaScript,
        "css" => Syntax::Css,
        _ => Syntax::Plain,
    }
}

/// Renders a Markdown string into `ui`.
pub fn show(ui: &mut egui::Ui, id_salt: usize, text: &str) {
    let blocks = parse_blocks(text);
    render_blocks(ui, id_salt, &blocks, 0);
}

fn render_blocks(ui: &mut egui::Ui, id_salt: usize, blocks: &[Block], depth: usize) {
    for (idx, block) in blocks.iter().enumerate() {
        if idx > 0 {
            ui.add_space(6.0);
        }
        match block {
            Block::Heading { level, text } => {
                let size = match level {
                    1 => 15.5,
                    2 => 14.5,
                    3 => 13.5,
                    _ => 12.5,
                };
                if *level <= 2 && idx > 0 {
                    ui.add_space(2.0);
                }
                let job = inline_layout_job(text, size, theme::TEXT_BRIGHT, true);
                ui.add(egui::Label::new(job).wrap().selectable(true));
                if *level <= 2 {
                    ui.add_space(1.0);
                    let w = ui.available_width();
                    let (rect, _) = ui.allocate_exact_size(vec2(w, 1.0), egui::Sense::hover());
                    ui.painter().hline(
                        rect.x_range(),
                        rect.center().y,
                        Stroke::new(1.0, theme::CARD_BORDER),
                    );
                }
            }
            Block::Paragraph(text) => {
                let job = inline_layout_job(text, 12.5, theme::TEXT, false);
                ui.add(egui::Label::new(job).wrap().selectable(true));
            }
            Block::CodeBlock { lang, code } => {
                render_code_block(ui, (id_salt, depth, idx), lang, code);
            }
            Block::List(items) => {
                render_list(ui, items);
            }
            Block::Quote(inner) => {
                egui::Frame::NONE
                    .fill(Color32::from_rgba_unmultiplied(0x30, 0x34, 0x3c, 0x60))
                    .corner_radius(CornerRadius::same(3))
                    .inner_margin(Margin {
                        left: 10,
                        right: 6,
                        top: 4,
                        bottom: 4,
                    })
                    .show(ui, |ui| {
                        ui.set_max_width(ui.available_width());
                        render_blocks(ui, id_salt.wrapping_mul(31).wrapping_add(idx), inner, depth + 1);
                        let r = ui.min_rect();
                        ui.painter().vline(
                            r.left() - 6.0,
                            r.y_range(),
                            Stroke::new(2.5, QUOTE_BAR),
                        );
                    });
            }
            Block::Table { headers, rows } => {
                render_table(ui, (id_salt, depth, idx), headers, rows);
            }
            Block::Rule => {
                ui.separator();
            }
        }
    }
}

fn render_list(ui: &mut egui::Ui, items: &[ListItem]) {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            ui.add_space(3.0);
        }
        let indent_px = (item.indent.min(4) as f32) * 14.0;
        let (marker_str, marker_color, marker_width) = match &item.marker {
            ListMarker::Bullet => {
                let glyph = match item.indent {
                    0 => "•",
                    1 => "◦",
                    _ => "▪",
                };
                (glyph.to_owned(), theme::LINK, 14.0)
            }
            ListMarker::Ordered(num) => (num.clone(), theme::TEXT_DIM, 22.0),
            ListMarker::Task(true) => ("☑".to_owned(), Color32::from_rgb(0x4e, 0xc9, 0xb0), 18.0),
            ListMarker::Task(false) => ("☐".to_owned(), theme::TEXT_DIM, 18.0),
        };

        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            if indent_px > 0.0 {
                ui.add_space(indent_px);
            }
            ui.add_sized(
                vec2(marker_width, 18.0),
                egui::Label::new(RichText::new(marker_str).size(12.5).color(marker_color))
                    .selectable(false),
            );
            let avail = ui.available_width().max(40.0);
            ui.vertical(|ui| {
                ui.set_max_width(avail);
                let job = inline_layout_job(&item.text, 12.5, theme::TEXT, false);
                ui.add(egui::Label::new(job).wrap().selectable(true));
            });
        });
    }
}

fn render_code_block(ui: &mut egui::Ui, id: (usize, usize, usize), lang: &str, code: &str) {
    let syntax = syntax_for_tag(lang);
    let mono = TextStyle::Monospace.resolve(ui.style());
    egui::Frame::NONE
        .fill(theme::EDITOR)
        .stroke(Stroke::new(1.0, theme::CARD_BORDER))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            if !lang.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(lang)
                            .size(10.5)
                            .color(theme::TEXT_DIM)
                            .family(theme::bold_family()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icons::button(ui, Icon::Copy, 16.0, "Copy code block").clicked() {
                            ui.ctx().copy_text(code.to_owned());
                        }
                    });
                });
                ui.add_space(2.0);
            }
            ScrollArea::horizontal()
                .id_salt(("agent_md_code", id.0, id.1, id.2))
                .show(ui, |ui| {
                    let mut job = LayoutJob::default();
                    for (i, line) in code.lines().enumerate() {
                        if i > 0 {
                            highlight::append(&mut job, "\n", theme::TEXT, &mono);
                        }
                        highlight_into(&mut job, line, syntax, &mono);
                    }
                    ui.add(egui::Label::new(job).extend().selectable(true));
                });
        });
}

fn render_table(
    ui: &mut egui::Ui,
    id: (usize, usize, usize),
    headers: &[String],
    rows: &[Vec<String>],
) {
    egui::Frame::NONE
        .fill(theme::EDITOR)
        .stroke(Stroke::new(1.0, theme::CARD_BORDER))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(6, 4))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width());
            ScrollArea::horizontal()
                .id_salt(("agent_md_table", id.0, id.1, id.2))
                .show(ui, |ui| {
                    egui::Grid::new(("agent_md_grid", id.0, id.1, id.2))
                        .striped(true)
                        .spacing(vec2(12.0, 4.0))
                        .show(ui, |ui| {
                            for h in headers {
                                let job = inline_layout_job(h, 11.5, theme::TEXT_BRIGHT, true);
                                ui.add(egui::Label::new(job).selectable(true));
                            }
                            ui.end_row();
                            for row in rows {
                                for cell in row {
                                    let job = inline_layout_job(cell, 11.5, theme::TEXT, false);
                                    ui.add(egui::Label::new(job).selectable(true));
                                }
                                ui.end_row();
                            }
                        });
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headings_lists_quotes_tables_and_code_blocks() {
        let md = "\
# Overview

**The app does not contain any easily identifiable code paths.**

Due to R8/ProGuard obfuscation, logic lives in `b8/`, `l6/`, or `de.chargecloud.chargecloud_dev`.

Typical flow:
- Cost data is retrieved via REST calls
  (likely Retrofit/OkHttp) to `https://api.example`.
- Triggered by a ViewModel.

Steps:
1. Capture live traffic.
2. Search obfuscated classes.

> Note: WebView pinning may apply.

| Method | Path |
| --- | --- |
| GET | `/v1/cost` |

```smali
.method public final l()V
    return-void
.end method
```
";
        let blocks = parse_blocks(md);
        assert_eq!(
            blocks[0],
            Block::Heading {
                level: 1,
                text: "Overview".to_owned(),
            }
        );
        assert_eq!(
            blocks[1],
            Block::Paragraph(
                "**The app does not contain any easily identifiable code paths.**".to_owned()
            )
        );
        assert!(matches!(&blocks[3], Block::Paragraph(p) if p == "Typical flow:"));
        let Block::List(bullets) = &blocks[4] else {
            panic!("expected bullet list: {:?}", blocks[4]);
        };
        assert_eq!(bullets.len(), 2);
        assert_eq!(
            bullets[0].text,
            "Cost data is retrieved via REST calls (likely Retrofit/OkHttp) to `https://api.example`."
        );
        let Block::List(numbered) = &blocks[6] else {
            panic!("expected numbered list: {:?}", blocks[6]);
        };
        assert_eq!(numbered.len(), 2);
        assert_eq!(numbered[0].marker, ListMarker::Ordered("1.".to_owned()));
        assert!(matches!(&blocks[7], Block::Quote(_)));
        assert!(matches!(&blocks[8], Block::Table { headers, rows } if headers.len() == 2 && rows.len() == 1));
        assert!(matches!(&blocks[9], Block::CodeBlock { lang, .. } if lang == "smali"));
    }

    #[test]
    fn parses_inline_bold_italic_code_links_and_keeps_snake_case() {
        let spans = parse_inline(
            "**Bold text** with `de.chargecloud_dev` and *italic* plus [docs](https://example.com) and ~~old~~",
        );
        assert!(spans.iter().any(|(t, s)| t == "Bold text" && s.bold));
        assert!(
            spans
                .iter()
                .any(|(t, s)| t == "de.chargecloud_dev" && s.code && !s.italic)
        );
        assert!(spans.iter().any(|(t, s)| t == "italic" && s.italic));
        assert!(spans.iter().any(|(t, s)| t == "docs" && s.link));
        assert!(spans.iter().any(|(t, s)| t == "old" && s.strike));

        // Unquoted snake_case identifiers must not toggle italics.
        let ident = parse_inline("check foo_bar_baz here");
        assert_eq!(ident.len(), 1);
        assert!(!ident[0].1.italic);
    }
}

