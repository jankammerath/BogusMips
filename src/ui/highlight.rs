//! Lightweight, line-based syntax highlighting for smali and XML.

use eframe::egui::text::{LayoutJob, TextFormat};
use eframe::egui::{Color32, FontId};

use crate::inspect::Syntax;

pub const TEXT: Color32 = Color32::from_rgb(0xd4, 0xd4, 0xd4);
pub const GUTTER: Color32 = Color32::from_rgb(0x6e, 0x76, 0x81);
const COMMENT: Color32 = Color32::from_rgb(0x6a, 0x99, 0x55);
const DIRECTIVE: Color32 = Color32::from_rgb(0xc5, 0x86, 0xc0);
const KEYWORD: Color32 = Color32::from_rgb(0x56, 0x9c, 0xd6);
const LABEL: Color32 = Color32::from_rgb(0xdc, 0xdc, 0xaa);
const STRING: Color32 = Color32::from_rgb(0xce, 0x91, 0x78);
const REGISTER: Color32 = Color32::from_rgb(0x9c, 0xdc, 0xfe);
const TYPE: Color32 = Color32::from_rgb(0x4e, 0xc9, 0xb0);
const NUMBER: Color32 = Color32::from_rgb(0xb5, 0xce, 0xa8);
const PUNCT: Color32 = Color32::from_rgb(0x80, 0x80, 0x80);

pub fn append(job: &mut LayoutJob, text: &str, color: Color32, font: &FontId) {
    if !text.is_empty() {
        job.append(text, 0.0, TextFormat::simple(font.clone(), color));
    }
}

pub fn highlight_into(job: &mut LayoutJob, line: &str, syntax: Syntax, font: &FontId) {
    match syntax {
        Syntax::Plain => append(job, line, TEXT, font),
        Syntax::Smali => smali(job, line, font),
        Syntax::Xml => xml(job, line, font),
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '$' | '-' | '/' | '<' | '>')
}

/// Returns the byte index just past a quoted literal starting at `start`.
fn quoted_end(s: &str, start: usize, quote: char) -> usize {
    let mut escaped = false;
    for (i, c) in s[start + 1..].char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == quote {
            return start + 1 + i + c.len_utf8();
        }
    }
    s.len()
}

fn smali(job: &mut LayoutJob, line: &str, font: &FontId) {
    let trimmed = line.trim_start();
    append(job, &line[..line.len() - trimmed.len()], TEXT, font);
    if trimmed.starts_with('#') {
        append(job, trimmed, COMMENT, font);
        return;
    }
    let first_end = trimmed.find(' ').unwrap_or(trimmed.len());
    let (first, rest) = trimmed.split_at(first_end);
    let color = match first.chars().next() {
        Some('.') => DIRECTIVE,
        Some(':') => LABEL,
        _ => KEYWORD,
    };
    append(job, first, color, font);

    let s = rest;
    let mut i = 0;
    let mut plain_start = 0;
    let flush = |job: &mut LayoutJob, from: usize, to: usize| append(job, &s[from..to], TEXT, font);
    while i < s.len() {
        let c = s[i..].chars().next().expect("in bounds");
        let prev_is_word = s[..i].chars().next_back().is_some_and(is_word);
        let token_end = match c {
            '"' => Some((quoted_end(s, i, '"'), STRING)),
            '\'' => Some((quoted_end(s, i, '\''), STRING)),
            '#' => Some((s.len(), COMMENT)),
            ':' if !prev_is_word => {
                let end = s[i + 1..]
                    .find(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                    .map_or(s.len(), |e| i + 1 + e);
                Some((end, LABEL))
            }
            'L' | '[' if !prev_is_word => {
                let start_of_class = s[i..].find(|ch| ch != '[').map(|e| i + e);
                match start_of_class {
                    Some(p) if s[p..].starts_with('L') => s[p..]
                        .find(';')
                        .filter(|&e| !s[p..p + e].contains(' '))
                        .map(|e| (p + e + 1, TYPE)),
                    Some(p) if c == '[' => {
                        Some((p + s[p..].chars().next().map_or(0, char::len_utf8), TYPE))
                    }
                    _ => None,
                }
            }
            'v' | 'p' if !prev_is_word => {
                let digits = s[i + 1..]
                    .find(|ch: char| !ch.is_ascii_digit())
                    .unwrap_or(s.len() - i - 1);
                let end = i + 1 + digits;
                let next_is_word = s[end..].chars().next().is_some_and(is_word);
                (digits > 0 && !next_is_word).then_some((end, REGISTER))
            }
            '-' | '0'..='9' if !prev_is_word => {
                let end = s[i + 1..]
                    .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.'))
                    .map_or(s.len(), |e| i + 1 + e);
                (c != '-' || s[i + 1..].starts_with(|ch: char| ch.is_ascii_digit()))
                    .then_some((end, NUMBER))
            }
            _ => None,
        };
        match token_end {
            Some((end, color)) => {
                flush(job, plain_start, i);
                append(job, &s[i..end], color, font);
                i = end;
                plain_start = end;
            }
            None => i += c.len_utf8(),
        }
    }
    flush(job, plain_start, s.len());
}

fn xml(job: &mut LayoutJob, line: &str, font: &FontId) {
    let s = line;
    let mut i = 0;
    let mut plain_start = 0;
    let flush = |job: &mut LayoutJob, from: usize, to: usize| append(job, &s[from..to], TEXT, font);
    while i < s.len() {
        let rest = &s[i..];
        let c = rest.chars().next().expect("in bounds");
        let token: Option<(usize, Color32)> = if rest.starts_with("<!--") {
            Some((rest.find("-->").map_or(s.len(), |e| i + e + 3), COMMENT))
        } else if c == '<' {
            let punct_len = if rest.starts_with("</") || rest.starts_with("<?") {
                2
            } else {
                1
            };
            flush(job, plain_start, i);
            append(job, &rest[..punct_len], PUNCT, font);
            i += punct_len;
            plain_start = i;
            let name_len = s[i..]
                .find(|ch: char| ch.is_whitespace() || matches!(ch, '>' | '/' | '?'))
                .unwrap_or(s.len() - i);
            Some((i + name_len, KEYWORD))
        } else if c == '"' {
            Some((quoted_end(s, i, '"'), STRING))
        } else if matches!(c, '>' | '/' | '?' | '=') {
            Some((i + 1, PUNCT))
        } else if c.is_alphabetic()
            && !s[..i]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric)
        {
            let len = rest
                .find(|ch: char| !(ch.is_alphanumeric() || matches!(ch, ':' | '_' | '-' | '.')))
                .unwrap_or(rest.len());
            rest[len..].starts_with('=').then_some((i + len, REGISTER))
        } else {
            None
        };
        match token {
            Some((end, color)) => {
                flush(job, plain_start, i);
                append(job, &s[i..end], color, font);
                i = end;
                plain_start = end;
            }
            None => i += c.len_utf8(),
        }
    }
    flush(job, plain_start, s.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sections(line: &str, syntax: Syntax) -> Vec<(String, Color32)> {
        let mut job = LayoutJob::default();
        highlight_into(&mut job, line, syntax, &FontId::monospace(12.0));
        job.sections
            .iter()
            .map(|s| (job.text[s.byte_range.clone()].to_owned(), s.format.color))
            .collect()
    }

    #[test]
    fn smali_tokens() {
        let line = "    invoke-virtual {p0, v1}, Lcom/Foo;->bar(I)V # call";
        let s = sections(line, Syntax::Smali);
        let text: String = s.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(text, line);
        assert!(s.contains(&("invoke-virtual".into(), KEYWORD)));
        assert!(s.contains(&("p0".into(), REGISTER)));
        assert!(s.contains(&("Lcom/Foo;".into(), TYPE)));
        assert!(s.contains(&("# call".into(), COMMENT)));

        let s = sections("    const-string v0, \"a\\\"b\"", Syntax::Smali);
        assert!(s.contains(&("\"a\\\"b\"".into(), STRING)));
        let s = sections("    if-eqz v0, :cond_1a", Syntax::Smali);
        assert!(s.contains(&(":cond_1a".into(), LABEL)));
        let s = sections("    const/4 v0, -0x1", Syntax::Smali);
        assert!(s.contains(&("-0x1".into(), NUMBER)));
    }

    #[test]
    fn xml_tokens() {
        let line = "<uses-sdk android:minSdkVersion=\"21\" />";
        let s = sections(line, Syntax::Xml);
        let text: String = s.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(text, line);
        assert!(s.contains(&("uses-sdk".into(), KEYWORD)));
        assert!(s.contains(&("android:minSdkVersion".into(), REGISTER)));
        assert!(s.contains(&("\"21\"".into(), STRING)));
    }

    #[test]
    fn handles_unicode_and_garbage() {
        for line in [
            "  ä\"ö", "<", "\"", "    :", "  L", "  [", "#ü", "  v", "<!-- x",
        ] {
            for syntax in [Syntax::Smali, Syntax::Xml] {
                let s = sections(line, syntax);
                let text: String = s.iter().map(|(t, _)| t.as_str()).collect();
                assert_eq!(text, line);
            }
        }
    }
}
