//! XML / HTML reindenter.
//!
//! Tags are put on their own lines and indented by nesting depth; elements
//! containing only short text stay on one line (`<b>text</b>`). In HTML,
//! void elements are handled, `<script>` and `<style>` contents are
//! beautified as JavaScript / CSS, and `<pre>` / `<textarea>` are kept
//! verbatim.

use super::{Format, Res, Writer, beautify};

const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];
const RAW: &[&str] = &["script", "style", "pre", "textarea"];
const INLINE_TEXT_MAX: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok<'a> {
    Open {
        name: &'a str,
        text: &'a str,
        self_closing: bool,
    },
    Close {
        name: &'a str,
        text: &'a str,
    },
    /// Comment, processing instruction, doctype or CDATA.
    Other(&'a str),
    Text(&'a str),
    /// Contents of a raw-text HTML element.
    Raw(&'a str),
}

fn find_from(src: &str, from: usize, needle: &str) -> Option<usize> {
    src.get(from..)?.find(needle).map(|p| from + p)
}

/// Position of `</name` (ASCII case-insensitive) at or after `from`.
fn find_close_ci(src: &str, from: usize, name: &str) -> Option<usize> {
    let b = src.as_bytes();
    let mut pos = from;
    while let Some(p) = find_from(src, pos, "</") {
        let start = p + 2;
        if b.len() >= start + name.len()
            && b[start..start + name.len()].eq_ignore_ascii_case(name.as_bytes())
        {
            return Some(p);
        }
        pos = p + 2;
    }
    None
}

fn tag_name(text: &str, skip: usize) -> &str {
    let rest = text.get(skip..).unwrap_or("");
    let end = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '/' | '>'))
        .unwrap_or(rest.len());
    &rest[..end]
}

fn tokenize(src: &str, html: bool) -> Vec<Tok<'_>> {
    let b = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            let end = find_from(src, i, "<").unwrap_or(src.len());
            toks.push(Tok::Text(&src[i..end]));
            i = end;
            continue;
        }
        let rest = &src[i..];
        let delimited = |open: usize, close: &str| {
            find_from(src, i + open, close).map_or(src.len(), |p| p + close.len())
        };
        let end = if rest.starts_with("<!--") {
            delimited(4, "-->")
        } else if rest.starts_with("<![CDATA[") {
            delimited(9, "]]>")
        } else if rest.starts_with("<?") {
            delimited(2, "?>")
        } else if rest.starts_with("<!") || rest.starts_with("</") {
            delimited(2, ">")
        } else if b
            .get(i + 1)
            .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, b'_' | b':'))
        {
            // Opening tag; `>` inside quoted attribute values does not end it.
            let mut j = i + 1;
            let mut quote = None;
            while j < b.len() {
                match (quote, b[j]) {
                    (None, q @ (b'"' | b'\'')) => quote = Some(q),
                    (Some(q), c) if c == q => quote = None,
                    (None, b'>') => break,
                    _ => {}
                }
                j += 1;
            }
            (j + 1).min(b.len())
        } else {
            // A lone `<` is text.
            let end = find_from(src, i + 1, "<").unwrap_or(src.len());
            toks.push(Tok::Text(&src[i..end]));
            i = end;
            continue;
        };
        let text = &src[i..end];
        if rest.starts_with("</") {
            toks.push(Tok::Close {
                name: tag_name(text, 2),
                text,
            });
        } else if rest.starts_with("<!") || rest.starts_with("<?") {
            toks.push(Tok::Other(text));
        } else {
            let name = tag_name(text, 1);
            let self_closing = text.ends_with("/>");
            toks.push(Tok::Open {
                name,
                text,
                self_closing,
            });
            let lower = name.to_ascii_lowercase();
            if html && !self_closing && RAW.contains(&lower.as_str()) {
                let close = find_close_ci(src, end, &lower).unwrap_or(src.len());
                toks.push(Tok::Raw(&src[end..close]));
                i = close;
                continue;
            }
        }
        i = end;
    }
    toks
}

fn collapse(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn same_name(a: &str, b: &str, html: bool) -> bool {
    if html {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

pub(super) fn format(src: &str, html: bool, w: &mut Writer) -> Res {
    let toks = tokenize(src, html);
    let mut stack: Vec<&str> = Vec::new();
    let mut inline_close = false;
    let mut i = 0;
    while i < toks.len() {
        match toks[i] {
            Tok::Text(t) => {
                let text = collapse(t);
                if !text.is_empty() {
                    w.newline();
                    w.write(&text)?;
                }
            }
            Tok::Other(t) => {
                w.newline();
                w.write(t)?;
                w.newline();
            }
            Tok::Raw(content) => {
                let lower = match i.checked_sub(1).map(|p| toks[p]) {
                    Some(Tok::Open { name, .. }) => name.to_ascii_lowercase(),
                    _ => String::new(),
                };
                match lower.as_str() {
                    "script" | "style" => {
                        let inner = content.trim();
                        if !inner.is_empty() {
                            let format = if lower == "style" {
                                Format::Css
                            } else {
                                Format::JavaScript
                            };
                            let formatted =
                                beautify(format, inner).unwrap_or_else(|| inner.to_owned());
                            w.indent();
                            for line in formatted.lines() {
                                w.newline();
                                w.write(line)?;
                            }
                            w.dedent();
                        }
                    }
                    _ => {
                        // <pre>/<textarea>: whitespace is significant.
                        w.write(content)?;
                        inline_close = true;
                    }
                }
            }
            Tok::Close { name, text } => {
                if !inline_close {
                    w.newline();
                }
                if let Some(pos) = stack.iter().rposition(|open| same_name(open, name, html)) {
                    for _ in pos..stack.len() {
                        w.dedent();
                    }
                    stack.truncate(pos);
                    // Re-render the indentation of this line at the new level.
                    if !inline_close {
                        w.newline();
                    }
                }
                w.write(text)?;
                w.newline();
                inline_close = false;
            }
            Tok::Open {
                name,
                text,
                self_closing,
            } => {
                w.newline();
                w.write(text)?;
                let lower = name.to_ascii_lowercase();
                if self_closing || (html && VOID.contains(&lower.as_str())) {
                    w.newline();
                } else if html && RAW.contains(&lower.as_str()) {
                    // Contents follow as a `Raw` token.
                } else {
                    let closes = |tok: Option<&Tok>| matches!(tok, Some(Tok::Close { name: n, .. }) if same_name(n, name, html));
                    let inline = match toks.get(i + 1) {
                        Some(Tok::Text(t)) if closes(toks.get(i + 2)) => {
                            let text = collapse(t);
                            (text.len() <= INLINE_TEXT_MAX).then_some((text, 2))
                        }
                        next if closes(next) => Some((String::new(), 1)),
                        _ => None,
                    };
                    match inline {
                        Some((text, skip)) => {
                            w.write(&text)?;
                            if let Some(Tok::Close { text: close, .. }) = toks.get(i + skip) {
                                w.write(close)?;
                            }
                            w.newline();
                            i += skip;
                        }
                        None => {
                            stack.push(name);
                            w.indent();
                            w.newline();
                        }
                    }
                }
            }
        }
        i += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Format, beautify};

    #[test]
    fn indents_xml() {
        let out = beautify(
            Format::Xml,
            "<?xml version=\"1.0\"?><a x=\"1>2\"><b>text</b><c/><d><e></e></d><!-- c --></a>",
        )
        .unwrap();
        assert_eq!(
            out,
            "<?xml version=\"1.0\"?>
<a x=\"1>2\">
    <b>text</b>
    <c/>
    <d>
        <e></e>
    </d>
    <!-- c -->
</a>
"
        );
    }

    #[test]
    fn html_specials() {
        let out = beautify(
            Format::Html,
            "<!DOCTYPE html><html><head><meta charset=utf-8><script>var a=1;if(a){b()}</script>\
             <style>a{color:red}</style></head><body><pre> keep\n  me </pre><p>Hi <b>x</b></p></body></HTML>",
        )
        .unwrap();
        assert_eq!(
            out,
            "<!DOCTYPE html>
<html>
    <head>
        <meta charset=utf-8>
        <script>
            var a = 1;
            if (a) {
              b()
            }
        </script>
        <style>
            a {
              color: red
            }
        </style>
    </head>
    <body>
        <pre> keep\n  me </pre>
        <p>
            Hi
            <b>x</b>
        </p>
    </body>
</HTML>
"
        );
    }
}
