//! Pretty-printing ("beautifying") of minified text content: JSON, XML/HTML,
//! CSS and JavaScript.
//!
//! The beautifiers only change whitespace between tokens. Every other
//! character is copied verbatim, so the output is equivalent to the input
//! (and invalid input is still shown in full, just formatted less nicely).

mod css;
mod js;
mod json;
mod markup;

/// Larger inputs are shown as-is.
pub const MAX_INPUT: usize = 32 << 20;
/// Indentation stops growing beyond this depth, which bounds the output size
/// for pathologically nested input.
const MAX_INDENT: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Json,
    Xml,
    Html,
    Css,
    JavaScript,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Json => "JSON",
            Format::Xml => "XML",
            Format::Html => "HTML",
            Format::Css => "CSS",
            Format::JavaScript => "JavaScript",
        }
    }
}

pub struct Processed {
    /// Detected format (used for syntax highlighting), if any.
    pub format: Option<Format>,
    /// The beautified text, if it differs from the input.
    pub beautified: Option<String>,
}

/// Detects the format of a text file and beautifies it if appropriate. JSON
/// is always pretty-printed; other formats only when they look minified, so
/// hand-formatted code keeps its layout.
pub fn process(path: &str, text: &str) -> Processed {
    let format = detect(path, text);
    let beautified = format
        .filter(|&f| text.len() <= MAX_INPUT && (f == Format::Json || looks_minified(text)))
        .and_then(|f| beautify(f, text))
        .filter(|out| out.trim_end() != text.trim_end());
    Processed { format, beautified }
}

/// Beautifies `text`. Returns `None` if the output would grow unreasonably.
pub fn beautify(format: Format, text: &str) -> Option<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let unit = match format {
        Format::Xml | Format::Html => "    ",
        _ => "  ",
    };
    let mut w = Writer::new(unit, text.len());
    let result = match format {
        Format::Json => json::format(text, &mut w),
        Format::Xml => markup::format(text, false, &mut w),
        Format::Html => markup::format(text, true, &mut w),
        Format::Css => css::format(text, &mut w),
        Format::JavaScript => js::format(text, &mut w),
    };
    result.ok()?;
    Some(w.finish())
}

pub fn detect(path: &str, text: &str) -> Option<Format> {
    let file = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let ext = file.rsplit_once('.').map_or("", |(_, e)| e);
    let by_ext = match ext {
        "json" | "geojson" | "webmanifest" | "map" | "har" => Some(Format::Json),
        "xml" | "svg" | "plist" | "xsd" | "xsl" | "xslt" | "rss" | "atom" | "kml" | "gpx" => {
            Some(Format::Xml)
        }
        "html" | "htm" | "xhtml" => Some(Format::Html),
        "css" => Some(Format::Css),
        "js" | "mjs" | "cjs" | "bundle" | "jsbundle" => Some(Format::JavaScript),
        _ => None,
    };
    if by_ext.is_some() {
        return by_ext;
    }
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if (t.starts_with('{') || t.starts_with('[')) && json::is_plausible(t) {
        Some(Format::Json)
    } else if t.starts_with("<?xml") {
        Some(Format::Xml)
    } else if t
        .get(..14)
        .is_some_and(|s| s.eq_ignore_ascii_case("<!doctype html"))
        || t.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("<html"))
    {
        Some(Format::Html)
    } else {
        None
    }
}

/// Minified files consist mostly of very long lines.
pub fn looks_minified(text: &str) -> bool {
    let mut long_bytes = 0usize;
    let mut lines = 0usize;
    for line in text.split('\n') {
        lines += 1;
        if line.len() > 200 {
            long_bytes += line.len();
        }
    }
    (long_bytes > 0 && long_bytes * 5 >= text.len()) || (lines <= 3 && text.trim().len() > 80)
}

pub(crate) struct Overflow;
pub(crate) type Res = Result<(), Overflow>;

/// Output buffer that tracks indentation and line starts.
pub(crate) struct Writer {
    out: String,
    level: usize,
    unit: &'static str,
    line_start: bool,
    limit: usize,
}

impl Writer {
    fn new(unit: &'static str, input_len: usize) -> Self {
        Self {
            out: String::with_capacity(input_len + input_len / 4),
            level: 0,
            unit,
            line_start: true,
            limit: input_len.saturating_mul(8).saturating_add(1 << 20),
        }
    }

    /// Appends text, indenting first if at the start of a line.
    pub(crate) fn write(&mut self, s: &str) -> Res {
        if s.is_empty() {
            return Ok(());
        }
        if self.line_start {
            for _ in 0..self.level.min(MAX_INDENT) {
                self.out.push_str(self.unit);
            }
            self.line_start = false;
        }
        self.out.push_str(s);
        if self.out.len() > self.limit {
            Err(Overflow)
        } else {
            Ok(())
        }
    }

    pub(crate) fn space(&mut self) {
        if !self.line_start && !self.out.ends_with([' ', '\n']) {
            self.out.push(' ');
        }
    }

    pub(crate) fn newline(&mut self) {
        if !self.line_start {
            let len = self.out.trim_end_matches(' ').len();
            self.out.truncate(len);
            self.out.push('\n');
            self.line_start = true;
        }
    }

    pub(crate) fn blank_line(&mut self) {
        self.newline();
        if !self.out.is_empty() && !self.out.ends_with("\n\n") {
            self.out.push('\n');
        }
    }

    pub(crate) fn indent(&mut self) {
        self.level += 1;
    }

    pub(crate) fn dedent(&mut self) {
        self.level = self.level.saturating_sub(1);
    }

    pub(crate) fn level(&self) -> usize {
        self.level
    }

    pub(crate) fn at_line_start(&self) -> bool {
        self.line_start
    }

    pub(crate) fn last_char(&self) -> Option<char> {
        self.out.chars().next_back()
    }

    fn finish(mut self) -> String {
        let len = self.out.trim_end().len();
        self.out.truncate(len);
        self.out.push('\n');
        self.out
    }
}

#[cfg(test)]
pub(crate) fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_formats() {
        assert_eq!(detect("assets/a.json", ""), Some(Format::Json));
        assert_eq!(detect("manifest", "{\"a\":1}"), Some(Format::Json));
        assert_eq!(detect("x.bin", "{not json"), None);
        assert_eq!(detect("index.android.bundle", ""), Some(Format::JavaScript));
        assert_eq!(detect("a/b.HTML", ""), Some(Format::Html));
        assert_eq!(detect("page", "<!DOCTYPE html><html>"), Some(Format::Html));
        assert_eq!(
            detect("data", "<?xml version=\"1.0\"?><a/>"),
            Some(Format::Xml)
        );
        assert_eq!(detect("dir.v2/readme", "hello"), None);
    }

    #[test]
    fn only_minified_code_is_reformatted() {
        let pretty = "function a() {\n  return 1;\n}\n".repeat(50);
        assert!(process("a.js", &pretty).beautified.is_none());
        let minified = "function a(){return 1}".repeat(50);
        assert!(process("a.js", &minified).beautified.is_some());
        // JSON is always pretty-printed.
        assert!(process("a.json", "{\"a\":1}").beautified.is_some());
        assert!(process("a.json", "{\n  \"a\": 1\n}\n").beautified.is_none());
    }

    #[test]
    fn garbage_never_panics_and_keeps_content() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let alphabet: Vec<char> =
            "{}[]()<>/\\*'\"`$:;,.=+-!?#@%^&|~ \n\tabcxyz019éü<!--CDATA[]]>?>/*"
                .chars()
                .collect();
        for _ in 0..3000 {
            let len = (seed % 64) as usize;
            let mut s = String::new();
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                s.push(alphabet[(seed % alphabet.len() as u64) as usize]);
            }
            for format in [
                Format::Json,
                Format::Xml,
                Format::Html,
                Format::Css,
                Format::JavaScript,
            ] {
                let out = beautify(format, &s).expect("small input never overflows");
                assert_eq!(
                    strip_ws(&out),
                    strip_ws(&s),
                    "{format:?} changed {s:?} into {out:?}"
                );
            }
        }
    }

    #[test]
    fn deep_nesting_is_bounded() {
        // Output is capped (indentation stops growing, and overly large
        // results are rejected so the raw text is shown instead).
        let deep = "[".repeat(200_000) + &"]".repeat(200_000);
        assert!(beautify(Format::Json, &deep).is_none());
        let deep = "[".repeat(2_000) + &"]".repeat(2_000);
        let out = beautify(Format::Json, &deep).unwrap();
        assert!(out.lines().all(|l| l.len() <= 2 * MAX_INDENT + 2));
    }
}
