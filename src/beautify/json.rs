//! JSON reindenter. Works on tokens rather than a parsed tree, so number
//! spellings, key order and duplicate keys are kept exactly as they are.

use super::{Res, Writer};

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_structural(b: u8) -> bool {
    matches!(b, b'"' | b'{' | b'}' | b'[' | b']' | b',' | b':') || is_ws(b)
}

/// Index just past the string starting at `start` (a `"`).
fn string_end(b: &[u8], start: usize) -> usize {
    let mut j = start + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

pub(super) fn format(src: &str, w: &mut Writer) -> Res {
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            c if is_ws(c) => i += 1,
            b'"' => {
                let end = string_end(b, i);
                w.write(&src[i..end])?;
                i = end;
            }
            c @ (b'{' | b'[') => {
                let close = if c == b'{' { b'}' } else { b']' };
                let mut j = i + 1;
                while j < b.len() && is_ws(b[j]) {
                    j += 1;
                }
                if b.get(j) == Some(&close) {
                    w.write(if c == b'{' { "{}" } else { "[]" })?;
                    i = j + 1;
                } else {
                    w.write(&src[i..=i])?;
                    w.indent();
                    w.newline();
                    i += 1;
                }
            }
            b'}' | b']' => {
                w.dedent();
                w.newline();
                w.write(&src[i..=i])?;
                if w.level() == 0 {
                    w.newline();
                }
                i += 1;
            }
            b',' => {
                w.write(",")?;
                w.newline();
                i += 1;
            }
            b':' => {
                w.write(": ")?;
                i += 1;
            }
            _ => {
                // Literals, numbers or (invalid) stray text, up to the next
                // structural byte; those are ASCII, so slicing stays on char
                // boundaries.
                let start = i;
                i += 1;
                while i < b.len() && !is_structural(b[i]) {
                    i += 1;
                }
                w.write(&src[start..i])?;
            }
        }
    }
    Ok(())
}

/// Cheap structural validation used to sniff JSON in files without a
/// `.json` extension.
pub(super) fn is_plausible(src: &str) -> bool {
    let b = src.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut i = 0;
    let mut values = 0;
    while i < b.len() {
        match b[i] {
            c if is_ws(c) => i += 1,
            b'"' => {
                let end = string_end(b, i);
                if end == b.len() && b.last() != Some(&b'"') || end - i < 2 {
                    return false;
                }
                values += 1;
                i = end;
            }
            b'{' => {
                stack.push(b'}');
                i += 1;
            }
            b'[' => {
                stack.push(b']');
                i += 1;
            }
            c @ (b'}' | b']') => {
                if stack.pop() != Some(c) {
                    return false;
                }
                i += 1;
            }
            b',' | b':' => i += 1,
            c if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'+' | b'.') => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'-' | b'+' | b'.'))
                {
                    i += 1;
                }
                let word = &src[start..i];
                let number = word.starts_with(|c: char| c.is_ascii_digit() || c == '-');
                if !(number || matches!(word, "true" | "false" | "null")) {
                    return false;
                }
                values += 1;
            }
            _ => return false,
        }
    }
    stack.is_empty() && (values > 0 || src.trim() == "{}" || src.trim() == "[]")
}

#[cfg(test)]
mod tests {
    use super::super::{Format, beautify};
    use super::*;

    #[test]
    fn pretty_prints() {
        let out = beautify(
            Format::Json,
            r#"{"a":1,"b":[true,null,{}],"c":{"d":"x,y:{}"},"e":[],"n":-1.5e+10}"#,
        )
        .unwrap();
        assert_eq!(
            out,
            r#"{
  "a": 1,
  "b": [
    true,
    null,
    {}
  ],
  "c": {
    "d": "x,y:{}"
  },
  "e": [],
  "n": -1.5e+10
}
"#
        );
    }

    #[test]
    fn keeps_escapes_and_unicode() {
        let out = beautify(Format::Json, r#"["a\"b\\",  "ü😀"]"#).unwrap();
        assert_eq!(out, "[\n  \"a\\\"b\\\\\",\n  \"ü😀\"\n]\n");
    }

    #[test]
    fn plausibility() {
        assert!(is_plausible(r#"{"a":[1,2,{"b":null}]}"#));
        assert!(is_plausible("[]"));
        assert!(!is_plausible("{a b}c"));
        assert!(!is_plausible("[1,2"));
        assert!(!is_plausible("{\"unterminated}"));
    }
}
