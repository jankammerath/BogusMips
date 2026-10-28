//! CSS reindenter: one declaration per line, rules separated by blank lines.

use super::{Res, Writer};

/// For each byte position, the next of `;`, `{`, `}` (outside strings and
/// comments) at or after it, or 0 if none. Used to tell declarations
/// (`color:red;`) from selectors (`a:hover{`) in linear time.
fn next_structural(b: &[u8]) -> Vec<u8> {
    let mut next = vec![0u8; b.len() + 1];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' | b'\'' => i = quoted_end(b, i),
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i += 2;
            }
            c @ (b';' | b'{' | b'}') => {
                next[i] = c;
                i += 1;
            }
            _ => i += 1,
        }
    }
    for i in (0..b.len()).rev() {
        if next[i] == 0 {
            next[i] = next[i + 1];
        }
    }
    next
}

fn quoted_end(b: &[u8], start: usize) -> usize {
    let quote = b[start];
    let mut j = start + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'\n' => return j,
            c if c == quote => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

pub(super) fn format(src: &str, w: &mut Writer) -> Res {
    let b = src.as_bytes();
    let next = next_structural(b);
    let mut i = 0;
    let mut parens = 0usize;
    let mut ws = false;
    while i < b.len() {
        let c = b[i];
        if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0c) {
            ws = true;
            i += 1;
            continue;
        }
        let pending_ws = std::mem::take(&mut ws);
        match c {
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = src
                    .get(i + 2..)
                    .and_then(|r| r.find("*/"))
                    .map_or(b.len(), |p| i + 2 + p + 2);
                let own_line = w.at_line_start();
                if pending_ws {
                    w.space();
                }
                w.write(&src[i..end])?;
                if own_line {
                    w.newline();
                }
                i = end;
            }
            b'"' | b'\'' => {
                let end = quoted_end(b, i);
                if pending_ws {
                    w.space();
                }
                w.write(&src[i..end])?;
                i = end;
            }
            b'{' => {
                w.space();
                w.write("{")?;
                w.indent();
                w.newline();
                i += 1;
            }
            b'}' => {
                w.dedent();
                w.newline();
                w.write("}")?;
                if w.level() == 0 {
                    w.blank_line();
                } else {
                    w.newline();
                }
                i += 1;
            }
            b';' => {
                w.write(";")?;
                if parens == 0 {
                    w.newline();
                }
                i += 1;
            }
            b':' if parens == 0 && w.level() > 0 && next[i] != b'{' => {
                // Declaration (`prop: value`); whitespace before is dropped.
                w.write(": ")?;
                i += 1;
            }
            b',' if parens == 0 => {
                w.write(",")?;
                if next[i] == b'{' {
                    // Selector list: one selector per line.
                    w.newline();
                } else {
                    w.write(" ")?;
                }
                i += 1;
            }
            _ => {
                if pending_ws {
                    w.space();
                }
                let start = i;
                match c {
                    b'(' => {
                        parens += 1;
                        i += 1;
                    }
                    b')' => {
                        parens = parens.saturating_sub(1);
                        i += 1;
                    }
                    _ => {
                        i += 1;
                        while i < b.len()
                            && !matches!(
                                b[i],
                                b' ' | b'\t'
                                    | b'\n'
                                    | b'\r'
                                    | 0x0c
                                    | b'/'
                                    | b'"'
                                    | b'\''
                                    | b'{'
                                    | b'}'
                                    | b';'
                                    | b':'
                                    | b','
                                    | b'('
                                    | b')'
                            )
                        {
                            i += 1;
                        }
                    }
                }
                w.write(&src[start..i])?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Format, beautify};

    #[test]
    fn formats_rules() {
        let out = beautify(
            Format::Css,
            "a:hover,b>c{color:red;background:url(data:image/png;base64,AA==)}\
             @media (max-width:600px){.x{margin:0 auto}}/*c*/d{content:\"{;}\"}",
        )
        .unwrap();
        assert_eq!(
            out,
            "a:hover,
b>c {
  color: red;
  background: url(data:image/png;base64,AA==)
}

@media (max-width:600px) {
  .x {
    margin: 0 auto
  }
}

/*c*/
d {
  content: \"{;}\"
}
"
        );
    }

    #[test]
    fn keeps_descendant_combinator_before_pseudo_class() {
        // `a :hover` (any hovered descendant) differs from `a:hover`.
        let out = beautify(Format::Css, "a :hover{x:y}").unwrap();
        assert!(out.starts_with("a :hover {"), "{out}");
    }
}
