//! JavaScript beautifier.
//!
//! A lexer splits the source into tokens (telling regex literals from
//! division, and scanning template literals with nested `${…}` expressions);
//! the formatter then only adds whitespace between tokens. Original line
//! breaks are kept, so automatic semicolon insertion behaves the same, and
//! whitespace that separated two tokens in the source is never removed where
//! that could merge them (`a + +b`, `1 .toString()`).

use super::{Res, Writer};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Word,
    Number,
    Str,
    Template,
    Regex,
    Punct,
    LineComment,
    BlockComment,
}

#[derive(Clone, Copy, Debug)]
struct Tok<'a> {
    kind: Kind,
    text: &'a str,
    ws_before: bool,
    nl_before: bool,
}

/// Keywords after which an expression (and thus a regex literal) may start.
const EXPRESSION_KEYWORDS: &[&str] = &[
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
    "extends",
];
const CONTROL_KEYWORDS: &[&str] = &["if", "for", "while", "switch", "catch", "with"];
const PUNCTUATORS: &[&str] = &[
    ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "=>", "==", "!=",
    "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    "**", "<<", ">>",
];
const ALWAYS_BINARY: &[&str] = &[
    "=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=",
    "??=", "==", "!=", "===", "!==", "<", ">", "<=", ">=", "&&", "||", "??", "=>", "?", "**", "<<",
    ">>", ">>>", "%", "&", "|", "^",
];

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'$' | b'_' | b'\\') || c >= 0x80
}

struct Lexer<'a> {
    src: &'a str,
    b: &'a [u8],
    i: usize,
    prev: Option<(Kind, &'a str)>,
    /// For each open `(`: whether it follows a control keyword (`if (`…).
    parens: Vec<bool>,
    last_paren_control: bool,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            b: src.as_bytes(),
            i: 0,
            prev: None,
            parens: Vec::new(),
            last_paren_control: false,
        }
    }

    fn regex_allowed(&self) -> bool {
        match self.prev {
            None => true,
            Some((Kind::Punct, ")")) => self.last_paren_control,
            Some((Kind::Punct, p)) => !matches!(p, "]" | "++" | "--"),
            Some((Kind::Word, w)) => EXPRESSION_KEYWORDS.contains(&w),
            _ => false,
        }
    }

    fn string_end(&self, start: usize) -> usize {
        let b = self.b;
        let quote = b[start];
        let mut j = start + 1;
        while j < b.len() {
            match b[j] {
                b'\\' if b.get(j + 1) == Some(&b'\r') && b.get(j + 2) == Some(&b'\n') => j += 3,
                b'\\' => j += 2,
                b'\n' | b'\r' => return j,
                c if c == quote => return j + 1,
                _ => j += 1,
            }
        }
        b.len()
    }

    fn template_end(&self, start: usize) -> usize {
        enum Frame {
            Template,
            Expr(u32),
        }
        let b = self.b;
        let mut frames = vec![Frame::Template];
        let mut j = start + 1;
        while j < b.len() {
            let Some(top) = frames.last_mut() else {
                return j;
            };
            match top {
                Frame::Template => match b[j] {
                    b'\\' => j += 2,
                    b'`' => {
                        frames.pop();
                        j += 1;
                        if frames.is_empty() {
                            return j;
                        }
                    }
                    b'$' if b.get(j + 1) == Some(&b'{') => {
                        frames.push(Frame::Expr(0));
                        j += 2;
                    }
                    _ => j += 1,
                },
                Frame::Expr(depth) => match b[j] {
                    b'{' => {
                        *depth += 1;
                        j += 1;
                    }
                    b'}' => {
                        if *depth == 0 {
                            frames.pop();
                        } else {
                            *depth -= 1;
                        }
                        j += 1;
                    }
                    b'`' => {
                        frames.push(Frame::Template);
                        j += 1;
                    }
                    b'"' | b'\'' => j = self.string_end(j),
                    b'/' if b.get(j + 1) == Some(&b'/') => {
                        j = self.src[j..].find('\n').map_or(b.len(), |p| j + p);
                    }
                    b'/' if b.get(j + 1) == Some(&b'*') => {
                        j = self.src[j + 2..]
                            .find("*/")
                            .map_or(b.len(), |p| j + 2 + p + 2);
                    }
                    _ => j += 1,
                },
            }
        }
        b.len()
    }

    fn regex_end(&self, start: usize) -> Option<usize> {
        let b = self.b;
        let mut j = start + 1;
        let mut in_class = false;
        while j < b.len() {
            match b[j] {
                b'\\' => {
                    if matches!(b.get(j + 1), None | Some(b'\n' | b'\r')) {
                        return None;
                    }
                    j += 2;
                    continue;
                }
                b'\n' | b'\r' => return None,
                b'[' => in_class = true,
                b']' => in_class = false,
                b'/' if !in_class => {
                    j += 1;
                    while j < b.len() && is_ident_byte(b[j]) && b[j] < 0x80 && b[j] != b'\\' {
                        j += 1;
                    }
                    return Some(j);
                }
                _ => {}
            }
            j += 1;
        }
        None
    }

    fn number_end(&self, start: usize) -> usize {
        let b = self.b;
        let hex = b.get(start + 1).is_some_and(|c| matches!(c, b'x' | b'X'));
        let mut j = start;
        loop {
            while j < b.len() && (b[j].is_ascii_alphanumeric() || matches!(b[j], b'_' | b'.')) {
                j += 1;
            }
            let exponent_sign = !hex
                && j > start
                && matches!(b[j - 1], b'e' | b'E')
                && matches!(b.get(j), Some(b'+' | b'-'));
            if !exponent_sign {
                return j;
            }
            j += 1;
        }
    }

    fn ident_end(&self, start: usize) -> usize {
        let b = self.b;
        let mut j = start + self.src[start..].chars().next().map_or(1, char::len_utf8);
        while j < b.len() {
            match b[j] {
                b'\\' if b.get(j + 1) == Some(&b'u') && b.get(j + 2) == Some(&b'{') => {
                    j = self.src[j..].find('}').map_or(b.len(), |p| j + p + 1);
                }
                c if c >= 0x80 => {
                    let ch = self.src[j..].chars().next().expect("in bounds");
                    if ch.is_whitespace() || ch == '\u{feff}' {
                        break;
                    }
                    j += ch.len_utf8();
                }
                c if is_ident_byte(c) => j += 1,
                _ => break,
            }
        }
        j
    }

    fn next(&mut self) -> Option<Tok<'a>> {
        let (b, src) = (self.b, self.src);
        let (mut ws, mut nl) = (false, false);
        while self.i < b.len() {
            match b[self.i] {
                b' ' | b'\t' | 0x0b | 0x0c => self.i += 1,
                b'\n' | b'\r' => {
                    nl = true;
                    self.i += 1;
                }
                c if c >= 0x80 => {
                    let ch = src[self.i..].chars().next().expect("in bounds");
                    if !(ch.is_whitespace() || ch == '\u{feff}') {
                        break;
                    }
                    nl |= matches!(ch, '\u{2028}' | '\u{2029}');
                    self.i += ch.len_utf8();
                }
                _ => break,
            }
            ws = true;
        }
        let start = self.i;
        let c = *b.get(start)?;
        let next = b.get(start + 1).copied();
        let (kind, end) = match c {
            b'#' if start == 0 && next == Some(b'!') => {
                (Kind::LineComment, src.find('\n').unwrap_or(b.len()))
            }
            b'/' if next == Some(b'/') => (
                Kind::LineComment,
                src[start..]
                    .find(['\n', '\r'])
                    .map_or(b.len(), |p| start + p),
            ),
            b'/' if next == Some(b'*') => (
                Kind::BlockComment,
                src[start + 2..]
                    .find("*/")
                    .map_or(b.len(), |p| start + 2 + p + 2),
            ),
            b'\'' | b'"' => (Kind::Str, self.string_end(start)),
            b'`' => (Kind::Template, self.template_end(start)),
            b'0'..=b'9' => (Kind::Number, self.number_end(start)),
            b'.' if next.is_some_and(|n| n.is_ascii_digit()) => {
                (Kind::Number, self.number_end(start))
            }
            b'/' if self.regex_allowed() => match self.regex_end(start) {
                Some(end) => (Kind::Regex, end),
                None => (Kind::Punct, start + 1),
            },
            c if is_ident_byte(c) || c == b'#' => {
                if c >= 0x80 {
                    (Kind::Word, self.ident_end(start))
                } else if c == b'#' && !next.is_some_and(is_ident_byte) {
                    (Kind::Punct, start + 1)
                } else {
                    (Kind::Word, self.ident_end(start))
                }
            }
            _ => {
                let rest = &src[start..];
                let punct = PUNCTUATORS.iter().find(|p| {
                    rest.starts_with(**p)
                        && !(**p == "?."
                            && rest.as_bytes().get(2).is_some_and(|d| d.is_ascii_digit()))
                });
                let len = punct.map_or_else(
                    || rest.chars().next().map_or(1, char::len_utf8),
                    |p| p.len(),
                );
                (Kind::Punct, start + len)
            }
        };
        let end = end.max(start + 1).min(b.len());
        let end = (end..=b.len())
            .find(|&e| src.is_char_boundary(e))
            .unwrap_or(b.len());
        self.i = end;
        let text = &src[start..end];

        if !matches!(kind, Kind::LineComment | Kind::BlockComment) {
            if kind == Kind::Punct {
                match text {
                    "(" => {
                        let control = matches!(self.prev, Some((Kind::Word, w)) if CONTROL_KEYWORDS.contains(&w));
                        self.parens.push(control);
                    }
                    ")" => self.last_paren_control = self.parens.pop().unwrap_or(false),
                    _ => {}
                }
            }
            self.prev = Some((kind, text));
        }
        Some(Tok {
            kind,
            text,
            ws_before: ws,
            nl_before: nl,
        })
    }
}

#[derive(Clone, Copy)]
struct Frame {
    open: u8,
    is_for: bool,
    ternary: u32,
}

impl Frame {
    fn new(open: u8, is_for: bool) -> Self {
        Self {
            open,
            is_for,
            ternary: 0,
        }
    }
}

fn is_operand_end(t: &Tok) -> bool {
    match t.kind {
        Kind::Word => !EXPRESSION_KEYWORDS.contains(&t.text),
        Kind::Number | Kind::Str | Kind::Template | Kind::Regex => true,
        Kind::Punct => matches!(t.text, ")" | "]" | "}" | "++" | "--"),
        _ => false,
    }
}

fn is_binary(t: &Tok, prev: Option<&Tok>) -> bool {
    t.kind == Kind::Punct
        && (ALWAYS_BINARY.contains(&t.text)
            || (matches!(t.text, "+" | "-" | "*" | "/") && prev.is_some_and(is_operand_end)))
}

fn needs_space(prev: Option<&Tok>, t: &Tok) -> bool {
    use Kind::*;
    let Some(p) = prev else {
        return false;
    };
    match (p.kind, t.kind) {
        (Word, Template) => false,
        (Word | Number, Word | Number | Str | Regex)
        | (Str | Template | Regex, Word | Number)
        | (Word | Number | Str | Template | Regex, Punct)
            if t.kind != Punct || t.text == "{" =>
        {
            true
        }
        (Word, Punct) => t.text == "(" && CONTROL_KEYWORDS.contains(&p.text),
        (Punct, Word | Number | Str | Regex | Template) => matches!(p.text, ")" | "}"),
        (Punct, Punct) => t.text == "{" && !matches!(p.text, "(" | "[" | "!" | "..." | "{"),
        _ => false,
    }
}

/// Whether removing the whitespace between the previous output and `t`
/// can never change how the code tokenizes.
fn safe_to_join(last: Option<char>, t: &Tok) -> bool {
    last.is_none_or(|c| matches!(c, '(' | '[' | '{' | ' ' | '\n'))
        || t.text.starts_with([')', ']', '}', ',', ';'])
}

/// Tokens that stay on the same line as a preceding `}`.
fn continues_after_brace(next: Option<&Tok>) -> bool {
    match next {
        Some(n) if n.nl_before => false,
        Some(n) => match n.kind {
            Kind::Punct => {
                matches!(
                    n.text,
                    ")" | "]" | "," | ";" | "." | "?." | "(" | "[" | ":" | "+" | "-" | "*" | "/"
                ) || ALWAYS_BINARY.contains(&n.text)
            }
            Kind::Word => matches!(n.text, "else" | "catch" | "finally"),
            Kind::Template => true,
            _ => false,
        },
        None => false,
    }
}

pub(super) fn format(src: &str, w: &mut Writer) -> Res {
    let mut lx = Lexer::new(src);
    // The root frame is never popped.
    let mut frames = vec![Frame::new(b'r', false)];
    let mut prev: Option<Tok> = None;
    let mut space_next = false;
    let mut case_depth: Option<usize> = None;
    let mut next = lx.next();

    while let Some(t) = next.take() {
        next = lx.next();
        if t.nl_before {
            w.newline();
        }
        match t.kind {
            Kind::LineComment => {
                if t.ws_before || !w.at_line_start() {
                    w.space();
                }
                w.write(t.text)?;
                w.newline();
                continue;
            }
            Kind::BlockComment => {
                if t.ws_before {
                    w.space();
                }
                w.write(t.text)?;
                space_next |= next.is_some_and(|n| n.ws_before);
                continue;
            }
            _ => {}
        }

        let p = prev.as_ref();
        let binary = is_binary(&t, p);
        let ternary_colon =
            t.kind == Kind::Punct && t.text == ":" && frames.last().is_some_and(|f| f.ternary > 0);
        let closing = t.kind == Kind::Punct && matches!(t.text, ")" | "]" | ";" | ",");
        let mut space = !closing && (space_next || binary || ternary_colon || needs_space(p, &t));
        if !space && t.ws_before && !safe_to_join(w.last_char(), &t) {
            space = true;
        }
        if space {
            w.space();
        }
        space_next = false;

        let top = frames.len() - 1;
        match (t.kind, t.text) {
            (Kind::Punct, "{") => {
                if let Some(close) = next.filter(|n| n.kind == Kind::Punct && n.text == "}") {
                    next = lx.next();
                    w.write("{}")?;
                    prev = Some(close);
                    continue;
                }
                w.write("{")?;
                frames.push(Frame::new(b'{', false));
                w.indent();
                w.newline();
            }
            (Kind::Punct, "}") => {
                if let Some(pos) = frames.iter().rposition(|f| f.open == b'{') {
                    frames.truncate(pos);
                }
                if case_depth.is_some_and(|d| d > frames.len()) {
                    case_depth = None;
                }
                w.dedent();
                w.newline();
                w.write("}")?;
                if !continues_after_brace(next.as_ref()) {
                    w.newline();
                }
            }
            (Kind::Punct, "(" | "[") => {
                let is_for =
                    t.text == "(" && p.is_some_and(|p| p.kind == Kind::Word && p.text == "for");
                frames.push(Frame::new(t.text.as_bytes()[0], is_for));
                w.write(t.text)?;
            }
            (Kind::Punct, ")" | "]") => {
                let open = if t.text == ")" { b'(' } else { b'[' };
                if frames[top].open == open {
                    frames.pop();
                }
                w.write(t.text)?;
            }
            (Kind::Punct, ";") => {
                w.write(";")?;
                if frames[top].open == b'(' && frames[top].is_for {
                    space_next = true;
                } else {
                    if case_depth == Some(frames.len()) {
                        case_depth = None;
                    }
                    w.newline();
                }
            }
            (Kind::Punct, ",") => {
                w.write(",")?;
                if frames[top].open == b'{' {
                    w.newline();
                } else {
                    space_next = true;
                }
            }
            (Kind::Punct, "?") => {
                frames[top].ternary += 1;
                w.write("?")?;
                space_next = true;
            }
            (Kind::Punct, ":") => {
                w.write(":")?;
                if ternary_colon {
                    frames[top].ternary -= 1;
                    space_next = true;
                } else if case_depth == Some(frames.len()) {
                    case_depth = None;
                    w.newline();
                } else {
                    space_next = true;
                }
            }
            (Kind::Word, "case" | "default") => {
                w.write(t.text)?;
                if frames[top].open == b'{' {
                    case_depth = Some(frames.len());
                }
            }
            _ => {
                w.write(t.text)?;
                space_next = binary;
            }
        }
        prev = Some(t);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Format, beautify, strip_ws};
    use super::*;

    fn fmt(src: &str) -> String {
        beautify(Format::JavaScript, src).unwrap()
    }

    fn tokens(src: &str) -> Vec<(Kind, String)> {
        let mut lx = Lexer::new(src);
        std::iter::from_fn(|| lx.next())
            .map(|t| (t.kind, t.text.to_owned()))
            .collect()
    }

    #[test]
    fn formats_minified_code() {
        assert_eq!(
            fmt("function a(b,c){if(b>c){return b}else{for(var i=0;i<c;i++)x(i);return c?b:-c}}"),
            "function a(b, c) {
  if (b > c) {
    return b
  } else {
    for (var i = 0; i < c; i++) x(i);
    return c ? b : -c
  }
}
"
        );
        assert_eq!(
            fmt("var o={a:1,b:[1,2],c:function(){},d:x=>x*2};"),
            "var o = {
  a: 1,
  b: [1, 2],
  c: function() {},
  d: x => x * 2
};
"
        );
        assert_eq!(
            fmt("switch(a){case 1:b();break;default:c()}"),
            "switch (a) {
  case 1:
  b();
  break;
  default:
  c()
}
"
        );
    }

    #[test]
    fn lexes_regex_vs_division() {
        let t = tokens("a=b/c/d;e=/x[/]y/g.test(f);if(g)/h/.test(i);j=(k)/2");
        let regexes: Vec<&str> = t
            .iter()
            .filter(|(k, _)| *k == Kind::Regex)
            .map(|(_, s)| s.as_str())
            .collect();
        assert_eq!(regexes, ["/x[/]y/g", "/h/"]);
    }

    #[test]
    fn lexes_templates_and_strings() {
        let src = "a=`x${b?`y${c}`:'}'}z`+\"q\\\"\";";
        let t = tokens(src);
        assert_eq!(t[2], (Kind::Template, "`x${b?`y${c}`:'}'}z`".to_owned()));
        assert_eq!(t[4], (Kind::Str, "\"q\\\"\"".to_owned()));
        assert_eq!(fmt(src), "a = `x${b?`y${c}`:'}'}z` + \"q\\\"\";\n");
    }

    #[test]
    fn never_merges_tokens() {
        assert_eq!(
            fmt("a=b+ +c,d=e- -f,g=1 .toString()"),
            "a = b + +c, d = e - -f, g = 1 .toString()\n"
        );
        assert_eq!(fmt("x=+ +y"), "x = + +y\n");
        assert_eq!(fmt("return/a/.test(b)"), "return /a/.test(b)\n");
    }

    #[test]
    fn keeps_line_breaks_for_asi() {
        let src = "a=1\n(b||c).d()\nreturn\nx";
        assert_eq!(strip_ws(&fmt(src)), strip_ws(src));
        assert_eq!(fmt(src).lines().count(), 4);
    }

    #[test]
    fn keeps_comments() {
        assert_eq!(fmt("a()//x\nb()/*y*/;c()"), "a() //x\nb()/*y*/;\nc()\n");
    }
}
