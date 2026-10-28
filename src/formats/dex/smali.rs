//! Renders a DEX class definition as a smali source file.

use std::collections::HashSet;
use std::fmt::Write;

use super::access::{Target, flags_to_string};
use super::values::{
    AnnotationsDirectory, EncodedValue, read_annotations_directory, read_static_values,
};
use super::{ClassDef, DexFile, EncodedField, EncodedMethod, disasm};

/// Escapes UTF-16 code units the way baksmali does: printable ASCII is kept,
/// everything else becomes `\n`, `\r`, `\t` or `\uXXXX`.
pub fn escape_utf16(units: impl IntoIterator<Item = u16>) -> String {
    let mut out = String::new();
    for u in units {
        match u {
            0x27 | 0x22 | 0x5c => {
                out.push('\\');
                out.push(char::from(u as u8));
            }
            0x20..=0x7e => out.push(char::from(u as u8)),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            _ => {
                let _ = write!(out, "\\u{u:04x}");
            }
        }
    }
    out
}

/// Escapes a string for use inside a smali string literal.
pub fn escape_string(s: &str) -> String {
    escape_utf16(s.encode_utf16())
}

fn with_flags(keyword: &str, flags: &str, rest: &str) -> String {
    if flags.is_empty() {
        format!("{keyword} {rest}")
    } else {
        format!("{keyword} {flags} {rest}")
    }
}

fn is_default_value(v: &EncodedValue) -> bool {
    use EncodedValue as V;
    match v {
        V::Null | V::Boolean(false) => true,
        V::Byte(x) => *x == 0,
        V::Short(x) => *x == 0,
        V::Char(x) => *x == 0,
        V::Int(x) => *x == 0,
        V::Long(x) => *x == 0,
        V::Float(x) => x.to_bits() == 0,
        V::Double(x) => x.to_bits() == 0,
        _ => false,
    }
}

pub fn class_to_smali(dex: &DexFile, class: &ClassDef) -> String {
    let mut out = String::new();
    let flags = flags_to_string(class.access_flags, Target::Class);
    let _ = writeln!(
        out,
        "{}",
        with_flags(".class", &flags, &dex.class_descriptor(class))
    );
    if let Some(sup) = class.superclass {
        let _ = writeln!(out, ".super {}", dex.type_descriptor(sup));
    }
    if let Some(src) = class.source_file {
        let _ = writeln!(out, ".source \"{}\"", escape_string(&dex.string(src)));
    }

    match dex.interfaces(class) {
        Ok(list) if !list.is_empty() => {
            out.push_str("\n\n# interfaces\n");
            for i in list {
                let _ = writeln!(out, ".implements {}", dex.type_descriptor(i));
            }
        }
        Ok(_) => {}
        Err(e) => {
            let _ = writeln!(out, "\n# ERROR: interfaces: {e}");
        }
    }

    let annotations = match read_annotations_directory(dex.data(), class.annotations_off) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(out, "\n# ERROR: annotations: {e}");
            AnnotationsDirectory::default()
        }
    };
    if !annotations.class.is_empty() {
        out.push_str("\n\n# annotations\n");
        dex.format_annotations(&mut out, &annotations.class, 0);
    }

    let data = match dex.class_data(class) {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(out, "\n# ERROR: class data: {e}");
            return out;
        }
    };

    let static_values = match read_static_values(dex.data(), class.static_values_off) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(out, "\n# ERROR: static values: {e}");
            Vec::new()
        }
    };

    let set_in_clinit = fields_set_in_clinit(dex, class, &data.direct_methods);
    write_fields(
        dex,
        &mut out,
        "# static fields",
        &data.static_fields,
        &static_values,
        &set_in_clinit,
        &annotations,
    );
    write_fields(
        dex,
        &mut out,
        "# instance fields",
        &data.instance_fields,
        &[],
        &HashSet::new(),
        &annotations,
    );
    write_methods(
        dex,
        &mut out,
        "# direct methods",
        &data.direct_methods,
        &annotations,
    );
    write_methods(
        dex,
        &mut out,
        "# virtual methods",
        &data.virtual_methods,
        &annotations,
    );
    out
}

/// Fields of this class assigned by `sput*` in its static initializer.
fn fields_set_in_clinit(dex: &DexFile, class: &ClassDef, direct: &[EncodedMethod]) -> HashSet<u32> {
    let clinit = direct.iter().find(|m| {
        m.code_off != 0
            && dex
                .method(m.method_idx)
                .is_some_and(|id| dex.string(id.name) == "<clinit>")
    });
    let Some(code) = clinit.and_then(|m| dex.code_item(m.code_off).ok()) else {
        return HashSet::new();
    };
    disasm::static_puts(&code)
        .into_iter()
        .filter(|&f| dex.field(f).is_some_and(|id| id.class == class.class_idx))
        .collect()
}

fn write_fields(
    dex: &DexFile,
    out: &mut String,
    title: &str,
    fields: &[EncodedField],
    values: &[EncodedValue],
    set_in_clinit: &HashSet<u32>,
    annotations: &AnnotationsDirectory,
) {
    if fields.is_empty() {
        return;
    }
    let _ = write!(out, "\n\n{title}\n");
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let flags = flags_to_string(field.access_flags, Target::Field);
        let mut value = values.get(i);
        let static_final = field.access_flags & 0x18 == 0x18;
        if static_final && set_in_clinit.contains(&field.field_idx) {
            match value {
                Some(v) if !is_default_value(v) => out.push_str(
                    "# The value of this static final field might be set in the static constructor\n",
                ),
                _ => value = None,
            }
        }
        let mut line = with_flags(".field", &flags, &dex.field_name_and_type(field.field_idx));
        if let Some(v) = value {
            line.push_str(" = ");
            line.push_str(&dex.format_value(v, 0));
        }
        let _ = writeln!(out, "{line}");
        let field_annotations = annotations.for_field(field.field_idx);
        if !field_annotations.is_empty() {
            dex.format_annotations(out, field_annotations, 4);
            out.push_str(".end field\n");
        }
    }
}

fn write_methods(
    dex: &DexFile,
    out: &mut String,
    title: &str,
    methods: &[EncodedMethod],
    annotations: &AnnotationsDirectory,
) {
    if methods.is_empty() {
        return;
    }
    let _ = write!(out, "\n\n{title}\n");
    for (i, method) in methods.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let flags = flags_to_string(method.access_flags, Target::Method);
        let _ = writeln!(
            out,
            "{}",
            with_flags(
                ".method",
                &flags,
                &dex.method_name_and_proto(method.method_idx)
            )
        );
        let method_annotations = annotations.for_method(method.method_idx);
        if method.code_off == 0 {
            if !method_annotations.is_empty() {
                dex.format_annotations(out, method_annotations, 4);
            }
        } else {
            match dex.code_item(method.code_off) {
                Ok(code) => {
                    let mut body = String::new();
                    disasm::disassemble(dex, &code, &mut body, "    ");
                    // `.locals` comes first, then annotations, then the code.
                    let (locals, rest) = body.split_once('\n').unwrap_or((&body, ""));
                    out.push_str(locals);
                    out.push('\n');
                    if !method_annotations.is_empty() {
                        out.push('\n');
                        dex.format_annotations(out, method_annotations, 4);
                    }
                    out.push_str(rest);
                }
                Err(e) => {
                    let _ = writeln!(out, "    # ERROR: code item: {e}");
                }
            }
        }
        out.push_str(".end method\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(escape_string("a\"b\\c\n\u{1}'"), "a\\\"b\\\\c\\n\\u0001\\'");
        assert_eq!(escape_string("ä😀"), "\\u00e4\\ud83d\\ude00");
    }
}
