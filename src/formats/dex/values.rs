//! `encoded_value`, `encoded_array` and annotation parsing / smali rendering.

use super::DexFile;
use super::javafmt::{double_to_string, float_to_string};
use super::smali::{escape_string, escape_utf16};
use crate::formats::reader::{Reader, Result, err};

const MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotation),
    Null,
    Boolean(bool),
}

#[derive(Debug, Clone)]
pub struct EncodedAnnotation {
    pub type_idx: u32,
    pub elements: Vec<(u32, EncodedValue)>,
}

#[derive(Debug, Clone)]
pub struct Annotation {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

#[derive(Debug, Clone, Default)]
pub struct AnnotationsDirectory {
    pub class: Vec<Annotation>,
    pub fields: Vec<(u32, Vec<Annotation>)>,
    pub methods: Vec<(u32, Vec<Annotation>)>,
}

impl AnnotationsDirectory {
    pub fn for_field(&self, idx: u32) -> &[Annotation] {
        lookup(&self.fields, idx)
    }

    pub fn for_method(&self, idx: u32) -> &[Annotation] {
        lookup(&self.methods, idx)
    }
}

fn lookup(list: &[(u32, Vec<Annotation>)], idx: u32) -> &[Annotation] {
    list.iter()
        .find(|(i, _)| *i == idx)
        .map(|(_, a)| a.as_slice())
        .unwrap_or_default()
}

fn sign_extend(value: u64, bytes: usize) -> i64 {
    let shift = 64 - 8 * bytes as u32;
    ((value << shift) as i64) >> shift
}

pub fn read_value(r: &mut Reader, depth: u32) -> Result<EncodedValue> {
    if depth > MAX_DEPTH {
        return err("encoded value nesting too deep");
    }
    let header = r.u8()?;
    let arg = usize::from(header >> 5);
    let size = arg + 1;
    let value_type = header & 0x1f;
    let check = |max: usize| {
        if size > max {
            err(format!(
                "invalid size {size} for encoded value type 0x{value_type:02x}"
            ))
        } else {
            Ok(())
        }
    };
    use EncodedValue as V;
    Ok(match value_type {
        0x00 => {
            check(1)?;
            V::Byte(r.u8()? as i8)
        }
        0x02 => {
            check(2)?;
            V::Short(sign_extend(r.uint_sized(size)?, size) as i16)
        }
        0x03 => {
            check(2)?;
            V::Char(r.uint_sized(size)? as u16)
        }
        0x04 => {
            check(4)?;
            V::Int(sign_extend(r.uint_sized(size)?, size) as i32)
        }
        0x06 => {
            check(8)?;
            V::Long(sign_extend(r.uint_sized(size)?, size))
        }
        0x10 => {
            check(4)?;
            let bits = (r.uint_sized(size)? as u32) << (8 * (4 - size));
            V::Float(f32::from_bits(bits))
        }
        0x11 => {
            check(8)?;
            let bits = r.uint_sized(size)? << (8 * (8 - size));
            V::Double(f64::from_bits(bits))
        }
        0x15..=0x1b => {
            check(4)?;
            let idx = r.uint_sized(size)? as u32;
            match value_type {
                0x15 => V::MethodType(idx),
                0x16 => V::MethodHandle(idx),
                0x17 => V::String(idx),
                0x18 => V::Type(idx),
                0x19 => V::Field(idx),
                0x1a => V::Method(idx),
                _ => V::Enum(idx),
            }
        }
        0x1c => V::Array(read_array(r, depth + 1)?),
        0x1d => V::Annotation(read_annotation(r, depth + 1)?),
        0x1e => V::Null,
        0x1f => V::Boolean(arg != 0),
        other => return err(format!("unknown encoded value type 0x{other:02x}")),
    })
}

pub fn read_array(r: &mut Reader, depth: u32) -> Result<Vec<EncodedValue>> {
    let size = r.uleb128()? as usize;
    let mut out = Vec::with_capacity(size.min(r.remaining()));
    for _ in 0..size {
        out.push(read_value(r, depth)?);
    }
    Ok(out)
}

pub fn read_annotation(r: &mut Reader, depth: u32) -> Result<EncodedAnnotation> {
    let type_idx = r.uleb128()?;
    let size = r.uleb128()? as usize;
    let mut elements = Vec::with_capacity(size.min(r.remaining() / 2));
    for _ in 0..size {
        let name = r.uleb128()?;
        elements.push((name, read_value(r, depth)?));
    }
    Ok(EncodedAnnotation { type_idx, elements })
}

fn read_annotation_set(data: &[u8], off: u32) -> Result<Vec<Annotation>> {
    if off == 0 {
        return Ok(Vec::new());
    }
    let mut r = Reader::at(data, off as usize)?;
    let size = r.u32()? as usize;
    if size.saturating_mul(4) > r.remaining() {
        return err(format!("annotation set at 0x{off:x} exceeds the file"));
    }
    let mut out = Vec::with_capacity(size);
    for _ in 0..size {
        let item_off = r.u32()? as usize;
        let mut item = Reader::at(data, item_off)?;
        let visibility = item.u8()?;
        out.push(Annotation {
            visibility,
            annotation: read_annotation(&mut item, 0)?,
        });
    }
    Ok(out)
}

pub fn read_annotations_directory(data: &[u8], off: u32) -> Result<AnnotationsDirectory> {
    if off == 0 {
        return Ok(AnnotationsDirectory::default());
    }
    let mut r = Reader::at(data, off as usize)?;
    let class_off = r.u32()?;
    let fields_size = r.u32()? as usize;
    let methods_size = r.u32()? as usize;
    let _params_size = r.u32()?;
    let total = fields_size.saturating_add(methods_size).saturating_mul(8);
    if total > r.remaining() {
        return err(format!(
            "annotations directory at 0x{off:x} exceeds the file"
        ));
    }
    let mut read_list = |n: usize| -> Result<Vec<(u32, Vec<Annotation>)>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let idx = r.u32()?;
            let set_off = r.u32()?;
            out.push((idx, read_annotation_set(data, set_off)?));
        }
        Ok(out)
    };
    let fields = read_list(fields_size)?;
    let methods = read_list(methods_size)?;
    Ok(AnnotationsDirectory {
        class: read_annotation_set(data, class_off)?,
        fields,
        methods,
    })
}

pub fn read_static_values(data: &[u8], off: u32) -> Result<Vec<EncodedValue>> {
    if off == 0 {
        return Ok(Vec::new());
    }
    read_array(&mut Reader::at(data, off as usize)?, 0)
}

pub fn hex_signed(v: i64) -> String {
    if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

impl DexFile {
    pub fn format_value(&self, value: &EncodedValue, indent: usize) -> String {
        use EncodedValue as V;
        match value {
            V::Byte(v) => format!("{}t", hex_signed(i64::from(*v))),
            V::Short(v) => format!("{}s", hex_signed(i64::from(*v))),
            V::Char(v) => format!("'{}'", escape_utf16([*v])),
            V::Int(v) => hex_signed(i64::from(*v)),
            V::Long(v) => format!("{}L", hex_signed(*v)),
            V::Float(v) => format!("{}f", float_to_string(*v)),
            V::Double(v) => double_to_string(*v),
            V::MethodType(idx) => self.proto_descriptor(*idx),
            V::MethodHandle(idx) => format!("method_handle@{idx}"),
            V::String(idx) => format!("\"{}\"", escape_string(&self.string(*idx))),
            V::Type(idx) => self.type_descriptor(*idx).into_owned(),
            V::Field(idx) => self.field_ref(*idx),
            V::Method(idx) => self.method_ref(*idx),
            V::Enum(idx) => format!(".enum {}", self.field_ref(*idx)),
            V::Array(items) => {
                if items.is_empty() {
                    return "{}".to_owned();
                }
                let pad = " ".repeat(indent + 4);
                let inner: Vec<String> = items
                    .iter()
                    .map(|v| format!("{pad}{}", self.format_value(v, indent + 4)))
                    .collect();
                format!("{{\n{}\n{}}}", inner.join(",\n"), " ".repeat(indent))
            }
            V::Annotation(a) => {
                let mut out = format!(".subannotation {}\n", self.type_descriptor(a.type_idx));
                self.format_elements(&mut out, a, indent + 4);
                out.push_str(&" ".repeat(indent));
                out.push_str(".end subannotation");
                out
            }
            V::Null => "null".to_owned(),
            V::Boolean(b) => b.to_string(),
        }
    }

    fn format_elements(&self, out: &mut String, a: &EncodedAnnotation, indent: usize) {
        for (name, value) in &a.elements {
            out.push_str(&" ".repeat(indent));
            out.push_str(&self.string(*name));
            out.push_str(" = ");
            out.push_str(&self.format_value(value, indent));
            out.push('\n');
        }
    }

    pub fn format_annotations(&self, out: &mut String, annotations: &[Annotation], indent: usize) {
        let pad = " ".repeat(indent);
        for (i, a) in annotations.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            let visibility = match a.visibility {
                0 => "build",
                1 => "runtime",
                2 => "system",
                _ => "unknown",
            };
            out.push_str(&format!(
                "{pad}.annotation {visibility} {}\n",
                self.type_descriptor(a.annotation.type_idx)
            ));
            self.format_elements(out, &a.annotation, indent + 4);
            out.push_str(&format!("{pad}.end annotation\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_primitives() {
        let v = read_value(&mut Reader::new(&[0x04, 0x2a]), 0).unwrap();
        assert!(matches!(v, EncodedValue::Int(42)));
        let v = read_value(&mut Reader::new(&[0x24, 0xff, 0xff]), 0).unwrap();
        assert!(matches!(v, EncodedValue::Int(-1)));
        let v = read_value(&mut Reader::new(&[0x3f]), 0).unwrap();
        assert!(matches!(v, EncodedValue::Boolean(true)));
        // 1.0f is 0x3f800000; only the two high-order bytes are stored.
        let v = read_value(&mut Reader::new(&[0x30, 0x80, 0x3f]), 0).unwrap();
        assert!(matches!(v, EncodedValue::Float(f) if f == 1.0));
        assert!(read_value(&mut Reader::new(&[0xe4, 0, 0, 0, 0, 0, 0, 0, 0]), 0).is_err());
    }

    #[test]
    fn signed_hex() {
        assert_eq!(hex_signed(-1), "-0x1");
        assert_eq!(hex_signed(255), "0xff");
        assert_eq!(hex_signed(i64::MIN), "-0x8000000000000000");
    }
}
