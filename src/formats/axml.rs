//! Decoder for Android binary XML (AXML), as used by `AndroidManifest.xml`
//! and compiled `res/**/*.xml` files inside an APK.

use std::collections::HashMap;
use std::fmt::Write;

use super::reader::{Reader, Result, err, read_u16, read_u32};

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const UTF8_FLAG: u32 = 1 << 8;
const NO_INDEX: u32 = 0xffff_ffff;
/// Maximum element nesting; deeper elements are skipped (Android layouts
/// rarely exceed a few dozen levels, crafted files can nest millions).
const MAX_DEPTH: usize = 256;
pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

#[derive(Debug, Clone, Default)]
pub struct XmlDocument {
    pub roots: Vec<XmlElement>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct XmlElement {
    pub name: String,
    pub namespaces: Vec<(String, String)>,
    pub attributes: Vec<XmlAttribute>,
    pub children: Vec<XmlNode>,
}

#[derive(Debug, Clone)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
}

#[derive(Debug, Clone)]
pub struct XmlAttribute {
    pub prefix: Option<String>,
    pub name: String,
    pub value: String,
    pub resource_id: Option<u32>,
}

impl XmlElement {
    /// Value of the first attribute with the given local name (any namespace).
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.as_str())
    }

    pub fn child_elements(&self) -> impl Iterator<Item = &XmlElement> {
        self.children.iter().filter_map(|c| match c {
            XmlNode::Element(e) => Some(e),
            XmlNode::Text(_) => None,
        })
    }
}

pub fn is_binary_xml(data: &[u8]) -> bool {
    data.len() >= 8 && data[0..2] == [0x03, 0x00] && data[2..4] == [0x08, 0x00]
}

/// Android framework attribute IDs, used when obfuscators strip attribute
/// names from the string pool (Android itself resolves attributes by ID).
fn android_attr_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101_0000 => "theme",
        0x0101_0001 => "label",
        0x0101_0002 => "icon",
        0x0101_0003 => "name",
        0x0101_0006 => "permission",
        0x0101_000e => "enabled",
        0x0101_000f => "debuggable",
        0x0101_0010 => "exported",
        0x0101_0011 => "process",
        0x0101_0018 => "authorities",
        0x0101_0024 => "value",
        0x0101_0025 => "resource",
        0x0101_020c => "minSdkVersion",
        0x0101_021b => "versionCode",
        0x0101_021c => "versionName",
        0x0101_0270 => "targetSdkVersion",
        0x0101_0280 => "allowBackup",
        0x0101_0572 => "compileSdkVersion",
        0x0101_0573 => "compileSdkVersionCodename",
        _ => return None,
    })
}

fn parse_string_pool(data: &[u8], start: usize, size: usize) -> Result<Vec<String>> {
    let mut r = Reader::at(data, start)?;
    r.skip(2)?;
    let header_size = usize::from(r.u16()?);
    r.skip(4)?;
    let count = r.u32()? as usize;
    let _style_count = r.u32()?;
    let flags = r.u32()?;
    let strings_start = r.u32()? as usize;
    if count.saturating_mul(4) > size {
        return err(format!(
            "string pool claims {count} strings, exceeding its chunk"
        ));
    }
    let utf8 = flags & UTF8_FLAG != 0;
    let mut offsets = Reader::at(data, start + header_size)?;
    let mut strings = Vec::with_capacity(count);
    for _ in 0..count {
        let off = offsets.u32()? as usize;
        let pos = start.saturating_add(strings_start).saturating_add(off);
        strings.push(read_pool_string(data, pos, utf8).unwrap_or_default());
    }
    Ok(strings)
}

fn read_pool_string(data: &[u8], pos: usize, utf8: bool) -> Result<String> {
    let mut r = Reader::at(data, pos)?;
    if utf8 {
        let len8 = |r: &mut Reader| -> Result<usize> {
            let b = r.u8()?;
            Ok(if b & 0x80 != 0 {
                (usize::from(b & 0x7f) << 8) | usize::from(r.u8()?)
            } else {
                usize::from(b)
            })
        };
        let _utf16_len = len8(&mut r)?;
        let len = len8(&mut r)?;
        Ok(String::from_utf8_lossy(r.bytes(len)?).into_owned())
    } else {
        let mut len = r.u16()? as usize;
        if len & 0x8000 != 0 {
            len = ((len & 0x7fff) << 16) | usize::from(r.u16()?);
        }
        if len.saturating_mul(2) > r.remaining() {
            return err("string exceeds data");
        }
        let units: Vec<u16> = (0..len).map(|_| r.u16()).collect::<Result<_>>()?;
        Ok(String::from_utf16_lossy(&units))
    }
}

fn complex_to_float(data: u32) -> f64 {
    const RADIX_MULTS: [f64; 4] = [
        1.0 / 256.0,
        1.0 / 256.0 / 128.0,
        1.0 / 256.0 / 32768.0,
        1.0 / 256.0 / 8_388_608.0,
    ];
    let mantissa = f64::from((data & 0xffff_ff00) as i32);
    mantissa * RADIX_MULTS[((data >> 4) & 0x3) as usize]
}

fn trim_float(v: f64) -> String {
    let s = format!("{v:.4}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    s.to_owned()
}

fn format_typed_value(data_type: u8, data: u32, strings: &[String]) -> String {
    match data_type {
        0x00 => String::new(),
        0x01 | 0x07 => match data {
            0 => "@null".to_owned(),
            d if d >> 24 == 0x01 => format!("@android:0x{d:08x}"),
            d => format!("@0x{d:08x}"),
        },
        0x02 | 0x08 => format!("?0x{data:08x}"),
        0x03 => strings.get(data as usize).cloned().unwrap_or_default(),
        0x04 => trim_float(f64::from(f32::from_bits(data))),
        0x05 => {
            const UNITS: [&str; 6] = ["px", "dp", "sp", "pt", "in", "mm"];
            let unit = UNITS.get((data & 0xf) as usize).copied().unwrap_or("?");
            format!("{}{unit}", trim_float(complex_to_float(data)))
        }
        0x06 => {
            let unit = if data & 0xf == 0 { "%" } else { "%p" };
            format!("{}{unit}", trim_float(complex_to_float(data) * 100.0))
        }
        0x10 => (data as i32).to_string(),
        0x11 => format!("0x{data:x}"),
        0x12 => (data != 0).to_string(),
        0x1c | 0x1e => format!("#{data:08x}"),
        0x1d | 0x1f => format!("#{:06x}", data & 0x00ff_ffff),
        t => format!("0x{data:08x} (type 0x{t:02x})"),
    }
}

pub fn parse(data: &[u8]) -> Result<XmlDocument> {
    if !is_binary_xml(data) {
        return err("not an Android binary XML file");
    }
    let header_size = usize::from(read_u16(data, 2)?);
    let declared = read_u32(data, 4)? as usize;
    let mut doc = XmlDocument::default();
    if declared != data.len() {
        doc.warnings.push(format!(
            "header declares {declared} bytes, file has {}",
            data.len()
        ));
    }
    let end = data.len();

    let mut strings: Vec<String> = Vec::new();
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut ns_prefixes: HashMap<String, String> = HashMap::new();
    let mut pending_ns: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut skipped_depth = 0usize;

    let str_at = |strings: &[String], idx: u32| -> String {
        if idx == NO_INDEX {
            String::new()
        } else {
            strings.get(idx as usize).cloned().unwrap_or_default()
        }
    };

    let mut pos = header_size.max(8);
    while pos + 8 <= end {
        let chunk_type = read_u16(data, pos)?;
        let chunk_header = usize::from(read_u16(data, pos + 2)?);
        let chunk_size = read_u32(data, pos + 4)? as usize;
        if chunk_size < 8 || pos + chunk_size > end {
            doc.warnings.push(format!(
                "invalid chunk size {chunk_size} at offset 0x{pos:x}"
            ));
            break;
        }
        let ext = pos + chunk_header;
        match chunk_type {
            RES_STRING_POOL_TYPE => strings = parse_string_pool(data, pos, chunk_size)?,
            RES_XML_RESOURCE_MAP_TYPE => {
                resource_ids = (ext..pos + chunk_size)
                    .step_by(4)
                    .filter_map(|o| read_u32(data, o).ok())
                    .collect();
            }
            RES_XML_START_NAMESPACE_TYPE => {
                let prefix = str_at(&strings, read_u32(data, ext)?);
                let uri = str_at(&strings, read_u32(data, ext + 4)?);
                ns_prefixes.insert(uri.clone(), prefix.clone());
                pending_ns.push((prefix, uri));
            }
            RES_XML_END_NAMESPACE_TYPE => {}
            RES_XML_START_ELEMENT_TYPE if stack.len() >= MAX_DEPTH => {
                if skipped_depth == 0 {
                    doc.warnings.push(format!(
                        "elements nested deeper than {MAX_DEPTH} levels were skipped"
                    ));
                }
                skipped_depth += 1;
            }
            RES_XML_END_ELEMENT_TYPE if skipped_depth > 0 => skipped_depth -= 1,
            RES_XML_START_ELEMENT_TYPE => {
                let mut r = Reader::at(data, ext)?;
                let ns = r.u32()?;
                let name = str_at(&strings, r.u32()?);
                let attr_start = usize::from(r.u16()?);
                let attr_size = usize::from(r.u16()?).max(20);
                let attr_count = usize::from(r.u16()?);

                let prefix_for = |ns_idx: u32| -> Option<String> {
                    if ns_idx == NO_INDEX {
                        return None;
                    }
                    let uri = str_at(&strings, ns_idx);
                    Some(ns_prefixes.get(&uri).cloned().unwrap_or_else(|| {
                        if uri == ANDROID_NS {
                            "android".to_owned()
                        } else {
                            format!("ns{}", ns_idx)
                        }
                    }))
                };

                let element_name = match prefix_for(ns) {
                    Some(p) if !p.is_empty() => format!("{p}:{name}"),
                    _ => name,
                };
                let mut element = XmlElement {
                    name: element_name,
                    namespaces: std::mem::take(&mut pending_ns),
                    ..Default::default()
                };
                for i in 0..attr_count {
                    let mut a = Reader::at(data, ext + attr_start + i * attr_size)?;
                    let attr_ns = a.u32()?;
                    let name_idx = a.u32()?;
                    let raw_value = a.u32()?;
                    a.skip(3)?;
                    let data_type = a.u8()?;
                    let value_data = a.u32()?;

                    let resource_id = resource_ids.get(name_idx as usize).copied();
                    let mut attr_name = str_at(&strings, name_idx);
                    if attr_name.is_empty() {
                        attr_name = match resource_id {
                            Some(id) => android_attr_name(id)
                                .map(str::to_owned)
                                .unwrap_or_else(|| format!("attr_0x{id:08x}")),
                            None => format!("attr_{name_idx}"),
                        };
                    }
                    let value = if data_type == 0x03 && raw_value != NO_INDEX {
                        str_at(&strings, raw_value)
                    } else {
                        format_typed_value(data_type, value_data, &strings)
                    };
                    element.attributes.push(XmlAttribute {
                        prefix: prefix_for(attr_ns).filter(|p| !p.is_empty()),
                        name: attr_name,
                        value,
                        resource_id,
                    });
                }
                stack.push(element);
            }
            RES_XML_END_ELEMENT_TYPE => {
                if let Some(element) = stack.pop() {
                    attach(&mut stack, &mut doc.roots, element);
                } else {
                    doc.warnings
                        .push(format!("unbalanced end element at offset 0x{pos:x}"));
                }
            }
            RES_XML_CDATA_TYPE => {
                let text = str_at(&strings, read_u32(data, ext)?);
                if let Some(parent) = stack.last_mut() {
                    if !text.trim().is_empty() {
                        parent.children.push(XmlNode::Text(text));
                    }
                }
            }
            RES_XML_TYPE => {
                doc.warnings
                    .push(format!("nested XML chunk at offset 0x{pos:x} ignored"));
            }
            _ => {}
        }
        pos += chunk_size;
    }

    if !stack.is_empty() {
        doc.warnings
            .push(format!("{} element(s) were not closed", stack.len()));
        while let Some(element) = stack.pop() {
            attach(&mut stack, &mut doc.roots, element);
        }
    }
    Ok(doc)
}

fn attach(stack: &mut [XmlElement], roots: &mut Vec<XmlElement>, element: XmlElement) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(XmlNode::Element(element)),
        None => roots.push(element),
    }
}

fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            c if (c as u32) < 0x20 && c != '\t' => {
                let _ = write!(out, "&#{};", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

impl XmlDocument {
    pub fn to_xml_string(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        for w in &self.warnings {
            let _ = writeln!(out, "<!-- WARNING: {} -->", w.replace("--", "- -"));
        }
        for root in &self.roots {
            write_element(&mut out, root, 0);
        }
        out
    }

    pub fn root(&self) -> Option<&XmlElement> {
        self.roots.first()
    }
}

fn write_element(out: &mut String, e: &XmlElement, depth: usize) {
    let pad = "    ".repeat(depth);
    let mut attrs: Vec<String> = e
        .namespaces
        .iter()
        .map(|(prefix, uri)| {
            if prefix.is_empty() {
                format!("xmlns=\"{}\"", escape_xml(uri))
            } else {
                format!("xmlns:{prefix}=\"{}\"", escape_xml(uri))
            }
        })
        .collect();
    attrs.extend(e.attributes.iter().map(|a| match &a.prefix {
        Some(p) => format!("{p}:{}=\"{}\"", a.name, escape_xml(&a.value)),
        None => format!("{}=\"{}\"", a.name, escape_xml(&a.value)),
    }));

    let _ = write!(out, "{pad}<{}", e.name);
    let attr_pad = format!("\n{pad}    ");
    for (i, a) in attrs.iter().enumerate() {
        out.push_str(if i == 0 { " " } else { &attr_pad });
        out.push_str(a);
    }
    if e.children.is_empty() {
        out.push_str(" />\n");
        return;
    }
    out.push_str(">\n");
    for child in &e.children {
        match child {
            XmlNode::Element(c) => write_element(out, c, depth + 1),
            XmlNode::Text(t) => {
                let _ = writeln!(out, "{pad}    {}", escape_xml(t.trim()));
            }
        }
    }
    let _ = writeln!(out, "{pad}</{}>", e.name);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(kind: u16, header: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(kind.to_le_bytes());
        v.extend(header.to_le_bytes());
        v.extend(((body.len() + 8) as u32).to_le_bytes());
        v.extend(body);
        v
    }

    fn string_pool(strings: &[&str]) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut data = Vec::new();
        for s in strings {
            offsets.extend((data.len() as u32).to_le_bytes());
            data.extend((s.len() as u16).to_le_bytes());
            for u in s.encode_utf16() {
                data.extend(u.to_le_bytes());
            }
            data.extend([0, 0]);
        }
        let mut body = Vec::new();
        body.extend((strings.len() as u32).to_le_bytes());
        body.extend(0u32.to_le_bytes());
        body.extend(0u32.to_le_bytes());
        body.extend((28 + offsets.len() as u32).to_le_bytes());
        body.extend(0u32.to_le_bytes());
        body.extend(offsets);
        body.extend(data);
        chunk(RES_STRING_POOL_TYPE, 28, &body)
    }

    fn node(kind: u16, ext: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body.extend(ext);
        chunk(kind, 16, &body)
    }

    #[test]
    fn decodes_minimal_manifest() {
        let pool = string_pool(&[
            "android",
            ANDROID_NS,
            "manifest",
            "package",
            "com.example",
            "",
        ]);
        let mut start = Vec::new();
        start.extend(NO_INDEX.to_le_bytes());
        start.extend(2u32.to_le_bytes());
        start.extend(20u16.to_le_bytes());
        start.extend(20u16.to_le_bytes());
        start.extend(2u16.to_le_bytes());
        start.extend([0u8; 6]);
        // package="com.example"
        start.extend(NO_INDEX.to_le_bytes());
        start.extend(3u32.to_le_bytes());
        start.extend(4u32.to_le_bytes());
        start.extend([8, 0, 0, 0x03]);
        start.extend(4u32.to_le_bytes());
        // android:<stripped name>=0x1 with resource id versionCode
        start.extend(1u32.to_le_bytes());
        start.extend(5u32.to_le_bytes());
        start.extend(NO_INDEX.to_le_bytes());
        start.extend([8, 0, 0, 0x10]);
        start.extend(1u32.to_le_bytes());

        let mut res_map = Vec::new();
        for _ in 0..5 {
            res_map.extend(0u32.to_le_bytes());
        }
        res_map.extend(0x0101_021bu32.to_le_bytes());

        let mut ns = Vec::new();
        ns.extend(0u32.to_le_bytes());
        ns.extend(1u32.to_le_bytes());
        let mut end = Vec::new();
        end.extend(NO_INDEX.to_le_bytes());
        end.extend(2u32.to_le_bytes());

        let mut body = pool;
        body.extend(chunk(RES_XML_RESOURCE_MAP_TYPE, 8, &res_map));
        body.extend(node(RES_XML_START_NAMESPACE_TYPE, &ns));
        body.extend(node(RES_XML_START_ELEMENT_TYPE, &start));
        body.extend(node(RES_XML_END_ELEMENT_TYPE, &end));
        let file = chunk(RES_XML_TYPE, 8, &body);

        let doc = parse(&file).unwrap();
        let root = doc.root().unwrap();
        assert_eq!(root.name, "manifest");
        assert_eq!(root.attr("package"), Some("com.example"));
        assert_eq!(root.attr("versionCode"), Some("1"));
        let xml = doc.to_xml_string();
        assert!(xml.contains("xmlns:android=\"http://schemas.android.com/apk/res/android\""));
        assert!(xml.contains("android:versionCode=\"1\""));
        assert!(doc.warnings.is_empty());
    }

    #[test]
    fn limits_nesting_depth() {
        let pool = string_pool(&["a"]);
        let mut start = Vec::new();
        start.extend(NO_INDEX.to_le_bytes());
        start.extend(0u32.to_le_bytes());
        start.extend(20u16.to_le_bytes());
        start.extend(20u16.to_le_bytes());
        start.extend([0u8; 8]);
        let mut body = pool;
        let element = node(RES_XML_START_ELEMENT_TYPE, &start);
        for _ in 0..100_000 {
            body.extend(&element);
        }
        let doc = parse(&chunk(RES_XML_TYPE, 8, &body)).unwrap();
        assert!(doc.warnings.iter().any(|w| w.contains("nested deeper")));
        assert!(doc.to_xml_string().len() < 1_000_000);
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse(&[0x03, 0x00, 0x08, 0x00]).is_err());
        let doc = parse(&[
            0x03, 0x00, 0x08, 0x00, 0xff, 0, 0, 0, 1, 0, 0x1c, 0, 0xff, 0xff, 0, 0,
        ]);
        assert!(doc.is_ok_and(|d| d.roots.is_empty() && !d.warnings.is_empty()));
    }

    #[test]
    fn typed_values() {
        assert_eq!(format_typed_value(0x12, 0xffff_ffff, &[]), "true");
        assert_eq!(format_typed_value(0x1c, 0xff00_ff00, &[]), "#ff00ff00");
        assert_eq!(format_typed_value(0x01, 0x7f01_0001, &[]), "@0x7f010001");
        // 16dp: mantissa 16 << 8, radix 0, unit dp (1)
        assert_eq!(format_typed_value(0x05, (16 << 8) | 1, &[]), "16dp");
    }
}
