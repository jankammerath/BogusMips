//! Formatting of Android `Res_value`s (as used in binary XML and
//! `resources.arsc`), including resolution of resource IDs to names.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::arsc::ResourceTable;

pub const TYPE_NULL: u8 = 0x00;
pub const TYPE_REFERENCE: u8 = 0x01;
pub const TYPE_ATTRIBUTE: u8 = 0x02;
pub const TYPE_STRING: u8 = 0x03;
pub const TYPE_FLOAT: u8 = 0x04;
pub const TYPE_DIMENSION: u8 = 0x05;
pub const TYPE_FRACTION: u8 = 0x06;
pub const TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
pub const TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;
pub const TYPE_INT_DEC: u8 = 0x10;
pub const TYPE_INT_HEX: u8 = 0x11;
pub const TYPE_INT_BOOLEAN: u8 = 0x12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Enum,
    Flags,
}

/// Named values of an `enum` or `flag` attribute.
#[derive(Debug, Clone)]
pub struct Symbols {
    pub kind: SymbolKind,
    pub values: Vec<(String, u32)>,
}

impl Symbols {
    /// `enum` → the matching name; `flag` → names joined by `|`.
    pub fn describe(&self, data: u32) -> Option<String> {
        if let Some((name, _)) = self.values.iter().find(|(_, v)| *v == data) {
            return Some(name.clone());
        }
        if self.kind == SymbolKind::Enum {
            return None;
        }
        let mut sorted: Vec<(usize, &(String, u32))> = self
            .values
            .iter()
            .enumerate()
            .filter(|(_, (_, v))| *v != 0)
            .collect();
        // Prefer multi-bit flags, then larger values; print in declaration order.
        sorted.sort_by(|a, b| {
            b.1.1
                .count_ones()
                .cmp(&a.1.1.count_ones())
                .then(b.1.1.cmp(&a.1.1))
        });
        let mut remaining = data;
        let mut picked = Vec::new();
        for (index, (_, value)) in sorted {
            if remaining != 0 && remaining & value == *value {
                picked.push(index);
                remaining &= !value;
            }
        }
        picked.sort_unstable();
        let names: Vec<&str> = picked.iter().map(|&i| self.values[i].0.as_str()).collect();
        (remaining == 0 && !names.is_empty()).then(|| names.join("|"))
    }
}

/// Public Android framework resources, generated from the SDK by
/// `tools/gen_framework_resources.py`.
struct Framework {
    names: HashMap<u32, (String, String)>,
    symbols: HashMap<u32, Symbols>,
}

fn framework() -> &'static Framework {
    static FRAMEWORK: OnceLock<Framework> = OnceLock::new();
    FRAMEWORK.get_or_init(|| {
        let mut fw = Framework {
            names: HashMap::new(),
            symbols: HashMap::new(),
        };
        let data = include_str!("../../media/android/framework-resources.txt");
        for line in data.lines().filter(|l| !l.starts_with('#')) {
            let mut parts = line.split(' ');
            let (Some(kind), Some(id)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(id) = u32::from_str_radix(id, 16) else {
                continue;
            };
            match kind {
                "r" => {
                    if let (Some(t), Some(name)) = (parts.next(), parts.next()) {
                        fw.names.insert(id, (t.to_owned(), name.to_owned()));
                    }
                }
                "e" | "f" => {
                    let values = parts
                        .filter_map(|p| p.split_once('='))
                        .filter_map(|(n, v)| parse_int(v).map(|v| (n.to_owned(), v)))
                        .collect();
                    let kind = if kind == "e" {
                        SymbolKind::Enum
                    } else {
                        SymbolKind::Flags
                    };
                    fw.symbols.insert(id, Symbols { kind, values });
                }
                _ => {}
            }
        }
        fw
    })
}

fn parse_int(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<i64>().ok().map(|v| v as u32)
    }
}

/// Framework resource name such as `attr/label`.
pub fn framework_name(id: u32) -> Option<(&'static str, &'static str)> {
    framework()
        .names
        .get(&id)
        .map(|(t, n)| (t.as_str(), n.as_str()))
}

/// Resolves resource IDs using the Android framework table and any number of
/// app resource tables (an APK and its splits).
#[derive(Default, Clone, Copy)]
pub struct Resolver<'a> {
    tables: &'a [&'a ResourceTable],
}

impl<'a> Resolver<'a> {
    pub fn new(tables: &'a [&'a ResourceTable]) -> Self {
        Self { tables }
    }

    /// `type/name` for app resources, `android:type/name` for framework ones.
    pub fn name(&self, id: u32) -> Option<String> {
        if id >> 24 == 0x01 {
            return framework_name(id).map(|(t, n)| format!("android:{t}/{n}"));
        }
        self.tables.iter().find_map(|t| t.resource_name(id))
    }

    /// Attribute name as written in XML: `android:textColor` or `colorPrimary`.
    pub fn attr_name(&self, id: u32) -> Option<String> {
        let name = self.name(id)?;
        Some(match name.split_once('/') {
            Some((prefix, local)) => match prefix.split_once(':') {
                Some((package, _)) => format!("{package}:{local}"),
                None => local.to_owned(),
            },
            None => name,
        })
    }

    pub fn symbols(&self, attr: u32) -> Option<Symbols> {
        if attr >> 24 == 0x01 {
            return framework().symbols.get(&attr).cloned();
        }
        self.tables.iter().find_map(|t| t.attr_symbols(attr))
    }
}

/// Android's `complexToFloat`, computed in `f32` like the platform does.
fn complex_to_float(data: u32) -> f32 {
    const RADIX_MULTS: [f32; 4] = [
        1.0 / 256.0,
        1.0 / 256.0 / 128.0,
        1.0 / 256.0 / 32768.0,
        1.0 / 256.0 / 8_388_608.0,
    ];
    let mantissa = (data & 0xffff_ff00) as i32 as f32;
    mantissa * RADIX_MULTS[((data >> 4) & 0x3) as usize]
}

/// Shortest exact representation, without a trailing `.0` (`8`, `18.659973`).
fn format_float(v: f32) -> String {
    format!("{v}")
}

/// Formats a typed value. `attr` is the attribute the value belongs to (if
/// any), used to name `enum` / `flag` values.
pub fn format_value(
    data_type: u8,
    data: u32,
    strings: &[String],
    resolver: &Resolver,
    attr: Option<u32>,
) -> String {
    match data_type {
        TYPE_NULL => {
            if data == 1 {
                "@empty".to_owned()
            } else {
                String::new()
            }
        }
        TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE => match data {
            0 => "@null".to_owned(),
            d => resolver.name(d).map_or_else(
                || {
                    if d >> 24 == 0x01 {
                        format!("@android:0x{d:08x}")
                    } else {
                        format!("@0x{d:08x}")
                    }
                },
                |n| format!("@{n}"),
            ),
        },
        // Attribute references use the short form: `?colorPrimary`,
        // `?android:textColorPrimary`.
        TYPE_ATTRIBUTE | TYPE_DYNAMIC_ATTRIBUTE => match resolver.name(data) {
            Some(n) if n.contains("attr/") => format!("?{}", n.replacen("attr/", "", 1)),
            Some(n) => format!("?{n}"),
            None => format!("?0x{data:08x}"),
        },
        TYPE_STRING => strings.get(data as usize).cloned().unwrap_or_default(),
        TYPE_FLOAT => format_float(f32::from_bits(data)),
        TYPE_DIMENSION => {
            const UNITS: [&str; 6] = ["px", "dp", "sp", "pt", "in", "mm"];
            let unit = UNITS.get((data & 0xf) as usize).copied().unwrap_or("?");
            format!("{}{unit}", format_float(complex_to_float(data)))
        }
        TYPE_FRACTION => {
            let unit = if data & 0xf == 0 { "%" } else { "%p" };
            format!("{}{unit}", format_float(complex_to_float(data) * 100.0))
        }
        TYPE_INT_DEC | TYPE_INT_HEX => {
            if let Some(name) = attr
                .and_then(|a| resolver.symbols(a))
                .and_then(|s| s.describe(data))
            {
                return name;
            }
            if data_type == TYPE_INT_DEC {
                (data as i32).to_string()
            } else {
                format!("0x{data:x}")
            }
        }
        TYPE_INT_BOOLEAN => (data != 0).to_string(),
        0x1c | 0x1e => format!("#{data:08x}"),
        0x1d | 0x1f => format!("#{:06x}", data & 0x00ff_ffff),
        t => format!("0x{data:08x} (type 0x{t:02x})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_names() {
        assert_eq!(framework_name(0x0101_0000), Some(("attr", "theme")));
        let r = Resolver::default();
        assert_eq!(r.name(0x0101_0001).as_deref(), Some("android:attr/label"));
        assert_eq!(r.attr_name(0x0101_0001).as_deref(), Some("android:label"));
        assert_eq!(
            format_value(TYPE_REFERENCE, 0x0101_0001, &[], &r, None),
            "@android:attr/label"
        );
        assert_eq!(
            format_value(TYPE_REFERENCE, 0x7f01_0001, &[], &r, None),
            "@0x7f010001"
        );
        assert_eq!(
            format_value(TYPE_ATTRIBUTE, 0x0101_0001, &[], &r, None),
            "?android:label"
        );
    }

    #[test]
    fn symbols() {
        let r = Resolver::default();
        // android:protectionLevel
        let level = 0x0101_0009;
        assert_eq!(
            format_value(TYPE_INT_HEX, 0x2, &[], &r, Some(level)),
            "signature"
        );
        assert_eq!(
            format_value(TYPE_INT_HEX, 0x12, &[], &r, Some(level)),
            "signature|privileged"
        );
        // android:screenOrientation
        assert_eq!(
            format_value(TYPE_INT_DEC, 1, &[], &r, Some(0x0101_001e)),
            "portrait"
        );
        assert_eq!(
            format_value(TYPE_INT_DEC, 77, &[], &r, Some(0x0101_001e)),
            "77"
        );
    }

    #[test]
    fn typed_values() {
        let r = Resolver::default();
        assert_eq!(format_value(0x12, 0xffff_ffff, &[], &r, None), "true");
        assert_eq!(format_value(0x1c, 0xff00_ff00, &[], &r, None), "#ff00ff00");
        assert_eq!(format_value(0x05, (16 << 8) | 1, &[], &r, None), "16dp");
        // 18.659973dp must not be rounded: mantissa 611450 / 2^15 (radix 2).
        let dim = (611_450u32 << 8) | (2 << 4) | 1;
        assert_eq!(format_value(0x05, dim, &[], &r, None), "18.659973dp");
        assert_eq!(format_value(0x04, 0.5f32.to_bits(), &[], &r, None), "0.5");
    }
}
