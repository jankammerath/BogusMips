//! Parser for Android's compiled resource table (`resources.arsc`) and
//! generation of the `res/values*/*.xml` files it was compiled from.
//!
//! Format reference: `ResourceTypes.h` in AOSP (frameworks/base/libs/androidfw).

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use super::axml::parse_string_pool;
use super::reader::{Reader, Result, err, read_u16, read_u32};
use super::resvalue::{
    Resolver, SymbolKind, Symbols, TYPE_DIMENSION, TYPE_FRACTION, TYPE_INT_BOOLEAN, TYPE_INT_DEC,
    TYPE_INT_HEX, TYPE_STRING, format_value,
};

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_TYPE: u16 = 0x0002;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;

const FLAG_COMPLEX: u16 = 0x0001;
const FLAG_COMPACT: u16 = 0x0008;
const TYPE_FLAG_SPARSE: u8 = 0x01;
const TYPE_FLAG_OFFSET16: u8 = 0x02;

const ATTR_TYPE: u32 = 0x0100_0000;
const ATTR_MIN: u32 = 0x0100_0001;
const ATTR_MAX: u32 = 0x0100_0002;
const ATTR_L10N: u32 = 0x0100_0003;
const ATTR_OTHER: u32 = 0x0100_0004;
const ATTR_MANY: u32 = 0x0100_0009;
const ARRAY_BASE: u32 = 0x0200_0000;
const FORMAT_ENUM: u32 = 1 << 16;
const FORMAT_FLAGS: u32 = 1 << 17;

/// Upper bound for nested data, protecting against crafted tables.
const MAX_BAG_ITEMS: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Value {
    pub data_type: u8,
    pub data: u32,
}

#[derive(Debug, Clone)]
pub enum EntryValue {
    Simple(Value),
    Bag {
        parent: u32,
        items: Vec<(u32, Value)>,
    },
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub index: u16,
    pub key: String,
    pub value: EntryValue,
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Qualifier suffix as used in directory names, e.g. `de-rAT-night-v31`.
    pub qualifiers: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub struct ResType {
    pub id: u8,
    pub name: String,
    pub configs: Vec<Config>,
}

#[derive(Debug, Clone)]
pub struct ResPackage {
    pub id: u32,
    pub name: String,
    pub types: Vec<ResType>,
}

pub struct ResourceTable {
    pub strings: Vec<String>,
    pub packages: Vec<ResPackage>,
    pub warnings: Vec<String>,
    /// Resource ID → (package index, type index); the key is looked up from
    /// the first config containing the entry.
    names: HashMap<u32, (usize, usize, String)>,
}

/// A generated `res/values*/…xml` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValuesFile {
    pub dir: String,
    pub file: String,
    pub source: ValuesSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValuesSource {
    Values {
        package: usize,
        res_type: usize,
        config: usize,
    },
    Public {
        package: usize,
    },
}

fn read_value(data: &[u8], off: usize) -> Result<Value> {
    let mut r = Reader::at(data, off)?;
    let _size = r.u16()?;
    let _res0 = r.u8()?;
    Ok(Value {
        data_type: r.u8()?,
        data: r.u32()?,
    })
}

fn unpack_locale_part(bytes: [u8; 2], base: u8) -> String {
    if bytes[0] == 0 {
        return String::new();
    }
    if bytes[0] & 0x80 != 0 {
        let first = bytes[1] & 0x1f;
        let second = ((bytes[1] & 0xe0) >> 5) | ((bytes[0] & 0x03) << 3);
        let third = (bytes[0] & 0x7c) >> 2;
        return [first, second, third]
            .iter()
            .map(|&c| char::from(base.wrapping_add(c)))
            .collect();
    }
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect()
}

fn ascii_field(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|&&b| b != 0)
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|&b| char::from(b))
        .collect()
}

/// Builds the resource qualifier string (e.g. `de-rAT-land-xhdpi-v21`) from a
/// `ResTable_config`.
fn config_qualifiers(c: &[u8]) -> String {
    let u8_at = |o: usize| c.get(o).copied().unwrap_or(0);
    let u16_at = |o: usize| {
        c.get(o..o + 2)
            .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
    };
    let mut q: Vec<String> = Vec::new();

    let (mcc, mnc) = (u16_at(4), u16_at(6));
    if mcc != 0 {
        q.push(format!("mcc{mcc:03}"));
    }
    if mnc != 0 {
        q.push(if mnc == 0xffff {
            "mnc00".to_owned()
        } else {
            format!("mnc{mnc:02}")
        });
    }

    let language = unpack_locale_part([u8_at(8), u8_at(9)], b'a');
    let region = unpack_locale_part([u8_at(10), u8_at(11)], b'0');
    let script = c.get(36..40).map(ascii_field).unwrap_or_default();
    let variant = c.get(40..48).map(ascii_field).unwrap_or_default();
    if !language.is_empty() {
        if script.is_empty() && variant.is_empty() && language.len() == 2 && region.len() <= 2 {
            q.push(language);
            if !region.is_empty() {
                q.push(format!("r{region}"));
            }
        } else {
            let mut b = format!("b+{language}");
            for part in [&script, &region, &variant] {
                if !part.is_empty() {
                    b = format!("{b}+{part}");
                }
            }
            q.push(b);
        }
    }

    let screen_layout = u8_at(28);
    let ui_mode = u8_at(29);
    match screen_layout & 0xc0 {
        0x40 => q.push("ldltr".into()),
        0x80 => q.push("ldrtl".into()),
        _ => {}
    }
    let sw = u16_at(30);
    if sw != 0 {
        q.push(format!("sw{sw}dp"));
    }
    let (w, h) = (u16_at(32), u16_at(34));
    if w != 0 {
        q.push(format!("w{w}dp"));
    }
    if h != 0 {
        q.push(format!("h{h}dp"));
    }
    match screen_layout & 0x0f {
        1 => q.push("small".into()),
        2 => q.push("normal".into()),
        3 => q.push("large".into()),
        4 => q.push("xlarge".into()),
        _ => {}
    }
    match screen_layout & 0x30 {
        0x10 => q.push("notlong".into()),
        0x20 => q.push("long".into()),
        _ => {}
    }
    let layout2 = u8_at(48);
    match layout2 & 0x03 {
        1 => q.push("notround".into()),
        2 => q.push("round".into()),
        _ => {}
    }
    let color = u8_at(49);
    match color & 0x03 {
        1 => q.push("nowidecg".into()),
        2 => q.push("widecg".into()),
        _ => {}
    }
    match color & 0x0c {
        0x04 => q.push("lowdr".into()),
        0x08 => q.push("highdr".into()),
        _ => {}
    }
    match u8_at(12) {
        1 => q.push("port".into()),
        2 => q.push("land".into()),
        3 => q.push("square".into()),
        _ => {}
    }
    match ui_mode & 0x0f {
        2 => q.push("desk".into()),
        3 => q.push("car".into()),
        4 => q.push("television".into()),
        5 => q.push("appliance".into()),
        6 => q.push("watch".into()),
        7 => q.push("vrheadset".into()),
        _ => {}
    }
    match ui_mode & 0x30 {
        0x10 => q.push("notnight".into()),
        0x20 => q.push("night".into()),
        _ => {}
    }
    match u16_at(14) {
        0 => {}
        120 => q.push("ldpi".into()),
        160 => q.push("mdpi".into()),
        213 => q.push("tvdpi".into()),
        240 => q.push("hdpi".into()),
        320 => q.push("xhdpi".into()),
        480 => q.push("xxhdpi".into()),
        640 => q.push("xxxhdpi".into()),
        0xfffe => q.push("anydpi".into()),
        0xffff => q.push("nodpi".into()),
        d => q.push(format!("{d}dpi")),
    }
    match u8_at(13) {
        1 => q.push("notouch".into()),
        2 => q.push("stylus".into()),
        3 => q.push("finger".into()),
        _ => {}
    }
    let input_flags = u8_at(18);
    match input_flags & 0x03 {
        1 => q.push("keysexposed".into()),
        2 => q.push("keyshidden".into()),
        3 => q.push("keyssoft".into()),
        _ => {}
    }
    match u8_at(16) {
        1 => q.push("nokeys".into()),
        2 => q.push("qwerty".into()),
        3 => q.push("12key".into()),
        _ => {}
    }
    match input_flags & 0x0c {
        0x04 => q.push("navexposed".into()),
        0x08 => q.push("navhidden".into()),
        _ => {}
    }
    match u8_at(17) {
        1 => q.push("nonav".into()),
        2 => q.push("dpad".into()),
        3 => q.push("trackball".into()),
        4 => q.push("wheel".into()),
        _ => {}
    }
    let (screen_w, screen_h) = (u16_at(20), u16_at(22));
    if screen_w != 0 && screen_h != 0 {
        q.push(format!("{screen_w}x{screen_h}"));
    }
    let sdk = u16_at(24);
    if sdk != 0 {
        q.push(format!("v{sdk}"));
    }
    q.join("-")
}

impl ResourceTable {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if read_u16(data, 0)? != RES_TABLE_TYPE {
            return err("not a resource table");
        }
        let header_size = usize::from(read_u16(data, 2)?);
        let mut table = ResourceTable {
            strings: Vec::new(),
            packages: Vec::new(),
            warnings: Vec::new(),
            names: HashMap::new(),
        };
        let declared = read_u32(data, 4)? as usize;
        if declared != data.len() {
            table.warnings.push(format!(
                "header declares {declared} bytes, file has {}",
                data.len()
            ));
        }

        let mut pos = header_size.max(12);
        while pos + 8 <= data.len() {
            let chunk_type = read_u16(data, pos)?;
            let size = read_u32(data, pos + 4)? as usize;
            if size < 8 || pos + size > data.len() {
                table
                    .warnings
                    .push(format!("invalid chunk size {size} at offset 0x{pos:x}"));
                break;
            }
            match chunk_type {
                RES_STRING_POOL_TYPE => table.strings = parse_string_pool(data, pos, size)?,
                RES_TABLE_PACKAGE_TYPE => match parse_package(data, pos, size, &mut table.warnings)
                {
                    Ok(p) => table.packages.push(p),
                    Err(e) => table.warnings.push(format!("package at 0x{pos:x}: {e}")),
                },
                _ => {}
            }
            pos += size;
        }

        for (pi, package) in table.packages.iter().enumerate() {
            for (ti, res_type) in package.types.iter().enumerate() {
                for config in &res_type.configs {
                    for entry in &config.entries {
                        let id = (package.id << 24)
                            | (u32::from(res_type.id) << 16)
                            | u32::from(entry.index);
                        table
                            .names
                            .entry(id)
                            .or_insert_with(|| (pi, ti, entry.key.clone()));
                    }
                }
            }
        }
        Ok(table)
    }

    /// `type/name` (or `package:type/name` for other packages).
    pub fn resource_name(&self, id: u32) -> Option<String> {
        let (pi, ti, key) = self.names.get(&id)?;
        let package = &self.packages[*pi];
        let type_name = &package.types[*ti].name;
        if package.id == 0x7f || self.packages.len() == 1 {
            Some(format!("{type_name}/{key}"))
        } else {
            Some(format!("{}:{type_name}/{key}", package.name))
        }
    }

    fn find_entry(&self, id: u32) -> Option<(&ResType, &Entry)> {
        let (pi, ti, _) = self.names.get(&id)?;
        let res_type = &self.packages[*pi].types[*ti];
        let index = (id & 0xffff) as u16;
        // Prefer the default configuration.
        let mut configs: Vec<&Config> = res_type.configs.iter().collect();
        configs.sort_by_key(|c| !c.qualifiers.is_empty());
        configs
            .into_iter()
            .find_map(|c| c.entries.iter().find(|e| e.index == index))
            .map(|e| (res_type, e))
    }

    /// Named values of an app-defined `enum`/`flag` attribute.
    pub fn attr_symbols(&self, id: u32) -> Option<Symbols> {
        let (res_type, entry) = self.find_entry(id)?;
        if res_type.name != "attr" {
            return None;
        }
        let EntryValue::Bag { items, .. } = &entry.value else {
            return None;
        };
        let format = items.iter().find(|(k, _)| *k == ATTR_TYPE)?.1.data;
        let kind = if format & FORMAT_FLAGS != 0 {
            SymbolKind::Flags
        } else if format & FORMAT_ENUM != 0 {
            SymbolKind::Enum
        } else {
            return None;
        };
        let values = items
            .iter()
            .filter(|(k, _)| k >> 24 != 0x01)
            .filter_map(|(k, v)| {
                let name = self.resource_name(*k)?;
                Some((name.rsplit('/').next()?.to_owned(), v.data))
            })
            .collect();
        Some(Symbols { kind, values })
    }

    /// Resolves `@string/name` to its default-configuration text.
    pub fn string_by_reference(&self, reference: &str) -> Option<String> {
        let (type_name, key) = reference.strip_prefix('@')?.split_once('/')?;
        for package in &self.packages {
            let Some(res_type) = package.types.iter().find(|t| t.name == type_name) else {
                continue;
            };
            let mut configs: Vec<&Config> = res_type.configs.iter().collect();
            configs.sort_by_key(|c| !c.qualifiers.is_empty());
            for config in configs {
                if let Some(Entry {
                    value: EntryValue::Simple(v),
                    ..
                }) = config.entries.iter().find(|e| e.key == key)
                {
                    if v.data_type == TYPE_STRING {
                        return self.strings.get(v.data as usize).cloned();
                    }
                }
            }
        }
        None
    }

    /// Archive paths referenced by file-based resources, with their names
    /// (e.g. `res/a0.xml` → `["@layout/activity_main"]`).
    pub fn file_references(&self) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for package in &self.packages {
            for res_type in &package.types {
                for config in &res_type.configs {
                    for entry in &config.entries {
                        if let EntryValue::Simple(v) = &entry.value {
                            if v.data_type != TYPE_STRING {
                                continue;
                            }
                            let Some(path) = self.strings.get(v.data as usize) else {
                                continue;
                            };
                            if path.starts_with("res/") {
                                let mut name = format!("@{}/{}", res_type.name, entry.key);
                                if !config.qualifiers.is_empty() {
                                    name = format!("{name} ({})", config.qualifiers);
                                }
                                map.entry(path.clone()).or_default().push(name);
                            }
                        }
                    }
                }
            }
        }
        map
    }

    fn is_file_value(&self, v: &Value) -> bool {
        v.data_type == TYPE_STRING
            && self
                .strings
                .get(v.data as usize)
                .is_some_and(|s| s.starts_with("res/"))
    }

    /// All `values*` files that can be generated from this table.
    pub fn values_files(&self) -> Vec<ValuesFile> {
        let mut files = Vec::new();
        let multi = self.packages.len() > 1;
        for (pi, package) in self.packages.iter().enumerate() {
            let prefix = if multi {
                format!("{}/", package.name)
            } else {
                String::new()
            };
            for (ti, res_type) in package.types.iter().enumerate() {
                for (ci, config) in res_type.configs.iter().enumerate() {
                    let has_values = config.entries.iter().any(|e| match &e.value {
                        EntryValue::Simple(v) => !self.is_file_value(v),
                        EntryValue::Bag { .. } => true,
                    });
                    if !has_values {
                        continue;
                    }
                    let dir = if config.qualifiers.is_empty() {
                        format!("{prefix}values")
                    } else {
                        format!("{prefix}values-{}", config.qualifiers)
                    };
                    let file = match res_type.name.as_str() {
                        "plurals" => "plurals.xml".to_owned(),
                        name => format!("{name}s.xml"),
                    };
                    files.push(ValuesFile {
                        dir,
                        file,
                        source: ValuesSource::Values {
                            package: pi,
                            res_type: ti,
                            config: ci,
                        },
                    });
                }
            }
            files.push(ValuesFile {
                dir: format!("{prefix}values"),
                file: "public.xml".to_owned(),
                source: ValuesSource::Public { package: pi },
            });
        }
        files
    }

    pub fn render(&self, source: ValuesSource, resolver: &Resolver) -> String {
        match source {
            ValuesSource::Values {
                package,
                res_type,
                config,
            } => self.values_xml(package, res_type, config, resolver),
            ValuesSource::Public { package } => self.public_xml(package),
        }
    }

    fn public_xml(&self, package: usize) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
        let package = &self.packages[package];
        for res_type in &package.types {
            let mut entries: BTreeMap<u16, &str> = BTreeMap::new();
            for config in &res_type.configs {
                for e in &config.entries {
                    entries.entry(e.index).or_insert(&e.key);
                }
            }
            for (index, key) in entries {
                let id = (package.id << 24) | (u32::from(res_type.id) << 16) | u32::from(index);
                let _ = writeln!(
                    out,
                    "    <public type=\"{}\" name=\"{}\" id=\"0x{id:08x}\" />",
                    res_type.name,
                    escape_xml(key)
                );
            }
        }
        out.push_str("</resources>\n");
        out
    }

    fn format(&self, v: &Value, resolver: &Resolver, attr: Option<u32>) -> String {
        format_value(v.data_type, v.data, &self.strings, resolver, attr)
    }

    fn values_xml(
        &self,
        package: usize,
        res_type: usize,
        config: usize,
        resolver: &Resolver,
    ) -> String {
        let res_type = &self.packages[package].types[res_type];
        let config = &res_type.configs[config];
        let type_name = res_type.name.as_str();
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
        let mut entries: Vec<&Entry> = config.entries.iter().collect();
        entries.sort_by_key(|e| e.index);

        for entry in entries {
            let name = escape_xml(&entry.key);
            match &entry.value {
                EntryValue::Simple(v) if self.is_file_value(v) => {}
                EntryValue::Simple(v) => {
                    let text = if v.data_type == TYPE_STRING {
                        escape_resource_string(&self.format(v, resolver, None))
                    } else {
                        escape_xml(&self.format(v, resolver, None))
                    };
                    // The typed element (`<dimen>`) only accepts values of
                    // its own type; anything else must be an `<item>`.
                    let natural = match type_name {
                        "string" => true,
                        "bool" => v.data_type == TYPE_INT_BOOLEAN,
                        "color" => (0x1c..=0x1f).contains(&v.data_type),
                        "dimen" => v.data_type == TYPE_DIMENSION,
                        "integer" => matches!(v.data_type, TYPE_INT_DEC | TYPE_INT_HEX),
                        "fraction" => v.data_type == TYPE_FRACTION,
                        _ => false,
                    };
                    let _ = if type_name == "id" {
                        writeln!(out, "    <item type=\"id\" name=\"{name}\" />")
                    } else if natural {
                        writeln!(out, "    <{type_name} name=\"{name}\">{text}</{type_name}>")
                    } else {
                        writeln!(
                            out,
                            "    <item type=\"{type_name}\" name=\"{name}\">{text}</item>"
                        )
                    };
                }
                EntryValue::Bag { parent, items } => match type_name {
                    "attr" => self.write_attr(&mut out, &name, items, resolver),
                    "plurals" => {
                        let _ = writeln!(out, "    <plurals name=\"{name}\">");
                        // Natural order: zero, one, two, few, many, other.
                        let mut sorted: Vec<&(u32, Value)> = items.iter().collect();
                        sorted.sort_by_key(|(k, _)| if *k == ATTR_OTHER { u32::MAX } else { *k });
                        for (key, v) in sorted {
                            if (ATTR_OTHER..=ATTR_MANY).contains(key) {
                                let quantity = ["other", "zero", "one", "two", "few", "many"]
                                    [(key - ATTR_OTHER) as usize];
                                let _ = writeln!(
                                    out,
                                    "        <item quantity=\"{quantity}\">{}</item>",
                                    escape_resource_string(&self.format(v, resolver, None))
                                );
                            }
                        }
                        out.push_str("    </plurals>\n");
                    }
                    "array" => {
                        let all =
                            |t: &dyn Fn(u8) -> bool| items.iter().all(|(_, v)| t(v.data_type));
                        let tag = if !items.is_empty() && all(&|t| t == TYPE_STRING) {
                            "string-array"
                        } else if !items.is_empty()
                            && all(&|t| t == TYPE_INT_DEC || t == TYPE_INT_HEX)
                        {
                            "integer-array"
                        } else {
                            "array"
                        };
                        let _ = writeln!(out, "    <{tag} name=\"{name}\">");
                        let mut sorted: Vec<&(u32, Value)> = items.iter().collect();
                        sorted.sort_by_key(|(k, _)| k.wrapping_sub(ARRAY_BASE));
                        for (_, v) in sorted {
                            let text = if v.data_type == TYPE_STRING {
                                escape_resource_string(&self.format(v, resolver, None))
                            } else {
                                escape_xml(&self.format(v, resolver, None))
                            };
                            let _ = writeln!(out, "        <item>{text}</item>");
                        }
                        let _ = writeln!(out, "    </{tag}>");
                    }
                    _ => {
                        let tag = if type_name == "style" {
                            "style"
                        } else {
                            type_name
                        };
                        // An explicit empty parent stops a dotted style name
                        // (`A.B`) from implicitly inheriting `A` when recompiled.
                        let parent_attr = if *parent == 0 && type_name == "style" {
                            " parent=\"\"".to_owned()
                        } else if *parent == 0 {
                            String::new()
                        } else {
                            let parent = format_value(0x01, *parent, &self.strings, resolver, None);
                            format!(" parent=\"{}\"", escape_xml(&parent))
                        };
                        if items.is_empty() {
                            let _ = writeln!(out, "    <{tag} name=\"{name}\"{parent_attr} />");
                            continue;
                        }
                        let _ = writeln!(out, "    <{tag} name=\"{name}\"{parent_attr}>");
                        for (key, v) in items {
                            let item_name = resolver
                                .attr_name(*key)
                                .unwrap_or_else(|| format!("0x{key:08x}"));
                            let text = if v.data_type == TYPE_STRING {
                                escape_resource_string(&self.format(v, resolver, Some(*key)))
                            } else {
                                escape_xml(&self.format(v, resolver, Some(*key)))
                            };
                            let _ = writeln!(
                                out,
                                "        <item name=\"{}\">{text}</item>",
                                escape_xml(&item_name)
                            );
                        }
                        let _ = writeln!(out, "    </{tag}>");
                    }
                },
            }
        }
        out.push_str("</resources>\n");
        out
    }

    fn write_attr(
        &self,
        out: &mut String,
        name: &str,
        items: &[(u32, Value)],
        resolver: &Resolver,
    ) {
        const FORMATS: [(u32, &str); 8] = [
            (1 << 0, "reference"),
            (1 << 1, "string"),
            (1 << 2, "integer"),
            (1 << 3, "boolean"),
            (1 << 4, "color"),
            (1 << 5, "float"),
            (1 << 6, "dimension"),
            (1 << 7, "fraction"),
        ];
        let format = items
            .iter()
            .find(|(k, _)| *k == ATTR_TYPE)
            .map_or(0, |(_, v)| v.data);
        let symbol_tag = if format & FORMAT_FLAGS != 0 {
            "flag"
        } else {
            "enum"
        };
        let formats: Vec<&str> = FORMATS
            .iter()
            .filter(|(bit, _)| format & bit != 0)
            .map(|(_, n)| *n)
            .collect();
        let mut attrs = format!("name=\"{name}\"");
        if !formats.is_empty() {
            let _ = write!(attrs, " format=\"{}\"", formats.join("|"));
        }
        for (key, label) in [(ATTR_MIN, "min"), (ATTR_MAX, "max")] {
            if let Some((_, v)) = items.iter().find(|(k, _)| *k == key) {
                let _ = write!(attrs, " {label}=\"{}\"", v.data as i32);
            }
        }
        if let Some((_, v)) = items.iter().find(|(k, _)| *k == ATTR_L10N) {
            if v.data != 0 {
                attrs.push_str(" localization=\"suggested\"");
            }
        }
        let symbols: Vec<&(u32, Value)> = items.iter().filter(|(k, _)| k >> 24 != 0x01).collect();
        if symbols.is_empty() {
            let _ = writeln!(out, "    <attr {attrs} />");
            return;
        }
        let _ = writeln!(out, "    <attr {attrs}>");
        for (key, v) in symbols {
            let symbol = resolver
                .name(*key)
                .and_then(|n| n.rsplit('/').next().map(str::to_owned))
                .unwrap_or_else(|| format!("0x{key:08x}"));
            let value = if symbol_tag == "flag" {
                format!("0x{:08x}", v.data)
            } else {
                (v.data as i32).to_string()
            };
            let _ = writeln!(
                out,
                "        <{symbol_tag} name=\"{}\" value=\"{value}\" />",
                escape_xml(&symbol)
            );
        }
        out.push_str("    </attr>\n");
    }

    /// Human-readable overview of the table.
    pub fn summary(&self) -> String {
        let mut out = String::from("resources.arsc\n\n");
        let _ = writeln!(out, "{} strings in the global pool", self.strings.len());
        for package in &self.packages {
            let _ = writeln!(out, "\npackage 0x{:02x} {}\n", package.id, package.name);
            for t in &package.types {
                let mut unique: Vec<u16> = t
                    .configs
                    .iter()
                    .flat_map(|c| c.entries.iter().map(|e| e.index))
                    .collect();
                unique.sort_unstable();
                unique.dedup();
                let _ = writeln!(
                    out,
                    "  {:<14}{:>6} entries in {:>3} configurations",
                    t.name,
                    unique.len(),
                    t.configs.len()
                );
            }
        }
        if !self.warnings.is_empty() {
            out.push_str("\nWarnings:\n");
            for w in &self.warnings {
                let _ = writeln!(out, "  ⚠ {w}");
            }
        }
        out
    }

    pub fn entry_count(&self) -> usize {
        self.names.len()
    }
}

fn parse_package(
    data: &[u8],
    start: usize,
    size: usize,
    warnings: &mut Vec<String>,
) -> Result<ResPackage> {
    let header_size = usize::from(read_u16(data, start + 2)?);
    let end = start + size;
    let id = read_u32(data, start + 8)?;
    let mut name_units = Vec::new();
    let mut r = Reader::at(data, start + 12)?;
    for _ in 0..128 {
        let u = r.u16()?;
        if u == 0 {
            break;
        }
        name_units.push(u);
    }
    let name = String::from_utf16_lossy(&name_units);
    let type_strings = read_u32(data, start + 268)? as usize;
    let key_strings = read_u32(data, start + 276)? as usize;
    let type_id_offset = if header_size >= 288 {
        read_u32(data, start + 284)? as usize
    } else {
        0
    };

    let pool_at = |off: usize| -> Result<Vec<String>> {
        let pos = start + off;
        if off == 0 || pos + 8 > end {
            return Ok(Vec::new());
        }
        let size = read_u32(data, pos + 4)? as usize;
        parse_string_pool(data, pos, size.min(end - pos))
    };
    let type_names = pool_at(type_strings)?;
    let key_names = pool_at(key_strings)?;

    let mut types: Vec<ResType> = Vec::new();
    let mut pos = start + header_size;
    while pos + 8 <= end {
        let chunk_type = read_u16(data, pos)?;
        let chunk_size = read_u32(data, pos + 4)? as usize;
        if chunk_size < 8 || pos + chunk_size > end {
            warnings.push(format!(
                "invalid chunk size {chunk_size} at offset 0x{pos:x}"
            ));
            break;
        }
        match chunk_type {
            RES_TABLE_TYPE_TYPE => match parse_type(data, pos, chunk_size, &key_names) {
                Ok((type_id, config)) => {
                    let type_name = (usize::from(type_id))
                        .checked_sub(1 + type_id_offset)
                        .and_then(|i| type_names.get(i))
                        .cloned()
                        .unwrap_or_else(|| format!("type{type_id:02x}"));
                    match types.iter_mut().find(|t| t.id == type_id) {
                        Some(t) => match t
                            .configs
                            .iter_mut()
                            .find(|c| c.qualifiers == config.qualifiers)
                        {
                            Some(existing) => existing.entries.extend(config.entries),
                            None => t.configs.push(config),
                        },
                        None => types.push(ResType {
                            id: type_id,
                            name: type_name,
                            configs: vec![config],
                        }),
                    }
                }
                Err(e) => warnings.push(format!("type chunk at 0x{pos:x}: {e}")),
            },
            RES_TABLE_TYPE_SPEC_TYPE | RES_STRING_POOL_TYPE => {}
            _ => {}
        }
        pos += chunk_size;
    }
    types.sort_by_key(|t| t.id);
    Ok(ResPackage { id, name, types })
}

fn parse_type(data: &[u8], start: usize, size: usize, keys: &[String]) -> Result<(u8, Config)> {
    let end = start + size;
    let header_size = usize::from(read_u16(data, start + 2)?);
    let mut r = Reader::at(data, start + 8)?;
    let type_id = r.u8()?;
    let flags = r.u8()?;
    let _reserved = r.u16()?;
    let entry_count = r.u32()? as usize;
    let entries_start = r.u32()? as usize;
    let config_size = (read_u32(data, start + 20)? as usize).min(end.saturating_sub(start + 20));
    let config = &data[start + 20..start + 20 + config_size];
    let qualifiers = config_qualifiers(config);

    let offsets_at = start + header_size;
    let mut slots: Vec<(u16, usize)> = Vec::new();
    let mut o = Reader::at(data, offsets_at)?;
    if flags & TYPE_FLAG_SPARSE != 0 {
        for _ in 0..entry_count.min(size / 4) {
            let index = o.u16()?;
            let offset = usize::from(o.u16()?) * 4;
            slots.push((index, offset));
        }
    } else if flags & TYPE_FLAG_OFFSET16 != 0 {
        for i in 0..entry_count.min(size / 2).min(0x10000) {
            let off = o.u16()?;
            if off != 0xffff {
                slots.push((i as u16, usize::from(off) * 4));
            }
        }
    } else {
        for i in 0..entry_count.min(size / 4).min(0x10000) {
            let off = o.u32()?;
            if off != 0xffff_ffff {
                slots.push((i as u16, off as usize));
            }
        }
    }

    let mut entries = Vec::with_capacity(slots.len());
    for (index, offset) in slots {
        let at = start + entries_start + offset;
        if at + 8 > end {
            continue;
        }
        let entry_size = usize::from(read_u16(data, at)?);
        let entry_flags = read_u16(data, at + 2)?;
        let (key_index, value) = if entry_flags & FLAG_COMPACT != 0 {
            let value = Value {
                data_type: (entry_flags >> 8) as u8,
                data: read_u32(data, at + 4)?,
            };
            (entry_size, EntryValue::Simple(value))
        } else {
            let key_index = read_u32(data, at + 4)? as usize;
            if entry_flags & FLAG_COMPLEX != 0 {
                let parent = read_u32(data, at + 8)?;
                let count = (read_u32(data, at + 12)? as usize).min(MAX_BAG_ITEMS);
                let mut items = Vec::new();
                let mut item_at = at + entry_size;
                for _ in 0..count {
                    if item_at + 12 > end {
                        break;
                    }
                    let name = read_u32(data, item_at)?;
                    items.push((name, read_value(data, item_at + 4)?));
                    item_at += 12;
                }
                (key_index, EntryValue::Bag { parent, items })
            } else {
                (
                    key_index,
                    EntryValue::Simple(read_value(data, at + entry_size)?),
                )
            }
        };
        let key = keys
            .get(key_index)
            .cloned()
            .unwrap_or_else(|| format!("entry_{index:04x}"));
        entries.push(Entry { index, key, value });
    }
    Ok((
        type_id,
        Config {
            qualifiers,
            entries,
        },
    ))
}

pub fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\t') => {
                let _ = write!(out, "&#{};", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Escapes text for a `<string>` resource the way aapt expects it.
pub fn escape_resource_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '@' | '?' if i == 0 => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualifiers() {
        let mut c = vec![0u8; 64];
        c[0..4].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(config_qualifiers(&c), "");
        c[8..10].copy_from_slice(b"de");
        c[10..12].copy_from_slice(b"AT");
        c[29] = 0x20; // night
        c[14..16].copy_from_slice(&320u16.to_le_bytes());
        c[24..26].copy_from_slice(&31u16.to_le_bytes());
        assert_eq!(config_qualifiers(&c), "de-rAT-night-xhdpi-v31");
        c[36..40].copy_from_slice(b"Latn");
        assert_eq!(config_qualifiers(&c), "b+de+Latn+AT-night-xhdpi-v31");
        // Truncated configs (old format) must not panic.
        assert_eq!(config_qualifiers(&c[..12]), "de-rAT");
    }

    #[test]
    fn escapes_strings() {
        assert_eq!(
            escape_resource_string("it's \"x\" & <y>"),
            "it\\'s \\\"x\\\" &amp; &lt;y&gt;"
        );
        assert_eq!(escape_resource_string("@not a ref\n"), "\\@not a ref\\n");
    }

    fn chunk(kind: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(kind.to_le_bytes());
        v.extend(((header.len() + 8) as u16).to_le_bytes());
        v.extend(((header.len() + body.len() + 8) as u32).to_le_bytes());
        v.extend(header);
        v.extend(body);
        v
    }

    fn pool(strings: &[&str]) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut data = Vec::new();
        for s in strings {
            offsets.extend((data.len() as u32).to_le_bytes());
            data.extend((s.encode_utf16().count() as u16).to_le_bytes());
            for u in s.encode_utf16() {
                data.extend(u.to_le_bytes());
            }
            data.extend([0, 0]);
        }
        let mut header = Vec::new();
        header.extend((strings.len() as u32).to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend(0u32.to_le_bytes());
        header.extend((28 + offsets.len() as u32).to_le_bytes());
        header.extend(0u32.to_le_bytes());
        let mut body = offsets;
        body.extend(data);
        chunk(RES_STRING_POOL_TYPE, &header, &body)
    }

    fn value(data_type: u8, data: u32) -> Vec<u8> {
        let mut v = vec![8, 0, 0, data_type];
        v.extend(data.to_le_bytes());
        v
    }

    /// A type chunk; `entries` are raw entry bytes (or `None` for a hole).
    fn type_chunk(id: u8, language: &[u8; 2], entries: &[Option<Vec<u8>>]) -> Vec<u8> {
        let mut config = vec![0u8; 64];
        config[0..4].copy_from_slice(&64u32.to_le_bytes());
        config[8..10].copy_from_slice(language);
        let mut offsets = Vec::new();
        let mut data: Vec<u8> = Vec::new();
        for e in entries {
            match e {
                Some(bytes) => {
                    offsets.extend((data.len() as u32).to_le_bytes());
                    data.extend(bytes);
                }
                None => offsets.extend(0xffff_ffffu32.to_le_bytes()),
            }
        }
        let mut header = vec![id, 0, 0, 0];
        header.extend((entries.len() as u32).to_le_bytes());
        header.extend(((8 + 12 + 64 + offsets.len()) as u32).to_le_bytes());
        header.extend(config);
        let mut body = offsets;
        body.extend(data);
        chunk(RES_TABLE_TYPE_TYPE, &header, &body)
    }

    fn simple(key: u32, v: Vec<u8>) -> Option<Vec<u8>> {
        let mut e = vec![8, 0, 0, 0];
        e.extend(key.to_le_bytes());
        e.extend(v);
        Some(e)
    }

    fn sample_table() -> Vec<u8> {
        // Global strings: 0 "Hello 'world'", 1 file path, 2 "Hallo"
        let global = pool(&["Hello 'world'", "res/layout/main.xml", "Hallo"]);
        let types = pool(&["string", "layout", "style", "dimen"]);
        let keys = pool(&["app_name", "main", "AppTheme", "margin"]);

        let mut style = vec![16, 0, 1, 0];
        style.extend(2u32.to_le_bytes());
        style.extend(0x0103_0005u32.to_le_bytes()); // parent @android:style/Theme
        style.extend(1u32.to_le_bytes());
        style.extend(0x0101_0098u32.to_le_bytes()); // android:textColor
        style.extend(value(0x1c, 0xff00_0000));

        let mut body = Vec::new();
        body.extend(type_chunk(1, b"\0\0", &[simple(0, value(TYPE_STRING, 0))]));
        body.extend(type_chunk(1, b"de", &[simple(0, value(TYPE_STRING, 2))]));
        body.extend(type_chunk(2, b"\0\0", &[simple(1, value(TYPE_STRING, 1))]));
        body.extend(type_chunk(3, b"\0\0", &[Some(style)]));
        // A fraction (50% = 0.5 = 2^22 / 2^23) stored in a dimen must be an <item>.
        body.extend(type_chunk(
            4,
            b"\0\0",
            &[None, simple(3, value(TYPE_FRACTION, (1 << 30) | (3 << 4)))],
        ));

        let mut header = Vec::new();
        header.extend(0x7fu32.to_le_bytes());
        let mut name = [0u8; 256];
        for (i, u) in "com.example".encode_utf16().enumerate() {
            name[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        header.extend(name);
        let type_pool_at = 288u32;
        let key_pool_at = type_pool_at + types.len() as u32;
        header.extend(type_pool_at.to_le_bytes());
        header.extend(4u32.to_le_bytes());
        header.extend(key_pool_at.to_le_bytes());
        header.extend(4u32.to_le_bytes());
        header.extend(0u32.to_le_bytes());
        let mut package_body = types;
        package_body.extend(keys);
        package_body.extend(body);
        let package = chunk(RES_TABLE_PACKAGE_TYPE, &header, &package_body);

        let mut table_body = global;
        table_body.extend(package);
        chunk(RES_TABLE_TYPE, &1u32.to_le_bytes(), &table_body)
    }

    #[test]
    fn decodes_table_and_generates_values() {
        let table = ResourceTable::parse(&sample_table()).unwrap();
        assert!(table.warnings.is_empty(), "{:?}", table.warnings);
        assert_eq!(table.packages[0].name, "com.example");
        assert_eq!(
            table.resource_name(0x7f01_0000).as_deref(),
            Some("string/app_name")
        );
        assert_eq!(
            table.resource_name(0x7f04_0001).as_deref(),
            Some("dimen/margin")
        );
        assert_eq!(
            table.string_by_reference("@string/app_name").as_deref(),
            Some("Hello 'world'")
        );
        assert_eq!(
            table.file_references().get("res/layout/main.xml"),
            Some(&vec!["@layout/main".to_owned()])
        );

        let files: Vec<String> = table
            .values_files()
            .iter()
            .map(|f| format!("{}/{}", f.dir, f.file))
            .collect();
        assert_eq!(
            files,
            [
                "values/strings.xml",
                "values-de/strings.xml",
                "values/styles.xml",
                "values/dimens.xml",
                "values/public.xml"
            ]
        );

        let resolver = Resolver::default();
        let render = |name: &str| {
            let f = table
                .values_files()
                .into_iter()
                .find(|f| format!("{}/{}", f.dir, f.file) == name)
                .unwrap();
            table.render(f.source, &resolver)
        };
        assert!(
            render("values/strings.xml")
                .contains("<string name=\"app_name\">Hello \\'world\\'</string>")
        );
        assert!(render("values-de/strings.xml").contains(">Hallo</string>"));
        let styles = render("values/styles.xml");
        assert!(
            styles.contains("<style name=\"AppTheme\" parent=\"@android:style/Theme\">"),
            "{styles}"
        );
        assert!(
            styles.contains("<item name=\"android:textColor\">#ff000000</item>"),
            "{styles}"
        );
        assert!(
            render("values/dimens.xml").contains("<item type=\"dimen\" name=\"margin\">50%</item>")
        );
        assert!(
            render("values/public.xml")
                .contains("<public type=\"layout\" name=\"main\" id=\"0x7f020000\" />")
        );
    }

    #[test]
    fn survives_truncation() {
        let table = sample_table();
        for len in (0..table.len()).step_by(7) {
            let _ = ResourceTable::parse(&table[..len]);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(ResourceTable::parse(&[0u8; 4]).is_err());
        let mut d = vec![0u8; 12];
        d[0..2].copy_from_slice(&RES_TABLE_TYPE.to_le_bytes());
        d[2..4].copy_from_slice(&12u16.to_le_bytes());
        d[4..8].copy_from_slice(&12u32.to_le_bytes());
        let t = ResourceTable::parse(&d).unwrap();
        assert!(t.packages.is_empty());
    }
}
