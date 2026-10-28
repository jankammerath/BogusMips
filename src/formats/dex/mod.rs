//! Parser for Dalvik Executable (DEX) files.
//!
//! Format reference: <https://source.android.com/docs/core/runtime/dex-format>

pub mod access;
pub mod disasm;
pub mod javafmt;
pub mod opcodes;
pub mod smali;
pub mod values;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use crate::formats::reader::{Reader, Result, err};

pub const NO_INDEX: u32 = 0xffff_ffff;
const HEADER_SIZE: usize = 0x70;
const ENDIAN_CONSTANT: u32 = 0x1234_5678;

#[derive(Debug, Clone)]
pub struct Header {
    pub version: String,
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub map_off: u32,
    pub string_ids: Section,
    pub type_ids: Section,
    pub proto_ids: Section,
    pub field_ids: Section,
    pub method_ids: Section,
    pub class_defs: Section,
    pub data: Section,
}

#[derive(Debug, Clone, Copy)]
pub struct Section {
    pub size: u32,
    pub off: u32,
}

#[derive(Debug, Clone)]
pub struct ProtoId {
    pub shorty: u32,
    pub return_type: u32,
    pub parameters: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldId {
    pub class: u32,
    pub type_: u32,
    pub name: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct MethodId {
    pub class: u32,
    pub proto: u32,
    pub name: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass: Option<u32>,
    pub interfaces_off: u32,
    pub source_file: Option<u32>,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
}

#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handlers: Vec<(u32, u32)>,
    pub catch_all: Option<u32>,
}

pub struct DexFile {
    data: Arc<[u8]>,
    pub header: Header,
    strings: Vec<Result<Arc<str>>>,
    types: Vec<u32>,
    protos: Vec<ProtoId>,
    fields: Vec<FieldId>,
    methods: Vec<MethodId>,
    pub class_defs: Vec<ClassDef>,
    /// Non-fatal problems found while parsing (often a sign of tampering).
    pub warnings: Vec<String>,
}

impl DexFile {
    pub fn parse(data: Arc<[u8]>) -> Result<Self> {
        let header = parse_header(&data)?;
        let mut warnings = Vec::new();

        if header.endian_tag != ENDIAN_CONSTANT {
            warnings.push(format!(
                "unexpected endian tag 0x{:08x} (big-endian DEX files are not supported)",
                header.endian_tag
            ));
        }
        if header.file_size as usize != data.len() {
            warnings.push(format!(
                "header file_size {} does not match actual size {}",
                header.file_size,
                data.len()
            ));
        }
        let computed = adler32(data.get(12..).unwrap_or_default());
        if computed != header.checksum {
            warnings.push(format!(
                "checksum mismatch: header 0x{:08x}, computed 0x{computed:08x}",
                header.checksum
            ));
        }

        // Overlapping or shared string offsets are a known way to make parsers
        // do quadratic work, so decoding is cached per offset and the total
        // number of scanned bytes is bounded by the file size.
        let mut budget = data.len().saturating_mul(2);
        let mut by_offset: HashMap<u32, Result<Arc<str>>> = HashMap::new();
        let strings = table(&data, header.string_ids, 4, "string_ids", |r| {
            let off = r.u32()?;
            Ok(by_offset
                .entry(off)
                .or_insert_with(|| read_string_data(&data, off as usize, &mut budget))
                .clone())
        })?;
        let types = table(&data, header.type_ids, 4, "type_ids", |r| r.u32())?;
        let protos = table(&data, header.proto_ids, 12, "proto_ids", |r| {
            let shorty = r.u32()?;
            let return_type = r.u32()?;
            let parameters_off = r.u32()?;
            let parameters = read_type_list(&data, parameters_off).unwrap_or_default();
            Ok(ProtoId {
                shorty,
                return_type,
                parameters,
            })
        })?;
        let fields = table(&data, header.field_ids, 8, "field_ids", |r| {
            Ok(FieldId {
                class: u32::from(r.u16()?),
                type_: u32::from(r.u16()?),
                name: r.u32()?,
            })
        })?;
        let methods = table(&data, header.method_ids, 8, "method_ids", |r| {
            Ok(MethodId {
                class: u32::from(r.u16()?),
                proto: u32::from(r.u16()?),
                name: r.u32()?,
            })
        })?;
        let class_defs = table(&data, header.class_defs, 32, "class_defs", |r| {
            let opt = |v: u32| (v != NO_INDEX).then_some(v);
            Ok(ClassDef {
                class_idx: r.u32()?,
                access_flags: r.u32()?,
                superclass: opt(r.u32()?),
                interfaces_off: r.u32()?,
                source_file: opt(r.u32()?),
                annotations_off: r.u32()?,
                class_data_off: r.u32()?,
                static_values_off: r.u32()?,
            })
        })?;

        let bad_strings = strings.iter().filter(|s| s.is_err()).count();
        if bad_strings > 0 {
            warnings.push(format!("{bad_strings} string(s) could not be decoded"));
        }

        Ok(Self {
            data,
            header,
            strings,
            types,
            protos,
            fields,
            methods,
            class_defs,
            warnings,
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn string_count(&self) -> usize {
        self.strings.len()
    }

    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    pub fn method_count(&self) -> usize {
        self.methods.len()
    }

    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    pub fn string(&self, idx: u32) -> Cow<'_, str> {
        match self.strings.get(idx as usize) {
            Some(Ok(s)) => Cow::Borrowed(s),
            Some(Err(_)) => Cow::Owned(format!("<invalid string@{idx}>")),
            None => Cow::Owned(format!("<string@{idx} out of range>")),
        }
    }

    pub fn type_descriptor(&self, idx: u32) -> Cow<'_, str> {
        match self.types.get(idx as usize) {
            Some(&s) => self.string(s),
            None => Cow::Owned(format!("<type@{idx} out of range>")),
        }
    }

    pub fn proto_descriptor(&self, idx: u32) -> String {
        match self.protos.get(idx as usize) {
            Some(proto) => {
                let mut out = String::from("(");
                for &p in &proto.parameters {
                    out.push_str(&self.type_descriptor(p));
                }
                out.push(')');
                out.push_str(&self.type_descriptor(proto.return_type));
                out
            }
            None => format!("<proto@{idx} out of range>"),
        }
    }

    pub fn field(&self, idx: u32) -> Option<&FieldId> {
        self.fields.get(idx as usize)
    }

    pub fn method(&self, idx: u32) -> Option<&MethodId> {
        self.methods.get(idx as usize)
    }

    pub fn proto(&self, idx: u32) -> Option<&ProtoId> {
        self.protos.get(idx as usize)
    }

    /// `name:Type`
    pub fn field_name_and_type(&self, idx: u32) -> String {
        match self.field(idx) {
            Some(f) => format!("{}:{}", self.string(f.name), self.type_descriptor(f.type_)),
            None => format!("<field@{idx} out of range>"),
        }
    }

    /// `Lclass;->name:Type`
    pub fn field_ref(&self, idx: u32) -> String {
        match self.field(idx) {
            Some(f) => format!(
                "{}->{}",
                self.type_descriptor(f.class),
                self.field_name_and_type(idx)
            ),
            None => format!("<field@{idx} out of range>"),
        }
    }

    /// `name(Params)Return`
    pub fn method_name_and_proto(&self, idx: u32) -> String {
        match self.method(idx) {
            Some(m) => format!("{}{}", self.string(m.name), self.proto_descriptor(m.proto)),
            None => format!("<method@{idx} out of range>"),
        }
    }

    /// `Lclass;->name(Params)Return`
    pub fn method_ref(&self, idx: u32) -> String {
        match self.method(idx) {
            Some(m) => format!(
                "{}->{}",
                self.type_descriptor(m.class),
                self.method_name_and_proto(idx)
            ),
            None => format!("<method@{idx} out of range>"),
        }
    }

    pub fn class_descriptor(&self, class: &ClassDef) -> Cow<'_, str> {
        self.type_descriptor(class.class_idx)
    }

    pub fn interfaces(&self, class: &ClassDef) -> Result<Vec<u32>> {
        read_type_list(&self.data, class.interfaces_off)
    }

    pub fn class_data(&self, class: &ClassDef) -> Result<ClassData> {
        if class.class_data_off == 0 {
            return Ok(ClassData::default());
        }
        let mut r = Reader::at(&self.data, class.class_data_off as usize)?;
        let static_size = r.uleb128()?;
        let instance_size = r.uleb128()?;
        let direct_size = r.uleb128()?;
        let virtual_size = r.uleb128()?;

        let read_fields = |r: &mut Reader, n: u32| -> Result<Vec<EncodedField>> {
            let mut out = Vec::with_capacity((n as usize).min(r.remaining() / 2));
            let mut idx = 0u32;
            for _ in 0..n {
                idx = idx.wrapping_add(r.uleb128()?);
                out.push(EncodedField {
                    field_idx: idx,
                    access_flags: r.uleb128()?,
                });
            }
            Ok(out)
        };
        let read_methods = |r: &mut Reader, n: u32| -> Result<Vec<EncodedMethod>> {
            let mut out = Vec::with_capacity((n as usize).min(r.remaining() / 3));
            let mut idx = 0u32;
            for _ in 0..n {
                idx = idx.wrapping_add(r.uleb128()?);
                out.push(EncodedMethod {
                    method_idx: idx,
                    access_flags: r.uleb128()?,
                    code_off: r.uleb128()?,
                });
            }
            Ok(out)
        };

        Ok(ClassData {
            static_fields: read_fields(&mut r, static_size)?,
            instance_fields: read_fields(&mut r, instance_size)?,
            direct_methods: read_methods(&mut r, direct_size)?,
            virtual_methods: read_methods(&mut r, virtual_size)?,
        })
    }

    pub fn code_item(&self, off: u32) -> Result<CodeItem> {
        let mut r = Reader::at(&self.data, off as usize)?;
        let registers_size = r.u16()?;
        let ins_size = r.u16()?;
        let outs_size = r.u16()?;
        let tries_size = r.u16()?;
        let debug_info_off = r.u32()?;
        let insns_size = r.u32()? as usize;
        if insns_size.saturating_mul(2) > r.remaining() {
            return err(format!(
                "code item at 0x{off:x} claims {insns_size} code units, exceeding the file"
            ));
        }
        let mut insns = Vec::with_capacity(insns_size);
        for _ in 0..insns_size {
            insns.push(r.u16()?);
        }

        let mut tries = Vec::with_capacity(usize::from(tries_size));
        if tries_size > 0 {
            if insns_size % 2 == 1 {
                r.skip(2)?;
            }
            let mut raw = Vec::with_capacity(usize::from(tries_size));
            for _ in 0..tries_size {
                raw.push((r.u32()?, r.u16()?, r.u16()?));
            }
            let handlers_base = r.pos();
            for (start_addr, insn_count, handler_off) in raw {
                let mut h = Reader::at(&self.data, handlers_base + usize::from(handler_off))?;
                let size = h.sleb128()?;
                let mut handlers = Vec::new();
                for _ in 0..size.unsigned_abs().min(0xffff) {
                    handlers.push((h.uleb128()?, h.uleb128()?));
                }
                let catch_all = if size <= 0 { Some(h.uleb128()?) } else { None };
                tries.push(TryItem {
                    start_addr,
                    insn_count,
                    handlers,
                    catch_all,
                });
            }
        }

        Ok(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            debug_info_off,
            insns,
            tries,
        })
    }
}

fn parse_header(data: &[u8]) -> Result<Header> {
    if data.len() < HEADER_SIZE {
        return err("file is too small to be a DEX file");
    }
    let magic = &data[..8];
    if &magic[..4] != b"dex\n" || magic[7] != 0 {
        return err("missing DEX magic");
    }
    let version = String::from_utf8_lossy(&magic[4..7]).into_owned();

    let mut r = Reader::at(data, 8)?;
    let checksum = r.u32()?;
    let mut signature = [0u8; 20];
    signature.copy_from_slice(r.bytes(20)?);
    let file_size = r.u32()?;
    let header_size = r.u32()?;
    let endian_tag = r.u32()?;
    let _link_size = r.u32()?;
    let _link_off = r.u32()?;
    let map_off = r.u32()?;
    let mut section = || -> Result<Section> {
        Ok(Section {
            size: r.u32()?,
            off: r.u32()?,
        })
    };
    Ok(Header {
        version,
        checksum,
        signature,
        file_size,
        header_size,
        endian_tag,
        map_off,
        string_ids: section()?,
        type_ids: section()?,
        proto_ids: section()?,
        field_ids: section()?,
        method_ids: section()?,
        class_defs: section()?,
        data: section()?,
    })
}

fn table<T>(
    data: &[u8],
    section: Section,
    item_size: usize,
    name: &str,
    mut parse: impl FnMut(&mut Reader) -> Result<T>,
) -> Result<Vec<T>> {
    let count = section.size as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    let end = (section.off as usize).saturating_add(count.saturating_mul(item_size));
    if end > data.len() {
        return err(format!(
            "{name} table ({count} entries at 0x{:x}) exceeds the file",
            section.off
        ));
    }
    let mut r = Reader::at(data, section.off as usize)?;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(parse(&mut r)?);
    }
    Ok(out)
}

fn read_type_list(data: &[u8], off: u32) -> Result<Vec<u32>> {
    if off == 0 {
        return Ok(Vec::new());
    }
    let mut r = Reader::at(data, off as usize)?;
    let size = r.u32()? as usize;
    if size.saturating_mul(2) > r.remaining() {
        return err(format!("type list at 0x{off:x} exceeds the file"));
    }
    (0..size).map(|_| r.u16().map(u32::from)).collect()
}

fn read_string_data(data: &[u8], off: usize, budget: &mut usize) -> Result<Arc<str>> {
    let mut r = Reader::at(data, off)?;
    let utf16_size = r.uleb128()? as usize;
    let start = r.pos();
    // MUTF-8 needs at most three bytes per UTF-16 unit, plus the terminator.
    let max_len = utf16_size.saturating_mul(3).saturating_add(1);
    let window = max_len.min(data.len() - start);
    let scan = window.min(*budget);
    match data[start..start + scan].iter().position(|&b| b == 0) {
        Some(len) => {
            *budget -= len + 1;
            decode_mutf8(&data[start..start + len]).map(Arc::from)
        }
        None => {
            *budget -= scan;
            if scan < window {
                err("string data budget exhausted (overlapping strings)")
            } else {
                err(format!("unterminated string at 0x{off:x}"))
            }
        }
    }
}

/// Decodes Modified UTF-8 as used by DEX (and JNI): NUL is encoded as two
/// bytes and supplementary characters as surrogate pairs.
pub fn decode_mutf8(bytes: &[u8]) -> Result<String> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let a = bytes[i];
        let cont = |j: usize| -> Result<u16> {
            match bytes.get(j) {
                Some(&b) if b & 0xc0 == 0x80 => Ok(u16::from(b & 0x3f)),
                _ => err("invalid MUTF-8 continuation byte"),
            }
        };
        if a < 0x80 {
            units.push(u16::from(a));
            i += 1;
        } else if a & 0xe0 == 0xc0 {
            units.push((u16::from(a & 0x1f) << 6) | cont(i + 1)?);
            i += 2;
        } else if a & 0xf0 == 0xe0 {
            units.push((u16::from(a & 0x0f) << 12) | (cont(i + 1)? << 6) | cont(i + 2)?);
            i += 3;
        } else {
            return err(format!("invalid MUTF-8 lead byte 0x{a:02x}"));
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// Converts a type descriptor such as `Ljava/lang/String;` or `[I` into its
/// Java source representation (`java.lang.String`, `int[]`).
pub fn descriptor_to_java(desc: &str) -> String {
    let dims = desc.chars().take_while(|&c| c == '[').count();
    let base = &desc[dims..];
    let name = match base {
        "V" => "void".to_owned(),
        "Z" => "boolean".to_owned(),
        "B" => "byte".to_owned(),
        "S" => "short".to_owned(),
        "C" => "char".to_owned(),
        "I" => "int".to_owned(),
        "J" => "long".to_owned(),
        "F" => "float".to_owned(),
        "D" => "double".to_owned(),
        _ if base.starts_with('L') && base.ends_with(';') && base.len() >= 2 => {
            base[1..base.len() - 1].replace('/', ".")
        }
        _ => base.to_owned(),
    };
    format!("{name}{}", "[]".repeat(dims))
}

/// Returns `true` if the data starts with the DEX magic.
pub fn is_dex(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..4] == b"dex\n" && data[7] == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutf8() {
        assert_eq!(decode_mutf8(b"hello").unwrap(), "hello");
        assert_eq!(decode_mutf8(&[0xc0, 0x80]).unwrap(), "\0");
        assert_eq!(decode_mutf8("äö€".as_bytes()).unwrap(), "äö€");
        // U+1F600 as a CESU-8 surrogate pair
        assert_eq!(
            decode_mutf8(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]).unwrap(),
            "😀"
        );
        assert!(decode_mutf8(&[0xff]).is_err());
    }

    #[test]
    fn adler() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn java_names() {
        assert_eq!(descriptor_to_java("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(descriptor_to_java("[[I"), "int[][]");
    }

    /// Minimal DEX with `count` string ids all pointing at `string_data`.
    fn dex_with_strings(count: usize, string_data: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; HEADER_SIZE];
        d[..8].copy_from_slice(b"dex\n035\0");
        d[40..44].copy_from_slice(&ENDIAN_CONSTANT.to_le_bytes());
        d[56..60].copy_from_slice(&(count as u32).to_le_bytes());
        d[60..64].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        let data_off = (HEADER_SIZE + count * 4) as u32;
        for _ in 0..count {
            d.extend(data_off.to_le_bytes());
        }
        d.extend(string_data);
        d
    }

    #[test]
    fn shares_duplicate_string_offsets() {
        let dex = DexFile::parse(Arc::from(dex_with_strings(1000, b"\x05hello\0"))).unwrap();
        assert_eq!(dex.string(999), "hello");
    }

    #[test]
    fn bounds_overlapping_strings() {
        // Many ids pointing into one long unterminated run, each claiming
        // ~2^28 UTF-16 units, must not take quadratic time.
        let run: Vec<u8> = [0xff, 0xff, 0xff, 0x7f].repeat(1_000_000);
        let mut d = dex_with_strings(1, &run);
        let count = 200_000u32;
        let base = (d.len() - run.len()) as u32;
        let mut ids = Vec::new();
        for i in 0..count {
            ids.extend((base + (i * 4) % run.len() as u32).to_le_bytes());
        }
        let ids_off = d.len() as u32;
        d.extend(ids);
        d[56..60].copy_from_slice(&count.to_le_bytes());
        d[60..64].copy_from_slice(&ids_off.to_le_bytes());
        let start = std::time::Instant::now();
        let dex = DexFile::parse(Arc::from(d)).unwrap();
        assert!(start.elapsed().as_secs() < 5, "took {:?}", start.elapsed());
        assert!(dex.string(0).contains("invalid"));
        assert!(
            dex.warnings
                .iter()
                .any(|w| w.contains("could not be decoded"))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(DexFile::parse(Arc::from(vec![0u8; 10])).is_err());
        assert!(DexFile::parse(Arc::from(vec![0u8; 0x70])).is_err());
    }
}
