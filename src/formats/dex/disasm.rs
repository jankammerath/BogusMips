//! Dalvik bytecode disassembler producing smali (baksmali-style) text.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;

use super::javafmt::{double_comment, float_comment, signed_int_or_long};
use super::opcodes::{Format, OpInfo, RefKind, op_info};
use super::smali::escape_string;
use super::values::hex_signed;
use super::{CodeItem, DexFile};

enum RegList {
    None,
    List(Vec<u16>),
    Range { first: u16, count: u16 },
}

struct Insn {
    addr: u32,
    op: u8,
    info: OpInfo,
    regs: Vec<u16>,
    list: RegList,
    literal: i64,
    target: i64,
    index: u32,
    index2: u32,
}

enum Item {
    Insn(Insn),
    PackedSwitch {
        addr: u32,
        first_key: i32,
        targets: Vec<i32>,
    },
    SparseSwitch {
        addr: u32,
        keys: Vec<i32>,
        targets: Vec<i32>,
    },
    ArrayData {
        addr: u32,
        width: u16,
        data: Vec<u8>,
    },
    Invalid {
        addr: u32,
        reason: String,
    },
}

impl Item {
    fn addr(&self) -> u32 {
        match self {
            Item::Insn(i) => i.addr,
            Item::PackedSwitch { addr, .. }
            | Item::SparseSwitch { addr, .. }
            | Item::ArrayData { addr, .. }
            | Item::Invalid { addr, .. } => *addr,
        }
    }
}

fn i32_at(u: &[u16], k: usize) -> i32 {
    (u32::from(u[k]) | (u32::from(u[k + 1]) << 16)) as i32
}

fn decode(insns: &[u16]) -> Vec<Item> {
    let mut items = Vec::new();
    let mut pc = 0usize;
    while pc < insns.len() {
        let addr = pc as u32;
        let unit = insns[pc];
        let op = (unit & 0xff) as u8;
        let rest = &insns[pc..];

        if op == 0 && (1..=3).contains(&(unit >> 8)) {
            match decode_payload(addr, rest) {
                Ok((item, size)) => {
                    items.push(item);
                    pc += size;
                }
                Err(reason) => {
                    items.push(Item::Invalid { addr, reason });
                    break;
                }
            }
            continue;
        }

        let info = op_info(op);
        let size = info.format.units();
        if rest.len() < size {
            items.push(Item::Invalid {
                addr,
                reason: format!("truncated {} instruction", info.name),
            });
            break;
        }
        items.push(Item::Insn(decode_insn(addr, op, info, &rest[..size])));
        pc += size;
    }
    items
}

fn decode_payload(addr: u32, u: &[u16]) -> Result<(Item, usize), String> {
    let need = |n: usize, what: &str| {
        if u.len() < n {
            Err(format!("truncated {what} payload"))
        } else {
            Ok(())
        }
    };
    match u[0] {
        0x0100 => {
            need(4, "packed-switch")?;
            let size = usize::from(u[1]);
            let total = 4 + size * 2;
            need(total, "packed-switch")?;
            let targets = (0..size).map(|i| i32_at(u, 4 + i * 2)).collect();
            Ok((
                Item::PackedSwitch {
                    addr,
                    first_key: i32_at(u, 2),
                    targets,
                },
                total,
            ))
        }
        0x0200 => {
            need(2, "sparse-switch")?;
            let size = usize::from(u[1]);
            let total = 2 + size * 4;
            need(total, "sparse-switch")?;
            let keys = (0..size).map(|i| i32_at(u, 2 + i * 2)).collect();
            let targets = (0..size).map(|i| i32_at(u, 2 + size * 2 + i * 2)).collect();
            Ok((
                Item::SparseSwitch {
                    addr,
                    keys,
                    targets,
                },
                total,
            ))
        }
        _ => {
            need(4, "array-data")?;
            let width = u[1];
            let count = i32_at(u, 2) as u32 as usize;
            let bytes = usize::from(width)
                .checked_mul(count)
                .ok_or("array-data payload too large")?;
            let total = 4 + bytes.div_ceil(2);
            need(total, "array-data")?;
            let data = u[4..total]
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .take(bytes)
                .collect();
            Ok((Item::ArrayData { addr, width, data }, total))
        }
    }
}

fn decode_insn(addr: u32, op: u8, info: OpInfo, u: &[u16]) -> Insn {
    use Format::*;
    let aa = u[0] >> 8;
    let a = (u[0] >> 8) & 0xf;
    let b = u[0] >> 12;
    let base = i64::from(addr);
    let mut insn = Insn {
        addr,
        op,
        info,
        regs: Vec::new(),
        list: RegList::None,
        literal: 0,
        target: 0,
        index: 0,
        index2: 0,
    };
    match info.format {
        F10x | Unused => {}
        F12x => insn.regs = vec![a, b],
        F11n => {
            insn.regs = vec![a];
            insn.literal = i64::from(((b as i8) << 4) >> 4);
        }
        F11x => insn.regs = vec![aa],
        F10t => insn.target = base + i64::from(aa as u8 as i8),
        F20t => insn.target = base + i64::from(u[1] as i16),
        F22x => insn.regs = vec![aa, u[1]],
        F21t => {
            insn.regs = vec![aa];
            insn.target = base + i64::from(u[1] as i16);
        }
        F21s => {
            insn.regs = vec![aa];
            insn.literal = i64::from(u[1] as i16);
        }
        F21h => {
            insn.regs = vec![aa];
            let shift = if op == 0x19 { 48 } else { 16 };
            insn.literal = i64::from(u[1] as i16) << shift;
        }
        F21c => {
            insn.regs = vec![aa];
            insn.index = u32::from(u[1]);
        }
        F23x => insn.regs = vec![aa, u[1] & 0xff, u[1] >> 8],
        F22b => {
            insn.regs = vec![aa, u[1] & 0xff];
            insn.literal = i64::from((u[1] >> 8) as u8 as i8);
        }
        F22t => {
            insn.regs = vec![a, b];
            insn.target = base + i64::from(u[1] as i16);
        }
        F22s => {
            insn.regs = vec![a, b];
            insn.literal = i64::from(u[1] as i16);
        }
        F22c => {
            insn.regs = vec![a, b];
            insn.index = u32::from(u[1]);
        }
        F32x => insn.regs = vec![u[1], u[2]],
        F30t => insn.target = base + i64::from(i32_at(u, 1)),
        F31t => {
            insn.regs = vec![aa];
            insn.target = base + i64::from(i32_at(u, 1));
        }
        F31i => {
            insn.regs = vec![aa];
            insn.literal = i64::from(i32_at(u, 1));
        }
        F31c => {
            insn.regs = vec![aa];
            insn.index = i32_at(u, 1) as u32;
        }
        F35c | F45cc => {
            let count = usize::from(b);
            let all = [
                u[2] & 0xf,
                (u[2] >> 4) & 0xf,
                (u[2] >> 8) & 0xf,
                u[2] >> 12,
                a,
            ];
            insn.list = RegList::List(all[..count.min(5)].to_vec());
            insn.index = u32::from(u[1]);
            if info.format == F45cc {
                insn.index2 = u32::from(u[3]);
            }
        }
        F3rc | F4rcc => {
            insn.list = RegList::Range {
                first: u[2],
                count: aa,
            };
            insn.index = u32::from(u[1]);
            if info.format == F4rcc {
                insn.index2 = u32::from(u[3]);
            }
        }
        F51l => {
            insn.regs = vec![aa];
            insn.literal = (u64::from(u[1])
                | (u64::from(u[2]) << 16)
                | (u64::from(u[3]) << 32)
                | (u64::from(u[4]) << 48)) as i64;
        }
    }
    insn
}

fn branch_prefix(op: u8) -> &'static str {
    match op {
        0x26 => "array",
        0x2b => "pswitch_data",
        0x2c => "sswitch_data",
        0x28..=0x2a => "goto",
        _ => "cond",
    }
}

/// Collects label references, then numbers them per prefix in address order
/// (`:cond_0`, `:cond_1`, ...), matching baksmali's naming.
#[derive(Default)]
struct Labels {
    refs: BTreeMap<&'static str, BTreeSet<i64>>,
    names: HashMap<(&'static str, i64), String>,
    /// Labels placed before the instruction at an address (excludes try_end).
    at: BTreeMap<i64, Vec<String>>,
}

impl Labels {
    fn add(&mut self, prefix: &'static str, addr: i64) {
        self.refs.entry(prefix).or_default().insert(addr);
    }

    fn finalize(&mut self) {
        for (&prefix, addrs) in &self.refs {
            for (i, &addr) in addrs.iter().enumerate() {
                let name = format!(":{prefix}_{i:x}");
                if prefix != "try_end" {
                    self.at.entry(addr).or_default().push(name.clone());
                }
                self.names.insert((prefix, addr), name);
            }
        }
    }

    fn name(&self, prefix: &'static str, addr: i64) -> String {
        self.names
            .get(&(prefix, addr))
            .cloned()
            .unwrap_or_else(|| format!(":{prefix}_at_{addr:x}"))
    }
}

struct Formatter<'a> {
    dex: &'a DexFile,
    labels: &'a Labels,
    param_base: u16,
    has_params: bool,
}

impl Formatter<'_> {
    fn reg(&self, r: u16) -> String {
        if self.has_params && r >= self.param_base {
            format!("p{}", r - self.param_base)
        } else {
            format!("v{r}")
        }
    }

    fn reference(&self, kind: RefKind, idx: u32) -> String {
        match kind {
            RefKind::None => String::new(),
            RefKind::String => format!("\"{}\"", escape_string(&self.dex.string(idx))),
            RefKind::Type => self.dex.type_descriptor(idx).into_owned(),
            RefKind::Field => self.dex.field_ref(idx),
            RefKind::Method => self.dex.method_ref(idx),
            RefKind::Proto => self.dex.proto_descriptor(idx),
            RefKind::CallSite => format!("call_site_{idx}"),
            RefKind::MethodHandle => format!("method_handle@{idx}"),
        }
    }

    fn reg_list(&self, list: &RegList) -> String {
        match list {
            RegList::None => "{}".to_owned(),
            RegList::List(regs) => {
                let regs: Vec<String> = regs.iter().map(|&r| self.reg(r)).collect();
                format!("{{{}}}", regs.join(", "))
            }
            RegList::Range { count: 0, .. } => "{}".to_owned(),
            RegList::Range { first, count } => {
                let last = first.saturating_add(count - 1);
                format!("{{{} .. {}}}", self.reg(*first), self.reg(last))
            }
        }
    }

    fn insn(&self, i: &Insn) -> String {
        use Format::*;
        let name = i.info.name;
        let regs: Vec<String> = i.regs.iter().map(|&r| self.reg(r)).collect();
        let lit = || hex_signed(i.literal);
        let target = || self.labels.name(branch_prefix(i.op), i.target);
        match i.info.format {
            F10x => name.to_owned(),
            Unused => format!("# unknown opcode 0x{:02x}", i.op),
            F12x | F22x | F32x | F23x | F11x => format!("{name} {}", regs.join(", ")),
            F11n | F22b | F22s => format!("{name} {}, {}", regs.join(", "), lit()),
            F21s | F21h | F31i | F51l => {
                let comment = if matches!(i.op, 0x16..=0x19) {
                    double_comment(i.literal)
                } else {
                    float_comment(i.literal as i32)
                };
                format!(
                    "{name} {}, {}{}",
                    regs.join(", "),
                    signed_int_or_long(i.literal),
                    comment.unwrap_or_default()
                )
            }
            F10t | F20t | F30t => format!("{name} {}", target()),
            F21t | F22t | F31t => format!("{name} {}, {}", regs.join(", "), target()),
            F21c | F31c | F22c => format!(
                "{name} {}, {}",
                regs.join(", "),
                self.reference(i.info.ref_kind, i.index)
            ),
            F35c | F3rc => format!(
                "{name} {}, {}",
                self.reg_list(&i.list),
                self.reference(i.info.ref_kind, i.index)
            ),
            F45cc | F4rcc => format!(
                "{name} {}, {}, {}",
                self.reg_list(&i.list),
                self.reference(RefKind::Method, i.index),
                self.reference(RefKind::Proto, i.index2)
            ),
        }
    }
}

fn array_element(chunk: &[u8]) -> String {
    let mut buf = [0u8; 8];
    buf[..chunk.len()].copy_from_slice(chunk);
    let raw = u64::from_le_bytes(buf);
    let shift = 64 - 8 * chunk.len() as u32;
    let value = ((raw << shift) as i64) >> shift;
    match chunk.len() {
        1 => format!("{}t", hex_signed(value)),
        2 => format!("{}s", hex_signed(value)),
        4 => format!(
            "{}{}",
            hex_signed(value),
            float_comment(value as i32).unwrap_or_default()
        ),
        8 => format!(
            "{}{}",
            signed_int_or_long(value),
            double_comment(value).unwrap_or_default()
        ),
        _ => signed_int_or_long(value),
    }
}

fn is_branch(format: Format) -> bool {
    matches!(
        format,
        Format::F10t | Format::F20t | Format::F30t | Format::F21t | Format::F22t | Format::F31t
    )
}

/// Field indices written by `sput*` instructions in the given code.
pub fn static_puts(code: &CodeItem) -> Vec<u32> {
    decode(&code.insns)
        .iter()
        .filter_map(|item| match item {
            Item::Insn(i) if (0x67..=0x6d).contains(&i.op) => Some(i.index),
            _ => None,
        })
        .collect()
}

/// Appends the smali body (`.locals`, instructions, labels, try/catch) of a
/// method to `out`. Each line is prefixed with `indent`.
pub fn disassemble(dex: &DexFile, code: &CodeItem, out: &mut String, indent: &str) {
    let items = decode(&code.insns);
    let mut labels = Labels::default();
    let mut payload_base: HashMap<i64, i64> = HashMap::new();

    for item in &items {
        if let Item::Insn(i) = item {
            if is_branch(i.info.format) {
                labels.add(branch_prefix(i.op), i.target);
                if matches!(i.op, 0x2b | 0x2c) {
                    payload_base.insert(i.target, i64::from(i.addr));
                }
            }
        }
    }
    let switch_target = |item: &Item| -> Option<(&'static str, i64, Vec<i64>)> {
        let (prefix, targets) = match item {
            Item::PackedSwitch { targets, .. } => ("pswitch", targets),
            Item::SparseSwitch { targets, .. } => ("sswitch", targets),
            _ => return None,
        };
        let addr = i64::from(item.addr());
        let base = payload_base.get(&addr).copied().unwrap_or(addr);
        Some((
            prefix,
            base,
            targets.iter().map(|&t| base + i64::from(t)).collect(),
        ))
    };
    for item in &items {
        if let Some((prefix, _, targets)) = switch_target(item) {
            for t in targets {
                labels.add(prefix, t);
            }
        }
    }
    for t in &code.tries {
        let start = i64::from(t.start_addr);
        labels.add("try_start", start);
        labels.add("try_end", start + i64::from(t.insn_count));
        for &(_, handler) in &t.handlers {
            labels.add("catch", i64::from(handler));
        }
        if let Some(handler) = t.catch_all {
            labels.add("catchall", i64::from(handler));
        }
    }
    labels.finalize();

    // try_end labels and .catch directives are emitted right after the last
    // instruction covered by the try block, as baksmali does.
    let mut catches: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for t in &code.tries {
        let start = i64::from(t.start_addr);
        let end = start + i64::from(t.insn_count);
        let start_label = labels.name("try_start", start);
        let end_label = labels.name("try_end", end);
        let entry = catches.entry(end).or_default();
        if !entry.contains(&end_label) {
            entry.push(end_label.clone());
        }
        for &(type_idx, handler) in &t.handlers {
            entry.push(format!(
                ".catch {} {{{start_label} .. {end_label}}} {}",
                dex.type_descriptor(type_idx),
                labels.name("catch", i64::from(handler))
            ));
        }
        if let Some(handler) = t.catch_all {
            entry.push(format!(
                ".catchall {{{start_label} .. {end_label}}} {}",
                labels.name("catchall", i64::from(handler))
            ));
        }
    }

    let fmt = Formatter {
        dex,
        labels: &labels,
        param_base: code.registers_size.saturating_sub(code.ins_size),
        has_params: code.ins_size > 0 && code.ins_size <= code.registers_size,
    };

    if code.ins_size <= code.registers_size {
        let _ = writeln!(
            out,
            "{indent}.locals {}",
            code.registers_size - code.ins_size
        );
    } else {
        let _ = writeln!(out, "{indent}.registers {}", code.registers_size);
    }

    let emit_catches = |out: &mut String, addr: i64| {
        if let Some(lines) = catches.get(&addr) {
            for line in lines {
                let _ = writeln!(out, "{indent}{line}");
            }
        }
    };

    let mut emitted: BTreeSet<i64> = BTreeSet::new();
    for item in &items {
        let addr = i64::from(item.addr());
        emit_catches(out, addr);
        out.push('\n');
        if let Some(names) = labels.at.get(&addr) {
            for name in names {
                let _ = writeln!(out, "{indent}{name}");
            }
            emitted.insert(addr);
        }
        match item {
            Item::Insn(i) => {
                let _ = writeln!(out, "{indent}{}", fmt.insn(i));
            }
            Item::PackedSwitch { first_key, .. } => {
                let (prefix, _, targets) = switch_target(item).expect("switch payload");
                let _ = writeln!(
                    out,
                    "{indent}.packed-switch {}",
                    hex_signed(i64::from(*first_key))
                );
                for t in targets {
                    let _ = writeln!(out, "{indent}    {}", labels.name(prefix, t));
                }
                let _ = writeln!(out, "{indent}.end packed-switch");
            }
            Item::SparseSwitch { keys, .. } => {
                let (prefix, _, targets) = switch_target(item).expect("switch payload");
                let _ = writeln!(out, "{indent}.sparse-switch");
                for (&k, t) in keys.iter().zip(targets) {
                    let _ = writeln!(
                        out,
                        "{indent}    {} -> {}",
                        hex_signed(i64::from(k)),
                        labels.name(prefix, t)
                    );
                }
                let _ = writeln!(out, "{indent}.end sparse-switch");
            }
            Item::ArrayData { width, data, .. } => {
                let _ = writeln!(out, "{indent}.array-data {width}");
                if *width > 0 {
                    for chunk in data.chunks(usize::from(*width)) {
                        if chunk.len() <= 8 {
                            let _ = writeln!(out, "{indent}    {}", array_element(chunk));
                        }
                    }
                }
                let _ = writeln!(out, "{indent}.end array-data");
            }
            Item::Invalid { reason, .. } => {
                let _ = writeln!(out, "{indent}# ERROR at 0x{addr:x}: {reason}");
            }
        }
    }

    let end = code.insns.len() as i64;
    for (&addr, _) in catches.range(end..) {
        emit_catches(out, addr);
    }
    let dangling: Vec<String> = labels
        .at
        .iter()
        .filter(|(addr, _)| !emitted.contains(addr))
        .flat_map(|(addr, names)| names.iter().map(move |n| format!("{n} (0x{addr:x})")))
        .collect();
    if !dangling.is_empty() {
        let _ = writeln!(
            out,
            "\n{indent}# WARNING: labels not on an instruction boundary: {}",
            dangling.join(", ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(units: &[u16]) -> Insn {
        match decode(units).into_iter().next().unwrap() {
            Item::Insn(i) => i,
            _ => panic!("expected instruction"),
        }
    }

    #[test]
    fn decodes_formats() {
        // const/4 v1, -0x1
        let i = decode_one(&[0xf112]);
        assert_eq!((i.regs.as_slice(), i.literal), (&[1u16][..], -1));
        // const/high16 v0, 0x7f010000
        let i = decode_one(&[0x0015, 0x7f01]);
        assert_eq!(i.literal, 0x7f01_0000);
        // const-wide/high16 v0, 0x4000000000000000L
        let i = decode_one(&[0x0019, 0x4000]);
        assert_eq!(i.literal, 0x4000_0000_0000_0000);
        // add-int/lit8 v0, v1, -0x2
        let i = decode_one(&[0x00d8, 0xfe01]);
        assert_eq!((i.regs.as_slice(), i.literal), (&[0u16, 1][..], -2));
        // invoke-virtual {v1, v2, v3}, method@5
        let i = decode_one(&[0x306e, 0x0005, 0x0321]);
        assert!(matches!(&i.list, RegList::List(r) if r == &[1, 2, 3]));
        assert_eq!(i.index, 5);
        // goto -0x2 from address 0
        let i = decode_one(&[0xfe28]);
        assert_eq!(i.target, -2);
    }

    #[test]
    fn decodes_payloads_and_truncation() {
        // packed-switch v0, +3 ; packed-switch payload (1 target)
        let items = decode(&[
            0x002b, 0x0003, 0x0000, 0x0100, 0x0001, 0x0005, 0x0000, 0x0010, 0x0000,
        ]);
        assert!(matches!(items[1], Item::PackedSwitch { first_key: 5, .. }));
        // truncated const-wide
        let items = decode(&[0x0018, 0x0001]);
        assert!(matches!(items[0], Item::Invalid { .. }));
        // truncated array payload
        let items = decode(&[0x0300, 0x0004, 0xffff, 0xffff]);
        assert!(matches!(items[0], Item::Invalid { .. }));
    }

    #[test]
    fn array_elements() {
        assert_eq!(array_element(&[0xff]), "-0x1t");
        assert_eq!(array_element(&[0x01, 0x00]), "0x1s");
        assert_eq!(array_element(&[0x10, 0, 0, 0]), "0x10");
        assert_eq!(array_element(&[0, 0, 0x80, 0x3f]), "0x3f800000    # 1.0f");
        assert_eq!(
            array_element(&[0, 0, 0, 0, 0, 0, 0, 0x40]),
            "0x4000000000000000L    # 2.0"
        );
    }
}
