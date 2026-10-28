//! Dalvik opcode table.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22b,
    F22t,
    F22s,
    F22c,
    F32x,
    F30t,
    F31t,
    F31i,
    F31c,
    F35c,
    F3rc,
    F45cc,
    F4rcc,
    F51l,
    /// Opcode not assigned in any public DEX version.
    Unused,
}

impl Format {
    /// Instruction size in 16-bit code units.
    pub fn units(self) -> usize {
        use Format::*;
        match self {
            F10x | F12x | F11n | F11x | F10t | Unused => 1,
            F20t | F22x | F21t | F21s | F21h | F21c | F23x | F22b | F22t | F22s | F22c => 2,
            F32x | F30t | F31t | F31i | F31c | F35c | F3rc => 3,
            F45cc | F4rcc => 4,
            F51l => 5,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefKind {
    None,
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

#[derive(Clone, Copy, Debug)]
pub struct OpInfo {
    pub name: &'static str,
    pub format: Format,
    pub ref_kind: RefKind,
}

const UNOPS: [&str; 21] = [
    "neg-int",
    "not-int",
    "neg-long",
    "not-long",
    "neg-float",
    "neg-double",
    "int-to-long",
    "int-to-float",
    "int-to-double",
    "long-to-int",
    "long-to-float",
    "long-to-double",
    "float-to-int",
    "float-to-long",
    "float-to-double",
    "double-to-int",
    "double-to-long",
    "double-to-float",
    "int-to-byte",
    "int-to-char",
    "int-to-short",
];

const BINOPS: [&str; 32] = [
    "add-int",
    "sub-int",
    "mul-int",
    "div-int",
    "rem-int",
    "and-int",
    "or-int",
    "xor-int",
    "shl-int",
    "shr-int",
    "ushr-int",
    "add-long",
    "sub-long",
    "mul-long",
    "div-long",
    "rem-long",
    "and-long",
    "or-long",
    "xor-long",
    "shl-long",
    "shr-long",
    "ushr-long",
    "add-float",
    "sub-float",
    "mul-float",
    "div-float",
    "rem-float",
    "add-double",
    "sub-double",
    "mul-double",
    "div-double",
    "rem-double",
];

const BINOPS_2ADDR: [&str; 32] = [
    "add-int/2addr",
    "sub-int/2addr",
    "mul-int/2addr",
    "div-int/2addr",
    "rem-int/2addr",
    "and-int/2addr",
    "or-int/2addr",
    "xor-int/2addr",
    "shl-int/2addr",
    "shr-int/2addr",
    "ushr-int/2addr",
    "add-long/2addr",
    "sub-long/2addr",
    "mul-long/2addr",
    "div-long/2addr",
    "rem-long/2addr",
    "and-long/2addr",
    "or-long/2addr",
    "xor-long/2addr",
    "shl-long/2addr",
    "shr-long/2addr",
    "ushr-long/2addr",
    "add-float/2addr",
    "sub-float/2addr",
    "mul-float/2addr",
    "div-float/2addr",
    "rem-float/2addr",
    "add-double/2addr",
    "sub-double/2addr",
    "mul-double/2addr",
    "div-double/2addr",
    "rem-double/2addr",
];

const LIT16: [&str; 8] = [
    "add-int/lit16",
    "rsub-int",
    "mul-int/lit16",
    "div-int/lit16",
    "rem-int/lit16",
    "and-int/lit16",
    "or-int/lit16",
    "xor-int/lit16",
];

const LIT8: [&str; 11] = [
    "add-int/lit8",
    "rsub-int/lit8",
    "mul-int/lit8",
    "div-int/lit8",
    "rem-int/lit8",
    "and-int/lit8",
    "or-int/lit8",
    "xor-int/lit8",
    "shl-int/lit8",
    "shr-int/lit8",
    "ushr-int/lit8",
];

const ARRAY_OPS: [&str; 14] = [
    "aget",
    "aget-wide",
    "aget-object",
    "aget-boolean",
    "aget-byte",
    "aget-char",
    "aget-short",
    "aput",
    "aput-wide",
    "aput-object",
    "aput-boolean",
    "aput-byte",
    "aput-char",
    "aput-short",
];

const INSTANCE_OPS: [&str; 14] = [
    "iget",
    "iget-wide",
    "iget-object",
    "iget-boolean",
    "iget-byte",
    "iget-char",
    "iget-short",
    "iput",
    "iput-wide",
    "iput-object",
    "iput-boolean",
    "iput-byte",
    "iput-char",
    "iput-short",
];

const STATIC_OPS: [&str; 14] = [
    "sget",
    "sget-wide",
    "sget-object",
    "sget-boolean",
    "sget-byte",
    "sget-char",
    "sget-short",
    "sput",
    "sput-wide",
    "sput-object",
    "sput-boolean",
    "sput-byte",
    "sput-char",
    "sput-short",
];

const INVOKES: [&str; 5] = [
    "invoke-virtual",
    "invoke-super",
    "invoke-direct",
    "invoke-static",
    "invoke-interface",
];

const INVOKES_RANGE: [&str; 5] = [
    "invoke-virtual/range",
    "invoke-super/range",
    "invoke-direct/range",
    "invoke-static/range",
    "invoke-interface/range",
];

const CMP: [&str; 5] = [
    "cmpl-float",
    "cmpg-float",
    "cmpl-double",
    "cmpg-double",
    "cmp-long",
];
const IF_TEST: [&str; 6] = ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"];
const IF_TESTZ: [&str; 6] = ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"];

pub fn op_info(op: u8) -> OpInfo {
    use Format::*;
    use RefKind as R;
    let i = |base: u8| usize::from(op - base);
    let (name, format, ref_kind) = match op {
        0x00 => ("nop", F10x, R::None),
        0x01 => ("move", F12x, R::None),
        0x02 => ("move/from16", F22x, R::None),
        0x03 => ("move/16", F32x, R::None),
        0x04 => ("move-wide", F12x, R::None),
        0x05 => ("move-wide/from16", F22x, R::None),
        0x06 => ("move-wide/16", F32x, R::None),
        0x07 => ("move-object", F12x, R::None),
        0x08 => ("move-object/from16", F22x, R::None),
        0x09 => ("move-object/16", F32x, R::None),
        0x0a => ("move-result", F11x, R::None),
        0x0b => ("move-result-wide", F11x, R::None),
        0x0c => ("move-result-object", F11x, R::None),
        0x0d => ("move-exception", F11x, R::None),
        0x0e => ("return-void", F10x, R::None),
        0x0f => ("return", F11x, R::None),
        0x10 => ("return-wide", F11x, R::None),
        0x11 => ("return-object", F11x, R::None),
        0x12 => ("const/4", F11n, R::None),
        0x13 => ("const/16", F21s, R::None),
        0x14 => ("const", F31i, R::None),
        0x15 => ("const/high16", F21h, R::None),
        0x16 => ("const-wide/16", F21s, R::None),
        0x17 => ("const-wide/32", F31i, R::None),
        0x18 => ("const-wide", F51l, R::None),
        0x19 => ("const-wide/high16", F21h, R::None),
        0x1a => ("const-string", F21c, R::String),
        0x1b => ("const-string/jumbo", F31c, R::String),
        0x1c => ("const-class", F21c, R::Type),
        0x1d => ("monitor-enter", F11x, R::None),
        0x1e => ("monitor-exit", F11x, R::None),
        0x1f => ("check-cast", F21c, R::Type),
        0x20 => ("instance-of", F22c, R::Type),
        0x21 => ("array-length", F12x, R::None),
        0x22 => ("new-instance", F21c, R::Type),
        0x23 => ("new-array", F22c, R::Type),
        0x24 => ("filled-new-array", F35c, R::Type),
        0x25 => ("filled-new-array/range", F3rc, R::Type),
        0x26 => ("fill-array-data", F31t, R::None),
        0x27 => ("throw", F11x, R::None),
        0x28 => ("goto", F10t, R::None),
        0x29 => ("goto/16", F20t, R::None),
        0x2a => ("goto/32", F30t, R::None),
        0x2b => ("packed-switch", F31t, R::None),
        0x2c => ("sparse-switch", F31t, R::None),
        0x2d..=0x31 => (CMP[i(0x2d)], F23x, R::None),
        0x32..=0x37 => (IF_TEST[i(0x32)], F22t, R::None),
        0x38..=0x3d => (IF_TESTZ[i(0x38)], F21t, R::None),
        0x44..=0x51 => (ARRAY_OPS[i(0x44)], F23x, R::None),
        0x52..=0x5f => (INSTANCE_OPS[i(0x52)], F22c, R::Field),
        0x60..=0x6d => (STATIC_OPS[i(0x60)], F21c, R::Field),
        0x6e..=0x72 => (INVOKES[i(0x6e)], F35c, R::Method),
        0x74..=0x78 => (INVOKES_RANGE[i(0x74)], F3rc, R::Method),
        0x7b..=0x8f => (UNOPS[i(0x7b)], F12x, R::None),
        0x90..=0xaf => (BINOPS[i(0x90)], F23x, R::None),
        0xb0..=0xcf => (BINOPS_2ADDR[i(0xb0)], F12x, R::None),
        0xd0..=0xd7 => (LIT16[i(0xd0)], F22s, R::None),
        0xd8..=0xe2 => (LIT8[i(0xd8)], F22b, R::None),
        0xfa => ("invoke-polymorphic", F45cc, R::Method),
        0xfb => ("invoke-polymorphic/range", F4rcc, R::Method),
        0xfc => ("invoke-custom", F35c, R::CallSite),
        0xfd => ("invoke-custom/range", F3rc, R::CallSite),
        0xfe => ("const-method-handle", F21c, R::MethodHandle),
        0xff => ("const-method-type", F21c, R::Proto),
        _ => ("<unused>", Unused, R::None),
    };
    OpInfo {
        name,
        format,
        ref_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_consistent() {
        assert_eq!(op_info(0x6e).name, "invoke-virtual");
        assert_eq!(op_info(0x78).name, "invoke-interface/range");
        assert_eq!(op_info(0xaf).name, "rem-double");
        assert_eq!(op_info(0xcf).name, "rem-double/2addr");
        assert_eq!(op_info(0xe2).name, "ushr-int/lit8");
        assert_eq!(op_info(0x8f).name, "int-to-short");
        assert_eq!(op_info(0x6d).name, "sput-short");
        assert_eq!(op_info(0x73).format, Format::Unused);
        assert_eq!(op_info(0x3e).format, Format::Unused);
        assert_eq!(op_info(0xe3).format, Format::Unused);
        let assigned = (0..=255u8)
            .filter(|&op| op_info(op).format != Format::Unused)
            .count();
        assert_eq!(assigned, 256 - 6 - 1 - 2 - 23);
    }
}
