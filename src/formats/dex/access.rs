//! Access flag rendering (`public static final ...`) as used by smali.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Class,
    Field,
    Method,
}

const FLAGS: &[(u32, &str, &[Target])] = &[
    (
        0x1,
        "public",
        &[Target::Class, Target::Field, Target::Method],
    ),
    (
        0x2,
        "private",
        &[Target::Class, Target::Field, Target::Method],
    ),
    (
        0x4,
        "protected",
        &[Target::Class, Target::Field, Target::Method],
    ),
    (
        0x8,
        "static",
        &[Target::Class, Target::Field, Target::Method],
    ),
    (
        0x10,
        "final",
        &[Target::Class, Target::Field, Target::Method],
    ),
    (0x20, "synchronized", &[Target::Method]),
    (0x40, "volatile", &[Target::Field]),
    (0x40, "bridge", &[Target::Method]),
    (0x80, "transient", &[Target::Field]),
    (0x80, "varargs", &[Target::Method]),
    (0x100, "native", &[Target::Method]),
    (0x200, "interface", &[Target::Class]),
    (0x400, "abstract", &[Target::Class, Target::Method]),
    (0x800, "strictfp", &[Target::Method]),
    (
        0x1000,
        "synthetic",
        &[Target::Class, Target::Field, Target::Method],
    ),
    (0x2000, "annotation", &[Target::Class]),
    (0x4000, "enum", &[Target::Class, Target::Field]),
    (0x10000, "constructor", &[Target::Method]),
    (0x20000, "declared-synchronized", &[Target::Method]),
];

pub fn flags_to_string(flags: u32, target: Target) -> String {
    FLAGS
        .iter()
        .filter(|(bit, _, targets)| flags & bit != 0 && targets.contains(&target))
        .map(|(_, name, _)| *name)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_flags() {
        assert_eq!(flags_to_string(0x11, Target::Class), "public final");
        assert_eq!(
            flags_to_string(0x10001, Target::Method),
            "public constructor"
        );
        assert_eq!(flags_to_string(0x40, Target::Field), "volatile");
        assert_eq!(flags_to_string(0x40, Target::Method), "bridge");
    }
}
