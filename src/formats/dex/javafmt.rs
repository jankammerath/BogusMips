//! Java-compatible number formatting, so that the disassembly matches what
//! baksmali (and therefore apktool) produces.

/// Shortest round-trip digits and decimal exponent of a finite, non-zero value,
/// e.g. 1234.5 -> ("12345", 3).
fn digits_and_exponent(scientific: &str) -> (String, i32) {
    let (mantissa, exp) = scientific.split_once('e').unwrap_or((scientific, "0"));
    let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
    (digits, exp.parse().unwrap_or(0))
}

/// Digits as Java's `Float/Double.toString` picks them: the shortest length
/// that round-trips (at least two digits), and among those the decimal
/// closest to the exact binary value, ties going to the even digit. E.g.
/// `Double.MIN_VALUE` is `4.9E-324`, and 3567412.25f is `3567412.2`.
fn java_digits(
    shortest: &str,
    rounded: impl Fn(usize) -> String,
    roundtrips: impl Fn(&str) -> bool,
) -> (String, i32) {
    let (digits, exp) = digits_and_exponent(shortest);
    let precision = digits.len().max(2) - 1;
    let candidate = rounded(precision);
    if roundtrips(&candidate) {
        digits_and_exponent(&candidate)
    } else {
        (digits, exp)
    }
}

/// Java's `Float.toString` / `Double.toString` given the shortest digits.
fn java_to_string(negative: bool, digits: &str, exp: i32, magnitude: f64) -> String {
    let sign = if negative { "-" } else { "" };
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    if (1e-3..1e7).contains(&magnitude) {
        if exp >= 0 {
            let int_len = exp as usize + 1;
            let int_part: String = if digits.len() >= int_len {
                digits[..int_len].to_owned()
            } else {
                format!("{digits}{}", "0".repeat(int_len - digits.len()))
            };
            let frac = digits
                .get(int_len..)
                .filter(|f| !f.is_empty())
                .unwrap_or("0");
            format!("{sign}{int_part}.{frac}")
        } else {
            format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize))
        }
    } else {
        let frac = if digits.len() > 1 { &digits[1..] } else { "0" };
        format!("{sign}{}.{frac}E{exp}", &digits[..1])
    }
}

pub fn float_to_string(v: f32) -> String {
    if v.is_nan() {
        return "NaN".to_owned();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-Infinity" } else { "Infinity" }.to_owned();
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    let x = v.abs();
    let (digits, exp) = java_digits(
        &format!("{x:e}"),
        |p| format!("{x:.p$e}"),
        |s| s.parse::<f32>() == Ok(x),
    );
    java_to_string(v < 0.0, &digits, exp, f64::from(x))
}

pub fn double_to_string(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_owned();
    }
    if v.is_infinite() {
        return if v < 0.0 { "-Infinity" } else { "Infinity" }.to_owned();
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    let x = v.abs();
    let (digits, exp) = java_digits(
        &format!("{x:e}"),
        |p| format!("{x:.p$e}"),
        |s| s.parse::<f64>() == Ok(x),
    );
    java_to_string(v < 0.0, &digits, exp, x)
}

/// `new DecimalFormat("0.####################E0").format(...)`
fn decimal_format(negative: bool, digits: &str, exp: i32) -> String {
    let sign = if negative { "-" } else { "" };
    let digits = digits.trim_end_matches('0');
    if digits.is_empty() {
        return format!("{sign}0E0");
    }
    if digits.len() == 1 {
        format!("{sign}{digits}E{exp}")
    } else {
        format!("{sign}{}.{}E{exp}", &digits[..1], &digits[1..])
    }
}

fn decimal_format_integer(v: i128) -> String {
    let s = v.unsigned_abs().to_string();
    decimal_format(v < 0, &s, s.len() as i32 - 1)
}

fn decimal_format_double(v: f64) -> String {
    if v == 0.0 {
        return decimal_format(v.is_sign_negative(), "0", 0);
    }
    let (digits, exp) = digits_and_exponent(&format!("{:e}", v.abs()));
    decimal_format(v < 0.0, &digits, exp)
}

/// Java `String.indexOf` semantics: -1 when not found.
fn index_of(s: &str, pat: &str) -> i64 {
    s.find(pat).map_or(-1, |i| i as i64)
}

fn strip_imprecision(s: String) -> String {
    let decimal_point = index_of(&s, ".");
    let exponent = index_of(&s, "E");
    for pat in ["000", "999"] {
        let at = index_of(&s, pat);
        if at > decimal_point && at < exponent {
            return format!("{}{}", &s[..at as usize], &s[exponent as usize..]);
        }
    }
    s
}

pub fn is_likely_float(value: i32) -> bool {
    const CANONICAL_NAN: i32 = 0x7fc0_0000;
    const MAX: i32 = 0x7f7f_ffff;
    let pi = std::f32::consts::PI.to_bits() as i32;
    let e = std::f32::consts::E.to_bits() as i32;
    if [CANONICAL_NAN, MAX, pi, e].contains(&value) {
        return true;
    }
    if value == i32::MAX || value == i32::MIN {
        return false;
    }
    let package_id = value >> 24;
    let resource_type = (value >> 16) & 0xff;
    let resource_id = value & 0xffff;
    if (package_id == 0x7f || package_id == 1) && resource_type < 0x1f && resource_id < 0xfff {
        return false;
    }
    let float = f32::from_bits(value as u32);
    if float.is_nan() {
        return false;
    }
    let as_int = decimal_format_integer(i128::from(value));
    let as_float = strip_imprecision(decimal_format_double(f64::from(float)));
    as_float.len() < as_int.len()
}

pub fn is_likely_double(value: i64) -> bool {
    const CANONICAL_NAN: i64 = 0x7ff8_0000_0000_0000;
    const MAX: i64 = 0x7fef_ffff_ffff_ffff;
    let pi = std::f64::consts::PI.to_bits() as i64;
    let e = std::f64::consts::E.to_bits() as i64;
    if [CANONICAL_NAN, MAX, pi, e].contains(&value) {
        return true;
    }
    if value == i64::MAX || value == i64::MIN {
        return false;
    }
    let double = f64::from_bits(value as u64);
    if double.is_nan() {
        return false;
    }
    let as_long = decimal_format_integer(i128::from(value));
    let as_double = strip_imprecision(decimal_format_double(double));
    as_double.len() < as_long.len()
}

/// baksmali's `    # 1.0f` comment for literals that are likely floats.
pub fn float_comment(value: i32) -> Option<String> {
    if !is_likely_float(value) {
        return None;
    }
    let f = f32::from_bits(value as u32);
    let text = if f == f32::INFINITY {
        "Float.POSITIVE_INFINITY".to_owned()
    } else if f == f32::NEG_INFINITY {
        "Float.NEGATIVE_INFINITY".to_owned()
    } else if f.is_nan() {
        "Float.NaN".to_owned()
    } else if f == f32::MAX {
        "Float.MAX_VALUE".to_owned()
    } else if f == std::f32::consts::PI {
        "(float)Math.PI".to_owned()
    } else if f == std::f32::consts::E {
        "(float)Math.E".to_owned()
    } else {
        format!("{}f", float_to_string(f))
    };
    Some(format!("    # {text}"))
}

/// baksmali's `    # 2.0` comment for wide literals that are likely doubles.
pub fn double_comment(value: i64) -> Option<String> {
    if !is_likely_double(value) {
        return None;
    }
    let d = f64::from_bits(value as u64);
    let text = if d == f64::INFINITY {
        "Double.POSITIVE_INFINITY".to_owned()
    } else if d == f64::NEG_INFINITY {
        "Double.NEGATIVE_INFINITY".to_owned()
    } else if d.is_nan() {
        "Double.NaN".to_owned()
    } else if d == f64::MAX {
        "Double.MAX_VALUE".to_owned()
    } else if d == std::f64::consts::PI {
        "Math.PI".to_owned()
    } else if d == std::f64::consts::E {
        "Math.E".to_owned()
    } else {
        double_to_string(d)
    };
    Some(format!("    # {text}"))
}

/// baksmali's `writeSignedIntOrLongTo`: hex with an `L` suffix only when the
/// value does not fit in an `int`.
pub fn signed_int_or_long(v: i64) -> String {
    let suffix = if i32::try_from(v).is_err() { "L" } else { "" };
    format!("{}{suffix}", super::values::hex_signed(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_strings() {
        assert_eq!(float_to_string(1.0), "1.0");
        assert_eq!(float_to_string(2.0009763), "2.0009763");
        assert_eq!(float_to_string(0.001), "0.001");
        assert_eq!(float_to_string(1e7), "1.0E7");
        assert_eq!(float_to_string(1.5e-4), "1.5E-4");
        assert_eq!(float_to_string(-123.25), "-123.25");
        assert_eq!(double_to_string(2.0), "2.0");
        assert_eq!(double_to_string(35.0), "35.0");
        assert_eq!(double_to_string(1e21), "1.0E21");
        assert_eq!(double_to_string(100.0), "100.0");
        assert_eq!(double_to_string(f64::from_bits(1)), "4.9E-324");
        assert_eq!(float_to_string(f32::from_bits(1)), "1.4E-45");
        assert_eq!(float_to_string(f32::from_bits(0x4a59_bcd1)), "3567412.2");
        assert_eq!(float_to_string(0.1), "0.1");
        assert_eq!(double_to_string(0.1 + 0.2), "0.30000000000000004");
    }

    #[test]
    fn decimal_format_matches_java() {
        assert_eq!(decimal_format_integer(1000), "1E3");
        assert_eq!(decimal_format_integer(0), "0E0");
        assert_eq!(decimal_format_integer(-15), "-1.5E1");
        assert_eq!(decimal_format_double(2.0), "2E0");
    }

    #[test]
    fn likely_values() {
        assert!(is_likely_float(0x3f80_0000)); // 1.0f
        assert!(is_likely_float(0x4000_0fff)); // 2.0009763f
        assert!(!is_likely_float(0x7f01_0001)); // resource id
        assert!(!is_likely_float(1000));
        assert!(!is_likely_float(0));
        assert!(is_likely_double(0x4000_0000_0000_0000)); // 2.0
        assert!(!is_likely_double(0));
        assert_eq!(float_comment(0x3f80_0000).unwrap(), "    # 1.0f");
        assert_eq!(double_comment(0x4041_8000_0000_0000).unwrap(), "    # 35.0");
        assert_eq!(signed_int_or_long(0x7a120), "0x7a120");
        assert_eq!(
            signed_int_or_long(0x4000_0000_0000_0000),
            "0x4000000000000000L"
        );
    }
}
