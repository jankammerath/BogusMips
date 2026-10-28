//! Content-based file type detection.

use super::{axml, dex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Empty,
    Dex,
    BinaryXml,
    ResourceTable,
    Image(&'static str),
    Elf,
    Zip,
    Text,
    Binary,
}

impl FileKind {
    pub fn description(self, data: &[u8]) -> String {
        match self {
            FileKind::Empty => "Empty file".to_owned(),
            FileKind::Dex => "Dalvik executable (DEX)".to_owned(),
            FileKind::BinaryXml => "Android binary XML".to_owned(),
            FileKind::ResourceTable => "Android resource table".to_owned(),
            FileKind::Image(fmt) => format!("{fmt} image"),
            FileKind::Elf => format!("ELF binary ({})", elf_machine(data)),
            FileKind::Zip => "ZIP archive".to_owned(),
            FileKind::Text => "Text".to_owned(),
            FileKind::Binary => "Binary data".to_owned(),
        }
    }
}

pub fn detect(name: &str, data: &[u8]) -> FileKind {
    let lower = name.to_ascii_lowercase();
    if data.is_empty() {
        FileKind::Empty
    } else if dex::is_dex(data) {
        FileKind::Dex
    } else if axml::is_binary_xml(data) {
        FileKind::BinaryXml
    } else if data.len() >= 4 && data[0..4] == [0x02, 0x00, 0x0c, 0x00] {
        FileKind::ResourceTable
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        FileKind::Image("PNG")
    } else if data.starts_with(&[0xff, 0xd8, 0xff]) {
        FileKind::Image("JPEG")
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        FileKind::Image("GIF")
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        FileKind::Image("WebP")
    } else if data.starts_with(b"BM") && lower.ends_with(".bmp") {
        FileKind::Image("BMP")
    } else if data.starts_with(b"\x7fELF") {
        FileKind::Elf
    } else if data.starts_with(b"PK\x03\x04") {
        FileKind::Zip
    } else if looks_like_text(data) {
        FileKind::Text
    } else {
        FileKind::Binary
    }
}

fn looks_like_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(64 * 1024)];
    if sample.contains(&0) {
        return false;
    }
    let valid = match std::str::from_utf8(sample) {
        Ok(_) => true,
        // A multi-byte character cut off by the sample boundary is fine.
        Err(e) => e.error_len().is_none(),
    };
    if !valid {
        return false;
    }
    let control = sample
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t' | 0x0c))
        .count();
    control * 100 <= sample.len()
}

fn elf_machine(data: &[u8]) -> &'static str {
    let machine = data
        .get(18..20)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    match machine {
        0x03 => "x86",
        0x28 => "ARM",
        0x3e => "x86-64",
        0xb7 => "AArch64",
        0xf3 => "RISC-V",
        _ => "unknown architecture",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects() {
        assert_eq!(detect("a", b""), FileKind::Empty);
        assert_eq!(detect("a.txt", b"hello\nworld"), FileKind::Text);
        assert_eq!(detect("a.bin", &[1, 2, 0, 3]), FileKind::Binary);
        assert_eq!(
            detect("x.png", b"\x89PNG\r\n\x1a\n...."),
            FileKind::Image("PNG")
        );
        assert_eq!(detect("classes.dex", b"dex\n035\0rest"), FileKind::Dex);
        assert_eq!(detect("lib.so", b"\x7fELF"), FileKind::Elf);
    }
}
