//! A lenient ZIP reader modelled on how Android reads APKs.
//!
//! Android (libziparchive) trusts the central directory, uses the local
//! header only to locate the entry data, and ignores malformed extra fields
//! or the encryption flag. Strict ZIP libraries reject such files, which
//! makes them a popular anti-analysis trick, so we mirror Android instead.

use std::io::Read;
use std::sync::Arc;

use flate2::Crc;

use super::reader::{Reader, Result, err, read_u16, read_u32};

const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATED: u16 = 8;

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    pub local_header_offset: u64,
    pub dos_time: u16,
    pub dos_date: u16,
}

impl ZipEntry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/') && self.size == 0
    }

    pub fn encrypted(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn method_name(&self) -> String {
        match self.method {
            0 => "Stored".to_owned(),
            8 => "Deflate".to_owned(),
            9 => "Deflate64".to_owned(),
            12 => "BZIP2".to_owned(),
            14 => "LZMA".to_owned(),
            93 => "Zstandard".to_owned(),
            99 => "AES".to_owned(),
            m => format!("Unknown ({m})"),
        }
    }

    /// Last modification time as `YYYY-MM-DD hh:mm:ss`, if the DOS date is valid.
    pub fn modified(&self) -> Option<String> {
        let (d, t) = (self.dos_date, self.dos_time);
        let (day, month, year) = (d & 0x1f, (d >> 5) & 0xf, 1980 + (d >> 9));
        if day == 0 || month == 0 || month > 12 {
            return None;
        }
        Some(format!(
            "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
            t >> 11,
            (t >> 5) & 0x3f,
            (t & 0x1f) * 2
        ))
    }
}

pub struct ZipArchive {
    data: Arc<[u8]>,
    pub entries: Vec<ZipEntry>,
    pub comment: String,
    pub warnings: Vec<String>,
}

/// Entry data plus notes about anything unusual found while extracting it.
pub struct Extracted {
    pub data: Vec<u8>,
    pub notes: Vec<String>,
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    let min = data.len().saturating_sub(22 + 0xffff);
    (min..=data.len() - 22)
        .rev()
        .find(|&pos| read_u32(data, pos).ok() == Some(EOCD_SIG))
}

/// Applies ZIP64 extended information (extra field 0x0001) leniently.
fn apply_zip64_extra(extra: &[u8], entry: &mut ZipEntry) {
    let mut r = Reader::new(extra);
    while r.remaining() >= 4 {
        let (Ok(id), Ok(len)) = (r.u16(), r.u16()) else {
            return;
        };
        let Ok(body) = r.bytes(usize::from(len)) else {
            return;
        };
        if id != 0x0001 {
            continue;
        }
        let mut b = Reader::new(body);
        if entry.size == 0xffff_ffff {
            if let Ok(v) = b.uint_sized(8) {
                entry.size = v;
            }
        }
        if entry.compressed_size == 0xffff_ffff {
            if let Ok(v) = b.uint_sized(8) {
                entry.compressed_size = v;
            }
        }
        if entry.local_header_offset == 0xffff_ffff {
            if let Ok(v) = b.uint_sized(8) {
                entry.local_header_offset = v;
            }
        }
        return;
    }
}

impl ZipArchive {
    pub fn parse(data: Arc<[u8]>) -> Result<Self> {
        let eocd = find_eocd(&data).ok_or_else(|| {
            super::reader::ParseError("end of central directory not found".to_owned())
        })?;
        let mut warnings = Vec::new();
        let mut r = Reader::at(&data, eocd + 4)?;
        let _disk = r.u16()?;
        let _cd_disk = r.u16()?;
        let _entries_on_disk = r.u16()?;
        let mut total_entries = u64::from(r.u16()?);
        let mut cd_size = u64::from(r.u32()?);
        let mut cd_offset = u64::from(r.u32()?);
        let comment_len = usize::from(r.u16()?);
        let comment = r
            .bytes(comment_len.min(r.remaining()))
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();

        let needs_zip64 =
            total_entries == 0xffff || cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff;
        if needs_zip64 && eocd >= 20 && read_u32(&data, eocd - 20).ok() == Some(ZIP64_LOCATOR_SIG) {
            let mut loc = Reader::at(&data, eocd - 12)?;
            let z64 = loc.uint_sized(8)? as usize;
            if read_u32(&data, z64).ok() == Some(ZIP64_EOCD_SIG) {
                let mut z = Reader::at(&data, z64 + 24)?;
                let _entries_on_disk = z.uint_sized(8)?;
                total_entries = z.uint_sized(8)?;
                cd_size = z.uint_sized(8)?;
                cd_offset = z.uint_sized(8)?;
            }
        }

        let cd_start = usize::try_from(cd_offset).unwrap_or(usize::MAX);
        if cd_start >= data.len() {
            return err(format!(
                "central directory offset 0x{cd_offset:x} is outside the file"
            ));
        }
        if cd_offset.saturating_add(cd_size) > eocd as u64 {
            warnings.push("central directory overlaps the end record".to_owned());
        }

        let mut entries = Vec::with_capacity(total_entries.min(1 << 20) as usize);
        let mut r = Reader::at(&data, cd_start)?;
        for i in 0..total_entries {
            match r.u32() {
                Ok(CENTRAL_SIG) => {}
                _ => {
                    warnings.push(format!(
                        "central directory ends after {i} of {total_entries} entries"
                    ));
                    break;
                }
            }
            let _made_by = r.u16()?;
            let _needed = r.u16()?;
            let flags = r.u16()?;
            let method = r.u16()?;
            let dos_time = r.u16()?;
            let dos_date = r.u16()?;
            let crc32 = r.u32()?;
            let compressed_size = u64::from(r.u32()?);
            let size = u64::from(r.u32()?);
            let name_len = usize::from(r.u16()?);
            let extra_len = usize::from(r.u16()?);
            let comment_len = usize::from(r.u16()?);
            let _disk_start = r.u16()?;
            let _internal = r.u16()?;
            let _external = r.u32()?;
            let local_header_offset = u64::from(r.u32()?);
            let name = String::from_utf8_lossy(r.bytes(name_len)?).into_owned();
            let extra = r.bytes(extra_len.min(r.remaining()))?;
            r.skip(comment_len.min(r.remaining()))?;

            let mut entry = ZipEntry {
                name,
                method,
                flags,
                crc32,
                compressed_size,
                size,
                local_header_offset,
                dos_time,
                dos_date,
            };
            apply_zip64_extra(extra, &mut entry);
            entries.push(entry);
        }

        Ok(Self {
            data,
            entries,
            comment,
            warnings,
        })
    }

    /// Offset of the entry's data, derived from its local file header.
    pub fn data_offset(&self, entry: &ZipEntry) -> Result<usize> {
        let off = usize::try_from(entry.local_header_offset).unwrap_or(usize::MAX);
        if read_u32(&self.data, off)? != LOCAL_SIG {
            return err(format!("no local file header at offset 0x{off:x}"));
        }
        let name_len = usize::from(read_u16(&self.data, off + 26)?);
        let extra_len = usize::from(read_u16(&self.data, off + 28)?);
        let start = off + 30 + name_len + extra_len;
        if start > self.data.len() {
            return err(format!(
                "local file header at 0x{off:x} extends past the end of the file"
            ));
        }
        Ok(start)
    }

    pub fn extract(&self, index: usize, limit: u64) -> Result<Extracted> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| super::reader::ParseError("invalid entry index".to_owned()))?;
        let mut notes = Vec::new();
        let start = self.data_offset(entry)?;
        let available = self.data.len().saturating_sub(start);
        let mut len = usize::try_from(entry.compressed_size).unwrap_or(usize::MAX);
        if len > available {
            notes.push(format!(
                "compressed size {} exceeds the file; data is truncated",
                entry.compressed_size
            ));
            len = available;
        }
        let raw = &self.data[start..start + len];
        if entry.encrypted() {
            notes.push("encryption flag is set but ignored (as Android does)".to_owned());
        }

        let inflate = |input: &[u8]| -> std::io::Result<Vec<u8>> {
            let mut out = Vec::new();
            flate2::read::DeflateDecoder::new(input)
                .take(limit + 1)
                .read_to_end(&mut out)?;
            Ok(out)
        };
        let data = match entry.method {
            METHOD_STORED => raw.to_vec(),
            METHOD_DEFLATED => inflate(raw).map_err(|e| {
                super::reader::ParseError(format!("deflate stream is corrupt: {e}"))
            })?,
            other => match inflate(raw) {
                Ok(d) => {
                    notes.push(format!(
                        "declared compression method {other} is not supported; data was deflate"
                    ));
                    d
                }
                Err(_) => {
                    notes.push(format!(
                        "declared compression method {other} is not supported; showing raw data"
                    ));
                    raw.to_vec()
                }
            },
        };
        if data.len() as u64 > limit {
            return err(format!(
                "entry is larger than the {} MiB limit",
                limit >> 20
            ));
        }
        if data.len() as u64 != entry.size {
            notes.push(format!(
                "declared size {} does not match actual size {}",
                entry.size,
                data.len()
            ));
        }
        let mut crc = Crc::new();
        crc.update(&data);
        if crc.sum() != entry.crc32 {
            notes.push(format!(
                "CRC-32 mismatch: declared 0x{:08x}, actual 0x{:08x}",
                entry.crc32,
                crc.sum()
            ));
        }
        Ok(Extracted { data, notes })
    }
}

/// Writes an uncompressed ZIP; used by tests to build synthetic packages.
#[cfg(test)]
pub(crate) fn write_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, content) in entries {
        let mut crc = Crc::new();
        crc.update(content);
        let offset = out.len() as u32;
        let header = |sig: u32, buf: &mut Vec<u8>, central: bool| {
            buf.extend(sig.to_le_bytes());
            if central {
                buf.extend(20u16.to_le_bytes());
            }
            buf.extend(20u16.to_le_bytes());
            buf.extend([0u8; 8]);
            buf.extend(crc.sum().to_le_bytes());
            buf.extend((content.len() as u32).to_le_bytes());
            buf.extend((content.len() as u32).to_le_bytes());
            buf.extend((name.len() as u16).to_le_bytes());
            buf.extend(0u16.to_le_bytes());
            if central {
                buf.extend([0u8; 10]);
                buf.extend(offset.to_le_bytes());
            }
            buf.extend(name.as_bytes());
        };
        header(LOCAL_SIG, &mut out, false);
        out.extend(*content);
        header(CENTRAL_SIG, &mut central, true);
    }
    let cd_offset = out.len() as u32;
    out.extend(&central);
    out.extend(EOCD_SIG.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((central.len() as u32).to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Builds a ZIP with one entry; `cd_extra` is written raw into the
    /// central directory record (to simulate malformed extra fields).
    fn build_zip(
        name: &str,
        content: &[u8],
        deflate: bool,
        flags: u16,
        cd_extra: &[u8],
    ) -> Vec<u8> {
        let payload = if deflate {
            let mut enc =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(content).unwrap();
            enc.finish().unwrap()
        } else {
            content.to_vec()
        };
        let mut crc = Crc::new();
        crc.update(content);
        let method: u16 = if deflate { 8 } else { 0 };
        let mut out = Vec::new();
        out.extend(LOCAL_SIG.to_le_bytes());
        out.extend(20u16.to_le_bytes());
        out.extend(flags.to_le_bytes());
        out.extend(method.to_le_bytes());
        out.extend([0u8; 4]);
        out.extend(crc.sum().to_le_bytes());
        out.extend((payload.len() as u32).to_le_bytes());
        out.extend((content.len() as u32).to_le_bytes());
        out.extend((name.len() as u16).to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(name.as_bytes());
        out.extend(&payload);
        let cd_start = out.len();
        out.extend(CENTRAL_SIG.to_le_bytes());
        out.extend(20u16.to_le_bytes());
        out.extend(20u16.to_le_bytes());
        out.extend(flags.to_le_bytes());
        out.extend(method.to_le_bytes());
        out.extend(0x6000u16.to_le_bytes());
        out.extend(0x5821u16.to_le_bytes());
        out.extend(crc.sum().to_le_bytes());
        out.extend((payload.len() as u32).to_le_bytes());
        out.extend((content.len() as u32).to_le_bytes());
        out.extend((name.len() as u16).to_le_bytes());
        out.extend((cd_extra.len() as u16).to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend([0u8; 8]);
        out.extend(0u32.to_le_bytes());
        out.extend(name.as_bytes());
        out.extend(cd_extra);
        let cd_size = out.len() - cd_start;
        out.extend(EOCD_SIG.to_le_bytes());
        out.extend([0u8; 4]);
        out.extend(1u16.to_le_bytes());
        out.extend(1u16.to_le_bytes());
        out.extend((cd_size as u32).to_le_bytes());
        out.extend((cd_start as u32).to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_stored_and_deflated() {
        for deflate in [false, true] {
            let zip = build_zip("a/b.txt", b"hello hello hello", deflate, 0, &[]);
            let archive = ZipArchive::parse(zip.into()).unwrap();
            assert_eq!(archive.entries.len(), 1);
            assert_eq!(archive.entries[0].name, "a/b.txt");
            assert_eq!(
                archive.entries[0].modified().unwrap(),
                "2024-01-01 12:00:00"
            );
            let x = archive.extract(0, 1 << 20).unwrap();
            assert_eq!(x.data, b"hello hello hello");
            assert!(x.notes.is_empty(), "{:?}", x.notes);
        }
    }

    #[test]
    fn tolerates_android_tricks() {
        // Padding-only extra field (as written by old zipalign / gomobile)
        // and a fake encryption flag.
        let zip = build_zip("classes.dex", b"dex", true, 1, &[0, 0, 0]);
        let archive = ZipArchive::parse(zip.into()).unwrap();
        let x = archive.extract(0, 1 << 20).unwrap();
        assert_eq!(x.data, b"dex");
        assert_eq!(x.notes.len(), 1);
    }

    #[test]
    fn writes_readable_zip() {
        let zip = write_stored_zip(&[("a", b"1"), ("b/c", b"22")]);
        let archive = ZipArchive::parse(zip.into()).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.extract(1, 100).unwrap().data, b"22");
    }

    #[test]
    fn rejects_garbage() {
        assert!(ZipArchive::parse(Arc::from(vec![0u8; 100])).is_err());
        let mut zip = build_zip("x", b"y", false, 0, &[]);
        let len = zip.len();
        zip[len - 6..len - 2].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert!(ZipArchive::parse(zip.into()).is_err());
    }
}
