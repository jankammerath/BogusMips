//! Exporting tree items to files.

use crate::formats::axml;
use crate::formats::detect::{FileKind, detect};
use crate::formats::dex::smali::class_to_smali;
use crate::formats::resvalue::Resolver;
use crate::package::{NodeId, NodeKind, Package};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExportKind {
    /// The file's bytes as stored in the archive (decompressed).
    Raw,
    /// Decoded binary XML, or beautified text: what the content view shows.
    AsShown,
    /// A class as smali.
    Smali,
    /// A `res/values*` file generated from `resources.arsc`.
    ResourceXml,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportOption {
    pub kind: ExportKind,
    pub label: &'static str,
    /// Suggested file name for the save dialog.
    pub file_name: String,
}

/// Simple class name for a descriptor: `Lcom/a/Foo$Bar;` → `Foo$Bar`.
fn class_file_stem(descriptor: &str) -> String {
    let inner = descriptor
        .strip_prefix('L')
        .and_then(|d| d.strip_suffix(';'))
        .unwrap_or(descriptor);
    let name = inner.rsplit('/').next().unwrap_or(inner);
    sanitize(if name.is_empty() { "class" } else { name })
}

/// Makes a name from inside the (untrusted) package safe as a file name.
fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c: char| c == '.' || c.is_whitespace());
    let mut out: String = trimmed.chars().take(200).collect();
    if out.is_empty() {
        out = "export".to_owned();
    }
    out
}

/// What the selected node can be exported as. The first option is the
/// primary one (used by File → Export…).
pub fn options(pkg: &Package, node: NodeId) -> Vec<ExportOption> {
    let option = |kind, label, name: &str| ExportOption {
        kind,
        label,
        file_name: sanitize(name),
    };
    match &pkg.nodes[node].kind {
        NodeKind::File(f) => {
            let entry = &pkg.files[*f];
            let mut out = vec![option(ExportKind::Raw, "Export…", entry.name())];
            if has_shown_form(pkg, *f) {
                out.push(option(
                    ExportKind::AsShown,
                    "Export as shown…",
                    entry.name(),
                ));
            }
            out
        }
        NodeKind::Class(c) => {
            let entry = &pkg.dex_files[c.dex];
            let descriptor = entry
                .dex
                .class_descriptor(&entry.dex.class_defs[c.class_def]);
            vec![ExportOption {
                kind: ExportKind::Smali,
                label: "Export as smali…",
                file_name: format!("{}.smali", class_file_stem(&descriptor)),
            }]
        }
        NodeKind::ResourceFile(a, i) => match pkg.archives[*a].values_files.get(*i) {
            Some(file) => vec![option(ExportKind::ResourceXml, "Export…", &file.file)],
            None => Vec::new(),
        },
        // An APK inside an XAPK is itself an archive entry.
        NodeKind::Archive(a) => match pkg.archives[*a].source_file {
            Some(f) => vec![option(ExportKind::Raw, "Export…", pkg.files[f].name())],
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn has_shown_form(pkg: &Package, file: usize) -> bool {
    let Ok(data) = pkg.read_file(file) else {
        return false;
    };
    match detect(pkg.files[file].name(), &data.bytes) {
        FileKind::BinaryXml => true,
        FileKind::Text => {
            let text = String::from_utf8_lossy(&data.bytes);
            crate::beautify::process(&pkg.files[file].path, &text)
                .beautified
                .is_some()
        }
        _ => false,
    }
}

/// Produces the bytes to write for `node` exported as `kind`.
pub fn export_bytes(pkg: &Package, node: NodeId, kind: ExportKind) -> Result<Vec<u8>, String> {
    match (&pkg.nodes[node].kind, kind) {
        (NodeKind::File(f), ExportKind::Raw) => Ok(pkg.read_file(*f)?.bytes.to_vec()),
        (NodeKind::Archive(a), ExportKind::Raw) => {
            let f = pkg.archives[*a]
                .source_file
                .ok_or("this archive is not stored inside another one")?;
            Ok(pkg.read_file(f)?.bytes.to_vec())
        }
        (NodeKind::File(f), ExportKind::AsShown) => {
            let data = pkg.read_file(*f)?;
            let entry = &pkg.files[*f];
            match detect(entry.name(), &data.bytes) {
                FileKind::BinaryXml => {
                    let tables = pkg.resource_tables();
                    let doc = axml::parse_with(&data.bytes, &Resolver::new(&tables))
                        .map_err(|e| format!("binary XML could not be decoded: {e}"))?;
                    Ok(doc.to_xml_string().into_bytes())
                }
                FileKind::Text => {
                    let text = String::from_utf8_lossy(&data.bytes);
                    let processed = crate::beautify::process(&entry.path, &text);
                    Ok(processed
                        .beautified
                        .unwrap_or_else(|| text.into_owned())
                        .into_bytes())
                }
                _ => Ok(data.bytes.to_vec()),
            }
        }
        (NodeKind::Class(c), ExportKind::Smali) => {
            let entry = &pkg.dex_files[c.dex];
            let class = &entry.dex.class_defs[c.class_def];
            Ok(class_to_smali(&entry.dex, class).into_bytes())
        }
        (NodeKind::ResourceFile(a, i), ExportKind::ResourceXml) => {
            let archive = &pkg.archives[*a];
            let (Some(table), Some(file)) = (&archive.resources, archive.values_files.get(*i))
            else {
                return Err("resource file not found".to_owned());
            };
            let tables = pkg.resource_tables();
            Ok(table
                .render(file.source, &Resolver::new(&tables))
                .into_bytes())
        }
        _ => Err("this item cannot be exported this way".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::zip::write_stored_zip;
    use std::path::Path;

    #[test]
    fn file_names_are_safe() {
        assert_eq!(class_file_stem("Lcom/example/Foo$Bar;"), "Foo$Bar");
        assert_eq!(class_file_stem("LFoo;"), "Foo");
        assert_eq!(sanitize("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize("a\\b:c*?\"<>|\u{1}"), "a_b_c_______");
        assert_eq!(sanitize(".."), "export");
        assert_eq!(sanitize(&"x".repeat(500)).len(), 200);
    }

    #[test]
    fn exports_files() {
        let json = br#"{"a":1}"#;
        let zip = write_stored_zip(&[("assets/config.json", json), ("assets/raw.bin", b"\0\x01")]);
        let pkg = Package::from_bytes(Path::new("t.apk"), zip.into()).unwrap();
        let node = |name: &str| pkg.nodes.iter().position(|n| n.label == name).unwrap();

        let opts = options(&pkg, node("config.json"));
        let kinds: Vec<ExportKind> = opts.iter().map(|o| o.kind).collect();
        assert_eq!(kinds, [ExportKind::Raw, ExportKind::AsShown]);
        assert_eq!(opts[0].file_name, "config.json");
        assert_eq!(
            export_bytes(&pkg, node("config.json"), ExportKind::Raw).unwrap(),
            json
        );
        let shown = export_bytes(&pkg, node("config.json"), ExportKind::AsShown).unwrap();
        assert_eq!(String::from_utf8(shown).unwrap(), "{\n  \"a\": 1\n}\n");

        // Plain binary files have no separate "as shown" form.
        assert_eq!(options(&pkg, node("raw.bin")).len(), 1);
        // Folders are not exportable.
        assert!(options(&pkg, node("assets")).is_empty());
        assert!(export_bytes(&pkg, node("assets"), ExportKind::Raw).is_err());
    }
}
