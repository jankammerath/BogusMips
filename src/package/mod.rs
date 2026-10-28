//! Loading of `.apk` / `.xapk` files into an in-memory, browsable model.

mod tree;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use std::collections::HashMap;

use crate::formats::arsc::{ResourceTable, ValuesFile};
use crate::formats::resvalue::Resolver;
use crate::formats::zip::ZipArchive;
use crate::formats::{axml, dex::DexFile};

pub use tree::{ClassRef, Node, NodeKind};

pub type ArchiveId = usize;
pub type FileId = usize;
pub type DexId = usize;
pub type NodeId = usize;

/// Upper bound for a single decompressed entry, protecting against zip bombs.
const MAX_ENTRY_SIZE: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageKind {
    Apk,
    Xapk,
}

pub struct Package {
    pub path: PathBuf,
    pub kind: PackageKind,
    pub archives: Vec<Archive>,
    pub files: Vec<FileEntry>,
    pub dex_files: Vec<DexEntry>,
    pub nodes: Vec<Node>,
}

pub struct Archive {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    /// The entry this archive was extracted from (for APKs inside an XAPK).
    pub source_file: Option<FileId>,
    pub manifest: Option<ManifestInfo>,
    /// Decoded `resources.arsc`, if present.
    pub resources: Option<ResourceTable>,
    /// The `res/values*/*.xml` files generated from `resources`.
    pub values_files: Vec<ValuesFile>,
    /// Archive path → names of the resources stored in that file.
    pub resource_files: HashMap<String, Vec<String>>,
    pub warnings: Vec<String>,
    zip: ZipArchive,
}

pub struct FileEntry {
    pub archive: ArchiveId,
    index: usize,
    pub path: String,
    pub size: u64,
    pub compressed_size: u64,
    pub method: String,
    pub crc32: u32,
    pub modified: Option<String>,
    pub encrypted: bool,
    pub data_offset: Option<u64>,
}

impl FileEntry {
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }
}

pub struct DexEntry {
    pub archive: ArchiveId,
    pub file: FileId,
    pub name: String,
    pub dex: Arc<DexFile>,
}

#[derive(Debug, Clone, Default)]
pub struct ManifestInfo {
    pub package: Option<String>,
    pub split: Option<String>,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub compile_sdk: Option<String>,
    pub app_label: Option<String>,
    pub app_class: Option<String>,
    pub debuggable: Option<String>,
    pub allow_backup: Option<String>,
    pub permissions: Vec<String>,
    pub activities: usize,
    pub services: usize,
    pub receivers: usize,
    pub providers: usize,
}

impl ManifestInfo {
    fn from_document(doc: &axml::XmlDocument) -> Option<Self> {
        let root = doc.root()?;
        let attr = |e: &axml::XmlElement, name: &str| e.attr(name).map(str::to_owned);
        let mut info = ManifestInfo {
            package: attr(root, "package"),
            split: attr(root, "split"),
            version_code: attr(root, "versionCode"),
            version_name: attr(root, "versionName"),
            compile_sdk: attr(root, "compileSdkVersion")
                .or_else(|| attr(root, "platformBuildVersionCode")),
            ..Default::default()
        };
        for child in root.child_elements() {
            match child.name.as_str() {
                "uses-sdk" => {
                    info.min_sdk = attr(child, "minSdkVersion");
                    info.target_sdk = attr(child, "targetSdkVersion");
                }
                "uses-permission" | "uses-permission-sdk-23" => {
                    if let Some(name) = child.attr("name") {
                        info.permissions.push(name.to_owned());
                    }
                }
                "application" => {
                    info.app_label = attr(child, "label");
                    info.app_class = attr(child, "name");
                    info.debuggable = attr(child, "debuggable");
                    info.allow_backup = attr(child, "allowBackup");
                    for component in child.child_elements() {
                        match component.name.as_str() {
                            "activity" | "activity-alias" => info.activities += 1,
                            "service" => info.services += 1,
                            "receiver" => info.receivers += 1,
                            "provider" => info.providers += 1,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Some(info)
    }
}

/// Raw bytes of an archive entry, plus a note if they had to be recovered.
pub struct FileData {
    pub bytes: Arc<[u8]>,
    pub note: Option<String>,
}

pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

fn is_dex_name(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("classes")?.strip_suffix(".dex")?;
    if rest.is_empty() {
        Some(1)
    } else {
        rest.parse().ok().filter(|n| *n >= 2)
    }
}

impl Package {
    pub fn open(path: &Path) -> Result<Self, String> {
        let bytes: Arc<[u8]> = std::fs::read(path)
            .map_err(|e| format!("Could not read {}: {e}", path.display()))?
            .into();
        Self::from_bytes(path, bytes)
    }

    pub fn from_bytes(path: &Path, bytes: Arc<[u8]>) -> Result<Self, String> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());

        let mut pkg = Package {
            path: path.to_owned(),
            kind: PackageKind::Apk,
            archives: Vec::new(),
            files: Vec::new(),
            dex_files: Vec::new(),
            nodes: Vec::new(),
        };
        let root = pkg
            .add_archive(name, bytes, None)
            .map_err(|e| format!("{} is not a valid APK/XAPK: {e}", path.display()))?;

        let has_manifest = pkg.find_file(root, "AndroidManifest.xml").is_some();
        let inner_apks: Vec<FileId> = pkg
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| f.archive == root && f.path.to_ascii_lowercase().ends_with(".apk"))
            .map(|(id, _)| id)
            .collect();
        let is_xapk_ext = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("xapk"));
        if is_xapk_ext || (!has_manifest && !inner_apks.is_empty()) {
            pkg.kind = PackageKind::Xapk;
        }

        let mut apks = Vec::new();
        if pkg.kind == PackageKind::Xapk {
            for file in inner_apks {
                let entry_name = pkg.files[file].name().to_owned();
                let loaded = pkg
                    .read_file(file)
                    .and_then(|data| pkg.add_archive(entry_name.clone(), data.bytes, Some(file)));
                match loaded {
                    Ok(id) => apks.push(id),
                    Err(e) => pkg.archives[root]
                        .warnings
                        .push(format!("{entry_name}: {e}")),
                }
            }
        } else {
            apks.push(root);
        }

        for &apk in &apks {
            pkg.load_resources(apk);
        }
        for &apk in &apks {
            pkg.load_manifest(apk);
            pkg.load_dex_files(apk);
        }
        pkg.nodes = tree::build(&pkg, root, &apks);
        Ok(pkg)
    }

    fn add_archive(
        &mut self,
        name: String,
        bytes: Arc<[u8]>,
        source_file: Option<FileId>,
    ) -> Result<ArchiveId, String> {
        let size = bytes.len() as u64;
        let sha256 = sha256_hex(&bytes);
        let zip = ZipArchive::parse(bytes).map_err(|e| e.to_string())?;
        let id = self.archives.len();
        let warnings = zip.warnings.clone();

        for (index, entry) in zip.entries.iter().enumerate() {
            if entry.is_dir() {
                continue;
            }
            self.files.push(FileEntry {
                archive: id,
                index,
                path: entry.name.clone(),
                size: entry.size,
                compressed_size: entry.compressed_size,
                method: entry.method_name(),
                crc32: entry.crc32,
                modified: entry.modified(),
                encrypted: entry.encrypted(),
                data_offset: zip.data_offset(entry).ok().map(|o| o as u64),
            });
        }

        self.archives.push(Archive {
            name,
            size,
            sha256,
            source_file,
            manifest: None,
            resources: None,
            values_files: Vec::new(),
            resource_files: HashMap::new(),
            warnings,
            zip,
        });
        Ok(id)
    }

    pub fn find_file(&self, archive: ArchiveId, path: &str) -> Option<FileId> {
        self.files
            .iter()
            .position(|f| f.archive == archive && f.path == path)
    }

    /// Reads and decompresses an entry. Anomalies that Android tolerates (bad
    /// CRC, fake encryption flag, wrong sizes) are reported in `note`.
    pub fn read_file(&self, id: FileId) -> Result<FileData, String> {
        let entry = self.files.get(id).ok_or("invalid file id")?;
        let extracted = self.archives[entry.archive]
            .zip
            .extract(entry.index, MAX_ENTRY_SIZE)
            .map_err(|e| e.to_string())?;
        Ok(FileData {
            bytes: extracted.data.into(),
            note: (!extracted.notes.is_empty()).then(|| extracted.notes.join("; ")),
        })
    }

    fn load_resources(&mut self, archive: ArchiveId) {
        let Some(file) = self.find_file(archive, "resources.arsc") else {
            return;
        };
        let result = self
            .read_file(file)
            .and_then(|d| ResourceTable::parse(&d.bytes).map_err(|e| e.to_string()));
        let a = &mut self.archives[archive];
        match result {
            Ok(table) => {
                a.warnings.extend(
                    table
                        .warnings
                        .iter()
                        .map(|w| format!("resources.arsc: {w}")),
                );
                a.values_files = table.values_files();
                a.resource_files = table.file_references();
                a.resources = Some(table);
            }
            Err(e) => a
                .warnings
                .push(format!("resources.arsc could not be decoded: {e}")),
        }
    }

    /// All decoded resource tables (an APK and its splits share IDs).
    pub fn resource_tables(&self) -> Vec<&ResourceTable> {
        self.archives
            .iter()
            .filter_map(|a| a.resources.as_ref())
            .collect()
    }

    fn load_manifest(&mut self, archive: ArchiveId) {
        let Some(file) = self.find_file(archive, "AndroidManifest.xml") else {
            self.archives[archive]
                .warnings
                .push("AndroidManifest.xml is missing".to_owned());
            return;
        };
        let tables = self.resource_tables();
        let resolver = Resolver::new(&tables);
        let result = self
            .read_file(file)
            .and_then(|d| axml::parse_with(&d.bytes, &resolver).map_err(|e| e.to_string()));
        let manifest = result.map(|doc| {
            ManifestInfo::from_document(&doc).map(|mut info| {
                // Show the actual app name next to its resource reference.
                if let Some(label) = &info.app_label {
                    if let Some(text) = tables.iter().find_map(|t| t.string_by_reference(label)) {
                        info.app_label = Some(format!("{text} ({label})"));
                    }
                }
                info
            })
        });
        match manifest {
            Ok(info) => self.archives[archive].manifest = info,
            Err(e) => self.archives[archive]
                .warnings
                .push(format!("AndroidManifest.xml could not be decoded: {e}")),
        }
    }

    fn load_dex_files(&mut self, archive: ArchiveId) {
        let mut dex: Vec<(u32, FileId)> = self
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| f.archive == archive)
            .filter_map(|(id, f)| is_dex_name(&f.path).map(|n| (n, id)))
            .collect();
        dex.sort();
        for (_, file) in dex {
            let name = self.files[file].path.clone();
            let parsed = self
                .read_file(file)
                .and_then(|d| DexFile::parse(d.bytes).map_err(|e| e.to_string()));
            match parsed {
                Ok(dex) => self.dex_files.push(DexEntry {
                    archive,
                    file,
                    name,
                    dex: Arc::new(dex),
                }),
                Err(e) => self.archives[archive]
                    .warnings
                    .push(format!("{name} could not be parsed: {e}")),
            }
        }
    }

    pub fn root(&self) -> NodeId {
        0
    }

    pub fn class_count(&self, archive: ArchiveId) -> usize {
        self.dex_files
            .iter()
            .filter(|d| d.archive == archive)
            .map(|d| d.dex.class_defs.len())
            .sum()
    }

    /// Slash-separated labels from the root to `node`.
    pub fn node_path(&self, node: NodeId) -> String {
        let mut parts = Vec::new();
        let mut current = Some(node);
        while let Some(id) = current {
            parts.push(self.nodes[id].label.as_str());
            current = self.nodes[id].parent;
        }
        parts.reverse();
        parts.join(" / ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::formats::zip::write_stored_zip;

    #[test]
    fn opens_xapk_with_split_apks() {
        let base = write_stored_zip(&[
            ("AndroidManifest.xml", b"not binary xml"),
            ("classes.dex", b"dex\n035\0garbage"),
            ("res/raw/a.txt", b"hello"),
        ]);
        let split = write_stored_zip(&[("lib/arm64-v8a/libx.so", b"\x7fELF")]);
        let xapk = write_stored_zip(&[
            ("manifest.json", b"{}"),
            ("com.example.apk", &base),
            ("config.arm64_v8a.apk", &split),
            ("Android/obb/com.example/main.1.obb", b"obb"),
        ]);
        let pkg = Package::from_bytes(Path::new("app.xapk"), xapk.into()).unwrap();
        assert_eq!(pkg.kind, PackageKind::Xapk);
        assert_eq!(pkg.archives.len(), 3);
        let root = &pkg.nodes[pkg.root()];
        let labels: Vec<&str> = root
            .children
            .iter()
            .map(|&c| pkg.nodes[c].label.as_str())
            .collect();
        assert_eq!(labels, ["com.example.apk", "config.arm64_v8a.apk", "Files"]);
        // Broken manifest and DEX are reported, not fatal.
        assert!(
            pkg.archives[1]
                .warnings
                .iter()
                .any(|w| w.contains("AndroidManifest"))
        );
        assert!(
            pkg.archives[1]
                .warnings
                .iter()
                .any(|w| w.contains("classes.dex"))
        );
        let text = pkg.find_file(1, "res/raw/a.txt").unwrap();
        assert_eq!(&*pkg.read_file(text).unwrap().bytes, b"hello");
        for node in 0..pkg.nodes.len() {
            let _ = crate::inspect::inspect(&pkg, node);
        }
    }

    #[test]
    fn rejects_non_zip() {
        assert!(Package::from_bytes(Path::new("x.apk"), Arc::from(&b"nope"[..])).is_err());
    }

    #[test]
    fn dex_names() {
        assert_eq!(is_dex_name("classes.dex"), Some(1));
        assert_eq!(is_dex_name("classes2.dex"), Some(2));
        assert_eq!(is_dex_name("classes1.dex"), None);
        assert_eq!(is_dex_name("assets/classes.dex"), None);
        assert_eq!(is_dex_name("classesX.dex"), None);
    }
}
