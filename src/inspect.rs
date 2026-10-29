//! Turns a selected tree node into displayable content and file information.

use std::io::Cursor;
use std::sync::Arc;

use crate::formats::arsc::{ResourceTable, ValuesSource};
use crate::formats::axml;
use crate::formats::detect::{FileKind, detect};
use crate::formats::dex::access::{Target, flags_to_string};
use crate::formats::dex::smali::class_to_smali;
use crate::formats::dex::{DexFile, descriptor_to_java};
use crate::formats::resvalue::Resolver;
use crate::package::{
    ArchiveId, ClassRef, FileId, ManifestInfo, NodeId, NodeKind, Package, PackageKind, sha256_hex,
    to_hex,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Syntax {
    Plain,
    Smali,
    Xml,
    Json,
    JavaScript,
    Css,
}

impl Syntax {
    fn of(format: Option<crate::beautify::Format>) -> Self {
        use crate::beautify::Format;
        match format {
            Some(Format::Json) => Syntax::Json,
            Some(Format::Xml | Format::Html) => Syntax::Xml,
            Some(Format::Css) => Syntax::Css,
            Some(Format::JavaScript) => Syntax::JavaScript,
            None => Syntax::Plain,
        }
    }
}

pub enum Content {
    Text { lines: Vec<String>, syntax: Syntax },
    Image { uri: String, bytes: Arc<[u8]> },
    Hex(Arc<[u8]>),
    Message(String),
}

fn lines_of(text: &str) -> Vec<String> {
    text.lines().map(|l| l.replace('\t', "    ")).collect()
}

impl Content {
    fn text(text: &str, syntax: Syntax) -> Self {
        Content::Text {
            lines: lines_of(text),
            syntax,
        }
    }
}

#[derive(Clone)]
pub struct InfoSection {
    pub title: String,
    pub rows: Vec<(String, String)>,
}

impl InfoSection {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.rows.push((key.into(), value.into()));
        self
    }

    fn opt(&mut self, key: &str, value: &Option<String>) -> &mut Self {
        if let Some(v) = value {
            self.row(key, v.clone());
        }
        self
    }
}

pub struct Inspection {
    pub node: NodeId,
    pub title: String,
    pub content: Content,
    /// Raw bytes of the selected file, allowing a hex view of any file.
    pub raw: Option<Arc<[u8]>>,
    /// The text as stored, when `content` shows a beautified version.
    pub original: Option<Vec<String>>,
    pub sections: Vec<InfoSection>,
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    let grouped = group_digits(bytes);
    if bytes < 1024 {
        return format!("{grouped} bytes");
    }
    let mut value = bytes as f64;
    let mut unit = "";
    for u in UNITS {
        value /= 1024.0;
        unit = u;
        if value < 1024.0 {
            break;
        }
    }
    format!("{value:.1} {unit} ({grouped} bytes)")
}

pub fn group_digits(n: impl ToString) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn inspect(pkg: &Package, node: NodeId) -> Inspection {
    let title = pkg.node_path(node);
    let mut inspection = Inspection {
        node,
        title,
        content: Content::Message(String::new()),
        raw: None,
        original: None,
        sections: Vec::new(),
    };
    match &pkg.nodes[node].kind {
        NodeKind::Archive(a) => inspect_archive(pkg, *a, &mut inspection),
        NodeKind::SourceRoot(a) => inspect_source_root(pkg, *a, &mut inspection),
        NodeKind::ResourcesRoot(a) => inspect_resources_root(pkg, *a, &mut inspection),
        NodeKind::ResourceDir(a, dir) => inspect_resource_dir(pkg, node, *a, dir, &mut inspection),
        NodeKind::ResourceFile(a, i) => inspect_resource_file(pkg, *a, *i, &mut inspection),
        NodeKind::FilesRoot(_) | NodeKind::Folder(_) => inspect_folder(pkg, node, &mut inspection),
        NodeKind::JavaPackage(name) => inspect_package(pkg, node, name, &mut inspection),
        NodeKind::File(f) => inspect_file(pkg, node, *f, &mut inspection),
        NodeKind::Class(c) => inspect_class(pkg, *c, &mut inspection),
    }
    inspection
}

fn descendants(pkg: &Package, node: NodeId) -> impl Iterator<Item = NodeId> + '_ {
    let mut stack = vec![node];
    std::iter::from_fn(move || {
        let id = stack.pop()?;
        stack.extend(pkg.nodes[id].children.iter().copied());
        Some(id)
    })
}

fn manifest_section(m: &ManifestInfo) -> InfoSection {
    let mut s = InfoSection::new("Manifest");
    s.opt("Package", &m.package)
        .opt("Split", &m.split)
        .opt("Version name", &m.version_name)
        .opt("Version code", &m.version_code)
        .opt("Min SDK", &m.min_sdk)
        .opt("Target SDK", &m.target_sdk)
        .opt("Compile SDK", &m.compile_sdk)
        .opt("App label", &m.app_label)
        .opt("Application class", &m.app_class)
        .opt("Debuggable", &m.debuggable)
        .opt("Allow backup", &m.allow_backup);
    s.row(
        "Components",
        format!(
            "{} activities, {} services, {} receivers, {} providers",
            m.activities, m.services, m.receivers, m.providers
        ),
    );
    s
}

fn inspect_archive(pkg: &Package, archive: ArchiveId, out: &mut Inspection) {
    let a = &pkg.archives[archive];
    let is_outer_xapk = pkg.kind == PackageKind::Xapk && archive == 0;
    let file_count = pkg.files.iter().filter(|f| f.archive == archive).count();
    let dex: Vec<_> = pkg
        .dex_files
        .iter()
        .filter(|d| d.archive == archive)
        .collect();

    let mut s = InfoSection::new("Archive");
    s.row("Name", a.name.clone()).row(
        "Type",
        match (is_outer_xapk, a.source_file.is_some()) {
            (true, _) => "XAPK bundle",
            (false, true) => "APK (inside XAPK)",
            (false, false) => "APK",
        },
    );
    if archive == 0 {
        s.row("Location", pkg.path.display().to_string());
    }
    s.row("Size", format_size(a.size))
        .row("Files", group_digits(file_count));
    if !is_outer_xapk {
        s.row("DEX files", dex.len().to_string())
            .row("Classes", group_digits(pkg.class_count(archive)));
    } else {
        s.row("Contained APKs", (pkg.archives.len() - 1).to_string());
    }
    let mut hashes = InfoSection::new("Hashes");
    hashes.row("SHA-256", a.sha256.clone());

    let mut text = format!("{}\n\n", a.name);
    if let Some(m) = &a.manifest {
        let field = |label: &str, v: &Option<String>| {
            v.as_ref()
                .map(|v| format!("{label:<14}{v}\n"))
                .unwrap_or_default()
        };
        text += &field("Package:", &m.package);
        text += &field("Split:", &m.split);
        text += &field("Version:", &m.version_name);
        text += &field("Version code:", &m.version_code);
        text += &field("Min SDK:", &m.min_sdk);
        text += &field("Target SDK:", &m.target_sdk);
        text.push('\n');
    }
    if is_outer_xapk {
        text += "Contained APKs:\n";
        for inner in pkg.archives.iter().skip(1) {
            text += &format!("  {}  ({})\n", inner.name, format_size(inner.size));
        }
    } else {
        text += &format!("{file_count} files, {} DEX files\n", dex.len());
        for d in &dex {
            text += &format!(
                "  {:<16}{} classes, {} methods\n",
                d.name,
                group_digits(d.dex.class_defs.len()),
                group_digits(d.dex.method_count())
            );
        }
    }
    if !a.warnings.is_empty() {
        text += "\nWarnings:\n";
        for w in &a.warnings {
            text += &format!("  ⚠ {w}\n");
        }
    }
    out.content = Content::text(&text, Syntax::Plain);

    out.sections.push(s);
    if let Some(m) = &a.manifest {
        out.sections.push(manifest_section(m));
        if !m.permissions.is_empty() {
            let mut p = InfoSection::new(format!("Permissions ({})", m.permissions.len()));
            for perm in &m.permissions {
                p.row("", perm.clone());
            }
            out.sections.push(p);
        }
    }
    out.sections.push(hashes);
    push_warnings(&mut out.sections, &a.warnings);
}

fn push_warnings(sections: &mut Vec<InfoSection>, warnings: &[String]) {
    if !warnings.is_empty() {
        let mut w = InfoSection::new("Warnings");
        for warning in warnings {
            w.row("⚠", warning.clone());
        }
        sections.push(w);
    }
}

fn dex_section(name: &str, dex: &DexFile) -> InfoSection {
    let h = &dex.header;
    let mut s = InfoSection::new(name.to_owned());
    s.row("Format version", h.version.clone())
        .row("Size", format_size(dex.data().len() as u64))
        .row("Classes", group_digits(dex.class_defs.len()))
        .row("Methods", group_digits(dex.method_count()))
        .row("Fields", group_digits(dex.field_count()))
        .row("Types", group_digits(dex.type_count()))
        .row("Strings", group_digits(dex.string_count()))
        .row("Checksum", format!("0x{:08x}", h.checksum))
        .row("Signature", to_hex(&h.signature));
    for w in &dex.warnings {
        s.row("⚠", w.clone());
    }
    s
}

fn inspect_source_root(pkg: &Package, archive: ArchiveId, out: &mut Inspection) {
    let mut text = String::from("Source code (smali disassembly)\n\n");
    let mut any = false;
    for d in pkg.dex_files.iter().filter(|d| d.archive == archive) {
        any = true;
        text += &format!(
            "{:<16}DEX {}  {} classes, {} methods, {} strings\n",
            d.name,
            d.dex.header.version,
            group_digits(d.dex.class_defs.len()),
            group_digits(d.dex.method_count()),
            group_digits(d.dex.string_count()),
        );
        out.sections.push(dex_section(&d.name, &d.dex));
    }
    if !any {
        text += "No DEX files were found in this APK.\n";
    }
    out.content = Content::text(&text, Syntax::Plain);
}

fn resources_section(table: &ResourceTable) -> InfoSection {
    let mut s = InfoSection::new("Resource table");
    for p in &table.packages {
        s.row("Package", format!("0x{:02x} {}", p.id, p.name));
    }
    let configs: usize = table
        .packages
        .iter()
        .flat_map(|p| &p.types)
        .map(|t| t.configs.len())
        .sum();
    s.row("Resources", group_digits(table.entry_count()))
        .row(
            "Types",
            table
                .packages
                .iter()
                .map(|p| p.types.len())
                .sum::<usize>()
                .to_string(),
        )
        .row("Type configurations", group_digits(configs))
        .row("Strings", group_digits(table.strings.len()));
    for w in &table.warnings {
        s.row("⚠", w.clone());
    }
    s
}

fn inspect_resources_root(pkg: &Package, archive: ArchiveId, out: &mut Inspection) {
    let a = &pkg.archives[archive];
    let Some(table) = &a.resources else {
        out.content = Content::Message("No resource table.".to_owned());
        return;
    };
    let mut text = table.summary();
    text += &format!(
        "\n{} value files generated in {} directories (select one to view it).\n",
        a.values_files.len(),
        {
            let mut dirs: Vec<&str> = a.values_files.iter().map(|f| f.dir.as_str()).collect();
            dirs.sort_unstable();
            dirs.dedup();
            dirs.len()
        }
    );
    out.content = Content::text(&text, Syntax::Plain);
    out.sections.push(resources_section(table));
}

fn inspect_resource_dir(
    pkg: &Package,
    node: NodeId,
    archive: ArchiveId,
    dir: &str,
    out: &mut Inspection,
) {
    let qualifiers = dir
        .rsplit('/')
        .next()
        .and_then(|d| d.strip_prefix("values-"))
        .unwrap_or("(default)");
    let files = pkg.nodes[node].children.len();
    let mut s = InfoSection::new("Resource directory");
    s.row("Path", format!("res/{dir}/"))
        .row("Qualifiers", qualifiers.to_owned())
        .row("Files", files.to_string())
        .row("Archive", pkg.archives[archive].name.clone());
    out.sections.push(s);
    out.content = Content::Message(format!(
        "res/{dir}/\n{files} files generated from resources.arsc\n\nSelect a file to view it."
    ));
}

fn inspect_resource_file(pkg: &Package, archive: ArchiveId, index: usize, out: &mut Inspection) {
    let a = &pkg.archives[archive];
    let (Some(table), Some(file)) = (&a.resources, a.values_files.get(index)) else {
        out.content = Content::Message("Resource file not found.".to_owned());
        return;
    };
    let tables = pkg.resource_tables();
    let xml = table.render(file.source, &Resolver::new(&tables));
    let mut s = InfoSection::new("Resource file");
    s.row("Path", format!("res/{}/{}", file.dir, file.file))
        .row("Generated from", format!("resources.arsc ({})", a.name));
    if let ValuesSource::Values {
        package,
        res_type,
        config,
    } = file.source
    {
        let t = &table.packages[package].types[res_type];
        let c = &t.configs[config];
        s.row("Type", t.name.clone())
            .row(
                "Qualifiers",
                if c.qualifiers.is_empty() {
                    "(default)".to_owned()
                } else {
                    c.qualifiers.clone()
                },
            )
            .row("Entries", group_digits(c.entries.len()));
    }
    out.sections.push(s);
    out.content = Content::text(&xml, Syntax::Xml);
}

fn inspect_folder(pkg: &Package, node: NodeId, out: &mut Inspection) {
    let (mut files, mut size, mut compressed) = (0usize, 0u64, 0u64);
    for id in descendants(pkg, node) {
        if let NodeKind::File(f) = pkg.nodes[id].kind {
            files += 1;
            size = size.saturating_add(pkg.files[f].size);
            compressed = compressed.saturating_add(pkg.files[f].compressed_size);
        }
    }
    let path = match &pkg.nodes[node].kind {
        NodeKind::Folder(p) => p.clone(),
        _ => "/".to_owned(),
    };
    let mut s = InfoSection::new("Folder");
    s.row("Path", path)
        .row("Files", group_digits(files))
        .row("Size", format_size(size))
        .row("Compressed", format_size(compressed));
    out.sections.push(s);
    out.content = Content::Message(format!(
        "{} files, {} uncompressed\n\nSelect a file to view its contents.",
        group_digits(files),
        format_size(size)
    ));
}

fn inspect_package(pkg: &Package, node: NodeId, name: &str, out: &mut Inspection) {
    let classes = descendants(pkg, node)
        .filter(|&id| matches!(pkg.nodes[id].kind, NodeKind::Class(_)))
        .count();
    let mut s = InfoSection::new("Package");
    s.row("Name", name.to_owned())
        .row("Classes", group_digits(classes));
    out.sections.push(s);
    out.content = Content::Message(format!(
        "package {name}\n{} classes\n\nSelect a class to view its disassembly.",
        group_digits(classes)
    ));
}

fn image_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()
}

fn inspect_file(pkg: &Package, node: NodeId, file: FileId, out: &mut Inspection) {
    let entry = &pkg.files[file];
    let mut s = InfoSection::new("File");
    s.row("Name", entry.name().to_owned())
        .row("Path", entry.path.clone())
        .row("Archive", pkg.archives[entry.archive].name.clone())
        .row("Size", format_size(entry.size))
        .row("Compressed", format_size(entry.compressed_size));
    if entry.size > 0 {
        s.row(
            "Ratio",
            format!(
                "{:.1}%",
                entry.compressed_size as f64 * 100.0 / entry.size as f64
            ),
        );
    }
    s.row("Compression", entry.method.clone())
        .row("CRC-32", format!("0x{:08x}", entry.crc32));
    if let Some(m) = &entry.modified {
        s.row("Modified", m.clone());
    }
    if let Some(off) = entry.data_offset {
        s.row("Data offset", format!("0x{off:x}"));
    }
    if entry.encrypted {
        s.row("⚠ Encrypted flag", "set (Android ignores this flag)");
    }

    let data = match pkg.read_file(file) {
        Ok(d) => d,
        Err(e) => {
            s.row("⚠ Error", e.clone());
            out.sections.push(s);
            out.content = Content::Message(format!("This file could not be read:\n\n{e}"));
            return;
        }
    };
    if let Some(note) = &data.note {
        s.row("⚠ Note", note.clone());
    }
    let bytes = data.bytes;
    let kind = detect(entry.name(), &bytes);
    s.row("Type", kind.description(&bytes));
    if let Some(names) = pkg.archives[entry.archive].resource_files.get(&entry.path) {
        for name in names {
            s.row("Resource", name.clone());
        }
    }
    out.sections.push(s);
    let mut hashes = InfoSection::new("Hashes");
    hashes.row("SHA-256", sha256_hex(&bytes));
    out.raw = Some(bytes.clone());

    out.content = match kind {
        FileKind::Empty => Content::Message("This file is empty.".to_owned()),
        FileKind::Dex => match DexFile::parse(bytes.clone()) {
            Ok(dex) => {
                let section = dex_section("DEX", &dex);
                let mut text = String::new();
                for (k, v) in &section.rows {
                    text += &format!("{k:<16}{v}\n");
                }
                out.sections.push(section);
                Content::text(&format!("{}\n\n{text}", entry.path), Syntax::Plain)
            }
            Err(e) => Content::Message(format!("DEX file could not be parsed: {e}")),
        },
        FileKind::BinaryXml => {
            match axml::parse_with(&bytes, &Resolver::new(&pkg.resource_tables())) {
                Ok(doc) => Content::text(&doc.to_xml_string(), Syntax::Xml),
                Err(e) => Content::Message(format!("Binary XML could not be decoded: {e}")),
            }
        }
        FileKind::Image(_) => {
            if let Some((w, h)) = image_dimensions(&bytes) {
                let mut img = InfoSection::new("Image");
                img.row("Dimensions", format!("{w} × {h} px"));
                out.sections.push(img);
            }
            Content::Image {
                uri: format!("bytes://{node}/{}", entry.path),
                bytes,
            }
        }
        FileKind::Text => {
            let text = String::from_utf8_lossy(&bytes);
            let processed = crate::beautify::process(&entry.path, &text);
            let syntax = Syntax::of(processed.format);
            if let Some(format) = processed.format {
                let mut view = InfoSection::new("View");
                view.row("Format", format.name());
                view.row(
                    "Beautified",
                    match &processed.beautified {
                        Some(b) => format!(
                            "Yes — {} → {} lines",
                            group_digits(text.lines().count()),
                            group_digits(b.lines().count())
                        ),
                        None => "No (already formatted)".to_owned(),
                    },
                );
                out.sections.push(view);
            }
            match processed.beautified {
                Some(beautified) => {
                    out.original = Some(lines_of(&text));
                    Content::text(&beautified, syntax)
                }
                None => Content::text(&text, syntax),
            }
        }
        FileKind::ResourceTable => {
            let own = pkg.archives[entry.archive]
                .resources
                .as_ref()
                .filter(|_| entry.path == "resources.arsc");
            let parsed;
            let table = match own {
                Some(t) => Some(t),
                None => {
                    parsed = ResourceTable::parse(&bytes).ok();
                    parsed.as_ref()
                }
            };
            match table {
                Some(t) => {
                    out.sections.push(resources_section(t));
                    let mut text = t.summary();
                    if own.is_some() {
                        text +=
                            "\nThe decoded values are listed under \"Resources\" in the tree.\n";
                    }
                    Content::text(&text, Syntax::Plain)
                }
                None => Content::Hex(bytes),
            }
        }
        FileKind::Elf | FileKind::Zip | FileKind::Binary => Content::Hex(bytes),
    };
    out.sections.push(hashes);
}

fn inspect_class(pkg: &Package, class: ClassRef, out: &mut Inspection) {
    let entry = &pkg.dex_files[class.dex];
    let dex = &entry.dex;
    let def = &dex.class_defs[class.class_def];
    let desc = dex.class_descriptor(def);

    let mut s = InfoSection::new("Class");
    s.row("Name", descriptor_to_java(&desc))
        .row("Descriptor", desc.clone().into_owned());
    let flags = flags_to_string(def.access_flags, Target::Class);
    s.row(
        "Access flags",
        if flags.is_empty() {
            format!("0x{:x}", def.access_flags)
        } else {
            format!("{flags} (0x{:x})", def.access_flags)
        },
    );
    if let Some(sup) = def.superclass {
        s.row("Superclass", descriptor_to_java(&dex.type_descriptor(sup)));
    }
    if let Ok(interfaces) = dex.interfaces(def) {
        for i in interfaces {
            s.row("Implements", descriptor_to_java(&dex.type_descriptor(i)));
        }
    }
    if let Some(src) = def.source_file {
        s.row("Source file", dex.string(src).into_owned());
    }
    s.row(
        "DEX file",
        format!("{} ({})", entry.name, pkg.archives[entry.archive].name),
    );
    match dex.class_data(def) {
        Ok(data) => {
            s.row(
                "Fields",
                format!(
                    "{} static, {} instance",
                    data.static_fields.len(),
                    data.instance_fields.len()
                ),
            )
            .row(
                "Methods",
                format!(
                    "{} direct, {} virtual",
                    data.direct_methods.len(),
                    data.virtual_methods.len()
                ),
            );
        }
        Err(e) => {
            s.row("⚠ Class data", e.to_string());
        }
    }
    out.sections.push(s);
    out.content = Content::text(&class_to_smali(dex, def), Syntax::Smali);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(format_size(12), "12 bytes");
        assert_eq!(format_size(1536), "1.5 KiB (1,536 bytes)");
        assert_eq!(group_digits(1234567), "1,234,567");
    }
}
