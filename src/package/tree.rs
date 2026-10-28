//! Builds the navigation tree shown in the left panel.

use std::collections::BTreeMap;

use super::{ArchiveId, DexId, FileId, NodeId, Package, PackageKind};

/// Hard limit for path / package nesting, protecting the UI against crafted
/// archives with absurdly deep paths.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassRef {
    pub dex: DexId,
    pub class_def: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Archive(ArchiveId),
    SourceRoot(ArchiveId),
    ResourcesRoot(ArchiveId),
    /// A generated `values*` directory.
    ResourceDir(ArchiveId, String),
    /// Index into `Archive::values_files`.
    ResourceFile(ArchiveId, usize),
    FilesRoot(ArchiveId),
    Folder(String),
    JavaPackage(String),
    File(FileId),
    Class(ClassRef),
}

impl NodeKind {
    pub fn is_container(&self) -> bool {
        !matches!(
            self,
            NodeKind::File(_) | NodeKind::Class(_) | NodeKind::ResourceFile(..)
        )
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub label: String,
    pub kind: NodeKind,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
}

#[derive(Default)]
struct PackageTree {
    packages: BTreeMap<String, PackageTree>,
    classes: Vec<(String, ClassRef)>,
}

#[derive(Default)]
struct DirTree {
    dirs: BTreeMap<String, DirTree>,
    files: Vec<(String, FileId)>,
}

fn split_limited(path: &str) -> Vec<String> {
    let mut parts: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    if parts.len() > MAX_DEPTH {
        let rest = parts.split_off(MAX_DEPTH - 1).join("/");
        parts.push(rest);
    }
    parts
}

struct Builder {
    nodes: Vec<Node>,
}

impl Builder {
    fn push(&mut self, label: String, kind: NodeKind, parent: Option<NodeId>) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(Node {
            label,
            kind,
            parent,
            children: Vec::new(),
        });
        if let Some(p) = parent {
            self.nodes[p].children.push(id);
        }
        id
    }

    fn apk(&mut self, pkg: &Package, archive: ArchiveId, parent: Option<NodeId>) -> NodeId {
        let node = self.push(
            pkg.archives[archive].name.clone(),
            NodeKind::Archive(archive),
            parent,
        );
        self.source(pkg, archive, node);
        self.resources(pkg, archive, node);
        self.files(pkg, archive, node);
        node
    }

    fn resources(&mut self, pkg: &Package, archive: ArchiveId, parent: NodeId) {
        if pkg.archives[archive].resources.is_none() {
            return;
        }
        let root = self.push(
            "Resources".to_owned(),
            NodeKind::ResourcesRoot(archive),
            Some(parent),
        );
        let mut dirs: BTreeMap<String, Vec<(String, usize)>> = BTreeMap::new();
        for (i, f) in pkg.archives[archive].values_files.iter().enumerate() {
            dirs.entry(f.dir.clone())
                .or_default()
                .push((f.file.clone(), i));
        }
        // `values` (the default configuration) first, then the qualified ones.
        let mut ordered: Vec<(String, Vec<(String, usize)>)> = dirs.into_iter().collect();
        ordered.sort_by(|a, b| (a.0 != "values", &a.0).cmp(&(b.0 != "values", &b.0)));
        for (dir, mut files) in ordered {
            let node = self.push(dir.clone(), NodeKind::ResourceDir(archive, dir), Some(root));
            files.sort();
            for (file, index) in files {
                self.push(file, NodeKind::ResourceFile(archive, index), Some(node));
            }
        }
    }

    fn source(&mut self, pkg: &Package, archive: ArchiveId, parent: NodeId) {
        let root = self.push(
            "Source code".to_owned(),
            NodeKind::SourceRoot(archive),
            Some(parent),
        );
        let mut tree = PackageTree::default();
        for (dex_id, entry) in pkg.dex_files.iter().enumerate() {
            if entry.archive != archive {
                continue;
            }
            for (idx, class) in entry.dex.class_defs.iter().enumerate() {
                let desc = entry.dex.class_descriptor(class);
                let class_ref = ClassRef {
                    dex: dex_id,
                    class_def: idx,
                };
                let inner = desc
                    .strip_prefix('L')
                    .and_then(|d| d.strip_suffix(';'))
                    .filter(|d| !d.is_empty());
                let (packages, name) = match inner {
                    Some(inner) => {
                        let mut parts = split_limited(inner);
                        let name = parts.pop().unwrap_or_else(|| inner.to_owned());
                        (parts, name)
                    }
                    None => (vec!["(invalid descriptors)".to_owned()], desc.into_owned()),
                };
                let mut node = &mut tree;
                for p in packages {
                    node = node.packages.entry(p).or_default();
                }
                node.classes.push((name, class_ref));
            }
        }
        self.emit_packages(tree, root, "");
    }

    fn emit_packages(&mut self, tree: PackageTree, parent: NodeId, prefix: &str) {
        for (name, mut sub) in tree.packages {
            let mut label = name;
            // Collapse chains like com -> example -> app into "com.example.app".
            while sub.classes.is_empty() && sub.packages.len() == 1 {
                let (child_name, child) = sub.packages.pop_first().expect("one child");
                label = format!("{label}.{child_name}");
                sub = child;
            }
            let full = if prefix.is_empty() {
                label.clone()
            } else {
                format!("{prefix}.{label}")
            };
            let node = self.push(label, NodeKind::JavaPackage(full.clone()), Some(parent));
            self.emit_packages(sub, node, &full);
        }
        let mut classes = tree.classes;
        classes.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, class_ref) in classes {
            self.push(name, NodeKind::Class(class_ref), Some(parent));
        }
    }

    fn files(&mut self, pkg: &Package, archive: ArchiveId, parent: NodeId) {
        let root = self.push(
            "Files".to_owned(),
            NodeKind::FilesRoot(archive),
            Some(parent),
        );
        let mut tree = DirTree::default();
        for (id, file) in pkg.files.iter().enumerate() {
            if file.archive != archive {
                continue;
            }
            let mut parts = split_limited(&file.path);
            let name = parts.pop().unwrap_or_else(|| file.path.clone());
            let mut node = &mut tree;
            for p in parts {
                node = node.dirs.entry(p).or_default();
            }
            node.files.push((name, id));
        }
        self.emit_dirs(tree, root, "");
    }

    fn emit_dirs(&mut self, tree: DirTree, parent: NodeId, prefix: &str) {
        for (name, sub) in tree.dirs {
            let path = format!("{prefix}{name}/");
            let node = self.push(name, NodeKind::Folder(path.clone()), Some(parent));
            self.emit_dirs(sub, node, &path);
        }
        let mut files = tree.files;
        files.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, id) in files {
            self.push(name, NodeKind::File(id), Some(parent));
        }
    }
}

pub fn build(pkg: &Package, root: ArchiveId, apks: &[ArchiveId]) -> Vec<Node> {
    let mut b = Builder { nodes: Vec::new() };
    match pkg.kind {
        PackageKind::Apk => {
            b.apk(pkg, root, None);
        }
        PackageKind::Xapk => {
            let node = b.push(
                pkg.archives[root].name.clone(),
                NodeKind::Archive(root),
                None,
            );
            for &apk in apks {
                b.apk(pkg, apk, Some(node));
            }
            b.files(pkg, root, node);
        }
    }
    b.nodes
}
