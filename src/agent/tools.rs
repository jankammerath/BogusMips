//! Agent context builder and tool execution over the disassembled source code,
//! resource files, and captured network traffic.

use std::fmt::Write;
use std::sync::Arc;

use regex::RegexBuilder;

use super::config::AgentConfig;
use super::json::JsonValue;
use crate::inspect::{Content, format_size, group_digits, inspect};
use crate::net::capture::{Capture, Flow};
use crate::package::{NodeId, NodeKind, Package, PackageKind};
use crate::search::searchable_lines;

/// Maximum characters of the currently selected file/flow included directly in
/// the system prompt.
const MAX_INLINE_CONTEXT: usize = 14_000;
/// Maximum characters returned by a single tool invocation.
const MAX_TOOL_OUTPUT: usize = 16_000;

/// Target referenced by an agent tool call, allowing the user to click a tool
/// badge in the chat to open that class/resource/file or network flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTarget {
    Node(NodeId),
    Flow(u64),
}

/// Summary of one tool call executed during an agent turn.
#[derive(Debug, Clone)]
pub struct ToolTrace {
    pub name: String,
    pub summary: String,
    pub target: Option<ToolTarget>,
}

/// Snapshot of the current workspace state passed to an agent turn.
#[derive(Clone)]
pub struct AgentContext {
    pub package: Option<Arc<Package>>,
    pub selected_node: Option<NodeId>,
    pub capture: Option<Arc<Capture>>,
    pub selected_flow: Option<u64>,
    pub include_source: bool,
    pub include_resources: bool,
    pub include_network: bool,
}

impl AgentContext {
    pub fn from_config(
        config: &AgentConfig,
        package: Option<Arc<Package>>,
        selected_node: Option<NodeId>,
        capture: Option<Arc<Capture>>,
        selected_flow: Option<u64>,
    ) -> Self {
        Self {
            package,
            selected_node,
            capture,
            selected_flow,
            include_source: config.include_source,
            include_resources: config.include_resources,
            include_network: config.include_network,
        }
    }
}

/// Builds the system prompt describing the assistant's role, available tools,
/// and the current package / editor / network context.
pub fn build_system_prompt(ctx: &AgentContext) -> String {
    let mut out = String::from(
        "You are the built-in AI reverse-engineering and security analysis agent inside BogusMips, \
         an Android APK/XAPK disassembler and MITM network traffic analyzer.\n\
         You help the user understand:\n\
         1. Disassembled Dalvik/ART bytecode (smali classes from classes*.dex).\n\
         2. Decoded Android resources (AndroidManifest.xml, resources.arsc values XMLs, layouts, assets).\n\
         3. Captured live HTTP/HTTPS network traffic from the Android emulator proxy.\n\n\
         When answering:\n\
         - Be concise, accurate, and cite exact class names, resource names, file paths, or flow IDs.\n\
         - Use your tools (`search_package`, `list_nodes`, `read_node`, `list_network_flows`, `inspect_network_flow`) \
         whenever you need to look up additional classes, resource files, strings, or network requests.\n\n",
    );

    if let Some(pkg) = &ctx.package {
        append_package_summary(&mut out, pkg, ctx);
        if let Some(node) = ctx.selected_node {
            append_selected_node(&mut out, pkg, node, ctx);
        }
    } else {
        out.push_str("## Package Status\nNo APK or XAPK package is currently open.\n\n");
    }

    if ctx.include_network {
        if let Some(capture) = &ctx.capture {
            append_network_summary(&mut out, capture, ctx.selected_flow);
        }
    }

    out
}

fn append_package_summary(out: &mut String, pkg: &Package, ctx: &AgentContext) {
    let kind = match pkg.kind {
        PackageKind::Apk => "APK",
        PackageKind::Xapk => "XAPK",
    };
    let total_classes: usize = pkg.dex_files.iter().map(|d| d.dex.class_defs.len()).sum();
    let _ = writeln!(
        out,
        "## Open Package: {} ({kind})",
        pkg.archives.first().map_or("unknown", |a| a.name.as_str())
    );
    let _ = writeln!(
        out,
        "- Archive entries: {} files, {} DEX files, {} classes",
        group_digits(pkg.files.len()),
        pkg.dex_files.len(),
        group_digits(total_classes)
    );

    for archive in &pkg.archives {
        if let Some(m) = &archive.manifest {
            if let Some(p) = &m.package {
                let _ = writeln!(out, "- Package name: `{p}`");
            }
            if let Some(v) = &m.version_name {
                let code = m.version_code.as_deref().unwrap_or("?");
                let _ = writeln!(out, "- Version: {v} (code {code})");
            }
            if m.min_sdk.is_some() || m.target_sdk.is_some() {
                let _ = writeln!(
                    out,
                    "- SDK: min={}, target={}",
                    m.min_sdk.as_deref().unwrap_or("?"),
                    m.target_sdk.as_deref().unwrap_or("?")
                );
            }
            if let Some(app_cls) = &m.app_class {
                let _ = writeln!(out, "- Application class: `{app_cls}`");
            }
            if let Some(dbg) = &m.debuggable {
                let _ = writeln!(out, "- Debuggable: {dbg}");
            }
            let _ = writeln!(
                out,
                "- Components: {} activities, {} services, {} receivers, {} providers",
                m.activities, m.services, m.receivers, m.providers
            );
            if !m.permissions.is_empty() {
                let shown: Vec<&str> = m.permissions.iter().take(25).map(String::as_str).collect();
                let _ = writeln!(out, "- Permissions ({}): {}", m.permissions.len(), shown.join(", "));
            }
        }
        if ctx.include_resources && !archive.values_files.is_empty() {
            let paths: Vec<String> = archive
                .values_files
                .iter()
                .take(20)
                .map(|v| format!("res/{}/{}", v.dir, v.file))
                .collect();
            let _ = writeln!(
                out,
                "- Generated resource value files ({}): {}",
                archive.values_files.len(),
                paths.join(", ")
            );
        }
    }
    out.push('\n');
}

fn is_node_allowed(pkg: &Package, node: NodeId, ctx: &AgentContext) -> bool {
    match &pkg.nodes[node].kind {
        NodeKind::Class(_) | NodeKind::SourceRoot(_) | NodeKind::JavaPackage(_) => {
            ctx.include_source
        }
        NodeKind::ResourcesRoot(_)
        | NodeKind::ResourceDir(..)
        | NodeKind::ResourceFile(..)
        | NodeKind::FilesRoot(_)
        | NodeKind::Folder(_)
        | NodeKind::File(_) => ctx.include_resources,
        NodeKind::Archive(_) => true,
    }
}

fn append_selected_node(out: &mut String, pkg: &Package, node: NodeId, ctx: &AgentContext) {
    if node >= pkg.nodes.len() || !is_node_allowed(pkg, node, ctx) {
        return;
    }
    let inspection = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inspect(pkg, node)));
    let Ok(inspection) = inspection else {
        return;
    };
    let _ = writeln!(out, "## Currently Selected Item in Editor: `{}` (node #{node})", inspection.title);
    for section in &inspection.sections {
        let pairs: Vec<String> = section
            .rows
            .iter()
            .take(10)
            .map(|(k, v)| if k.is_empty() { v.clone() } else { format!("{k}: {v}") })
            .collect();
        if !pairs.is_empty() {
            let _ = writeln!(out, "- {}: {}", section.title, pairs.join(" | "));
        }
    }
    if let Content::Text { lines, .. } = &inspection.content {
        out.push_str("\n```\n");
        let mut chars = 0;
        for (i, line) in lines.iter().enumerate() {
            let entry = format!("{:>4}: {}\n", i + 1, line);
            if chars + entry.len() > MAX_INLINE_CONTEXT {
                let _ = writeln!(
                    out,
                    "... (truncated at {} of {} lines; use `read_node` with start_line to read more)",
                    i,
                    lines.len()
                );
                break;
            }
            out.push_str(&entry);
            chars += entry.len();
        }
        out.push_str("```\n\n");
    }
}

fn append_network_summary(out: &mut String, capture: &Capture, selected_flow: Option<u64>) {
    let flows = capture.snapshot();
    let _ = writeln!(out, "## Captured Network Traffic ({} flows)", flows.len());
    if flows.is_empty() {
        out.push_str("No network requests captured yet.\n\n");
        return;
    }
    out.push_str("Recent flows:\n");
    for flow in flows.iter().rev().take(20).rev() {
        let status = flow
            .status
            .map(|s| s.to_string())
            .unwrap_or_else(|| flow.error.clone().unwrap_or_else(|| "pending".to_owned()));
        let _ = writeln!(
            out,
            "- Flow #{}: {} {} -> {} (req {} B, resp {} B)",
            flow.id,
            flow.method,
            flow.url(),
            status,
            flow.req_body.len(),
            flow.resp_body.len()
        );
    }
    out.push('\n');

    if let Some(id) = selected_flow {
        if let Some(flow) = flows.iter().find(|f| f.id == id) {
            let _ = writeln!(out, "### Currently Selected Network Flow #{id}");
            out.push_str(&format_flow_detail(flow, MAX_INLINE_CONTEXT / 2));
            out.push('\n');
        }
    }
}

fn format_flow_detail(flow: &Flow, max_body_chars: usize) -> String {
    let mut out = String::new();
    let status = flow
        .status
        .map(|s| format!("{s} {}", flow.reason))
        .unwrap_or_else(|| flow.error.clone().unwrap_or_else(|| "pending".to_owned()));
    let _ = writeln!(out, "URL: {} {}", flow.method, flow.url());
    let _ = writeln!(out, "Status: {status}");
    if let Some(d) = flow.duration {
        let _ = writeln!(out, "Duration: {} ms", d.as_millis());
    }
    out.push_str("Request Headers:\n");
    for (k, v) in &flow.req_headers.0 {
        let _ = writeln!(out, "  {k}: {v}");
    }
    if !flow.req_body.is_empty() {
        let (decoded, _) = flow.decoded_request();
        out.push_str("Request Body:\n");
        append_body_preview(&mut out, &decoded, max_body_chars);
    }
    if !flow.resp_headers.0.is_empty() {
        out.push_str("Response Headers:\n");
        for (k, v) in &flow.resp_headers.0 {
            let _ = writeln!(out, "  {k}: {v}");
        }
    }
    if !flow.resp_body.is_empty() {
        let (decoded, _) = flow.decoded_response();
        out.push_str("Response Body:\n");
        append_body_preview(&mut out, &decoded, max_body_chars);
    }
    out
}

fn append_body_preview(out: &mut String, bytes: &[u8], max_chars: usize) {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            let taken: String = text.chars().take(max_chars).collect();
            out.push_str(&taken);
            if text.len() > taken.len() {
                let _ = writeln!(out, "\n... (truncated, {} total)", format_size(bytes.len() as u64));
            } else if !taken.ends_with('\n') {
                out.push('\n');
            }
        }
        Err(_) => {
            let preview_len = bytes.len().min(64);
            let hex: Vec<String> = bytes[..preview_len].iter().map(|b| format!("{b:02x}")).collect();
            let _ = writeln!(
                out,
                "<binary {}, first {} bytes: {}>",
                format_size(bytes.len() as u64),
                preview_len,
                hex.join(" ")
            );
        }
    }
}

/// Tool schema definitions in a provider-neutral structure.
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters_schema: JsonValue,
}

pub fn tool_specs(ctx: &AgentContext) -> Vec<ToolSpec> {
    let mut specs = Vec::new();
    if ctx.package.is_some() && (ctx.include_source || ctx.include_resources) {
        specs.push(ToolSpec {
            name: "search_package",
            description: "Search across disassembled smali source code, decoded resource XML files (strings.xml, AndroidManifest.xml, etc.), and text assets in the open package using a regex or substring.",
            parameters_schema: JsonValue::obj([
                ("type", JsonValue::str("object")),
                (
                    "properties",
                    JsonValue::obj([
                        (
                            "query",
                            JsonValue::obj([
                                ("type", JsonValue::str("string")),
                                ("description", JsonValue::str("Substring or regular expression to search for.")),
                            ]),
                        ),
                        (
                            "scope",
                            JsonValue::obj([
                                ("type", JsonValue::str("string")),
                                ("description", JsonValue::str("Optional scope filter: 'all', 'source', 'resources', or 'files'.")),
                            ]),
                        ),
                    ]),
                ),
                ("required", JsonValue::arr([JsonValue::str("query")])),
            ]),
        });
        specs.push(ToolSpec {
            name: "list_nodes",
            description: "List disassembled classes, resource files, or archive files in the open APK/XAPK package, optionally filtered by name or path substring.",
            parameters_schema: JsonValue::obj([
                ("type", JsonValue::str("object")),
                (
                    "properties",
                    JsonValue::obj([
                        (
                            "category",
                            JsonValue::obj([
                                ("type", JsonValue::str("string")),
                                ("description", JsonValue::str("Category to list: 'classes', 'resources', or 'files'.")),
                            ]),
                        ),
                        (
                            "filter",
                            JsonValue::obj([
                                ("type", JsonValue::str("string")),
                                ("description", JsonValue::str("Optional case-insensitive substring to match against paths or class names.")),
                            ]),
                        ),
                    ]),
                ),
                ("required", JsonValue::arr([JsonValue::str("category")])),
            ]),
        });
        specs.push(ToolSpec {
            name: "read_node",
            description: "Read the disassembled smali code of a class, decoded XML of a resource file, or contents of a file in the package by path, class name, or node ID.",
            parameters_schema: JsonValue::obj([
                ("type", JsonValue::str("object")),
                (
                    "properties",
                    JsonValue::obj([
                        (
                            "target",
                            JsonValue::obj([
                                ("type", JsonValue::str("string")),
                                ("description", JsonValue::str("Class name (e.g. 'com.example.MainActivity'), file/resource path (e.g. 'res/values/strings.xml' or 'AndroidManifest.xml'), or '#<node_id>'.")),
                            ]),
                        ),
                        (
                            "start_line",
                            JsonValue::obj([
                                ("type", JsonValue::str("integer")),
                                ("description", JsonValue::str("Optional 1-based starting line number (default 1).")),
                            ]),
                        ),
                        (
                            "max_lines",
                            JsonValue::obj([
                                ("type", JsonValue::str("integer")),
                                ("description", JsonValue::str("Optional maximum number of lines to read (default 150).")),
                            ]),
                        ),
                    ]),
                ),
                ("required", JsonValue::arr([JsonValue::str("target")])),
            ]),
        });
    }
    if ctx.include_network && ctx.capture.is_some() {
        specs.push(ToolSpec {
            name: "list_network_flows",
            description: "List captured HTTP and HTTPS requests/responses from the network sniffer, optionally filtered by URL, host, or HTTP method.",
            parameters_schema: JsonValue::obj([
                ("type", JsonValue::str("object")),
                (
                    "properties",
                    JsonValue::obj([(
                        "filter",
                        JsonValue::obj([
                            ("type", JsonValue::str("string")),
                            ("description", JsonValue::str("Optional substring filter for URL, host, or HTTP method.")),
                        ]),
                    )]),
                ),
            ]),
        });
        specs.push(ToolSpec {
            name: "inspect_network_flow",
            description: "Inspect the full request headers, request body, response headers, response body, and timing of a captured HTTP/HTTPS flow by its numeric ID.",
            parameters_schema: JsonValue::obj([
                ("type", JsonValue::str("object")),
                (
                    "properties",
                    JsonValue::obj([(
                        "id",
                        JsonValue::obj([
                            ("type", JsonValue::str("integer")),
                            ("description", JsonValue::str("Numeric flow ID from `list_network_flows`.")),
                        ]),
                    )]),
                ),
                ("required", JsonValue::arr([JsonValue::str("id")])),
            ]),
        });
    }
    specs
}

/// Executes a tool call against the workspace context, returning the tool output
/// string and a [`ToolTrace`] for the UI.
pub fn execute_tool(name: &str, args: &JsonValue, ctx: &AgentContext) -> (String, ToolTrace) {
    match name {
        "search_package" => tool_search_package(args, ctx),
        "list_nodes" => tool_list_nodes(args, ctx),
        "read_node" => tool_read_node(args, ctx),
        "list_network_flows" => tool_list_network_flows(args, ctx),
        "inspect_network_flow" => tool_inspect_network_flow(args, ctx),
        other => (
            format!("Unknown tool '{other}'."),
            ToolTrace {
                name: other.to_owned(),
                summary: format!("Unknown tool {other}"),
                target: None,
            },
        ),
    }
}

fn tool_search_package(args: &JsonValue, ctx: &AgentContext) -> (String, ToolTrace) {
    let query = args
        .get("query")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .trim();
    let scope = args
        .get("scope")
        .and_then(JsonValue::as_str)
        .unwrap_or("all")
        .to_ascii_lowercase();
    let trace = ToolTrace {
        name: "search_package".to_owned(),
        summary: format!("Searched package for \"{query}\""),
        target: None,
    };
    let Some(pkg) = &ctx.package else {
        return ("No package is open.".to_owned(), trace);
    };
    if query.is_empty() {
        return ("Query must not be empty.".to_owned(), trace);
    }
    let regex = RegexBuilder::new(query)
        .case_insensitive(true)
        .size_limit(8 << 20)
        .build()
        .or_else(|_| {
            RegexBuilder::new(&regex::escape(query))
                .case_insensitive(true)
                .build()
        });
    let Ok(regex) = regex else {
        return ("Invalid search pattern.".to_owned(), trace);
    };

    let mut out = String::new();
    let mut match_count = 0usize;
    let mut first_node = None;

    for node in 0..pkg.nodes.len() {
        if !is_node_allowed(pkg, node, ctx) {
            continue;
        }
        let kind_matches = match (&pkg.nodes[node].kind, scope.as_str()) {
            (NodeKind::Class(_), "all" | "source" | "classes") => true,
            (NodeKind::ResourceFile(..), "all" | "resources") => true,
            (NodeKind::File(_), "all" | "files" | "resources") => true,
            _ => false,
        };
        if !kind_matches {
            continue;
        }
        let Some(lines) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            searchable_lines(pkg, node)
        }))
        .ok()
        .flatten() else {
            continue;
        };
        let path = pkg.node_path(node);
        for (line_idx, line) in lines.iter().enumerate() {
            if regex.is_match(line) {
                if first_node.is_none() {
                    first_node = Some(node);
                }
                match_count += 1;
                if match_count <= 40 && out.len() < MAX_TOOL_OUTPUT {
                    let snippet: String = line.trim().chars().take(180).collect();
                    let _ = writeln!(out, "[#{node}] {path}:{}  {snippet}", line_idx + 1);
                }
            }
        }
    }

    if match_count == 0 {
        out = format!("No matches found for '{query}'.");
    } else if match_count > 40 {
        let _ = writeln!(out, "... ({match_count} total matches; showing first 40)");
    }

    (
        out,
        ToolTrace {
            target: first_node.map(ToolTarget::Node),
            summary: format!("Searched \"{query}\" ({match_count} matches)"),
            ..trace
        },
    )
}

fn tool_list_nodes(args: &JsonValue, ctx: &AgentContext) -> (String, ToolTrace) {
    let category = args
        .get("category")
        .and_then(JsonValue::as_str)
        .unwrap_or("classes")
        .to_ascii_lowercase();
    let filter = args
        .get("filter")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let trace = ToolTrace {
        name: "list_nodes".to_owned(),
        summary: if filter.is_empty() {
            format!("Listed {category}")
        } else {
            format!("Listed {category} matching \"{filter}\"")
        },
        target: None,
    };
    let Some(pkg) = &ctx.package else {
        return ("No package is open.".to_owned(), trace);
    };

    let mut out = String::new();
    let mut count = 0usize;
    for node in 0..pkg.nodes.len() {
        if !is_node_allowed(pkg, node, ctx) {
            continue;
        }
        let include = match (&pkg.nodes[node].kind, category.as_str()) {
            (NodeKind::Class(_), "classes" | "source" | "all") => true,
            (NodeKind::ResourceFile(..), "resources" | "all") => true,
            (NodeKind::File(_), "files" | "all") => true,
            _ => false,
        };
        if !include {
            continue;
        }
        let path = pkg.node_path(node);
        if !filter.is_empty() && !path.to_ascii_lowercase().contains(&filter) {
            continue;
        }
        count += 1;
        if count <= 80 && out.len() < MAX_TOOL_OUTPUT {
            let _ = writeln!(out, "[#{node}] {path}");
        }
    }
    if count == 0 {
        out = format!("No {category} matched filter '{filter}'.");
    } else if count > 80 {
        let _ = writeln!(out, "... ({count} total items; showing first 80)");
    }
    (out, trace)
}

fn find_node(pkg: &Package, target: &str, ctx: &AgentContext) -> Option<NodeId> {
    let trimmed = target.trim();
    if let Some(id_str) = trimmed.strip_prefix('#') {
        if let Ok(id) = id_str.parse::<usize>() {
            if id < pkg.nodes.len() && is_node_allowed(pkg, id, ctx) {
                return Some(id);
            }
        }
    }
    if let Ok(id) = trimmed.parse::<usize>() {
        if id < pkg.nodes.len() && is_node_allowed(pkg, id, ctx) {
            return Some(id);
        }
    }
    let needle = trimmed
        .trim_end_matches(".smali")
        .replace('.', "/")
        .to_ascii_lowercase();
    let raw_lower = trimmed.to_ascii_lowercase();

    // 1. Exact label or file path match.
    for node in 0..pkg.nodes.len() {
        if !is_node_allowed(pkg, node, ctx) {
            continue;
        }
        let label = pkg.nodes[node].label.to_ascii_lowercase();
        let path = pkg.node_path(node).to_ascii_lowercase();
        if label == raw_lower || path == raw_lower {
            return Some(node);
        }
        if let NodeKind::File(f) = pkg.nodes[node].kind {
            if pkg.files[f].path.to_ascii_lowercase() == raw_lower {
                return Some(node);
            }
        }
        if let NodeKind::ResourceFile(a, i) = pkg.nodes[node].kind {
            let vf = &pkg.archives[a].values_files[i];
            let vf_path = format!("res/{}/{}", vf.dir, vf.file).to_ascii_lowercase();
            if vf_path == raw_lower || vf.file.to_ascii_lowercase() == raw_lower {
                return Some(node);
            }
        }
    }
    // 2. Suffix / substring match on leaf nodes (Class, ResourceFile, File).
    for node in 0..pkg.nodes.len() {
        if !is_node_allowed(pkg, node, ctx) {
            continue;
        }
        if !matches!(
            pkg.nodes[node].kind,
            NodeKind::Class(_) | NodeKind::ResourceFile(..) | NodeKind::File(_)
        ) {
            continue;
        }
        let path = pkg.node_path(node).to_ascii_lowercase();
        let normalized_path = path.replace(" / ", "/");
        if normalized_path.contains(&needle) || path.contains(&raw_lower) {
            return Some(node);
        }
    }
    None
}

fn tool_read_node(args: &JsonValue, ctx: &AgentContext) -> (String, ToolTrace) {
    let target = args
        .get("target")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .trim();
    let start_line = args
        .get("start_line")
        .and_then(JsonValue::as_usize)
        .unwrap_or(1)
        .max(1);
    let max_lines = args
        .get("max_lines")
        .and_then(JsonValue::as_usize)
        .unwrap_or(150)
        .clamp(1, 500);

    let Some(pkg) = &ctx.package else {
        return (
            "No package is open.".to_owned(),
            ToolTrace {
                name: "read_node".to_owned(),
                summary: format!("Read {target}"),
                target: None,
            },
        );
    };
    let Some(node) = find_node(pkg, target, ctx) else {
        return (
            format!("Could not find a class, resource, or file matching '{target}'."),
            ToolTrace {
                name: "read_node".to_owned(),
                summary: format!("Read {target} (not found)"),
                target: None,
            },
        );
    };

    let inspection = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inspect(pkg, node)));
    let Ok(inspection) = inspection else {
        return (
            format!("Error decoding node #{node}."),
            ToolTrace {
                name: "read_node".to_owned(),
                summary: format!("Read {}", pkg.nodes[node].label),
                target: Some(ToolTarget::Node(node)),
            },
        );
    };

    let mut out = format!("# {} (node #{node})\n", inspection.title);
    for s in &inspection.sections {
        for (k, v) in &s.rows {
            if k.is_empty() {
                let _ = writeln!(out, "- {v}");
            } else {
                let _ = writeln!(out, "- {k}: {v}");
            }
        }
    }
    match &inspection.content {
        Content::Text { lines, .. } => {
            let total = lines.len();
            let start = (start_line - 1).min(total);
            let end = (start + max_lines).min(total);
            let _ = writeln!(out, "\nLines {}..{} of {total}:", start + 1, end);
            for (i, line) in lines[start..end].iter().enumerate() {
                if out.len() + line.len() + 16 > MAX_TOOL_OUTPUT {
                    let _ = writeln!(out, "... (output size limit reached)");
                    break;
                }
                let _ = writeln!(out, "{:>4}: {}", start + i + 1, line);
            }
        }
        Content::Hex(raw) => {
            let _ = writeln!(out, "\nBinary file ({})", format_size(raw.len() as u64));
        }
        Content::Image { bytes, .. } => {
            let _ = writeln!(out, "\nImage file ({})", format_size(bytes.len() as u64));
        }
        Content::Message(msg) => {
            let _ = writeln!(out, "\n{msg}");
        }
    }

    (
        out,
        ToolTrace {
            name: "read_node".to_owned(),
            summary: format!("Read {}", pkg.nodes[node].label),
            target: Some(ToolTarget::Node(node)),
        },
    )
}

fn tool_list_network_flows(args: &JsonValue, ctx: &AgentContext) -> (String, ToolTrace) {
    let filter = args
        .get("filter")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let trace = ToolTrace {
        name: "list_network_flows".to_owned(),
        summary: if filter.is_empty() {
            "Listed network flows".to_owned()
        } else {
            format!("Listed network flows matching \"{filter}\"")
        },
        target: None,
    };
    let Some(capture) = &ctx.capture else {
        return ("Network capture is not available.".to_owned(), trace);
    };
    let flows = capture.snapshot();
    if flows.is_empty() {
        return ("No network requests have been captured yet.".to_owned(), trace);
    }
    let mut out = String::new();
    let mut count = 0usize;
    let mut first_id = None;
    for flow in &flows {
        let url = flow.url();
        if !filter.is_empty()
            && !url.to_ascii_lowercase().contains(&filter)
            && !flow.method.to_ascii_lowercase().contains(&filter)
        {
            continue;
        }
        if first_id.is_none() {
            first_id = Some(flow.id);
        }
        count += 1;
        if count <= 60 && out.len() < MAX_TOOL_OUTPUT {
            let status = flow
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| flow.error.clone().unwrap_or_else(|| "pending".to_owned()));
            let _ = writeln!(
                out,
                "Flow #{}: {} {} -> {} (req {} B, resp {} B)",
                flow.id,
                flow.method,
                url,
                status,
                flow.req_body.len(),
                flow.resp_body.len()
            );
        }
    }
    if count == 0 {
        out = format!("No captured network flows matched '{filter}'.");
    }
    (
        out,
        ToolTrace {
            target: first_id.map(ToolTarget::Flow),
            ..trace
        },
    )
}

fn tool_inspect_network_flow(args: &JsonValue, ctx: &AgentContext) -> (String, ToolTrace) {
    let id = args.get("id").and_then(JsonValue::as_u64).unwrap_or(0);
    let trace = ToolTrace {
        name: "inspect_network_flow".to_owned(),
        summary: format!("Inspected Flow #{id}"),
        target: Some(ToolTarget::Flow(id)),
    };
    let Some(capture) = &ctx.capture else {
        return ("Network capture is not available.".to_owned(), trace);
    };
    let Some(flow) = capture.get(id) else {
        return (
            format!("Flow #{id} not found."),
            ToolTrace {
                target: None,
                ..trace
            },
        );
    };
    (format_flow_detail(&flow, MAX_TOOL_OUTPUT / 2), trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn searches_and_reads_package_items_and_network_flows() {
        let zip = crate::formats::zip::write_stored_zip(&[
            ("assets/config.json", br#"{"api_url":"https://api.secret.example/v1"}"#),
            ("assets/readme.txt", b"hello world"),
        ]);
        let package = Arc::new(Package::from_bytes(Path::new("test.apk"), zip.into()).unwrap());
        let capture = Arc::new(Capture::new());
        let req = crate::net::http::Request::read(&mut std::io::BufReader::new(
            &b"POST /v1/login HTTP/1.1\r\nHost: api.secret.example\r\nContent-Length: 13\r\n\r\n{\"user\":\"qa\"}"[..],
        ))
        .unwrap()
        .unwrap();
        let info = crate::net::capture::RequestInfo::from_request(
            crate::net::capture::Scheme::Https,
            "api.secret.example:443",
            &req,
            64,
        );
        let pending = capture.start(&info);
        let resp = crate::net::http::Response::read(
            &mut std::io::BufReader::new(
                &b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"token\":\"xyz\"}"[..],
            ),
            "POST",
        )
        .unwrap();
        capture.finish_response(&pending, &resp, 64);

        let ctx = AgentContext {
            package: Some(package),
            selected_node: Some(0),
            capture: Some(capture),
            selected_flow: Some(0),
            include_source: true,
            include_resources: true,
            include_network: true,
        };

        let sys = build_system_prompt(&ctx);
        assert!(sys.contains("test.apk"));
        assert!(sys.contains("https://api.secret.example/v1/login"));

        let (search_out, trace) = execute_tool(
            "search_package",
            &JsonValue::obj([("query", JsonValue::str("api.secret.example"))]),
            &ctx,
        );
        assert!(search_out.contains("config.json"));
        assert!(trace.target.is_some());

        let (read_out, read_trace) = execute_tool(
            "read_node",
            &JsonValue::obj([("target", JsonValue::str("config.json"))]),
            &ctx,
        );
        assert!(read_out.contains("api_url"));
        assert!(matches!(read_trace.target, Some(ToolTarget::Node(_))));

        let (flow_out, flow_trace) = execute_tool(
            "inspect_network_flow",
            &JsonValue::obj([("id", JsonValue::Number(0.0))]),
            &ctx,
        );
        assert!(flow_out.contains("{\"token\":\"xyz\"}"));
        assert_eq!(flow_trace.target, Some(ToolTarget::Flow(0)));
    }
}
