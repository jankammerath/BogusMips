//! Developer tool: opens packages and inspects every tree node, reporting
//! timings and any content that could not be decoded.
//!
//! Usage: cargo run --release --example inspect_all -- <app.apk>...

use std::time::Instant;

use bogusmips::export;
use bogusmips::inspect::{Content, inspect};
use bogusmips::package::Package;

fn main() {
    for path in std::env::args_os().skip(1) {
        let path = std::path::PathBuf::from(path);
        let start = Instant::now();
        let pkg = match Package::open(&path) {
            Ok(p) => p,
            Err(e) => {
                println!("{}: ERROR {e}", path.display());
                continue;
            }
        };
        let opened = start.elapsed();
        let start = Instant::now();
        let mut messages = 0;
        let mut exports = 0;
        for node in 0..pkg.nodes.len() {
            for option in export::options(&pkg, node) {
                match export::export_bytes(&pkg, node, option.kind) {
                    Ok(_) => exports += 1,
                    Err(e) => println!("  export {} ({:?}): {e}", pkg.node_path(node), option.kind),
                }
            }
            let inspection = inspect(&pkg, node);
            if let Content::Message(m) = &inspection.content {
                if m.contains("could not") {
                    messages += 1;
                    println!("  {}: {m}", inspection.title);
                }
            }
            for section in &inspection.sections {
                for (k, v) in &section.rows {
                    if k.starts_with('⚠') {
                        println!("  {} [{k}] {v}", inspection.title);
                    }
                }
            }
        }
        println!(
            "{}: {} nodes, {} files, {} dex, opened in {:?}, inspected + exported all ({exports} exports) in {:?}, {messages} decode errors",
            path.display(),
            pkg.nodes.len(),
            pkg.files.len(),
            pkg.dex_files.len(),
            opened,
            start.elapsed()
        );
    }
}
