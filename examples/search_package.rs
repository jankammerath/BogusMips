//! Developer tool: searches the contents of a package like the Search view,
//! reporting index and search timings.
//!
//! Usage: cargo run --release --example search_package -- <app.apk> <query> [--regex] [--case] [--word]

use std::sync::atomic::AtomicBool;
use std::time::Instant;

use bogusmips::package::Package;
use bogusmips::search::{Progress, Query, build_corpus, search};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(path), Some(text)) = (args.first(), args.get(1)) else {
        eprintln!("usage: search_package <app.apk> <query> [--regex] [--case] [--word]");
        std::process::exit(2);
    };
    let flag = |f: &str| args.iter().any(|a| a == f);
    let query = Query {
        text: text.clone(),
        regex: flag("--regex"),
        match_case: flag("--case"),
        whole_word: flag("--word"),
    };
    let regex = query.compile().unwrap_or_else(|e| {
        eprintln!("invalid query: {e}");
        std::process::exit(2);
    });

    let pkg = Package::open(std::path::Path::new(path)).expect("readable package");
    let start = Instant::now();
    let corpus =
        build_corpus(&pkg, &AtomicBool::new(false), &Progress::default()).expect("not cancelled");
    let bytes: usize = corpus.docs.iter().map(|d| d.text_len()).sum();
    println!(
        "indexed {} documents ({} MiB) in {:?}",
        corpus.docs.len(),
        bytes >> 20,
        start.elapsed()
    );
    let start = Instant::now();
    let results = search(&corpus, &regex, &AtomicBool::new(false)).expect("not cancelled");
    println!(
        "{} results in {} files{} in {:?}",
        results.total_matches,
        results.files.len(),
        if results.truncated {
            " (truncated)"
        } else {
            ""
        },
        start.elapsed()
    );
    for file in results.files.iter().take(5) {
        for m in file.matches.iter().take(2) {
            println!(
                "  {}:{}  {}",
                pkg.node_path(file.node),
                m.line + 1,
                m.preview
            );
        }
    }
}
