//! Developer tool: beautifies a file and writes the result.
//!
//! Usage: cargo run --release --example beautify_file -- <in> <out> [json|xml|html|css|js]

use bogusmips::beautify::{Format, beautify, detect};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(input), Some(output)) = (args.first(), args.get(1)) else {
        eprintln!("usage: beautify_file <in> <out> [json|xml|html|css|js]");
        std::process::exit(2);
    };
    let text = std::fs::read_to_string(input).expect("readable UTF-8 file");
    let format = match args.get(2).map(String::as_str) {
        Some("json") => Format::Json,
        Some("xml") => Format::Xml,
        Some("html") => Format::Html,
        Some("css") => Format::Css,
        Some("js") => Format::JavaScript,
        _ => detect(input, &text).expect("unknown format"),
    };
    let start = std::time::Instant::now();
    let out = beautify(format, &text).expect("output size limit");
    eprintln!(
        "{input}: {} -> {} bytes, {} -> {} lines in {:?}",
        text.len(),
        out.len(),
        text.lines().count(),
        out.lines().count(),
        start.elapsed()
    );
    std::fs::write(output, out).expect("writable output");
}
