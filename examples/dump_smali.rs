//! Developer tool: writes the smali of every class in an APK/XAPK to a
//! directory (one file per class, apktool layout) for comparison with baksmali.
//!
//! Usage: cargo run --release --example dump_smali -- <app.apk> <out-dir>

use std::path::PathBuf;

use bogusmips::formats::dex::smali::class_to_smali;
use bogusmips::package::Package;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let (Some(input), Some(out)) = (args.next(), args.next()) else {
        eprintln!("usage: dump_smali <app.apk> <out-dir>");
        std::process::exit(2);
    };
    let pkg = Package::open(&PathBuf::from(input)).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let out = PathBuf::from(out);
    let mut count = 0;
    for (i, entry) in pkg.dex_files.iter().enumerate() {
        let dir = if i == 0 {
            "smali".to_owned()
        } else {
            format!("smali_classes{}", i + 1)
        };
        for class in &entry.dex.class_defs {
            let desc = entry.dex.class_descriptor(class);
            let rel = desc.trim_start_matches('L').trim_end_matches(';');
            let path = out.join(&dir).join(format!("{rel}.smali"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, class_to_smali(&entry.dex, class)).unwrap();
            count += 1;
        }
        for w in &entry.dex.warnings {
            eprintln!("{}: {w}", entry.name);
        }
    }
    for a in &pkg.archives {
        for w in &a.warnings {
            eprintln!("{}: {w}", a.name);
        }
    }
    eprintln!("wrote {count} classes");
}
