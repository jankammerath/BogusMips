//! Developer tool: writes the `res/values*/*.xml` files generated from every
//! `resources.arsc` in an APK/XAPK, for comparison with `apktool d`.
//!
//! Usage: cargo run --release --example dump_resources -- <app.apk> <out-dir>

use std::path::PathBuf;

use bogusmips::formats::resvalue::Resolver;
use bogusmips::package::Package;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let (Some(input), Some(out)) = (args.next(), args.next()) else {
        eprintln!("usage: dump_resources <app.apk> <out-dir>");
        std::process::exit(2);
    };
    let pkg = Package::open(&PathBuf::from(input)).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let tables = pkg.resource_tables();
    let resolver = Resolver::new(&tables);
    let out = PathBuf::from(out);
    let mut count = 0;
    for archive in &pkg.archives {
        let Some(table) = &archive.resources else {
            continue;
        };
        for w in &table.warnings {
            eprintln!("{}: {w}", archive.name);
        }
        for file in &archive.values_files {
            let path = out.join("res").join(&file.dir).join(&file.file);
            std::fs::create_dir_all(path.parent().expect("has parent")).expect("create dir");
            std::fs::write(&path, table.render(file.source, &resolver)).expect("write file");
            count += 1;
        }
    }
    eprintln!("wrote {count} files");
}
