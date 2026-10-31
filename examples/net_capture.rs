//! Developer tool: runs a full Network capture session headlessly, for
//! validating the emulator + proxy orchestration end-to-end.
//!
//! Usage: cargo run --example net_capture -- <app.apk|app.xapk> <AVD> [seconds] [--codeshare <owner/slug>] [--script <path_or_slug>]

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use bogusmips::net::bypass::ScriptSource;
use bogusmips::net::controller::{NetworkController, StartConfig};
use bogusmips::package::{Package, PackageKind};

fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let mut frida_scripts = Vec::new();
    let mut positional = Vec::new();

    let mut i = 0;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        if let Some(val) = arg
            .strip_prefix("--codeshare=")
            .or_else(|| arg.strip_prefix("--script="))
        {
            let source = ScriptSource::parse(val).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2);
            });
            frida_scripts.push(source.spec());
        } else if matches!(arg.as_str(), "--codeshare" | "-c" | "--script" | "-l") {
            let Some(val) = raw_args.get(i + 1) else {
                eprintln!("missing value after {arg}");
                std::process::exit(2);
            };
            let source = ScriptSource::parse(val).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2);
            });
            frida_scripts.push(source.spec());
            i += 1;
        } else {
            positional.push(arg.clone());
        }
        i += 1;
    }

    let mut positional = positional.into_iter();
    let (Some(input), Some(avd)) = (positional.next(), positional.next()) else {
        eprintln!(
            "usage: net_capture <app.apk|xapk> <AVD> [seconds] [--codeshare <owner/slug>] [--script <path_or_slug>]"
        );
        std::process::exit(2);
    };
    let seconds: u64 = positional.next().and_then(|s| s.parse().ok()).unwrap_or(90);
    let path = PathBuf::from(&input);
    let pkg = Package::open(&path).expect("open package");

    // Extract the APK(s) to install.
    let tmp = std::env::temp_dir().join(format!("bogusmips-net-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut apks = Vec::new();
    let mut package_name = None;
    if pkg.kind == PackageKind::Apk {
        apks.push(path.clone());
    } else {
        for (i, archive) in pkg.archives.iter().enumerate().skip(1) {
            if let Some(file) = archive.source_file {
                let data = pkg.read_file(file).expect("read inner apk");
                let out = tmp.join(format!("part{i}.apk"));
                std::fs::write(&out, &data.bytes).unwrap();
                apks.push(out);
            }
        }
    }
    for archive in &pkg.archives {
        if let Some(m) = &archive.manifest {
            if let Some(p) = &m.package {
                package_name = Some(p.clone());
                break;
            }
        }
    }
    eprintln!("package: {package_name:?}, {} apk(s)", apks.len());

    let mut controller = NetworkController::new();
    std::fs::write(tmp.join("ca.pem"), controller.ca_pem()).unwrap();
    controller.start(StartConfig {
        avd,
        apks,
        package: package_name,
        frida_scripts,
    });

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut last_phase = String::new();
    let mut last_count = 0;
    while Instant::now() < deadline {
        let (phase, error, log) = controller.status_snapshot();
        if phase.label() != last_phase {
            last_phase = phase.label().to_owned();
            eprintln!("[{last_phase}] {}", log.last().cloned().unwrap_or_default());
        }
        if let Some(error) = error {
            eprintln!("FAILED: {error}");
            break;
        }
        let flows = controller.capture().snapshot();
        if flows.len() != last_count {
            for flow in &flows[last_count..] {
                let status = flow
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "…".into());
                eprintln!("  {} {} {}", status, flow.method, flow.url());
            }
            last_count = flows.len();
        }
        let _ = std::io::stderr().flush();
        std::thread::sleep(Duration::from_millis(500));
    }

    let flows = controller.capture().snapshot();
    let https = flows.iter().filter(|f| f.scheme == bogusmips::net::capture::Scheme::Https).count();
    eprintln!(
        "\ncaptured {} flows ({https} https). stopping…",
        flows.len()
    );
    controller.stop();
    let _ = std::fs::remove_dir_all(&tmp);
}
