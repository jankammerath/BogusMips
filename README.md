# BogusMips

BogusMips is written in Rust and allows performing analyses on how far your Android app can be disassembled. It allows you to open the `*.apk` or `*.xapk` file of your app to see how far your app can be disassembled. 

## Features

- Open an `*.apk` or `*.xapk` with **File → Open…** (⌘O / Ctrl+O), by dropping it onto the window, or as a command-line argument.
- **Left: package tree**
  - **Source code**: every class from all `classes*.dex` files, grouped by Java package and disassembled to smali.
  - **Resources**: `resources.arsc` decoded into the `res/values*/*.xml` files it was compiled from (strings, colors, dimens, styles, attrs, arrays, plurals, …) plus `public.xml` with every resource ID.
  - **Files**: every entry in the archive.
  - XAPK bundles show each contained APK (base and split APKs) separately.
  - Filter box (⌘F) and keyboard navigation with the arrow keys.
- **Center: content of the selected item**
  - Classes are shown as smali (baksmali-compatible output).
  - Binary XML (`AndroidManifest.xml`, `res/**/*.xml`) is decoded. Resource references are resolved to names (`@string/app_name`, `@android:style/Theme`), and attribute values to their symbolic names (`protectionLevel="signature"`).
  - Images are previewed, text is shown as text, and everything else as a hex dump.
  - A hex view is available for any file.
- **Right: collapsible file information** (⌘I): size, compression, CRC, SHA-256, DEX header details, class details, manifest summary, permissions, and any anomalies found.

All parsers (ZIP, DEX, smali disassembler, binary XML, resource table) are implemented in this repository. They follow Android's behaviour rather than the specs, so tricks that break other tools still open. Examples: malformed extra fields, fake encryption flags, CRC mismatches, and bogus compression methods. Such tricks are reported as warnings.

Names of Android framework resources come from `media/android/framework-resources.txt`, generated from the Android SDK with `tools/gen_framework_resources.py` (AOSP, Apache License 2.0).

The UI uses the [Hack](https://github.com/source-foundry/Hack) font, which is embedded in the binary (`media/fonts`, see its [license](media/fonts/LICENSE.md)).

## Building & running

Requires Rust 1.85 or newer.

```sh
cargo run                         # debug build
cargo run --release -- app.apk    # optimized build, opening a file directly
```

## Testing

```sh
cargo test
BOGUSMIPS_TEST_APK=path/to/app.apk cargo test --release   # also render every node of a real package
```

Developer tools:

```sh
# Write the smali of every class (apktool layout), e.g. to diff against `apktool d -r`
cargo run --release --example dump_smali -- app.apk out-dir
# Write the res/values*/*.xml generated from resources.arsc, e.g. to diff against `apktool d`
cargo run --release --example dump_resources -- app.apk out-dir
# Open packages and inspect every node, reporting timings and decode errors
cargo run --release --example inspect_all -- app.apk other.xapk
```

## Project structure

```
src/
├── main.rs              # entry point, window setup
├── lib.rs
├── app.rs               # application state, menus, panels, background loading
├── inspect.rs           # turns a tree node into content + file information
├── package/
│   ├── mod.rs           # APK/XAPK loading, entry extraction, manifest summary
│   └── tree.rs          # navigation tree (source code by package, files by folder)
├── formats/
│   ├── reader.rs        # bounds-checked binary reader
│   ├── zip.rs           # lenient, Android-like ZIP reader
│   ├── axml.rs          # Android binary XML decoder
│   ├── arsc.rs          # resources.arsc parser, values XML generation
│   ├── resvalue.rs      # typed value formatting, resource name resolution
│   ├── detect.rs        # file type detection
│   └── dex/
│       ├── mod.rs       # DEX parser
│       ├── opcodes.rs   # Dalvik opcode table
│       ├── disasm.rs    # bytecode → smali instructions
│       ├── smali.rs     # class → smali file
│       ├── values.rs    # encoded values and annotations
│       ├── javafmt.rs   # Java-compatible number formatting (baksmali parity)
│       └── access.rs    # access flags
└── ui/
    ├── theme.rs         # dark theme (egui widgets + native window frame)
    ├── tree_view.rs     # left panel
    ├── content_view.rs  # center panel (text, hex, image)
    ├── info_panel.rs    # right panel
    └── highlight.rs     # smali / XML syntax highlighting
```
