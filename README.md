# BogusMips

BogusMips is written in Rust and allows performing analyses on how far your Android app can be disassembled. It allows you to open the `*.apk` or `*.aab` file of your app to see how far your app can be disassembled. 

## Building & running

Requires Rust 1.85 or newer.

```sh
cargo run            # debug build
cargo run --release  # optimized build
```

## Project structure

```
src/
├── main.rs        # entry point, window setup
├── app.rs         # application state and main UI loop
└── ui/
    ├── mod.rs
    └── theme.rs   # dark theme (egui widgets + native window frame)
```
