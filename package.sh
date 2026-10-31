#!/usr/bin/env bash
# Builds release install packages for BogusMips stamped with the current git commit hash:
#   - BogusMips-Windows-x64-<githash>.zip
#   - BogusMips-Windows-Arm64-<githash>.zip
#   - BogusMips-macOS-<githash>.dmg

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

export PATH="$HOME/.cargo/bin:/opt/homebrew/opt/rustup/bin:/opt/homebrew/opt/llvm/bin:/opt/homebrew/opt/lld/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

APP_NAME="BogusMips"
BUNDLE_ID="com.bogusmips.app"
GITHASH="${GITHASH:-$(git rev-parse --short HEAD)}"
BASE_VERSION="$(awk -F'"' '/^version *= *"/ { print $2; exit }' Cargo.toml)"
FULL_VERSION="${BASE_VERSION}+${GITHASH}"

BUILD_MACOS=1
BUILD_WINDOWS=1
for arg in "$@"; do
    case "$arg" in
        --macos-only)
            BUILD_WINDOWS=0
            ;;
        --windows-only)
            BUILD_MACOS=0
            ;;
        -h|--help)
            echo "Usage: $0 [--macos-only | --windows-only]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

echo "==> Packaging ${APP_NAME} version ${FULL_VERSION} (commit ${GITHASH})"

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bogusmips-pkg.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

ensure_rustup() {
    if ! command -v rustup >/dev/null 2>&1; then
        if command -v rustup-init >/dev/null 2>&1; then
            echo "==> Initializing rustup toolchain..."
            rustup-init -y --no-modify-path --default-toolchain stable
        elif command -v brew >/dev/null 2>&1; then
            echo "==> Installing rustup via Homebrew..."
            brew install rustup
            /opt/homebrew/opt/rustup/bin/rustup-init -y --no-modify-path --default-toolchain stable
        else
            echo "Error: rustup is required to install cross-compilation targets." >&2
            exit 1
        fi
    fi

    if ! rustup show active-toolchain >/dev/null 2>&1; then
        rustup default stable
    fi
}

ensure_windows_cross_tools() {
    ensure_rustup
    rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc

    if [[ "$(uname -s)" != MINGW* && "$(uname -s)" != MSYS* && "$(uname -s)" != CYGWIN* ]]; then
        if ! command -v clang-cl >/dev/null 2>&1 || ! command -v llvm-lib >/dev/null 2>&1; then
            if command -v brew >/dev/null 2>&1; then
                echo "==> Installing llvm via Homebrew..."
                brew install llvm
            else
                echo "Error: clang-cl and llvm-lib (from LLVM) are required for Windows cross-compilation." >&2
                exit 1
            fi
        fi

        if ! command -v lld-link >/dev/null 2>&1; then
            if command -v brew >/dev/null 2>&1; then
                echo "==> Installing lld via Homebrew..."
                brew install lld
            else
                echo "Error: lld-link (from LLD) is required for Windows cross-compilation." >&2
                exit 1
            fi
        fi

        if ! cargo xwin --version >/dev/null 2>&1; then
            echo "==> Installing cargo-xwin..."
            cargo install --locked cargo-xwin
        fi
    fi
}

build_windows_target() {
    local target="$1"
    local arch_label="$2"
    local zip_name="${APP_NAME}-Windows-${arch_label}-${GITHASH}.zip"

    echo "==> Building ${APP_NAME} for Windows ${arch_label} (${target})..."
    if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* || "$(uname -s)" == CYGWIN* ]]; then
        cargo build --release --target "$target"
    else
        cargo xwin build --release --target "$target"
    fi

    local bin_path="target/${target}/release/bogusmips.exe"
    if [[ ! -f "$bin_path" ]]; then
        echo "Error: expected Windows binary not found at $bin_path" >&2
        exit 1
    fi

    local win_stage="${STAGE_DIR}/win-${arch_label}"
    mkdir -p "$win_stage"
    cp "$bin_path" "${win_stage}/${APP_NAME}.exe"
    cp README.md "${win_stage}/README.md"

    rm -f "${ROOT_DIR}/${zip_name}"
    (
        cd "$win_stage"
        zip -q -9 -r "${ROOT_DIR}/${zip_name}" "${APP_NAME}.exe" README.md
    )
    echo "    Created ${zip_name}"
}

generate_macos_icns() {
    local out_icns="$1"
    local iconset_dir="${STAGE_DIR}/AppIcon.iconset"
    local master_png="${STAGE_DIR}/AppIcon-1024.png"
    mkdir -p "$iconset_dir"

    echo "==> Generating macOS AppIcon.icns..."
    if cargo run --release --example render_icon -- "$master_png" >/dev/null 2>&1 && [[ -f "$master_png" ]]; then
        :
    else
        cp "media/AppIcon/BogusMipsAppIcon.png" "$master_png"
    fi

    for size in 16 32 128 256 512; do
        local size2x=$((size * 2))
        sips -s format png -z "$size" "$size" "$master_png" --out "${iconset_dir}/icon_${size}x${size}.png" >/dev/null
        sips -s format png -z "$size2x" "$size2x" "$master_png" --out "${iconset_dir}/icon_${size}x${size}@2x.png" >/dev/null
    done

    iconutil -c icns "$iconset_dir" -o "$out_icns"
}

build_macos_dmg() {
    if [[ "$(uname -s)" != "Darwin" ]]; then
        echo "Error: building the macOS DMG requires macOS (hdiutil / iconutil)." >&2
        exit 1
    fi

    local dmg_name="${APP_NAME}-macOS-${GITHASH}.dmg"
    local app_dir="${STAGE_DIR}/dmg/${APP_NAME}.app"
    local contents_dir="${app_dir}/Contents"
    local macos_dir="${contents_dir}/MacOS"
    local resources_dir="${contents_dir}/Resources"

    mkdir -p "$macos_dir" "$resources_dir"

    if command -v rustup >/dev/null 2>&1 && rustup show active-toolchain >/dev/null 2>&1; then
        echo "==> Building ${APP_NAME} for macOS Universal (arm64 + x86_64)..."
        rustup target add aarch64-apple-darwin x86_64-apple-darwin
        cargo build --release --target aarch64-apple-darwin
        cargo build --release --target x86_64-apple-darwin
        lipo -create \
            "target/aarch64-apple-darwin/release/bogusmips" \
            "target/x86_64-apple-darwin/release/bogusmips" \
            -output "${macos_dir}/bogusmips"
    else
        echo "==> Building ${APP_NAME} for macOS ($(uname -m))..."
        cargo build --release
        cp "target/release/bogusmips" "${macos_dir}/bogusmips"
    fi
    chmod +x "${macos_dir}/bogusmips"

    generate_macos_icns "${resources_dir}/AppIcon.icns"

    cat > "${contents_dir}/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleExecutable</key>
    <string>bogusmips</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${BASE_VERSION} (${GITHASH})</string>
    <key>CFBundleVersion</key>
    <string>${GITHASH}</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>CFBundleDocumentTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeExtensions</key>
            <array>
                <string>apk</string>
                <string>xapk</string>
            </array>
            <key>CFBundleTypeName</key>
            <string>Android Package</string>
            <key>CFBundleTypeRole</key>
            <string>Viewer</string>
            <key>LSHandlerRank</key>
            <string>Alternate</string>
        </dict>
    </array>
</dict>
</plist>
EOF

    if command -v codesign >/dev/null 2>&1; then
        codesign --force --deep --sign - "$app_dir"
    fi

    ln -s /Applications "${STAGE_DIR}/dmg/Applications"

    rm -f "${ROOT_DIR}/${dmg_name}"
    echo "==> Creating ${dmg_name}..."
    hdiutil create \
        -volname "${APP_NAME}" \
        -srcfolder "${STAGE_DIR}/dmg" \
        -ov \
        -format UDZO \
        "${ROOT_DIR}/${dmg_name}" >/dev/null

    echo "    Created ${dmg_name}"
}

if [[ "$BUILD_WINDOWS" -eq 1 ]]; then
    ensure_windows_cross_tools
    build_windows_target "x86_64-pc-windows-msvc" "x64"
    build_windows_target "aarch64-pc-windows-msvc" "Arm64"
fi

if [[ "$BUILD_MACOS" -eq 1 ]]; then
    build_macos_dmg
fi

echo "==> Done! Generated packages for commit ${GITHASH}:"
[[ "$BUILD_WINDOWS" -eq 1 ]] && ls -lh "${ROOT_DIR}/${APP_NAME}-Windows-x64-${GITHASH}.zip" "${ROOT_DIR}/${APP_NAME}-Windows-Arm64-${GITHASH}.zip"
[[ "$BUILD_MACOS" -eq 1 ]] && ls -lh "${ROOT_DIR}/${APP_NAME}-macOS-${GITHASH}.dmg"

