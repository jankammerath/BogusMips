//! Optional Google Play Services availability bypass.
//!
//! Rootable `google_apis` emulators carry an older Google Play Services build
//! than many apps are compiled against, so a `GoogleApiAvailability`
//! availability check returns `SERVICE_VERSION_UPDATE_REQUIRED` and the app
//! aborts before any traffic is produced. To keep such apps running during a
//! capture we inject [frida-gadget](https://frida.re/docs/gadget/) with a tiny
//! script that forces those checks to report `SUCCESS` (0). The gadget is
//! loaded into the target app via the `wrap.<package>` property (`LD_PRELOAD`),
//! so no frida tooling is needed on the host or a frida-server on the device.
//!
//! This only makes the *presence* check pass — it does not provide the
//! services themselves, which is all that is needed to keep root/environment
//! checks from blocking network analysis.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// frida release whose gadget is downloaded. Kept current but pinned so the
/// download URL is deterministic.
pub const FRIDA_VERSION: &str = "17.24.3";

/// The frida script the gadget runs before the app's entry point. It forces
/// the common Play Services availability checks to return
/// `ConnectionResult.SUCCESS` (0).
pub fn bypass_script() -> &'static str {
    r#"Java.perform(function () {
  function force0(className, method) {
    try {
      var cls = Java.use(className);
      cls[method].overloads.forEach(function (ov) {
        ov.implementation = function () {
          return 0; // ConnectionResult.SUCCESS
        };
      });
    } catch (e) {
      // Class or method not present in this app; ignore.
    }
  }
  force0('com.google.android.gms.common.GoogleApiAvailability', 'isGooglePlayServicesAvailable');
  force0('com.google.android.gms.common.GoogleApiAvailabilityLight', 'isGooglePlayServicesAvailable');
  force0('com.google.android.gms.common.GooglePlayServicesUtil', 'isGooglePlayServicesAvailable');
  force0('com.google.android.gms.common.GooglePlayServicesUtilLight', 'isGooglePlayServicesAvailable');
});
"#
}

/// The gadget configuration (Script interaction) that auto-loads `script_path`.
pub fn gadget_config(script_path: &str) -> String {
    format!(
        "{{\n  \"interaction\": {{\n    \"type\": \"script\",\n    \"path\": \"{script_path}\"\n  }}\n}}\n"
    )
}

/// Maps an Android ABI (`ro.product.cpu.abi`) to frida's release asset token.
pub fn frida_abi(device_abi: &str) -> Option<&'static str> {
    match device_abi.trim() {
        "arm64-v8a" => Some("arm64"),
        "armeabi-v7a" | "armeabi" => Some("arm"),
        "x86_64" => Some("x86_64"),
        "x86" => Some("x86"),
        _ => None,
    }
}

/// GitHub release URL of the gadget `.so.xz` for `abi`.
pub fn gadget_url(version: &str, abi: &str) -> String {
    format!(
        "https://github.com/frida/frida/releases/download/{version}/frida-gadget-{version}-android-{abi}.so.xz"
    )
}

/// Directory where downloaded gadgets are cached between sessions.
pub fn cache_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(dir).join("bogusmips");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".cache/bogusmips");
    }
    std::env::temp_dir().join("bogusmips")
}

/// Ensures the decompressed frida gadget for `abi` exists in `cache_dir`,
/// downloading and decompressing it on first use. Returns its path.
pub fn ensure_gadget(cache_dir: &Path, abi: &str) -> Result<PathBuf, String> {
    let dest = cache_dir.join(format!("frida-gadget-{FRIDA_VERSION}-android-{abi}.so"));
    if dest.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Ok(dest);
    }
    std::fs::create_dir_all(cache_dir).map_err(|e| e.to_string())?;

    let url = gadget_url(FRIDA_VERSION, abi);
    let compressed = cache_dir.join(format!("frida-gadget-{FRIDA_VERSION}-android-{abi}.so.xz"));
    download(&url, &compressed)?;

    let bytes = std::fs::read(&compressed).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    lzma_rs::xz_decompress(&mut std::io::Cursor::new(bytes), &mut out)
        .map_err(|e| format!("could not decompress the frida gadget: {e}"))?;
    let _ = std::fs::remove_file(&compressed);
    // Sanity check: the gadget is an ELF shared library.
    if out.get(..4) != Some(ELF_MAGIC) {
        return Err("the downloaded frida gadget is not a valid library".into());
    }
    std::fs::write(&dest, &out).map_err(|e| e.to_string())?;
    Ok(dest)
}

const ELF_MAGIC: &[u8] = b"\x7fELF";

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let output = Command::new("curl")
        .arg("-fL")
        .args(["--retry", "2", "-o"])
        .arg(dest)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("could not run curl to download the frida gadget: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "could not download the frida gadget from {url}: {}",
            err.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_forces_success() {
        let s = bypass_script();
        assert!(s.contains("com.google.android.gms.common.GoogleApiAvailability"));
        assert!(s.contains("isGooglePlayServicesAvailable"));
        assert!(s.contains("return 0"));
        assert!(s.contains("Java.perform"));
    }

    #[test]
    fn config_points_at_script() {
        let cfg = gadget_config("/data/local/tmp/x.js");
        assert!(cfg.contains("\"type\": \"script\""));
        assert!(cfg.contains("\"path\": \"/data/local/tmp/x.js\""));
    }

    #[test]
    fn maps_known_abis() {
        assert_eq!(frida_abi("arm64-v8a"), Some("arm64"));
        assert_eq!(frida_abi("armeabi-v7a"), Some("arm"));
        assert_eq!(frida_abi("x86_64"), Some("x86_64"));
        assert_eq!(frida_abi("x86"), Some("x86"));
        assert_eq!(frida_abi("mips"), None);
    }

    #[test]
    fn builds_gadget_url() {
        let url = gadget_url(FRIDA_VERSION, "arm64");
        assert!(url.starts_with("https://github.com/frida/frida/releases/download/"));
        assert!(url.ends_with(&format!("frida-gadget-{FRIDA_VERSION}-android-arm64.so.xz")));
    }
}
