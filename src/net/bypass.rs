//! Optional Play Services availability and root-detection bypass.
//!
//! Rootable `google_apis` emulators carry an older Google Play Services build
//! than many apps are compiled against (so `GoogleApiAvailability` returns
//! `SERVICE_VERSION_UPDATE_REQUIRED`), and their `userdebug` build looks rooted
//! to apps (`ro.debuggable=1`, `test-keys`, RootBeer, …). Either makes an app
//! abort before producing any traffic. To keep such apps running during a
//! capture we inject [frida-gadget](https://frida.re/docs/gadget/) with a small
//! script that forces the Play Services availability checks to report
//! `SUCCESS` (0) and neutralises the common root checks. The gadget is loaded
//! into the target app via the `wrap.<package>` property (`LD_PRELOAD`), so no
//! frida tooling is needed on the host or a frida-server on the device.
//!
//! This only makes the checks pass — it does not provide the services or
//! un-root the device — which is all that is needed to keep these environment
//! checks from blocking network analysis. It cannot defeat server-side
//! attestation such as the Play Integrity API.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// frida release whose gadget is downloaded. Pinned to the last 16.x, because
/// 17.x removed the built-in `Java`/`ObjC` script globals this bypass relies
/// on (they became ES-module imports needing a bundler). Override with the
/// `BOGUSMIPS_FRIDA_VERSION` environment variable, e.g. to match a device's
/// Android version.
pub const FRIDA_VERSION: &str = "16.7.19";

/// The frida version to download — [`FRIDA_VERSION`] unless overridden by the
/// `BOGUSMIPS_FRIDA_VERSION` environment variable.
pub fn frida_version() -> String {
    std::env::var("BOGUSMIPS_FRIDA_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| FRIDA_VERSION.to_owned())
}

/// The frida script the gadget runs before the app's entry point. It forces
/// the common Play Services availability checks to return
/// `ConnectionResult.SUCCESS` (0) and makes the common root-detection checks
/// report an unrooted device.
pub fn bypass_script() -> &'static str {
    r#"Java.perform(function () {
  function hookReturn(className, method, value) {
    try {
      var cls = Java.use(className);
      if (!cls[method]) return;
      cls[method].overloads.forEach(function (ov) {
        ov.implementation = function () { return value; };
      });
    } catch (e) {
      // Class or method not present in this app; ignore.
    }
  }

  // --- Google Play Services availability -> ConnectionResult.SUCCESS (0) ---
  ['com.google.android.gms.common.GoogleApiAvailability',
   'com.google.android.gms.common.GoogleApiAvailabilityLight',
   'com.google.android.gms.common.GooglePlayServicesUtil',
   'com.google.android.gms.common.GooglePlayServicesUtilLight'].forEach(function (c) {
    hookReturn(c, 'isGooglePlayServicesAvailable', 0);
  });

  // --- RootBeer: every detection method reports "not rooted" ---
  ['isRooted', 'isRootedWithBusyBoxCheck', 'isRootedWithoutBusyBoxCheck',
   'detectRootManagementApps', 'detectPotentiallyDangerousApps', 'detectRootCloakingApps',
   'detectTestKeys', 'checkForBusyBoxBinary', 'checkForSuBinary', 'checkSuExists',
   'checkForRWPaths', 'checkForDangerousProps', 'checkForRootNative',
   'checkForMagiskBinary', 'checkForBinary'].forEach(function (m) {
    hookReturn('com.scottyab.rootbeer.RootBeer', m, false);
  });

  // --- Build fingerprint: hide the userdebug test-keys tag ---
  try {
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
  } catch (e) {}

  // --- Dangerous system properties report safe values ---
  try {
    var SystemProperties = Java.use('android.os.SystemProperties');
    var safe = { 'ro.debuggable': '0', 'ro.secure': '1', 'service.adb.root': '0',
                 'ro.build.tags': 'release-keys', 'ro.build.type': 'user',
                 'ro.build.selinux': '1' };
    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
      var k = '' + key;
      if (Object.prototype.hasOwnProperty.call(safe, k)) return safe[k];
      return this.get(key);
    };
    SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
      var k = '' + key;
      if (Object.prototype.hasOwnProperty.call(safe, k)) return safe[k];
      return this.get(key, def);
    };
  } catch (e) {}

  // --- Hide root artifacts from File.exists() ---
  try {
    var File = Java.use('java.io.File');
    var markers = ['su', 'magisk', 'superuser', 'supersu', 'busybox', 'xposed',
                   'frida', '/sbin/.magisk', '/cache/.disable_magisk', 'Superuser.apk'];
    File.exists.implementation = function () {
      try {
        var path = ('' + this.getAbsolutePath()).toLowerCase();
        for (var i = 0; i < markers.length; i++) {
          if (path.indexOf(markers[i]) !== -1) return false;
        }
      } catch (e) {}
      return this.exists();
    };
  } catch (e) {}

  // --- Make `su` / `which su` / magisk shell-outs fail ---
  function isRootCmd(s) {
    if (s === null || s === undefined) return false;
    s = '' + s;
    return s === 'su' || /(^|\/)su(\s|$)/.test(s) || s.indexOf('which su') !== -1 ||
           s.indexOf('busybox') !== -1 || s.indexOf('magisk') !== -1 || s.indexOf('Superuser') !== -1;
  }
  try {
    var Runtime = Java.use('java.lang.Runtime');
    var IOException = Java.use('java.io.IOException');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      if (isRootCmd(cmd)) throw IOException.$new('No such file or directory');
      return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
      var joined = '';
      try { joined = cmds ? cmds.join(' ') : ''; } catch (e) {}
      if (isRootCmd(joined)) throw IOException.$new('No such file or directory');
      return this.exec(cmds);
    };
  } catch (e) {}
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
    let version = frida_version();
    let dest = cache_dir.join(format!("frida-gadget-{version}-android-{abi}.so"));
    if dest.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Ok(dest);
    }
    std::fs::create_dir_all(cache_dir).map_err(|e| e.to_string())?;

    let url = gadget_url(&version, abi);
    let compressed = cache_dir.join(format!("frida-gadget-{version}-android-{abi}.so.xz"));
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
    fn script_forces_success_and_hides_root() {
        let s = bypass_script();
        assert!(s.contains("com.google.android.gms.common.GoogleApiAvailability"));
        assert!(s.contains("isGooglePlayServicesAvailable"));
        assert!(s.contains("Java.perform"));
        // Root-detection bypass.
        assert!(s.contains("com.scottyab.rootbeer.RootBeer"));
        assert!(s.contains("release-keys"));
        assert!(s.contains("ro.debuggable"));
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
