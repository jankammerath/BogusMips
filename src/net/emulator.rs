//! Android emulator control via the SDK's `emulator` and `adb` tools:
//! discovering AVDs, starting one through the proxy, installing the proxy CA
//! as a system trust anchor, installing/launching the app, and routing its
//! traffic through the proxy.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::bypass;

/// Host address the emulator uses to reach the machine it runs on.
pub const HOST_ALIAS: &str = "10.0.2.2";

#[derive(Debug, Clone)]
pub struct Avd {
    pub name: String,
    /// `userdebug` images allow `adb root` and installing a system CA.
    pub rootable: bool,
    pub image: String,
    pub api: Option<u32>,
}

/// A located Android SDK.
#[derive(Debug, Clone)]
pub struct Sdk {
    pub root: PathBuf,
}

impl Sdk {
    pub fn detect() -> Option<Sdk> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        for var in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
            if let Some(v) = std::env::var_os(var) {
                candidates.push(PathBuf::from(v));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            candidates.push(home.join("Library/Android/sdk"));
            candidates.push(home.join("Android/Sdk"));
            candidates.push(home.join("AppData/Local/Android/Sdk"));
        }
        candidates
            .into_iter()
            .find(|p| tool(p, "adb").exists())
            .map(|root| Sdk { root })
    }

    pub fn adb(&self) -> PathBuf {
        tool(&self.root, "adb")
    }

    pub fn emulator(&self) -> PathBuf {
        self.root.join("emulator").join(exe("emulator"))
    }

    /// Lists AVDs, marking those that can be rooted (needed for HTTPS).
    pub fn list_avds(&self) -> Vec<Avd> {
        let output = Command::new(self.emulator())
            .arg("-list-avds")
            .output()
            .ok();
        let names = output
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        names
            .lines()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(|name| self.describe_avd(name))
            .collect()
    }

    fn describe_avd(&self, name: &str) -> Avd {
        let config = avd_config_path(name).and_then(|p| std::fs::read_to_string(p).ok());
        let image = config
            .as_deref()
            .and_then(|c| ini_value(c, "image.sysdir.1"))
            .unwrap_or_default();
        let tag = config
            .as_deref()
            .and_then(|c| ini_value(c, "tag.id"))
            .unwrap_or_default();
        let build_type = std::fs::read_to_string(self.root.join(&image).join("build.prop"))
            .ok()
            .and_then(|p| ini_value(&p, "ro.build.type"));
        // Play Store images are `user` builds and cannot be rooted.
        let rootable = match build_type.as_deref() {
            Some(t) => t == "userdebug" || t == "eng",
            None => !tag.contains("playstore"),
        };
        let api = image
            .split('/')
            .find_map(|s| s.strip_prefix("android-"))
            .and_then(|s| s.split('.').next())
            .and_then(|s| s.parse().ok());
        Avd {
            name: name.to_owned(),
            rootable,
            image,
            api,
        }
    }
}

fn tool(root: &Path, name: &str) -> PathBuf {
    root.join("platform-tools").join(exe(name))
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

fn avd_config_path(name: &str) -> Option<PathBuf> {
    let home = std::env::var_os("ANDROID_AVD_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".android/avd")))?;
    Some(home.join(format!("{name}.avd")).join("config.ini"))
}

fn ini_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim().to_owned())
    })
}

/// Command-line arguments to launch `avd` routed through the proxy.
pub fn emulator_args(avd: &str, proxy_port: u16) -> Vec<String> {
    // The proxy is applied via the guest's global HTTP proxy setting (see
    // `set_global_proxy`), which — unlike the emulator's `-http-proxy` flag —
    // also routes HTTPS (as CONNECT). `proxy_port` is unused here.
    let _ = proxy_port;
    vec![
        "-avd".into(),
        avd.into(),
        // Needed so the system partition can be remounted for the CA.
        "-writable-system".into(),
        "-no-snapshot".into(),
        "-no-boot-anim".into(),
    ]
}

/// A shell script (run as root on the device) that installs `filename`
/// (a PEM certificate already pushed to `/data/local/tmp`) as a system trust
/// anchor. On API 34+ the Conscrypt trust store lives in an APEX and each
/// process has its own mount namespace, so a plain mount is not enough: an
/// overlay directory (existing certs plus ours) is bind-mounted over the
/// system and Conscrypt trust stores in **every** process's mount namespace
/// via `nsenter`. Covering every namespace (not just `zygote`) is required
/// because apps can be forked from the pre-warmed USAP process pool, and
/// already-running apps/system services otherwise keep the old store.
pub fn ca_install_script(filename: &str) -> String {
    format!(
        r#"SRC=/data/local/tmp/{filename}
OVERLAY=/data/local/tmp/bogusmips-cacerts
SYS=/system/etc/security/cacerts
APEX=/apex/com.android.conscrypt/cacerts

# Build (or refresh) the overlay directory: existing certs plus ours.
# Use `cp` (not a `>` redirect, which is mangled by the adb/su shell layers).
mkdir -p -m 755 "$OVERLAY"
if [ -d "$APEX" ]; then cp "$APEX"/* "$OVERLAY"/ 2>/dev/null; fi
cp "$SYS"/* "$OVERLAY"/ 2>/dev/null
cp "$SRC" "$OVERLAY"/{filename}
chown root:root "$OVERLAY"/* 2>/dev/null
chmod 644 "$OVERLAY"/*
# Relabel the directory itself as well as the files: apps run in restricted
# SELinux domains and are denied `search` on a `shell_data_file` directory,
# so without this the mounted store is unreadable ("Trust anchor not found").
chcon u:object_r:system_security_cacerts_file:s0 "$OVERLAY" "$OVERLAY"/* 2>/dev/null

mount_dirs() {{
  PID="$1"
  for DIR in "$SYS" "$APEX"; do
    if [ -d "$DIR" ]; then
      if [ -z "$PID" ]; then
        mount --bind "$OVERLAY" "$DIR" 2>/dev/null
      else
        nsenter -t "$PID" -m -- mount --bind "$OVERLAY" "$DIR" 2>/dev/null
      fi
    fi
  done
}}

# Mount in the init/global namespace first.
mount_dirs ""

# Then propagate into every distinct process mount namespace. This covers
# zygote/zygote64 (new apps inherit it), the pre-forked USAP pool, and every
# already-running app and system service (which pick it up on their next TLS
# handshake). Deduplicate by namespace id so each namespace is mounted once.
SEEN=" "
for P in /proc/[0-9]*; do
  NS=$(readlink "$P/ns/mnt" 2>/dev/null)
  [ -z "$NS" ] && continue
  case "$SEEN" in *" $NS "*) continue;; esac
  SEEN="$SEEN$NS "
  mount_dirs "${{P#/proc/}}"
done
# Only report success if the overlay cert is actually present and non-empty.
[ -s "$OVERLAY"/{filename} ] && echo INSTALLED"#
    )
}

/// Errors / progress are reported as strings.
pub type Step = Result<String, String>;

pub struct Emulator {
    sdk: Sdk,
    child: Option<Child>,
    pub serial: String,
}

impl Emulator {
    /// Starts `avd` through the proxy. Does not wait for boot.
    pub fn start(sdk: &Sdk, avd: &str, proxy_port: u16) -> Result<Emulator, String> {
        let child = Command::new(sdk.emulator())
            .args(emulator_args(avd, proxy_port))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Could not start the emulator: {e}"))?;
        Ok(Emulator {
            sdk: sdk.clone(),
            child: Some(child),
            serial: String::new(),
        })
    }

    fn adb(&self, args: &[&str]) -> Step {
        let mut full: Vec<&str> = Vec::new();
        if !self.serial.is_empty() {
            full.push("-s");
            full.push(&self.serial);
        }
        full.extend_from_slice(args);
        run(&self.sdk.adb(), &full)
    }

    /// Waits until a device appears and finishes booting.
    pub fn wait_for_boot(&mut self, timeout: Duration, cancel: &dyn Fn() -> bool) -> Step {
        let deadline = Instant::now() + timeout;
        // Find the serial of our just-started emulator.
        while self.serial.is_empty() {
            if cancel() {
                return Err("cancelled".into());
            }
            if Instant::now() > deadline {
                return Err("timed out waiting for the emulator to appear".into());
            }
            if let Ok(list) = run(&self.sdk.adb(), &["devices"]) {
                if let Some(serial) = list
                    .lines()
                    .filter_map(|l| l.strip_suffix("\tdevice"))
                    .find(|s| s.starts_with("emulator-"))
                {
                    self.serial = serial.to_owned();
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        while Instant::now() < deadline {
            if cancel() {
                return Err("cancelled".into());
            }
            if let Ok(out) = self.adb(&["shell", "getprop", "sys.boot_completed"]) {
                if out.trim() == "1" {
                    return Ok(format!("{} booted", self.serial));
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err("timed out waiting for the emulator to boot".into())
    }

    /// Switches adbd to root and remounts the system partition.
    pub fn enable_root(&self) -> Step {
        let out = self.adb(&["root"])?;
        if out.to_lowercase().contains("cannot run as root") {
            return Err("this emulator image cannot be rooted (use a non-Play-Store image)".into());
        }
        // adbd restarts; wait for it to come back.
        std::thread::sleep(Duration::from_secs(2));
        let _ = self.adb(&["wait-for-device"]);
        let _ = self.adb(&["remount"]);
        Ok("root enabled".into())
    }

    /// Pushes the CA (PEM) and installs it as a system trust anchor.
    pub fn install_ca(&self, ca_pem: &[u8], filename: &str) -> Step {
        let remote = format!("/data/local/tmp/{filename}");
        self.push_bytes(ca_pem, &remote)?;
        // Push the install script as a file and execute it, rather than passing
        // the multi-line body through `sh -c "..."` where the adb/su shell
        // layers re-split and mangle it (breaking redirects and later commands).
        let script = ca_install_script(filename);
        let remote_script = "/data/local/tmp/bogusmips_ca_install.sh";
        self.push_bytes(script.as_bytes(), remote_script)?;
        let out = self
            .adb(&["shell", "su", "root", "sh", remote_script])
            .or_else(|_| self.adb(&["shell", "sh", remote_script]))?;
        if out.contains("INSTALLED") {
            Ok("CA installed".into())
        } else {
            Err(format!("CA install did not complete: {out}"))
        }
    }

    fn push_bytes(&self, data: &[u8], remote: &str) -> Step {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("bogusmips-{}.tmp", std::process::id()));
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        let result = self.adb(&["push", &tmp.to_string_lossy(), remote]);
        let _ = std::fs::remove_file(&tmp);
        result.map(|_| "pushed".into())
    }

    /// Installs an APK, or multiple split APKs (XAPK), by local path.
    pub fn install_app(&self, apks: &[PathBuf]) -> Step {
        let mut args: Vec<String> = Vec::new();
        if apks.len() > 1 {
            args.push("install-multiple".into());
        } else {
            args.push("install".into());
        }
        args.extend(["-r".into(), "-t".into(), "-g".into()]);
        for apk in apks {
            args.push(apk.to_string_lossy().into_owned());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self.adb(&refs)?;
        if out.to_lowercase().contains("success") {
            Ok("app installed".into())
        } else {
            Err(format!("app install failed: {out}"))
        }
    }

    /// Routes all guest traffic through the proxy (reached via the host alias).
    pub fn set_global_proxy(&self, proxy_port: u16) -> Step {
        let proxy = format!("{HOST_ALIAS}:{proxy_port}");
        self.adb(&["shell", "settings", "put", "global", "http_proxy", &proxy])
            .map(|_| format!("proxy set to {proxy}"))
    }

    /// Launches the app's main activity.
    pub fn launch(&self, package: &str) -> Step {
        let out = self.adb(&[
            "shell",
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ])?;
        if out.to_lowercase().contains("no activities found") {
            return Err(format!("could not launch {package}"));
        }
        Ok(format!("launched {package}"))
    }

    pub fn clear_proxy(&self) {
        let _ = self.adb(&["shell", "settings", "put", "global", "http_proxy", ":0"]);
    }

    /// The device's primary ABI (e.g. `arm64-v8a`), used to pick the gadget.
    pub fn device_abi(&self) -> Result<String, String> {
        self.adb(&["shell", "getprop", "ro.product.cpu.abi"])
            .map(|s| s.trim().to_owned())
    }

    /// Arms the Play Services availability and root-detection bypass for
    /// `package`: pushes the frida gadget, its config and the bypass script,
    /// and sets the `wrap.<package>` property so the gadget is `LD_PRELOAD`ed
    /// when the app next starts (which must be *after* this call).
    pub fn install_bypass(&self, gadget_local: &Path, package: &str) -> Step {
        self.install_frida_script(gadget_local, package, bypass::bypass_script())
    }

    /// Pushes `gadget_local`, its config, and the assembled `script_js` (the
    /// built-in bypass and/or user-selected Frida scripts), then sets
    /// `wrap.<package>` so `frida-gadget` is `LD_PRELOAD`ed on app launch.
    pub fn install_frida_script(
        &self,
        gadget_local: &Path,
        package: &str,
        script_js: &str,
    ) -> Step {
        const GADGET: &str = "/data/local/tmp/bogusmips-gadget.so";
        const SCRIPT: &str = "/data/local/tmp/bogusmips-bypass.js";
        // frida accepts either form; push both so it is found regardless.
        const CONFIG: &str = "/data/local/tmp/bogusmips-gadget.config";
        const CONFIG_SO: &str = "/data/local/tmp/bogusmips-gadget.config.so";

        let local = gadget_local.to_string_lossy();
        self.adb(&["push", &local, GADGET])?;
        self.push_bytes(script_js.as_bytes(), SCRIPT)?;
        let cfg = bypass::gadget_config(SCRIPT);
        self.push_bytes(cfg.as_bytes(), CONFIG)?;
        self.push_bytes(cfg.as_bytes(), CONFIG_SO)?;

        // The app's SELinux domain must be able to read and execute the gadget;
        // files left in /data/local/tmp carry `shell_data_file`, which apps may
        // not map as code, so relabel them like app native libraries.
        let _ = self.adb(&["shell", "chmod", "644", GADGET, SCRIPT, CONFIG, CONFIG_SO]);
        let _ = self.adb(&[
            "shell",
            "chcon",
            "u:object_r:apk_data_file:s0",
            GADGET,
            SCRIPT,
            CONFIG,
            CONFIG_SO,
        ]);

        let prop = format!("wrap.{package}");
        let value = format!("LD_PRELOAD={GADGET}");
        self.adb(&["shell", "setprop", &prop, &value])
            .map_err(|e| format!("could not arm the bypass (setprop {prop}): {e}"))?;
        Ok("Frida gadget armed".into())
    }

    /// Clears the device's logcat ring buffer before launching the instrumented
    /// app so subsequent [`Self::frida_log_lines`] calls only return fresh output.
    pub fn clear_logcat(&self) {
        let _ = self.adb(&["logcat", "-c"]);
    }

    /// Returns lines logged by `frida-gadget` (`console.log` / `send`) to the
    /// `Frida` logcat tag.
    pub fn frida_log_lines(&self) -> Vec<String> {
        let Ok(out) = self.adb(&["logcat", "-d", "-v", "raw", "-s", "Frida:V"]) else {
            return Vec::new();
        };
        out.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("--------- beginning of"))
            .map(ToOwned::to_owned)
            .collect()
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        self.clear_proxy();
        if let Some(mut child) = self.child.take() {
            let _ = self.adb(&["emu", "kill"]);
            // Give it a moment, then ensure the process is gone.
            std::thread::sleep(Duration::from_millis(300));
            let _ = child.kill();
        }
    }
}

fn run(program: &Path, args: &[&str]) -> Step {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success() {
        Ok(stdout)
    } else if !stderr.trim().is_empty() {
        Err(stderr.trim().to_owned())
    } else {
        Err(stdout.trim().to_owned())
    }
}

/// Writes the CA certificate (PEM) so the user can install it manually when
/// a rootable emulator is not available.
pub fn save_ca_pem(path: &Path, pem: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(pem.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_emulator_args() {
        let args = emulator_args("Medium_Phone", 8123);
        assert!(args.contains(&"-avd".to_string()));
        assert!(args.contains(&"Medium_Phone".to_string()));
        assert!(!args.iter().any(|a| a.contains("-http-proxy")));
        assert!(args.contains(&"-writable-system".to_string()));
    }

    #[test]
    fn ca_script_targets_both_stores_and_all_namespaces() {
        let script = ca_install_script("b13f7cfc.0");
        assert!(script.contains("/system/etc/security/cacerts"));
        assert!(script.contains("/apex/com.android.conscrypt/cacerts"));
        assert!(script.contains("b13f7cfc.0"));
        assert!(script.contains("chcon u:object_r:system_security_cacerts_file"));
        // Propagates into every process mount namespace (covers USAP pool and
        // already-running apps), deduplicated by namespace id.
        assert!(script.contains("/proc/[0-9]*"));
        assert!(script.contains("ns/mnt"));
        assert!(script.contains("nsenter -t"));
        assert!(script.contains("echo INSTALLED"));
    }

    #[test]
    fn parses_ini_values() {
        let ini = "image.sysdir.1=system-images/android-37.0/google_apis/arm64-v8a/\ntag.id=google_apis\n";
        assert_eq!(
            ini_value(ini, "tag.id").as_deref(),
            Some("google_apis")
        );
        assert_eq!(ini_value(ini, "missing"), None);
    }

    #[test]
    fn detects_sdk_if_present() {
        // Only asserts the detection does not panic; environments vary.
        let _ = Sdk::detect();
    }
}
