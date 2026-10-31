//! Optional Play Services availability / root-detection bypass and user-defined
//! Frida scripts (including Frida CodeShare `owner/slug` scripts such as
//! `dzonerzy/aesinfo`, local `.js` files, and `http(s)://` script URLs).
//!
//! Rootable `google_apis` emulators carry an older Google Play Services build
//! than many apps are compiled against (so `GoogleApiAvailability` returns
//! `SERVICE_VERSION_UPDATE_REQUIRED`), and their `userdebug` build looks rooted
//! to apps (`ro.debuggable=1`, `test-keys`, RootBeer, …). Either makes an app
//! abort before producing any traffic. To keep such apps running during a
//! capture — and to let users run custom instrumentation such as
//! `frida --codeshare dzonerzy/aesinfo` — we inject
//! [frida-gadget](https://frida.re/docs/gadget/) into the target app via the
//! `wrap.<package>` property (`LD_PRELOAD`), so no frida tooling is needed on
//! the host or a frida-server on the device.
//!
//! The built-in bypass only makes the checks pass — it does not provide the
//! services or un-root the device — which is all that is needed to keep these
//! environment checks from blocking network analysis. It cannot defeat
//! server-side attestation such as the Play Integrity API.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::agent::json::JsonValue;

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
    r#"(function () {
  // Remember what we've already hooked so re-applying never re-replaces an
  // implementation (repeated replacement destabilises frida's trampolines).
  var hooked = {};
  function hookReturn(className, method, value) {
    var key = className + '#' + method;
    if (hooked[key]) return;
    try {
      var cls = Java.use(className);
      if (!cls[method]) return;
      cls[method].overloads.forEach(function (ov) {
        ov.implementation = function () { return value; };
      });
      hooked[key] = true;
    } catch (e) {
      // Class or method not present / not loaded yet; a later pass may catch it.
    }
  }

  var buildDone = false;
  var propsDone = false;
  function applyHooks() {
    // --- Google Play Services availability -> ConnectionResult.SUCCESS (0) ---
    ['com.google.android.gms.common.GoogleApiAvailability',
     'com.google.android.gms.common.GoogleApiAvailabilityLight',
     'com.google.android.gms.common.GooglePlayServicesUtil',
     'com.google.android.gms.common.GooglePlayServicesUtilLight'].forEach(function (c) {
      hookReturn(c, 'isGooglePlayServicesAvailable', 0);
    });

    // --- RootBeer: every detection method reports "not rooted" (this also
    // covers su-binary/busybox/magisk probes, so we avoid the crash-prone
    // global File.exists / Runtime.exec overrides). ---
    ['isRooted', 'isRootedWithBusyBoxCheck', 'isRootedWithoutBusyBoxCheck',
     'detectRootManagementApps', 'detectPotentiallyDangerousApps', 'detectRootCloakingApps',
     'detectTestKeys', 'checkForBusyBoxBinary', 'checkForSuBinary', 'checkSuExists',
     'checkForRWPaths', 'checkForDangerousProps', 'checkForRootNative',
     'checkForMagiskBinary', 'checkForBinary'].forEach(function (m) {
      hookReturn('com.scottyab.rootbeer.RootBeer', m, false);
    });

    // --- Build fingerprint: hide the userdebug test-keys tag ---
    if (!buildDone) {
      try { Java.use('android.os.Build').TAGS.value = 'release-keys'; buildDone = true; } catch (e) {}
    }

    // --- Dangerous system properties report safe values ---
    if (!propsDone) {
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
        propsDone = true;
      } catch (e) {}
    }
  }

  // The gadget is loaded via LD_PRELOAD before ART is initialised. Using the
  // Java bridge too early aborts the process ("system_class_loader_ == nullptr
  // implies IsAotCompiler"), and polling Java.available in a tight loop starves
  // frida's own initialisation, so we simply defer with a few gently-spaced
  // one-shot timers starting safely after ART is up (~1.5s). Re-applying is
  // idempotent and catches classes (e.g. RootBeer) loaded a little later.
  // NOTE: checks that run during very early app startup (before ~1.5s) can
  // still win this race; beating those reliably needs frida spawn-gating.
  var delays = [2000, 3500, 5500, 8000];
  var i = 0;
  function schedule() {
    try { Java.perform(applyHooks); } catch (e) { /* ART not ready yet */ }
    i += 1;
    if (i < delays.length) setTimeout(schedule, delays[i] - delays[i - 1]);
  }
  setTimeout(schedule, delays[0]);
})();
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

/// A user-defined Frida script entry (CodeShare slug, URL, or local `.js` path)
/// that can be individually enabled or disabled for network capture sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FridaScriptEntry {
    /// Canonical script specification: e.g. `"dzonerzy/aesinfo"`,
    /// `"/path/to/script.js"`, or `"https://example.com/hook.js"`.
    pub spec: String,
    /// Whether this script is enabled for the capture session.
    pub enabled: bool,
}

impl FridaScriptEntry {
    pub fn new(spec: impl Into<String>, enabled: bool) -> Self {
        Self {
            spec: spec.into(),
            enabled,
        }
    }
}

/// Persisted Frida configuration (the built-in bypass toggle and user-defined
/// scripts with their enabled/disabled state).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FridaConfig {
    pub bypass_checks: bool,
    pub scripts: Vec<FridaScriptEntry>,
}

impl FridaConfig {
    pub fn to_json(&self) -> JsonValue {
        let scripts = self.scripts.iter().map(|s| {
            JsonValue::obj([
                ("spec", JsonValue::str(&s.spec)),
                ("enabled", JsonValue::Bool(s.enabled)),
            ])
        });
        JsonValue::obj([
            ("bypass_checks", JsonValue::Bool(self.bypass_checks)),
            ("scripts", JsonValue::arr(scripts)),
        ])
    }

    pub fn from_json(val: &JsonValue) -> Self {
        let mut cfg = Self::default();
        if let Some(b) = val.get("bypass_checks").and_then(JsonValue::as_bool) {
            cfg.bypass_checks = b;
        }
        if let Some(arr) = val.get("scripts").and_then(JsonValue::as_array) {
            for item in arr {
                if let Some(spec) = item.get("spec").and_then(JsonValue::as_str) {
                    let trimmed = spec.trim();
                    if !trimmed.is_empty() {
                        let enabled = item
                            .get("enabled")
                            .and_then(JsonValue::as_bool)
                            .unwrap_or(true);
                        cfg.scripts.push(FridaScriptEntry::new(trimmed, enabled));
                    }
                }
            }
        }
        cfg
    }

    pub fn config_path() -> PathBuf {
        if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(dir).join("bogusmips/frida.json");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".config/bogusmips/frida.json");
        }
        std::env::temp_dir().join("bogusmips-frida.json")
    }

    pub fn load() -> Self {
        Self::load_from(&Self::config_path())
    }

    pub fn load_from(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| JsonValue::parse(&s).ok())
            .map(|v| Self::from_json(&v))
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&Self::config_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, self.to_json().to_json_string()).map_err(|e| e.to_string())
    }
}

/// Resolved source of a user-defined Frida script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptSource {
    /// A Frida CodeShare project (`owner/slug`), e.g. `dzonerzy/aesinfo`.
    CodeShare { owner: String, slug: String },
    /// A direct HTTP/HTTPS URL to a Frida script or CodeShare JSON endpoint.
    Url(String),
    /// A local `.js` file path on the host machine.
    File(PathBuf),
}

impl ScriptSource {
    /// Parses a single user-supplied script reference:
    /// - A Frida CodeShare slug (`dzonerzy/aesinfo` or `@dzonerzy/aesinfo`)
    /// - A CLI invocation (`frida --codeshare dzonerzy/aesinfo`, `-c owner/slug`, `-l file.js`)
    /// - A CodeShare URL (`https://codeshare.frida.re/@dzonerzy/aesinfo/`)
    /// - A direct `http(s)://` script URL
    /// - A local `.js` file path
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut specs = parse_script_specs(raw)?;
        if specs.is_empty() {
            return Err("script specification cannot be empty".into());
        }
        Ok(specs.remove(0))
    }

    /// Canonical display/storage string for this script source.
    pub fn spec(&self) -> String {
        match self {
            ScriptSource::CodeShare { owner, slug } => format!("{owner}/{slug}"),
            ScriptSource::Url(url) => url.clone(),
            ScriptSource::File(path) => path.to_string_lossy().into_owned(),
        }
    }

    /// Short description of the script's origin for UI tooltips.
    pub fn description(&self) -> String {
        match self {
            ScriptSource::CodeShare { owner, slug } => {
                format!("Frida CodeShare: https://codeshare.frida.re/@{owner}/{slug}/")
            }
            ScriptSource::Url(url) => format!("Remote Frida script: {url}"),
            ScriptSource::File(path) => format!("Local Frida script: {}", path.display()),
        }
    }
}

/// Parses one or more script specifications from user input. Accepts plain
/// CodeShare slugs (`dzonerzy/aesinfo`), full `frida --codeshare ...` command
/// lines (even with multiple `--codeshare` / `-c` / `-l` flags), CodeShare or
/// raw `http(s)://` URLs, and local `.js` file paths.
pub fn parse_script_specs(raw: &str) -> Result<Vec<ScriptSource>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("script specification cannot be empty".into());
    }

    // Check if the user pasted a `frida ...` CLI command or `--codeshare` / `-l` flags.
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let has_cli_flags = tokens.iter().any(|t| {
        *t == "frida"
            || *t == "--codeshare"
            || *t == "-c"
            || *t == "-l"
            || *t == "--load"
            || t.starts_with("--codeshare=")
            || t.starts_with("--load=")
    });

    if has_cli_flags {
        let mut extracted = Vec::new();
        let mut i = 0;
        while i < tokens.len() {
            let t = tokens[i];
            if let Some(val) = t
                .strip_prefix("--codeshare=")
                .or_else(|| t.strip_prefix("--load="))
            {
                if !val.is_empty() {
                    extracted.push(parse_single_token(val)?);
                }
            } else if matches!(t, "--codeshare" | "-c" | "-l" | "--load") {
                let Some(next) = tokens.get(i + 1) else {
                    return Err(format!("missing script name after '{t}'"));
                };
                extracted.push(parse_single_token(next)?);
                i += 1;
            }
            i += 1;
        }
        if !extracted.is_empty() {
            return Ok(extracted);
        }
    }

    Ok(vec![parse_single_token(trimmed)?])
}

fn parse_single_token(raw: &str) -> Result<ScriptSource, String> {
    let s = raw.trim().trim_matches(|c| c == '"' || c == '\'');
    if s.is_empty() {
        return Err("script specification cannot be empty".into());
    }

    // 1. HTTP / HTTPS URLs (including codeshare.frida.re links).
    if s.starts_with("https://") || s.starts_with("http://") {
        if let Some((owner, slug)) = parse_codeshare_url(s) {
            return Ok(ScriptSource::CodeShare { owner, slug });
        }
        return Ok(ScriptSource::Url(s.to_owned()));
    }

    // 2. Home-relative file path (`~/...`).
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(ScriptSource::File(PathBuf::from(home).join(rest)));
        }
        return Ok(ScriptSource::File(PathBuf::from(s)));
    }

    // 3. Explicit local file path (absolute, relative `./` or `../`, Windows drive,
    // `.js` extension, or an existing path on disk).
    let looks_like_path = s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('\\')
        || (s.len() > 2 && s.as_bytes()[1] == b':')
        || s.to_ascii_lowercase().ends_with(".js")
        || Path::new(s).exists();
    if looks_like_path {
        return Ok(ScriptSource::File(PathBuf::from(s)));
    }

    // 4. Frida CodeShare slug (`owner/slug` or `@owner/slug`).
    let clean = s.strip_prefix('@').unwrap_or(s).trim_end_matches('/');
    if let Some((owner, slug)) = clean.split_once('/') {
        if is_valid_codeshare_part(owner) && is_valid_codeshare_part(slug) {
            return Ok(ScriptSource::CodeShare {
                owner: owner.to_owned(),
                slug: slug.to_owned(),
            });
        }
    }

    Err(format!(
        "invalid Frida script '{s}': expected a CodeShare slug (e.g. dzonerzy/aesinfo), a local .js path, or an https:// URL"
    ))
}

fn parse_codeshare_url(url: &str) -> Option<(String, String)> {
    let rest = url
        .strip_prefix("https://codeshare.frida.re/")
        .or_else(|| url.strip_prefix("http://codeshare.frida.re/"))?;
    let path = rest.split(['?', '#']).next().unwrap_or(rest).trim_matches('/');
    let pair = path
        .strip_prefix('@')
        .or_else(|| path.strip_prefix("api/project/"))?;
    let (owner, slug) = pair.split_once('/')?;
    let slug = slug.trim_matches('/');
    if is_valid_codeshare_part(owner) && is_valid_codeshare_part(slug) {
        Some((owner.to_owned(), slug.to_owned()))
    } else {
        None
    }
}

fn is_valid_codeshare_part(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && !part.contains('/')
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Frida CodeShare API URL returning the project JSON (`{"source": "..."}`).
pub fn codeshare_url(owner: &str, slug: &str) -> String {
    format!("https://codeshare.frida.re/api/project/{owner}/{slug}/")
}

/// Extracts the JavaScript source from a Frida CodeShare API JSON response, or
/// returns `body` directly if it is already raw JavaScript.
pub fn extract_codeshare_source(body: &str) -> Result<String, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Err("the Frida script is empty".into());
    }
    if trimmed.starts_with('{') {
        if let Ok(json) = JsonValue::parse(trimmed) {
            if let Some(src) = json.get("source").and_then(JsonValue::as_str) {
                if src.trim().is_empty() {
                    return Err("the CodeShare response contained an empty 'source' field".into());
                }
                return Ok(src.to_owned());
            }
            if let Some(detail) = json
                .get("detail")
                .or_else(|| json.get("error"))
                .and_then(JsonValue::as_str)
            {
                return Err(format!("CodeShare error: {detail}"));
            }
            return Err("the CodeShare JSON response did not contain a 'source' field".into());
        }
    }
    Ok(body.to_owned())
}

/// Resolves and loads a Frida script (`owner/slug`, URL, or local file path),
/// caching downloaded CodeShare scripts under `cache_dir/codeshare/`.
/// Returns `(canonical_spec, js_source)`.
pub fn load_script(cache_dir: &Path, spec: &str) -> Result<(String, String), String> {
    let source = ScriptSource::parse(spec)?;
    let canonical = source.spec();
    match source {
        ScriptSource::CodeShare { owner, slug } => {
            let cs_dir = cache_dir.join("codeshare");
            let cached = cs_dir.join(format!("{owner}__{slug}.js"));
            if let Ok(existing) = std::fs::read_to_string(&cached) {
                if !existing.trim().is_empty() {
                    return Ok((canonical, existing));
                }
            }
            std::fs::create_dir_all(&cs_dir).map_err(|e| e.to_string())?;
            let url = codeshare_url(&owner, &slug);
            let tmp = cs_dir.join(format!("{owner}__{slug}.json.tmp"));
            download(&url, &tmp).map_err(|e| {
                format!("could not download Frida CodeShare script '{owner}/{slug}': {e}")
            })?;
            let raw = std::fs::read_to_string(&tmp).map_err(|e| e.to_string());
            let _ = std::fs::remove_file(&tmp);
            let raw = raw?;
            let js = extract_codeshare_source(&raw)
                .map_err(|e| format!("invalid CodeShare script '{owner}/{slug}': {e}"))?;
            std::fs::write(&cached, &js).map_err(|e| e.to_string())?;
            Ok((canonical, js))
        }
        ScriptSource::Url(url) => {
            let scripts_dir = cache_dir.join("scripts");
            std::fs::create_dir_all(&scripts_dir).map_err(|e| e.to_string())?;
            let tmp = scripts_dir.join(format!("download-{}.tmp", std::process::id()));
            download(&url, &tmp)
                .map_err(|e| format!("could not download Frida script from {url}: {e}"))?;
            let raw = std::fs::read_to_string(&tmp).map_err(|e| e.to_string());
            let _ = std::fs::remove_file(&tmp);
            let js = extract_codeshare_source(&raw?)?;
            Ok((canonical, js))
        }
        ScriptSource::File(path) => {
            let js = std::fs::read_to_string(&path)
                .map_err(|e| format!("could not read Frida script {}: {e}", path.display()))?;
            if js.trim().is_empty() {
                return Err(format!("Frida script {} is empty", path.display()));
            }
            Ok((canonical, js))
        }
    }
}

/// Assembles the single JavaScript payload executed by `frida-gadget`:
/// - When `bypass_checks` is `true`, includes [`bypass_script`].
/// - When `user_scripts` (`(spec, js_source)`) is non-empty, installs a
///   compatibility and safety shim for Frida CodeShare scripts (such as
///   `dzonerzy/aesinfo` and `fdciabdul/frida-multiple-bypass`):
///   1. Forwards `send(...)` messages to `console.log` so output appears in
///      `logcat` and the BogusMips Network log without a Frida TCP client.
///   2. Polyfills legacy Frida 12 `Memory.readCString` / `readUtf8String` /
///      `writeUtf8String` APIs and guards `Interceptor.attach` against hooking
///      `libc.so` `fopen`/`access`/`__system_property_get`/`system` (which
///      corrupt `.rodata` or deadlock `frida-gadget` on Android 14/15).
///   3. Protects ART bootstrap classes (`java.lang.String`, `java.io.File`,
///      `java.io.UnixFileSystem`, `java.io.BufferedReader`, `java.lang.Runtime`,
///      `java.lang.ProcessImpl`, `java.lang.ProcessBuilder`) and prevents
///      repeated `.implementation` replacement on the same method overload from
///      corrupting ART trampolines.
///   4. Runs `setTimeout` callbacks and each user script inside `Java.perform`
///      once ART is initialized (~2s after `LD_PRELOAD`), emitting structured
///      `[bogusmips:script:start|ok|error]` status markers for the UI.
pub fn build_gadget_script(bypass_checks: bool, user_scripts: &[(String, String)]) -> String {
    if bypass_checks && user_scripts.is_empty() {
        return bypass_script().to_owned();
    }

    let mut out = String::new();
    if bypass_checks {
        out.push_str(bypass_script());
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }

    if !user_scripts.is_empty() {
        out.push_str(
            r#"(function () {
  if (typeof globalThis.__bogusmipsWrapped !== 'undefined') return;
  globalThis.__bogusmipsWrapped = true;
  var origSetTimeout = globalThis.setTimeout;
  var origSetImmediate = globalThis.setImmediate;
  globalThis.__bogusmipsOrigSetTimeout = origSetTimeout;
  globalThis.__bogusmipsArtReady = false;

  // 1. Forward send(...) to console.log so CodeShare scripts using send()
  //    appear in logcat and the Network view.
  if (typeof send === 'function') {
    var origSend = send;
    globalThis.send = function (message, data) {
      try {
        var text = (typeof message === 'string') ? message : JSON.stringify(message);
        console.log(text);
      } catch (e) {}
      try { return origSend(message, data); } catch (e) {}
    };
  }

  // 2. Polyfill Frida 12 Memory.* helpers used by older CodeShare scripts
  //    (e.g. fdciabdul/frida-multiple-bypass).
  if (typeof Memory !== 'undefined') {
    if (typeof Memory.readCString !== 'function') {
      Memory.readCString = function (p) {
        try { return ptr(p).readCString(); } catch (e) { return ''; }
      };
    }
    if (typeof Memory.readUtf8String !== 'function') {
      Memory.readUtf8String = function (p) {
        try { return ptr(p).readUtf8String(); } catch (e) { return ''; }
      };
    }
    if (typeof Memory.writeUtf8String !== 'function') {
      Memory.writeUtf8String = function (p, _s) {
        // Never overwrite caller string literals in-place (.rodata -> SIGSEGV).
        return p;
      };
    }
  }

  // 3. Guard Module.findExportByName & Interceptor.attach against hooking
  //    high-frequency libc.so functions (fopen, access, __system_property_get,
  //    system) that deadlock frida-gadget or corrupt read-only caller memory.
  var unsafeNativeAddrs = {};
  var unsafeLibcSymbols = {
    'fopen': true, 'fopen64': true, 'open': true, 'open64': true, 'openat': true,
    'access': true, 'faccessat': true, 'stat': true, 'lstat': true, 'fstat': true,
    '__system_property_get': true, '__system_property_read': true, 'system': true
  };
  if (typeof Module !== 'undefined' && typeof Module.findExportByName === 'function') {
    var origFindExport = Module.findExportByName.bind(Module);
    Module.findExportByName = function (moduleName, exportName) {
      var addr = origFindExport(moduleName, exportName);
      try {
        var mod = moduleName ? ('' + moduleName).toLowerCase() : '';
        var sym = '' + exportName;
        if ((mod === '' || mod.indexOf('libc.so') !== -1) && unsafeLibcSymbols[sym] && addr) {
          unsafeNativeAddrs[addr.toString()] = sym;
        }
      } catch (e) {}
      return addr;
    };
  }
  if (typeof Interceptor !== 'undefined' && typeof Interceptor.attach === 'function') {
    var origAttach = Interceptor.attach.bind(Interceptor);
    var attachedAddrs = {};
    Interceptor.attach = function (target, callbacksOrProbe, data) {
      try {
        if (!target) return { detach: function () {} };
        var key = target.toString();
        if (key === '0x0' || key === '0' || unsafeNativeAddrs[key] || attachedAddrs[key]) {
          return { detach: function () {} };
        }
        attachedAddrs[key] = true;
        return origAttach(target, callbacksOrProbe, data);
      } catch (e) {
        return { detach: function () {} };
      }
    };
  }

  // 4. Protect ART on Android 14/15 (API 34/35):
  //    - Block replacing methods on bootstrap core-oj classes (String, File,
  //      UnixFileSystem, BufferedReader, Runtime, ProcessImpl, ProcessBuilder)
  //      which ART & Frida invoke inside JNI transitions (causing recursion/SIGABRT).
  //    - Guard against replacing the same method overload's `.implementation`
  //      multiple times (which corrupts Frida's ART trampolines).
  //    - Make Java.enumerateLoadedClassesSync() fast on large multi-dex apps.
  //    - Ensure setTimeout/setImmediate callbacks run attached to the JVM via
  //      Java.perform so scripts calling Java.use inside setTimeout do not crash.
  if (typeof Java !== 'undefined' && typeof Java.perform === 'function') {
    var origPerform = Java.perform.bind(Java);
    globalThis.__bogusmipsOrigPerform = origPerform;
    var origUse = Java.use.bind(Java);
    var unsafeJavaClasses = {
      'java.lang.String': true,
      'java.io.File': true,
      'java.io.UnixFileSystem': true,
      'java.io.BufferedReader': true,
      'java.lang.Runtime': true,
      'java.lang.ProcessImpl': true,
      'java.lang.ProcessBuilder': true,
      'java.lang.ProcessManager': true
    };
    var hookedJavaOverloads = {};

    function guardOverload(className, methodName, ov, sigKey, blockAll) {
      if (!ov || ov.__bogusmipsGuarded) return ov;
      try {
        var origDesc = Object.getOwnPropertyDescriptor(ov, 'implementation')
          || Object.getOwnPropertyDescriptor(Object.getPrototypeOf(ov), 'implementation');
        if (origDesc && origDesc.set && origDesc.get) {
          Object.defineProperty(ov, 'implementation', {
            configurable: true,
            get: function () { return origDesc.get.call(this); },
            set: function (fn) {
              if (blockAll) return;
              var k = className + '#' + methodName + ':' + sigKey;
              if (hookedJavaOverloads[k]) return;
              hookedJavaOverloads[k] = true;
              try { origDesc.set.call(this, fn); } catch (e) {}
            }
          });
        }
        ov.__bogusmipsGuarded = true;
      } catch (e) {}
      return ov;
    }

    function guardMethod(className, methodName, m, blockAll) {
      if (!m || m.__bogusmipsMethodGuarded) return m;
      try {
        guardOverload(className, methodName, m, 'default', blockAll);
        if (Array.isArray(m.overloads)) {
          m.overloads.forEach(function (ov, idx) {
            guardOverload(className, methodName, ov, 'ov' + idx, blockAll);
          });
        }
        if (typeof m.overload === 'function') {
          var origOverload = m.overload.bind(m);
          m.overload = function () {
            var args = Array.prototype.slice.call(arguments);
            var ov = origOverload.apply(m, args);
            return guardOverload(className, methodName, ov, args.join(','), blockAll);
          };
        }
        m.__bogusmipsMethodGuarded = true;
      } catch (e) {}
      return m;
    }

    Java.use = function (className) {
      var name = '' + className;
      var cls = origUse(name);
      var blockAll = !!unsafeJavaClasses[name];
      if (cls && typeof Proxy === 'function') {
        return new Proxy(cls, {
          get: function (target, prop, receiver) {
            var val = Reflect.get(target, prop, receiver);
            if (typeof prop === 'string' && val && (typeof val === 'function' || typeof val === 'object')) {
              if (Array.isArray(val.overloads) || typeof val.overload === 'function') {
                return guardMethod(name, prop, val, blockAll);
              }
            }
            return val;
          }
        });
      }
      return cls;
    };

    Java.enumerateLoadedClassesSync = function () {
      return [];
    };

    Java.perform = function (fn) {
      var retryDelays = [1500, 2000, 2500];
      var attempt = 0;
      function tryPerform() {
        try {
          origPerform(function () {
            globalThis.__bogusmipsArtReady = true;
            try {
              fn();
            } catch (innerErr) {
              console.log('[frida] ' + innerErr);
            }
          });
        } catch (e) {
          if (attempt < retryDelays.length) {
            var d = retryDelays[attempt++];
            origSetTimeout(tryPerform, d);
          } else {
            console.log('[frida] Java.perform failed: ' + e);
          }
        }
      }
      tryPerform();
    };

    // Ensure setTimeout / setImmediate callbacks spawned by user scripts run
    // attached to the JVM so direct Java.use(...) calls inside setTimeout work.
    globalThis.setTimeout = function (cb, delay) {
      var d = (typeof delay === 'number' && delay > 0) ? delay : 0;
      return origSetTimeout(function () {
        if (typeof cb !== 'function') return;
        if (globalThis.__bogusmipsArtReady) {
          Java.perform(cb);
        } else {
          try { cb(); } catch (e) { console.log('[frida] ' + e); }
        }
      }, d);
    };
    if (typeof origSetImmediate === 'function') {
      globalThis.setImmediate = function (cb) {
        return globalThis.setTimeout(cb, 0);
      };
    }
  }
})();
"#,
        );

        for (spec, source) in user_scripts {
            let label = spec.replace('\\', "\\\\").replace('\'', "\\'");
            out.push_str(&format!(
                r#"
// --- Frida script: {spec} ---
(function () {{
  var spec = '{label}';
  var schedule = globalThis.__bogusmipsOrigSetTimeout || setTimeout;
  var delays = [2000, 3500, 5500];
  var attempt = 0;
  function runScript() {{
    try {{
      var perform = globalThis.__bogusmipsOrigPerform
        || ((typeof Java !== 'undefined' && Java.perform) ? Java.perform.bind(Java) : null);
      if (perform) {{
        perform(function () {{
          globalThis.__bogusmipsArtReady = true;
          console.log('[bogusmips:script:start] ' + spec);
          try {{
            (function () {{
{source}
            }})();
            schedule(function () {{
              console.log('[bogusmips:script:ok] ' + spec);
            }}, 50);
          }} catch (scriptErr) {{
            console.log('[bogusmips:script:error] ' + spec + ' | ' + scriptErr);
          }}
        }});
      }} else {{
        console.log('[bogusmips:script:start] ' + spec);
        (function () {{
{source}
        }})();
        console.log('[bogusmips:script:ok] ' + spec);
      }}
    }} catch (artErr) {{
      if (attempt < delays.length - 1) {{
        attempt += 1;
        schedule(runScript, delays[attempt] - delays[attempt - 1]);
      }} else {{
        console.log('[bogusmips:script:error] ' + spec + ' | ' + artErr);
      }}
    }}
  }}
  schedule(runScript, delays[0]);
}})();
"#
            ));
        }
    }

    out
}

fn download(url: &str, dest: &Path) -> Result<(), String> {
    let output = Command::new("curl")
        .arg("-fL")
        .args(["--retry", "2", "-o"])
        .arg(dest)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("could not run curl to download {url}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "could not download from {url}: {}",
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

    #[test]
    fn parses_codeshare_slugs_cli_commands_urls_and_files() {
        assert_eq!(
            ScriptSource::parse("dzonerzy/aesinfo").unwrap(),
            ScriptSource::CodeShare {
                owner: "dzonerzy".into(),
                slug: "aesinfo".into(),
            }
        );
        assert_eq!(
            ScriptSource::parse("@dzonerzy/aesinfo/").unwrap(),
            ScriptSource::CodeShare {
                owner: "dzonerzy".into(),
                slug: "aesinfo".into(),
            }
        );
        assert_eq!(
            ScriptSource::parse("frida --codeshare dzonerzy/aesinfo -f com.example.app").unwrap(),
            ScriptSource::CodeShare {
                owner: "dzonerzy".into(),
                slug: "aesinfo".into(),
            }
        );
        assert_eq!(
            ScriptSource::parse("https://codeshare.frida.re/@dzonerzy/aesinfo/").unwrap(),
            ScriptSource::CodeShare {
                owner: "dzonerzy".into(),
                slug: "aesinfo".into(),
            }
        );
        assert_eq!(
            ScriptSource::parse("https://codeshare.frida.re/api/project/dzonerzy/aesinfo/").unwrap(),
            ScriptSource::CodeShare {
                owner: "dzonerzy".into(),
                slug: "aesinfo".into(),
            }
        );
        assert_eq!(
            ScriptSource::parse("https://example.com/custom.js").unwrap(),
            ScriptSource::Url("https://example.com/custom.js".into())
        );
        assert_eq!(
            ScriptSource::parse("/tmp/my_hook.js").unwrap(),
            ScriptSource::File(PathBuf::from("/tmp/my_hook.js"))
        );

        let multi = parse_script_specs(
            "frida --codeshare dzonerzy/aesinfo -c pcipolloni/universal-android-ssl-pinning-bypass-with-frida -l /tmp/extra.js",
        )
        .unwrap();
        assert_eq!(multi.len(), 3);
        assert_eq!(multi[0].spec(), "dzonerzy/aesinfo");
        assert_eq!(
            multi[1].spec(),
            "pcipolloni/universal-android-ssl-pinning-bypass-with-frida"
        );
        assert_eq!(multi[2].spec(), "/tmp/extra.js");

        assert!(ScriptSource::parse("").is_err());
        assert!(ScriptSource::parse("not_a_slug").is_err());
    }

    #[test]
    fn extracts_codeshare_json_source_and_builds_combined_script() {
        let api_json = r#"{
            "id": "123",
            "owner": "dzonerzy",
            "slug": "aesinfo",
            "project_name": "AESInfo",
            "source": "Java.perform(function() { console.log('AES hooked'); });"
        }"#;
        let js = extract_codeshare_source(api_json).unwrap();
        assert_eq!(js, "Java.perform(function() { console.log('AES hooked'); });");

        let combined = build_gadget_script(
            true,
            &[("dzonerzy/aesinfo".into(), js.clone())],
        );
        assert!(combined.contains("isGooglePlayServicesAvailable"));
        assert!(combined.contains("dzonerzy/aesinfo"));
        assert!(combined.contains("AES hooked"));
        assert!(combined.contains("__bogusmipsWrapped"));

        let only_user = build_gadget_script(
            false,
            &[("dzonerzy/aesinfo".into(), js)],
        );
        assert!(!only_user.contains("isGooglePlayServicesAvailable"));
        assert!(only_user.contains("AES hooked"));
    }

    #[test]
    fn loads_cached_codeshare_and_local_file_scripts() {
        let dir = std::env::temp_dir().join(format!("bogusmips-frida-test-{}", std::process::id()));
        let cs_dir = dir.join("codeshare");
        std::fs::create_dir_all(&cs_dir).unwrap();
        std::fs::write(
            cs_dir.join("dzonerzy__aesinfo.js"),
            "Java.perform(function () { send('aes'); });",
        )
        .unwrap();

        let (spec, code) = load_script(&dir, "frida --codeshare dzonerzy/aesinfo").unwrap();
        assert_eq!(spec, "dzonerzy/aesinfo");
        assert!(code.contains("send('aes')"));

        let local_path = dir.join("custom.js");
        std::fs::write(&local_path, "console.log('custom');").unwrap();
        let (local_spec, local_code) =
            load_script(&dir, &local_path.to_string_lossy()).unwrap();
        assert_eq!(local_spec, local_path.to_string_lossy());
        assert_eq!(local_code, "console.log('custom');");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn roundtrips_frida_config_json() {
        let cfg = FridaConfig {
            bypass_checks: true,
            scripts: vec![
                FridaScriptEntry::new("dzonerzy/aesinfo", true),
                FridaScriptEntry::new("/tmp/hook.js", false),
            ],
        };
        let json = cfg.to_json().to_json_string();
        let parsed = FridaConfig::from_json(&JsonValue::parse(&json).unwrap());
        assert_eq!(parsed, cfg);
    }
}
