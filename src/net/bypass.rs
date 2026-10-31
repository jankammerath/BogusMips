//! User-defined Frida scripts (including Frida CodeShare `owner/slug` scripts
//! such as `dzonerzy/aesinfo` or `fdciabdul/frida-multiple-bypass`, local `.js`
//! files, and `http(s)://` script URLs).
//!
//! To let users run custom Frida instrumentation during a network capture
//! without needing `frida` CLI tooling on the host or `frida-server` on the
//! device, we inject [frida-gadget](https://frida.re/docs/gadget/) into the
//! target app via the `wrap.<package>` property (`LD_PRELOAD`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::agent::json::JsonValue;

/// frida release whose gadget is downloaded. Pinned to the last 16.x, because
/// 17.x removed the built-in `Java`/`ObjC` script globals that existing
/// CodeShare scripts rely on (they became ES-module imports needing a bundler).
/// Override with the `BOGUSMIPS_FRIDA_VERSION` environment variable, e.g. to
/// match a device's Android version.
pub const FRIDA_VERSION: &str = "16.7.19";

/// The frida version to download — [`FRIDA_VERSION`] unless overridden by the
/// `BOGUSMIPS_FRIDA_VERSION` environment variable.
pub fn frida_version() -> String {
    std::env::var("BOGUSMIPS_FRIDA_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| FRIDA_VERSION.to_owned())
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

/// Persisted Frida configuration (user-defined scripts with their
/// enabled/disabled state).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FridaConfig {
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
        JsonValue::obj([("scripts", JsonValue::arr(scripts))])
    }

    pub fn from_json(val: &JsonValue) -> Self {
        let mut cfg = Self::default();
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

/// Logcat tag written by the gadget wrapper via `android.util.Log` and
/// `liblog.so`'s `__android_log_write`.
pub const FRIDA_LOGCAT_TAG: &str = "BogusMipsFrida";

/// Device file where the gadget wrapper appends all status markers and script
/// `console.log` / `send` output so the host can read them reliably via `adb`.
pub const FRIDA_DEVICE_LOG_PATH: &str = "/data/local/tmp/bogusmips-frida.log";

/// Assembles the JavaScript payload executed by `frida-gadget` for the enabled
/// `user_scripts` (`(spec, js_source)`):
/// 1. Bridges `console.log` / `console.warn` / `console.error` / `send(...)`
///    to [`FRIDA_DEVICE_LOG_PATH`] (via Frida's built-in `File` API), Android's
///    `android.util.Log`, and `liblog.so` (`__android_log_write` with tag
///    [`FRIDA_LOGCAT_TAG`]), because autonomous `frida-gadget` in `"script"`
///    interaction mode only prints to `stdout`.
/// 2. Polyfills legacy Frida 12 `Memory.readCString` / `readUtf8String` /
///    `writeUtf8String` APIs and guards `Interceptor.attach` against hooking
///    `libc.so` `fopen`/`access`/`__system_property_get`/`system` (which
///    corrupt `.rodata` or deadlock `frida-gadget` on Android 14/15).
/// 3. Avoids touching `globalThis.Java` during `LD_PRELOAD` (`t = 0ms`, before
///    ART exists, which would break `frida-java-bridge`'s lazy initialization).
///    Once ART is up, installs in-place guards on bootstrap classes, makes
///    `Field.set(null, ...)` on `static final` fields (such as `Build.TAGS` in
///    `fdciabdul/frida-multiple-bypass`) fall back to Frida's JNI field setter
///    instead of throwing `IllegalAccessException`, applies baseline root/GMS
///    environment hooks, and runs each user script inside `Java.perform`.
pub fn build_gadget_script(user_scripts: &[(String, String)]) -> String {
    if user_scripts.is_empty() {
        return String::new();
    }

    let mut out = String::from(
        r#"(function () {
  if (typeof globalThis.__bogusmipsWrapped !== 'undefined') return;
  globalThis.__bogusmipsWrapped = true;
  var origSetTimeout = globalThis.setTimeout;
  var origSetImmediate = globalThis.setImmediate;
  var FridaFile = (typeof File === 'function') ? File : null;
  var origFindExport = (typeof Module !== 'undefined' && typeof Module.findExportByName === 'function')
    ? Module.findExportByName.bind(Module)
    : null;
  var logWrite = null;
  var logTag = null;
  var javaLog = null;

  function writeOutput(msg) {
    var text = '' + msg;
    // Channel 1: append to /data/local/tmp/bogusmips-frida.log via Frida's File API.
    if (FridaFile) {
      try {
        var f = new FridaFile('/data/local/tmp/bogusmips-frida.log', 'a');
        f.write(text + '\n');
        f.flush();
        f.close();
      } catch (e) {}
    }
    // Channel 2: android.util.Log.i once ART is up.
    if (javaLog) {
      try {
        javaLog.i('BogusMipsFrida', text);
        return;
      } catch (e) {}
    }
    // Channel 3: lazy liblog.so __android_log_write fallback.
    try {
      if (!logWrite && origFindExport) {
        var logAddr = origFindExport('liblog.so', '__android_log_write')
          || origFindExport(null, '__android_log_write');
        if (logAddr) {
          logWrite = new NativeFunction(logAddr, 'int', ['int', 'pointer', 'pointer']);
          logTag = Memory.allocUtf8String('BogusMipsFrida');
        }
      }
      if (logWrite && logTag) {
        var s = Memory.allocUtf8String(text);
        logWrite(4, logTag, s);
      }
    } catch (e) {}
  }

  function formatArgs(args) {
    var parts = [];
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      if (typeof a === 'string') parts.push(a);
      else if (a instanceof Error) parts.push(a.message || ('' + a));
      else {
        try { parts.push(JSON.stringify(a)); } catch (e) { parts.push('' + a); }
      }
    }
    return parts.join(' ');
  }

  var origConsoleLog = console.log ? console.log.bind(console) : function () {};
  var origConsoleWarn = console.warn ? console.warn.bind(console) : origConsoleLog;
  var origConsoleError = console.error ? console.error.bind(console) : origConsoleLog;
  console.log = function () {
    writeOutput(formatArgs(arguments));
    try { origConsoleLog.apply(console, arguments); } catch (e) {}
  };
  console.warn = function () {
    writeOutput(formatArgs(arguments));
    try { origConsoleWarn.apply(console, arguments); } catch (e) {}
  };
  console.error = function () {
    writeOutput(formatArgs(arguments));
    try { origConsoleError.apply(console, arguments); } catch (e) {}
  };
  if (typeof send === 'function') {
    var origSend = send;
    globalThis.send = function (message, data) {
      try {
        var text = (typeof message === 'string') ? message : JSON.stringify(message);
        writeOutput(text);
      } catch (e) {}
      try { return origSend(message, data); } catch (e) {}
    };
  }

  writeOutput('[bogusmips:gadget:loaded]');

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
  if (origFindExport) {
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

  // 4. Do NOT touch `Java` at t = 0ms (during LD_PRELOAD, before ART is
  //    initialised), because accessing any property on `Java` triggers
  //    frida-java-bridge's lazy initialisation prematurely and breaks it.
  var shimsInstalled = false;
  var origPerform = null;
  var origUse = null;
  var envHooked = {};

  function applyBaselineEnvHooks() {
    if (!origUse) return;
    function hookReturn(className, method, value) {
      var key = className + '#' + method;
      if (envHooked[key]) return;
      try {
        var cls = Java.use(className);
        if (!cls || !cls[method]) return;
        cls[method].overloads.forEach(function (ov) {
          ov.implementation = function () { return value; };
        });
        envHooked[key] = true;
      } catch (e) {}
    }

    ['com.google.android.gms.common.GoogleApiAvailability',
     'com.google.android.gms.common.GoogleApiAvailabilityLight',
     'com.google.android.gms.common.GooglePlayServicesUtil',
     'com.google.android.gms.common.GooglePlayServicesUtilLight'].forEach(function (c) {
      hookReturn(c, 'isGooglePlayServicesAvailable', 0);
    });

    ['isRooted', 'isRootedWithBusyBoxCheck', 'isRootedWithoutBusyBoxCheck',
     'detectRootManagementApps', 'detectPotentiallyDangerousApps', 'detectRootCloakingApps',
     'detectTestKeys', 'checkForBusyBoxBinary', 'checkForSuBinary', 'checkSuExists',
     'checkForRWPaths', 'checkForDangerousProps', 'checkForRootNative',
     'checkForMagiskBinary', 'checkForBinary'].forEach(function (m) {
      hookReturn('com.scottyab.rootbeer.RootBeer', m, false);
    });
    hookReturn('com.scottyab.rootbeer.RootBeerNative', 'checkForRoot', 0);
    hookReturn('com.scottyab.rootbeer.RootBeerNative', 'isLibraryLoaded', false);

    if (!envHooked['Build.TAGS']) {
      try {
        var Build = origUse('android.os.Build');
        Build.TAGS.value = 'release-keys';
        Build.TYPE.value = 'user';
        envHooked['Build.TAGS'] = true;
      } catch (e) {}
    }

    if (!envHooked['File.exists']) {
      try {
        var JFile = Java.use('java.io.File');
        var badNames = {
          'su': true, 'busybox': true, 'supersu': true, 'Superuser.apk': true,
          'KingoUser.apk': true, 'SuperSu.apk': true, 'magisk': true, 'daemonsu': true
        };
        JFile.exists.implementation = function () {
          try {
            var name = '' + this.getName();
            if (badNames[name]) return false;
          } catch (e) {}
          return this.exists();
        };
        envHooked['File.exists'] = true;
      } catch (e) {}
    }

    if (!envHooked['SystemProperties']) {
      try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        var safe = {
          'ro.debuggable': '0',
          'ro.secure': '1',
          'service.adb.root': '0',
          'ro.build.tags': 'release-keys',
          'ro.build.type': 'user',
          'ro.build.selinux': '1'
        };
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
        envHooked['SystemProperties'] = true;
      } catch (e) {}
    }
  }

  function installJavaShims() {
    if (shimsInstalled) return;
    shimsInstalled = true;
    origPerform = Java.perform.bind(Java);
    origUse = Java.use.bind(Java);
    try { javaLog = origUse('android.util.Log'); } catch (e) {}

    // Allow reflection Field.set(null, val) on static final fields (e.g.
    // Build.TAGS in fdciabdul/frida-multiple-bypass) to fall back to Frida's
    // JNI field setter instead of throwing IllegalAccessException on Android 12+.
    try {
      var Field = origUse('java.lang.reflect.Field');
      Field.set.overload('java.lang.Object', 'java.lang.Object').implementation = function (obj, val) {
        try {
          return this.set(obj, val);
        } catch (e) {
          try {
            var clsName = '' + this.getDeclaringClass().getName();
            var fldName = '' + this.getName();
            var w = origUse(clsName);
            if (w && w[fldName]) w[fldName].value = val;
          } catch (e2) {}
        }
      };
    } catch (e) {}

    // Methods that need in-place overload guarding:
    // - java.lang.String#contains is blocked completely (causes infinite
    //   recursion inside frida-java-bridge).
    // - File/Runtime/ProcessBuilder/SystemProperties/PackageManager methods
    //   are guarded with blockAll=false so scripts like fdciabdul/frida-multiple-bypass
    //   that assign `.implementation` multiple times on the same overload
    //   update the JS callback in-place without crashing ART.
    var blockedClassMethods = {
      'java.lang.String': ['contains']
    };
    var guardedClassMethods = {
      'java.io.File': ['exists'],
      'java.io.UnixFileSystem': ['checkAccess'],
      'java.io.BufferedReader': ['readLine'],
      'java.lang.Runtime': ['exec'],
      'java.lang.ProcessImpl': ['start'],
      'java.lang.ProcessBuilder': ['start'],
      'java.lang.ProcessManager': ['exec'],
      'android.os.SystemProperties': ['get'],
      'android.app.ApplicationPackageManager': ['getPackageInfo']
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
              if (blockAll || typeof fn !== 'function') return;
              ov.__bogusmipsUserFn = fn;
              var k = className + '#' + methodName + ':' + sigKey;
              if (hookedJavaOverloads[k]) return;
              hookedJavaOverloads[k] = true;
              try {
                origDesc.set.call(this, function () {
                  return ov.__bogusmipsUserFn.apply(this, arguments);
                });
              } catch (e) {}
            }
          });
        }
        ov.__bogusmipsGuarded = true;
      } catch (e) {}
      return ov;
    }

    function guardMethodOnClass(cls, className, methodName, blockAll) {
      try {
        var m = cls[methodName];
        if (!m || m.__bogusmipsMethodGuarded) return;
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
    }

    Java.use = function (className) {
      var name = '' + className;
      var cls = origUse(name);
      if (!cls) return cls;
      var blocked = blockedClassMethods[name];
      if (blocked) {
        for (var i = 0; i < blocked.length; i++) {
          guardMethodOnClass(cls, name, blocked[i], true);
        }
      }
      var guarded = guardedClassMethods[name];
      if (guarded) {
        for (var j = 0; j < guarded.length; j++) {
          guardMethodOnClass(cls, name, guarded[j], false);
        }
      }
      return cls;
    };

    Java.enumerateLoadedClassesSync = function () {
      return [];
    };

    Java.perform = function (fn) {
      try {
        origPerform(function () {
          try {
            fn();
          } catch (innerErr) {
            console.log('[frida] ' + innerErr);
          }
        });
      } catch (e) {
        console.log('[frida] ' + e);
      }
    };

    globalThis.setTimeout = function (cb, delay) {
      var d = (typeof delay === 'number' && delay > 0) ? delay : 0;
      return origSetTimeout(function () {
        if (typeof cb !== 'function') return;
        Java.perform(cb);
      }, d);
    };
    if (typeof origSetImmediate === 'function') {
      globalThis.setImmediate = function (cb) {
        return globalThis.setTimeout(cb, 0);
      };
    }
  }

  var scripts = [
"#,
    );

    for (spec, source) in user_scripts {
        let label = spec.replace('\\', "\\\\").replace('\'', "\\'");
        out.push_str(&format!(
            r#"    {{
      spec: '{label}',
      run: function () {{
{source}
      }}
    }},
"#
        ));
    }

    out.push_str(
        r#"  ];

  var delays = [1000, 2000, 3500, 5500, 8000];
  var attempt = 0;
  function bootAfterArt() {
    try {
      Java.perform(function () {
        installJavaShims();
        applyBaselineEnvHooks();
        for (var i = 0; i < scripts.length; i++) {
          var s = scripts[i];
          console.log('[bogusmips:script:start] ' + s.spec);
          try {
            s.run();
            console.log('[bogusmips:script:ok] ' + s.spec);
          } catch (scriptErr) {
            console.log('[bogusmips:script:error] ' + s.spec + ' | ' + scriptErr);
          }
        }
        // Re-apply baseline hooks for classes (e.g. RootBeer) loaded lazily.
        origSetTimeout(function () {
          try { origPerform(applyBaselineEnvHooks); } catch (e) {}
        }, 1500);
        origSetTimeout(function () {
          try { origPerform(applyBaselineEnvHooks); } catch (e) {}
        }, 3500);
      });
    } catch (artErr) {
      attempt += 1;
      if (attempt < delays.length) {
        origSetTimeout(bootAfterArt, delays[attempt] - delays[attempt - 1]);
      } else {
        for (var j = 0; j < scripts.length; j++) {
          console.log('[bogusmips:script:error] ' + scripts[j].spec + ' | ' + artErr);
        }
      }
    }
  }
  origSetTimeout(bootAfterArt, delays[0]);
})();
"#,
    );

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

        let combined = build_gadget_script(&[("dzonerzy/aesinfo".into(), js)]);
        assert!(combined.contains("dzonerzy/aesinfo"));
        assert!(combined.contains("AES hooked"));
        assert!(combined.contains("__bogusmipsWrapped"));
        assert!(combined.contains("__android_log_write"));
        assert!(combined.contains(FRIDA_LOGCAT_TAG));
        assert!(combined.contains("[bogusmips:script:start]"));
        assert!(combined.contains("[bogusmips:script:ok]"));

        assert!(build_gadget_script(&[]).is_empty());
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
