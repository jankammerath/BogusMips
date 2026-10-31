//! Orchestrates a capture session: starts the proxy and emulator, installs
//! the CA and the app, and routes the app's traffic through the proxy. All
//! of this runs on a background thread; the UI polls [`NetworkController`].

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::ca::CertAuthority;
use super::bypass;
use super::capture::Capture;
use super::emulator::{Emulator, Sdk};
use super::proxy::Proxy;

const BOOT_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_LOG: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Idle,
    StartingProxy,
    StartingEmulator,
    WaitingForBoot,
    EnablingRoot,
    InstallingCa,
    InstallingApp,
    InstallingBypass,
    Launching,
    Capturing,
    Stopped,
    Failed,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Idle => "Idle",
            Phase::StartingProxy => "Starting proxy",
            Phase::StartingEmulator => "Starting emulator",
            Phase::WaitingForBoot => "Waiting for the emulator to boot",
            Phase::EnablingRoot => "Enabling root",
            Phase::InstallingCa => "Installing the proxy certificate",
            Phase::InstallingApp => "Installing the app",
            Phase::InstallingBypass => "Injecting Frida scripts",
            Phase::Launching => "Launching the app",
            Phase::Capturing => "Capturing",
            Phase::Stopped => "Stopped",
            Phase::Failed => "Failed",
        }
    }

    pub fn is_active(self) -> bool {
        !matches!(self, Phase::Idle | Phase::Stopped | Phase::Failed)
    }
}

/// Live runtime state of an enabled Frida script during a capture session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptState {
    /// Downloading or reading the script on the host.
    Loading,
    /// Pushed to the emulator and armed via `frida-gadget`; waiting for the app
    /// to launch and initialize ART.
    Injected,
    /// Confirmed loaded and executing inside the target app (`messages` is the
    /// number of log/send messages emitted by Frida).
    Active { messages: usize },
    /// Failed to load on the host or threw an exception in the app.
    Error(String),
}

#[derive(Default)]
pub struct Status {
    pub phase: Phase,
    pub log: Vec<(Instant, String)>,
    pub error: Option<String>,
    pub proxy_port: Option<u16>,
    pub scripts: Vec<(String, ScriptState)>,
}

impl Status {
    fn log(&mut self, message: impl Into<String>) {
        self.log.push((Instant::now(), message.into()));
        if self.log.len() > MAX_LOG {
            let excess = self.log.len() - MAX_LOG;
            self.log.drain(0..excess);
        }
    }

    pub fn set_script_state(&mut self, spec: &str, state: ScriptState) {
        if let Some((_, slot)) = self.scripts.iter_mut().find(|(s, _)| s == spec) {
            *slot = state;
        } else {
            self.scripts.push((spec.to_owned(), state));
        }
    }

    /// Processes one line from the `Frida` logcat tag, updating per-script
    /// runtime state and recording user-visible output in [`Self::log`].
    pub fn ingest_frida_line(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }
        if let Some(spec) = trimmed.strip_prefix("[bogusmips:script:start]") {
            let spec = spec.trim();
            if !self
                .scripts
                .iter()
                .any(|(s, st)| s == spec && matches!(st, ScriptState::Active { .. }))
            {
                self.set_script_state(spec, ScriptState::Injected);
            }
            return;
        }
        if let Some(spec) = trimmed.strip_prefix("[bogusmips:script:ok]") {
            let spec = spec.trim();
            let messages = self
                .scripts
                .iter()
                .find(|(s, _)| s == spec)
                .and_then(|(_, st)| match st {
                    ScriptState::Active { messages } => Some(*messages),
                    _ => None,
                })
                .unwrap_or(0);
            self.set_script_state(spec, ScriptState::Active { messages });
            self.log(format!("✔ Frida script loaded & working: {spec}"));
            return;
        }
        if let Some(rest) = trimmed.strip_prefix("[bogusmips:script:error]") {
            let (spec, err) = rest
                .split_once('|')
                .map_or((rest.trim(), "script execution error"), |(s, e)| {
                    (s.trim(), e.trim())
                });
            self.set_script_state(spec, ScriptState::Error(err.to_owned()));
            self.log(format!("✖ Frida script error ({spec}): {err}"));
            return;
        }

        // Any output emitted by the script in the target process confirms the
        // script is running and increments its message counter.
        for (_, state) in &mut self.scripts {
            match state {
                ScriptState::Injected => *state = ScriptState::Active { messages: 1 },
                ScriptState::Active { messages } => *messages += 1,
                ScriptState::Loading | ScriptState::Error(_) => {}
            }
        }
        self.log(format!("[frida] {trimmed}"));
    }
}

/// What to capture.
#[derive(Clone, Default)]
pub struct StartConfig {
    pub avd: String,
    /// APK file paths to install (base + splits); empty to sniff without
    /// installing anything.
    pub apks: Vec<PathBuf>,
    /// Package to launch after install.
    pub package: Option<String>,
    /// Enabled user-defined Frida scripts (CodeShare slugs like
    /// `dzonerzy/aesinfo`, URLs, or local `.js` paths) to inject via
    /// `frida-gadget`.
    pub frida_scripts: Vec<String>,
}

pub struct NetworkController {
    ca: Arc<CertAuthority>,
    capture: Arc<Capture>,
    status: Arc<Mutex<Status>>,
    cancel: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    sdk: Option<Sdk>,
}

impl Default for NetworkController {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkController {
    pub fn new() -> Self {
        Self {
            ca: Arc::new(CertAuthority::new().unwrap_or_else(|_| {
                // Generation only fails if the crypto backend is unavailable.
                panic!("failed to generate a CA certificate")
            })),
            capture: Arc::new(Capture::new()),
            status: Arc::new(Mutex::new(Status::default())),
            cancel: Arc::new(AtomicBool::new(false)),
            handle: None,
            sdk: Sdk::detect(),
        }
    }

    pub fn sdk(&self) -> Option<&Sdk> {
        self.sdk.as_ref()
    }

    pub fn capture(&self) -> &Arc<Capture> {
        &self.capture
    }

    pub fn ca_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    pub fn phase(&self) -> Phase {
        self.status.lock().unwrap().phase
    }

    pub fn is_running(&self) -> bool {
        self.phase().is_active()
    }

    /// The current status: phase, error and recent log lines.
    pub fn status_snapshot(&self) -> (Phase, Option<String>, Vec<String>) {
        let status = self.status.lock().unwrap();
        (
            status.phase,
            status.error.clone(),
            status.log.iter().map(|(_, m)| m.clone()).collect(),
        )
    }

    /// Live status of each Frida script configured for the current or last session.
    pub fn script_statuses(&self) -> Vec<(String, ScriptState)> {
        self.status.lock().unwrap().scripts.clone()
    }

    /// Processes a Frida log line, updating per-script runtime status and the
    /// session log.
    pub fn record_frida_line(&self, line: &str) {
        self.status.lock().unwrap().ingest_frida_line(line);
    }

    pub fn start(&mut self, config: StartConfig) {
        if self.is_running() {
            return;
        }
        let Some(sdk) = self.sdk.clone() else {
            let mut status = self.status.lock().unwrap();
            status.phase = Phase::Failed;
            status.error = Some("No Android SDK found. Set ANDROID_HOME.".to_owned());
            return;
        };
        self.cancel.store(false, Ordering::Relaxed);
        {
            let mut status = self.status.lock().unwrap();
            *status = Status::default();
        }
        let ca = self.ca.clone();
        let capture = self.capture.clone();
        let status = self.status.clone();
        let cancel = self.cancel.clone();
        self.handle = Some(std::thread::spawn(move || {
            run_session(sdk, ca, capture, config, status, cancel);
        }));
    }

    pub fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let mut status = self.status.lock().unwrap();
        if status.phase != Phase::Failed {
            status.phase = Phase::Stopped;
        }
    }
}

impl Drop for NetworkController {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_session(
    sdk: Sdk,
    ca: Arc<CertAuthority>,
    capture: Arc<Capture>,
    config: StartConfig,
    status: Arc<Mutex<Status>>,
    cancel: Arc<AtomicBool>,
) {
    let set_phase = |phase: Phase, message: &str| {
        let mut s = status.lock().unwrap();
        s.phase = phase;
        s.log(message.to_owned());
    };
    let fail = |message: String| {
        let mut s = status.lock().unwrap();
        s.phase = Phase::Failed;
        s.log(format!("Error: {message}"));
        s.error = Some(message);
    };
    let is_cancelled = || cancel.load(Ordering::Relaxed);

    macro_rules! step {
        ($phase:expr, $label:expr, $body:expr) => {{
            if is_cancelled() {
                return;
            }
            set_phase($phase, $label);
            match $body {
                Ok(msg) => status.lock().unwrap().log(msg),
                Err(e) => return fail(e),
            }
        }};
    }

    set_phase(Phase::StartingProxy, "Starting the interception proxy");
    let proxy = match Proxy::start(ca.clone(), capture) {
        Ok(proxy) => proxy,
        Err(e) => return fail(format!("could not start the proxy: {e}")),
    };
    let port = proxy.port();
    status.lock().unwrap().proxy_port = Some(port);
    status.lock().unwrap().log(format!("Proxy listening on 127.0.0.1:{port}"));

    set_phase(Phase::StartingEmulator, &format!("Starting emulator {}", config.avd));
    let mut emulator = match Emulator::start(&sdk, &config.avd, port) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };

    {
        if is_cancelled() {
            return;
        }
        set_phase(Phase::WaitingForBoot, "Waiting for the emulator to boot");
        if let Err(e) = emulator.wait_for_boot(BOOT_TIMEOUT, &is_cancelled) {
            return fail(e);
        }
    }
    step!(Phase::EnablingRoot, "Enabling root access", emulator.enable_root());
    step!(
        Phase::EnablingRoot,
        "Routing traffic through the proxy",
        emulator.set_global_proxy(port)
    );
    step!(
        Phase::InstallingCa,
        "Installing the proxy CA certificate",
        emulator.install_ca(ca.ca_cert_pem().as_bytes(), &ca.android_cert_filename())
    );
    if !config.apks.is_empty() {
        step!(
            Phase::InstallingApp,
            "Installing the app",
            emulator.install_app(&config.apks)
        );
    }
    let needs_frida = !config.frida_scripts.is_empty();
    if let Some(package) = &config.package {
        if needs_frida {
            let install_frida = || -> Result<String, String> {
                {
                    let mut s = status.lock().unwrap();
                    for spec in &config.frida_scripts {
                        s.set_script_state(spec, ScriptState::Loading);
                    }
                }
                let abi = emulator.device_abi()?;
                let frida_abi = bypass::frida_abi(&abi)
                    .ok_or_else(|| format!("no frida gadget for this device ABI ({abi})"))?;
                let cache = bypass::cache_dir();
                status
                    .lock()
                    .unwrap()
                    .log("Downloading the frida gadget…".to_owned());
                let gadget = bypass::ensure_gadget(&cache, frida_abi)?;
                let mut loaded = Vec::with_capacity(config.frida_scripts.len());
                for spec in &config.frida_scripts {
                    status
                        .lock()
                        .unwrap()
                        .log(format!("Loading Frida script {spec}…"));
                    match bypass::load_script(&cache, spec) {
                        Ok((canonical, js)) => {
                            loaded.push((canonical, js));
                        }
                        Err(e) => {
                            status
                                .lock()
                                .unwrap()
                                .set_script_state(spec, ScriptState::Error(e.clone()));
                            return Err(e);
                        }
                    }
                }
                let combined = bypass::build_gadget_script(&loaded);
                emulator.clear_logcat();
                let res = emulator.install_frida_script(&gadget, package, &combined)?;
                {
                    let mut s = status.lock().unwrap();
                    for (canonical, _) in &loaded {
                        s.set_script_state(canonical, ScriptState::Injected);
                    }
                }
                Ok(res)
            };
            let label = format!("Injecting {} Frida script(s)", config.frida_scripts.len());
            step!(Phase::InstallingBypass, &label, install_frida());
        }
        step!(Phase::Launching, "Launching the app", emulator.launch(package));
    }

    set_phase(Phase::Capturing, "Capturing traffic");
    let mut frida_seen = 0usize;
    let mut tick = 0u32;
    while !is_cancelled() {
        std::thread::sleep(Duration::from_millis(200));
        tick = tick.wrapping_add(1);
        if needs_frida && tick % 3 == 0 {
            let lines = emulator.frida_log_lines();
            if lines.len() > frida_seen {
                let mut s = status.lock().unwrap();
                for line in &lines[frida_seen..] {
                    s.ingest_frida_line(line);
                }
                frida_seen = lines.len();
            }
        }
    }
    // Dropping `emulator` clears the proxy setting and shuts it down; dropping
    // `proxy` stops the listener.
    drop(emulator);
    drop(proxy);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_labels_and_activity() {
        assert_eq!(Phase::default(), Phase::Idle);
        assert!(Phase::Capturing.is_active());
        assert!(!Phase::Failed.is_active());
        assert!(!Phase::Idle.is_active());
        assert_eq!(Phase::InstallingCa.label(), "Installing the proxy certificate");
    }

    #[test]
    fn log_is_capped() {
        let mut status = Status::default();
        for i in 0..MAX_LOG + 20 {
            status.log(format!("line {i}"));
        }
        assert_eq!(status.log.len(), MAX_LOG);
        assert_eq!(status.log.last().unwrap().1, format!("line {}", MAX_LOG + 19));
    }

    #[test]
    fn start_without_sdk_reports_error() {
        let mut controller = NetworkController::new();
        controller.sdk = None;
        controller.start(StartConfig {
            avd: "x".into(),
            apks: vec![],
            package: None,
            frida_scripts: Vec::new(),
        });
        let (phase, error, _) = controller.status_snapshot();
        assert_eq!(phase, Phase::Failed);
        assert!(error.unwrap().contains("SDK"));
        assert!(!controller.is_running());
    }

    #[test]
    fn controller_exposes_ca_and_capture() {
        let controller = NetworkController::new();
        assert!(controller.ca_pem().contains("BEGIN CERTIFICATE"));
        assert!(controller.capture().is_empty());
    }

    #[test]
    fn ingests_frida_status_markers_and_messages() {
        let mut status = Status::default();
        let spec = "fdciabdul/frida-multiple-bypass";
        status.set_script_state(spec, ScriptState::Loading);
        status.ingest_frida_line(&format!("[bogusmips:script:start] {spec}"));
        assert_eq!(status.scripts[0].1, ScriptState::Injected);

        status.ingest_frida_line("[+] SSLContext");
        assert_eq!(status.scripts[0].1, ScriptState::Active { messages: 1 });

        status.ingest_frida_line(&format!("[bogusmips:script:ok] {spec}"));
        assert_eq!(status.scripts[0].1, ScriptState::Active { messages: 1 });

        status.ingest_frida_line("Unpinning setup completed");
        assert_eq!(status.scripts[0].1, ScriptState::Active { messages: 2 });
    }
}
