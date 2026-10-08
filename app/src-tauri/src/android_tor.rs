//! Android-owned Tor supervisor bridge.
//!
//! The Android side owns the native Tor worker and its foreground/lifecycle
//! policy. Rust owns the authenticated control connection, SAFECOOKIE policy,
//! listener discovery, bootstrap readiness and the generation-bound room lease.
//! There is intentionally no environment or system-Tor fallback in this
//! module.

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ghostchat::transport::{TorConfig, TorDaemon};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::{AppHandle, Manager, Runtime};

use super::TorLease;

const ANDROID_TOR_PLUGIN_ID: &str = "org.lord.ghostchat.tor";
const ANDROID_TOR_PLUGIN_CLASS: &str = "GhostChatTorPlugin";
const CONTROL_FILE_MAX_BYTES: u64 = 256;
const BOOTSTRAP_DEADLINE: Duration = Duration::from_secs(180);
const BOOTSTRAP_POLL_INTERVAL: Duration = Duration::from_millis(500);
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const START_WAIT_TIMEOUT: Duration = Duration::from_secs(200);
const STOP_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const COOKIE_BYTES: u64 = 32;

static GENERATION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AndroidTorStatus {
    Stopped,
    Starting(Option<u8>),
    Ready(u8),
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimePhase {
    Stopped,
    Starting,
    Ready,
    Stopping,
    Failed,
}

struct RuntimeState {
    phase: RuntimePhase,
    native_start_in_flight: bool,
    generation: Option<String>,
    daemon: Option<TorDaemon>,
    config: Option<TorConfig>,
    lease: Option<TorLease>,
    event_channel: Option<Channel<NativeTorEvent>>,
    progress: Option<u8>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            phase: RuntimePhase::Stopped,
            native_start_in_flight: false,
            generation: None,
            daemon: None,
            config: None,
            lease: None,
            event_channel: None,
            progress: None,
        }
    }
}

/// The plugin handle is only available on Android, so the manager remains
/// generic over the Tauri runtime while the room-facing lease is type-erased
/// by the parent app module.
pub(crate) struct AndroidTorManager<R: Runtime> {
    plugin: PluginHandle<R>,
    state: Arc<Mutex<RuntimeState>>,
    changed: Arc<Condvar>,
}

impl<R: Runtime> AndroidTorManager<R> {
    fn new(plugin: PluginHandle<R>) -> Self {
        Self {
            plugin,
            state: Arc::new(Mutex::new(RuntimeState::default())),
            changed: Arc::new(Condvar::new()),
        }
    }

    fn start_and_wait(&self) -> Result<(TorConfig, TorLease), String> {
        let mut discarded_lease = None;
        let stop_deadline = Instant::now() + STOP_WAIT_TIMEOUT;
        let (generation, start_new) = loop {
            let mut state = self.lock_state()?;
            match state.phase {
                RuntimePhase::Ready => {
                    let config = state.config.clone().ok_or_else(|| {
                        "Android Tor runtime has no managed configuration".to_string()
                    })?;
                    let lease = state
                        .lease
                        .clone()
                        .ok_or_else(|| "Android Tor runtime has no active lease".to_string())?;
                    return Ok((config, lease));
                }
                RuntimePhase::Starting => {
                    let generation = state.generation.clone().ok_or_else(|| {
                        "Android Tor runtime is starting without a generation".to_string()
                    })?;
                    if state.native_start_in_flight {
                        break (generation, false);
                    } else {
                        state.native_start_in_flight = true;
                        break (generation, true);
                    }
                }
                RuntimePhase::Stopping => {
                    let remaining = stop_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err("Android Tor runtime stop timed out".to_string());
                    }
                    let (state, result) = self
                        .changed
                        .wait_timeout(state, remaining)
                        .map_err(|_| "Android Tor runtime state is poisoned".to_string())?;
                    drop(state);
                    if result.timed_out() {
                        return Err("Android Tor runtime stop timed out".to_string());
                    }
                }
                RuntimePhase::Stopped | RuntimePhase::Failed => {
                    let generation = fresh_generation();
                    state.phase = RuntimePhase::Starting;
                    state.native_start_in_flight = true;
                    state.generation = Some(generation.clone());
                    state.daemon = None;
                    state.config = None;
                    state.event_channel = None;
                    discarded_lease = state.lease.take();
                    state.progress = None;
                    self.changed.notify_all();
                    break (generation, true);
                }
            }
        };
        drop(discarded_lease);

        // A concurrent room start shares this generation's startup instead of
        // racing a second worker into existence.
        if !start_new {
            return self.wait_until_ready(&generation);
        }

        let event_state = Arc::clone(&self.state);
        let event_changed = Arc::clone(&self.changed);
        let event_generation = generation.clone();
        let on_event = Channel::<NativeTorEvent>::new(move |body: InvokeResponseBody| {
            let Ok(event) = body.deserialize::<NativeTorEvent>() else {
                // Keep malformed native diagnostics bounded and do not
                // surface them to the UI or logs.
                return Ok(());
            };
            if event.generation != event_generation {
                return Ok(());
            }
            if matches!(event.event.as_str(), "failed" | "stopped") {
                if let Ok(mut state) = event_state.lock() {
                    if state.generation.as_deref() == Some(event.generation.as_str()) {
                        if state.phase != RuntimePhase::Stopping {
                            state.phase = RuntimePhase::Failed;
                            state.native_start_in_flight = false;
                            state.progress = None;
                            event_changed.notify_all();
                        }
                    }
                }
            }
            Ok(())
        });
        {
            let mut state = self.lock_state()?;
            if state.generation.as_deref() != Some(generation.as_str())
                || state.phase != RuntimePhase::Starting
            {
                return Err("Android Tor runtime generation changed before startup".to_string());
            }
            state.event_channel = Some(on_event.clone());
        }
        let request = NativeStartRequest {
            generation: generation.clone(),
            on_event,
        };
        let response = match self
            .plugin
            .run_mobile_plugin::<NativeStartResponse>("start", request)
        {
            Ok(response) => response,
            Err(error) => {
                log_android_tor_error(&format!("native start request failed: {error}"));
                self.fail_start(&generation, None);
                return Err(format!("Android Tor supervisor start failed: {error}"));
            }
        };

        let result = self.finish_start(&generation, response);
        if let Err(error) = &result {
            log_android_tor_error(&format!("runtime startup failed: {error}"));
            self.fail_start(&generation, None);
        }
        result
    }

    fn wait_until_ready(&self, generation: &str) -> Result<(TorConfig, TorLease), String> {
        let deadline = Instant::now() + START_WAIT_TIMEOUT;
        loop {
            let state = self.lock_state()?;
            if state.generation.as_deref() != Some(generation) {
                return Err("Android Tor runtime generation changed while starting".to_string());
            }
            match state.phase {
                RuntimePhase::Ready => {
                    let config = state.config.clone().ok_or_else(|| {
                        "Android Tor runtime has no managed configuration".to_string()
                    })?;
                    let lease = state
                        .lease
                        .clone()
                        .ok_or_else(|| "Android Tor runtime has no active lease".to_string())?;
                    return Ok((config, lease));
                }
                RuntimePhase::Failed | RuntimePhase::Stopped | RuntimePhase::Stopping => {
                    return Err("Android Tor runtime failed while starting".to_string());
                }
                RuntimePhase::Starting => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(state);
                self.fail_start(generation, None);
                return Err("Android Tor runtime bootstrap timed out".to_string());
            }
            let wait = self.changed.wait_timeout(state, remaining);
            match wait {
                Ok((state, result)) => {
                    drop(state);
                    if result.timed_out() {
                        self.fail_start(generation, None);
                        return Err("Android Tor runtime bootstrap timed out".to_string());
                    }
                }
                Err(_) => return Err("Android Tor runtime state is poisoned".to_string()),
            }
        }
    }

    fn finish_start(
        &self,
        generation: &str,
        response: NativeStartResponse,
    ) -> Result<(TorConfig, TorLease), String> {
        if response.generation != generation {
            return Err("Android Tor supervisor returned a stale generation".to_string());
        }
        if response.app_uid == 0 || response.app_uid != response.worker_uid {
            return Err("Android Tor supervisor UID boundary is invalid".to_string());
        }

        let paths = OwnedRuntimePaths::validate(&response)?;
        let control_addr = read_control_address(&paths.control_port_file)?;
        if !control_addr.ip().is_loopback() || control_addr.port() == 0 {
            return Err("Android Tor control endpoint is not a loopback TCP address".to_string());
        }

        let base_config = TorConfig::default()
            // Tor chooses the managed SOCKS listener. Port zero is only a
            // placeholder until authenticated GETINFO discovery below.
            .with_socks_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_control_addr(control_addr)
            .with_cookie_path(paths.cookie_path.clone())
            .require_safe_cookie();
        let daemon = TorDaemon::connect(base_config.clone())
            .map_err(|error| android_tor_error("control authentication", error))?;

        if let Err(error) = daemon.take_ownership() {
            daemon.shutdown();
            return Err(android_tor_error("control ownership", error));
        }
        let socks_addr = match daemon.socks_addr() {
            Ok(address) => address,
            Err(error) => {
                daemon.shutdown();
                return Err(android_tor_error("SOCKS listener discovery", error));
            }
        };
        {
            let mut state = self.lock_state()?;
            if state.generation.as_deref() != Some(generation)
                || state.phase != RuntimePhase::Starting
            {
                daemon.shutdown();
                return Err("Android Tor runtime generation changed during bootstrap".to_string());
            }
            state.daemon = Some(daemon.clone());
        }
        let progress = match self.wait_for_bootstrap(generation, &daemon) {
            Ok(progress) => progress,
            Err(error) => {
                daemon.shutdown();
                return Err(android_tor_error("Tor bootstrap", error));
            }
        };

        let runtime = Arc::new(AndroidTorLease {
            generation: generation.to_string(),
            daemon: daemon.clone(),
            plugin: self.plugin.clone(),
            state: Arc::clone(&self.state),
            changed: Arc::clone(&self.changed),
            released: AtomicBool::new(false),
            health: Mutex::new(None),
        });
        let stop_runtime = Arc::clone(&runtime);
        let health_runtime = Arc::clone(&runtime);
        let lease = TorLease::managed(
            move || stop_runtime.release(),
            move || health_runtime.is_healthy(),
        );
        let config = base_config.with_socks_addr(socks_addr);

        let generation_matches = {
            let mut state = self.lock_state()?;
            if state.generation.as_deref() != Some(generation)
                || state.phase != RuntimePhase::Starting
            {
                false
            } else {
                state.daemon = Some(daemon.clone());
                state.config = Some(config.clone());
                state.lease = Some(lease.clone());
                state.event_channel = None;
                state.progress = Some(progress);
                state.native_start_in_flight = false;
                state.phase = RuntimePhase::Ready;
                self.changed.notify_all();
                true
            }
        };
        if !generation_matches {
            drop(lease);
            return Err("Android Tor runtime generation changed during startup".to_string());
        }
        Ok((config, lease))
    }

    fn fail_start(&self, generation: &str, daemon: Option<TorDaemon>) {
        if let Some(daemon) = daemon {
            let _ = daemon.signal_shutdown();
            daemon.shutdown();
        }
        let _ = self.plugin.run_mobile_plugin::<NativeStopResponse>(
            "stop",
            NativeStopRequest {
                generation: generation.to_string(),
            },
        );
        let discarded_lease = if let Ok(mut state) = self.state.lock() {
            if state.generation.as_deref() == Some(generation) {
                state.phase = RuntimePhase::Failed;
                state.native_start_in_flight = false;
                state.generation = None;
                state.daemon = None;
                state.config = None;
                state.event_channel = None;
                let lease = state.lease.take();
                state.progress = None;
                self.changed.notify_all();
                lease
            } else {
                None
            }
        } else {
            None
        };
        drop(discarded_lease);
    }

    fn wait_for_bootstrap(
        &self,
        generation: &str,
        daemon: &TorDaemon,
    ) -> Result<u8, ghostchat::transport::TorError> {
        let deadline = Instant::now() + BOOTSTRAP_DEADLINE;
        loop {
            let progress = daemon.bootstrap_progress()?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| ghostchat::transport::TorError::Unavailable)?;
            if state.generation.as_deref() != Some(generation)
                || state.phase != RuntimePhase::Starting
            {
                return Err(ghostchat::transport::TorError::Unavailable);
            }
            state.progress = Some(progress);
            self.changed.notify_all();
            drop(state);

            if progress >= 100 {
                return Ok(progress);
            }
            if Instant::now() >= deadline {
                return Err(ghostchat::transport::TorError::Timeout);
            }
            thread::sleep(BOOTSTRAP_POLL_INTERVAL);
        }
    }

    fn status(&self) -> AndroidTorStatus {
        let (phase, generation, daemon, progress) = match self.state.lock() {
            Ok(state) => (
                state.phase,
                state.generation.clone(),
                state.daemon.clone(),
                state.progress,
            ),
            Err(_) => return AndroidTorStatus::Unavailable,
        };
        match phase {
            RuntimePhase::Starting => AndroidTorStatus::Starting(progress),
            RuntimePhase::Ready => {
                let Some(daemon) = daemon else {
                    return AndroidTorStatus::Unavailable;
                };
                match daemon.bootstrap_progress() {
                    Ok(value) if value >= 100 && generation.is_some() => {
                        if let Ok(mut state) = self.state.lock() {
                            if state.phase == RuntimePhase::Ready {
                                state.progress = Some(value);
                            }
                        }
                        AndroidTorStatus::Ready(value)
                    }
                    Ok(value) if value < 100 => AndroidTorStatus::Starting(Some(value)),
                    Ok(value) => AndroidTorStatus::Starting(Some(value)),
                    Err(_) => {
                        if let Ok(mut state) = self.state.lock() {
                            if state.phase == RuntimePhase::Ready {
                                state.phase = RuntimePhase::Failed;
                                state.native_start_in_flight = false;
                                self.changed.notify_all();
                            }
                        }
                        AndroidTorStatus::Unavailable
                    }
                }
            }
            RuntimePhase::Stopped | RuntimePhase::Failed => AndroidTorStatus::Stopped,
            RuntimePhase::Stopping => AndroidTorStatus::Unavailable,
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, RuntimeState>, String> {
        self.state
            .lock()
            .map_err(|_| "Android Tor runtime state is poisoned".to_string())
    }
}

/// Register the native plugin and make its Rust manager available to app
/// commands. The Java/Kotlin plugin must be non-exported and same-UID; Rust
/// validates the returned UID and private run metadata before use.
pub(crate) fn plugin<R: Runtime>() -> TauriPlugin<R> {
    Builder::<R>::new("android-tor")
        .setup(|app, api| {
            let handle =
                api.register_android_plugin(ANDROID_TOR_PLUGIN_ID, ANDROID_TOR_PLUGIN_CLASS)?;
            app.manage(AndroidTorManager::new(handle));
            Ok(())
        })
        .build()
}

pub(crate) fn acquire<R: Runtime>(app: &AppHandle<R>) -> Result<(TorConfig, TorLease), String> {
    let manager = app
        .try_state::<AndroidTorManager<R>>()
        .ok_or_else(|| "Android Tor supervisor plugin is unavailable".to_string())?;
    manager.start_and_wait()
}

pub(crate) fn status<R: Runtime>(app: &AppHandle<R>) -> AndroidTorStatus {
    app.try_state::<AndroidTorManager<R>>()
        .map(|manager| manager.status())
        .unwrap_or(AndroidTorStatus::Unavailable)
}

struct AndroidTorLease<R: Runtime> {
    generation: String,
    daemon: TorDaemon,
    plugin: PluginHandle<R>,
    state: Arc<Mutex<RuntimeState>>,
    changed: Arc<Condvar>,
    released: AtomicBool,
    health: Mutex<Option<(Instant, bool)>>,
}

impl<R: Runtime> AndroidTorLease<R> {
    fn is_healthy(&self) -> bool {
        if self.released.load(Ordering::Acquire) {
            return false;
        }
        let (phase, generation) = match self.state.lock() {
            Ok(state) => (state.phase, state.generation.clone()),
            Err(_) => return false,
        };
        if phase != RuntimePhase::Ready || generation.as_deref() != Some(self.generation.as_str()) {
            return false;
        }

        if let Ok(health) = self.health.lock() {
            if let Some((checked_at, value)) = *health {
                if checked_at.elapsed() < HEALTH_CHECK_INTERVAL {
                    return value;
                }
            }
        }

        let value = self
            .daemon
            .bootstrap_progress()
            .map(|progress| progress >= 100)
            .unwrap_or(false);
        if let Ok(mut health) = self.health.lock() {
            *health = Some((Instant::now(), value));
        }
        if !value {
            if let Ok(mut state) = self.state.lock() {
                if state.generation.as_deref() == Some(self.generation.as_str()) {
                    state.phase = RuntimePhase::Failed;
                    self.changed.notify_all();
                }
            }
        }
        value
    }

    fn release(&self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }

        if let Ok(mut state) = self.state.lock() {
            if state.generation.as_deref() == Some(self.generation.as_str()) {
                state.phase = RuntimePhase::Stopping;
                self.changed.notify_all();
            }
        }

        // TAKEOWNERSHIP makes this authenticated connection the supervisor.
        // SIGNAL SHUTDOWN is orderly; closing the connection is the bounded
        // fallback that also removes connection-owned onion services.
        let _ = self.daemon.signal_shutdown();
        self.daemon.shutdown();
        let response = self.plugin.run_mobile_plugin::<NativeStopResponse>(
            "stop",
            NativeStopRequest {
                generation: self.generation.clone(),
            },
        );
        let stop_confirmed = response
            .as_ref()
            .map(|response| response.generation == self.generation && response.stopped)
            .unwrap_or(false);

        let discarded_lease = if let Ok(mut state) = self.state.lock() {
            if state.generation.as_deref() == Some(self.generation.as_str()) {
                state.phase = if stop_confirmed {
                    RuntimePhase::Stopped
                } else {
                    RuntimePhase::Failed
                };
                state.native_start_in_flight = false;
                state.generation = None;
                state.daemon = None;
                state.config = None;
                state.event_channel = None;
                let lease = state.lease.take();
                state.progress = None;
                self.changed.notify_all();
                lease
            } else {
                None
            }
        } else {
            None
        };
        drop(discarded_lease);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeStartRequest {
    generation: String,
    on_event: Channel<NativeTorEvent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeStartResponse {
    generation: String,
    no_backup_dir: PathBuf,
    run_dir: PathBuf,
    control_port_file: PathBuf,
    cookie_path: PathBuf,
    app_uid: u32,
    worker_uid: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeStopRequest {
    generation: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeStopResponse {
    generation: String,
    stopped: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeTorEvent {
    generation: String,
    event: String,
}

struct OwnedRuntimePaths {
    control_port_file: PathBuf,
    cookie_path: PathBuf,
}

impl OwnedRuntimePaths {
    fn validate(response: &NativeStartResponse) -> Result<Self, String> {
        // Android owns the permissions on its noBackupFilesDir parent (often
        // 0771 inside the app sandbox). Enforce 0700 on the Tor generation
        // directory that contains runtime metadata and credentials.
        let no_backup_dir =
            canonical_directory(&response.no_backup_dir, response.app_uid, false)?;
        let run_dir = canonical_directory(&response.run_dir, response.app_uid, true)?;
        let expected_run_dir = no_backup_dir.join("tor/run").join(&response.generation);
        if run_dir != expected_run_dir {
            return Err("Android Tor run directory does not match its generation".to_string());
        }
        let control_port_file = canonical_private_file(
            &response.control_port_file,
            &run_dir,
            &run_dir.join("control.port"),
            CONTROL_FILE_MAX_BYTES,
            response.app_uid,
        )?;
        let cookie_path = canonical_private_file(
            &response.cookie_path,
            &run_dir,
            &run_dir.join("control.cookie"),
            COOKIE_BYTES,
            response.app_uid,
        )?;
        let cookie_metadata = fs::metadata(&cookie_path)
            .map_err(|_| "Android Tor cookie is unavailable".to_string())?;
        if cookie_metadata.len() != COOKIE_BYTES {
            return Err("Android Tor cookie must be exactly 32 bytes".to_string());
        }
        Ok(Self {
            control_port_file,
            cookie_path,
        })
    }
}

fn canonical_directory(
    path: &Path,
    expected_uid: u32,
    require_private_mode: bool,
) -> Result<PathBuf, String> {
    reject_relative_components(path)?;
    let canonical = fs::canonicalize(path)
        .map_err(|_| "Android Tor private runtime directory is unavailable".to_string())?;
    let metadata = fs::metadata(&canonical)
        .map_err(|_| "Android Tor private runtime directory is unavailable".to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != expected_uid
        || (require_private_mode && metadata.mode() & 0o077 != 0)
    {
        return Err("Android Tor runtime directory is not private".to_string());
    }
    Ok(canonical)
}

fn canonical_private_file(
    path: &Path,
    parent: &Path,
    expected_path: &Path,
    max_bytes: u64,
    expected_uid: u32,
) -> Result<PathBuf, String> {
    reject_relative_components(path)?;
    let canonical = fs::canonicalize(path)
        .map_err(|_| "Android Tor runtime metadata file is unavailable".to_string())?;
    if canonical != expected_path || !canonical.starts_with(parent) {
        return Err("Android Tor runtime metadata escaped its private run directory".to_string());
    }
    let metadata = fs::metadata(&canonical)
        .map_err(|_| "Android Tor runtime metadata file is unavailable".to_string())?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
        || metadata.uid() != expected_uid
    {
        return Err("Android Tor runtime metadata file has an invalid size".to_string());
    }
    if metadata.mode() & 0o077 != 0 {
        return Err("Android Tor runtime metadata file is not private".to_string());
    }
    Ok(canonical)
}

fn reject_relative_components(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("Android Tor runtime path is not absolute and canonical".to_string());
    }
    Ok(())
}

fn read_control_address(path: &Path) -> Result<SocketAddr, String> {
    let metadata = fs::metadata(path)
        .map_err(|_| "Android Tor control endpoint file is unavailable".to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > CONTROL_FILE_MAX_BYTES {
        return Err("Android Tor control endpoint file has an invalid size".to_string());
    }
    let bytes = fs::read(path)
        .map_err(|_| "Android Tor control endpoint file could not be read".to_string())?;
    if bytes.len() as u64 > CONTROL_FILE_MAX_BYTES || bytes.contains(&0) {
        return Err("Android Tor control endpoint file is malformed".to_string());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "Android Tor control endpoint file is not UTF-8".to_string())?;
    let mut lines = text.lines();
    let value = lines
        .next()
        .map(str::trim)
        .and_then(|line| {
            line.strip_prefix("ControlPort=")
                .or_else(|| line.strip_prefix("PORT="))
                .or(Some(line))
        })
        .map(str::trim)
        .ok_or_else(|| "Android Tor control endpoint file is empty".to_string())?;
    if lines.any(|line| !line.trim().is_empty()) {
        return Err("Android Tor control endpoint file has trailing data".to_string());
    }
    let value = value.trim_matches('"');
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| "Android Tor control endpoint file contains an invalid address".to_string())?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err("Android Tor control endpoint is not a loopback address".to_string());
    }
    Ok(address)
}

fn fresh_generation() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let counter = GENERATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:016x}{counter:016x}")
}

fn android_tor_error(operation: &str, error: ghostchat::transport::TorError) -> String {
    format!("Android Tor {operation} failed: {error}")
}

#[cfg(target_os = "android")]
#[link(name = "log")]
extern "C" {
    fn __android_log_write(priority: i32, tag: *const std::ffi::c_char, text: *const std::ffi::c_char) -> i32;
}

#[cfg(target_os = "android")]
fn log_android_tor_error(message: &str) {
    let Ok(tag) = std::ffi::CString::new("GhostChatTorRust") else {
        return;
    };
    let Ok(text) = std::ffi::CString::new(message) else {
        return;
    };
    unsafe {
        let _ = __android_log_write(6, tag.as_ptr(), text.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generations_are_lowercase_fixed_width_and_fresh() {
        let first = fresh_generation();
        let second = fresh_generation();
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_ne!(first, second);
    }

    #[test]
    fn control_file_parser_accepts_only_one_socket_address_line() {
        let path = std::env::temp_dir().join(format!(
            "ghostchat-android-control-{}-{}",
            std::process::id(),
            GENERATION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, b"127.0.0.1:12345\n").unwrap();
        let address = read_control_address(&path).unwrap();
        assert_eq!(address, SocketAddr::from(([127, 0, 0, 1], 12345)));
        fs::write(&path, b"PORT=127.0.0.1:12345\n").unwrap();
        assert_eq!(read_control_address(&path).unwrap().port(), 12345);
        fs::write(&path, b"10.0.0.1:12345\n").unwrap();
        assert!(read_control_address(&path).is_err());
        fs::write(&path, b"127.0.0.1:12345\nextra\n").unwrap();
        assert!(read_control_address(&path).is_err());
        let _ = fs::remove_file(path);
    }
}
