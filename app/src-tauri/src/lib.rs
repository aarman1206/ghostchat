use std::env;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(not(target_os = "android"))]
use ghostchat::transport::TorConfig;
#[cfg(not(target_os = "android"))]
use ghostchat::TorDaemon;
use ghostchat::{
    ChatMessage, LocalRoom, NetworkRoom, NetworkUiEvent, ParticipantId, RoomSnapshot,
    SessionConfig, TorInvitation,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime, State};

#[cfg(target_os = "android")]
mod android_tor;

// Core caps the encoded invitation at 8 KiB. The UI accepts its hexadecimal
// representation, which is two ASCII characters per encoded byte.
const MAX_INVITATION_TEXT_BYTES: usize = 2 * 8 * 1024;
const MAX_MESSAGE_CHARS: usize = 4_000;
const MAX_MESSAGE_BYTES: usize = MAX_MESSAGE_CHARS * 4;
const MAX_DISPLAY_NAME_BYTES: usize = 32 * 4;
const MAX_ROOM_NAME_BYTES: usize = 48 * 4;
const PARTICIPANT_ID_BYTES: usize = 66;
const SESSION_ID_BYTES: usize = 32;
const PUMP_TICK: Duration = Duration::from_millis(100);
const EXIT_CLEANUP_BUDGET: Duration = Duration::from_secs(2);

type SharedState = Arc<Mutex<AppStateInner>>;
type StopSignal = Arc<(Mutex<bool>, Condvar)>;

pub struct AppState {
    shared: SharedState,
    status_check_in_flight: Arc<AtomicBool>,
    snapshot_in_flight: Arc<AtomicBool>,
    operation_signal: Arc<Condvar>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(AppStateInner {
                room: None,
                current_participant: None,
                active_session_id: None,
                active_is_creator: None,
                scheduler: None,
                operation_in_flight: false,
                closing: false,
            })),
            status_check_in_flight: Arc::new(AtomicBool::new(false)),
            snapshot_in_flight: Arc::new(AtomicBool::new(false)),
            operation_signal: Arc::new(Condvar::new()),
        }
    }
}

struct AppStateInner {
    room: Option<ActiveRoom>,
    current_participant: Option<ParticipantId>,
    active_session_id: Option<String>,
    active_is_creator: Option<bool>,
    scheduler: Option<Scheduler>,
    operation_in_flight: bool,
    closing: bool,
}

/// A room-owned Tor runtime lease.
///
/// Desktop uses a no-op lease because the configured external daemon is not
/// owned by GhostChat. Android leases own one native supervisor generation;
/// all cloned room handles share the same idempotent stop and health state.
#[derive(Clone)]
struct TorLease {
    inner: Arc<TorLeaseInner>,
}

struct TorLeaseInner {
    released: AtomicBool,
    stop: Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    healthy: Box<dyn Fn() -> bool + Send + Sync + 'static>,
}

impl TorLease {
    #[cfg(not(target_os = "android"))]
    fn none() -> Self {
        Self {
            inner: Arc::new(TorLeaseInner {
                released: AtomicBool::new(false),
                stop: Mutex::new(Some(Box::new(|| {}))),
                healthy: Box::new(|| true),
            }),
        }
    }

    #[cfg(target_os = "android")]
    fn managed(
        stop: impl FnOnce() + Send + 'static,
        healthy: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(TorLeaseInner {
                released: AtomicBool::new(false),
                stop: Mutex::new(Some(Box::new(stop))),
                healthy: Box::new(healthy),
            }),
        }
    }

    fn release(&self) {
        if !self.inner.released.swap(true, Ordering::AcqRel) {
            let mut stop = match self.inner.stop.lock() {
                Ok(stop) => stop,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(stop) = stop.take() {
                stop();
            }
        }
    }

    fn is_healthy(&self) -> bool {
        !self.inner.released.load(Ordering::Acquire) && (self.inner.healthy)()
    }
}

impl Drop for TorLeaseInner {
    fn drop(&mut self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            let stop = match self.stop.get_mut() {
                Ok(stop) => stop,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(stop) = stop.take() {
                stop();
            }
        }
    }
}

/// A cloneable handle to the one room owned by the application.
///
/// The local variant is deliberately only reachable through the explicit
/// `GHOSTCHAT_TRANSPORT=local` setting in debug builds or a build with the
/// `local-transport` feature. Default release builds reject that setting and
/// never fall back from Tor after an error.
#[derive(Clone)]
enum ActiveRoom {
    Local(Arc<Mutex<LocalRoom>>),
    Network { room: NetworkRoom, tor: TorLease },
}

impl ActiveRoom {
    fn snapshot(&self, participant: Option<&ParticipantId>) -> Result<RoomSnapshot, String> {
        match self {
            Self::Local(room) => {
                let participant = participant.ok_or_else(|| "no active participant".to_string())?;
                let room = room
                    .lock()
                    .map_err(|_| "local room lock poisoned".to_string())?;
                room.snapshot(participant)
                    .map_err(|error| error.to_string())
            }
            Self::Network { room, .. } => room.snapshot().map_err(|error| error.to_string()),
        }
    }

    fn send_message(
        &self,
        participant: Option<&ParticipantId>,
        body: &str,
    ) -> Result<ChatMessage, String> {
        match self {
            Self::Local(room) => {
                let participant = participant.ok_or_else(|| "no active participant".to_string())?;
                let mut room = room
                    .lock()
                    .map_err(|_| "local room lock poisoned".to_string())?;
                room.send_message(participant, body)
                    .map_err(|error| error.to_string())
            }
            Self::Network { room, .. } => {
                room.send_message(body).map_err(|error| error.to_string())
            }
        }
    }

    fn advance_epoch(&self) -> Result<u64, String> {
        match self {
            Self::Local(room) => room
                .lock()
                .map_err(|_| "local room lock poisoned".to_string())?
                .advance_epoch()
                .map_err(|error| error.to_string()),
            Self::Network { room, .. } => room.advance_epoch().map_err(|error| error.to_string()),
        }
    }

    fn poll(&self) -> Result<Vec<NetworkUiEvent>, String> {
        match self {
            Self::Local(_) => Ok(Vec::new()),
            Self::Network { room, .. } => room.poll().map_err(|error| error.to_string()),
        }
    }

    fn is_creator(&self) -> Result<bool, String> {
        match self {
            Self::Local(_) => Ok(true),
            Self::Network { room, .. } => room.is_creator().map_err(|error| error.to_string()),
        }
    }

    fn remove_participant(&self, participant_id: &str) -> Result<(), String> {
        match self {
            Self::Local(_) => {
                Err("participant removal is only available for Tor rooms".to_string())
            }
            Self::Network { room, .. } => room
                .remove_participant(participant_id)
                .map_err(|error| error.to_string()),
        }
    }

    fn shutdown(&mut self) -> Result<(), String> {
        match self {
            Self::Local(room) => room
                .lock()
                .map_err(|_| "local room lock poisoned".to_string())?
                .shutdown()
                .map_err(|error| error.to_string()),
            Self::Network { room, tor } => {
                let result = room.shutdown().map_err(|error| error.to_string());
                tor.release();
                result
            }
        }
    }

    fn runtime_healthy(&self) -> bool {
        match self {
            Self::Local(_) => true,
            Self::Network { tor, .. } => tor.is_healthy(),
        }
    }
}

struct Scheduler {
    stop: Arc<AtomicBool>,
    signal: StopSignal,
    handle: Option<JoinHandle<()>>,
}

struct OperationGuard {
    shared: SharedState,
    signal: Arc<Condvar>,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.shared.lock() {
            inner.operation_in_flight = false;
            self.signal.notify_all();
        }
    }
}

struct InFlightLease(Arc<AtomicBool>);

impl InFlightLease {
    fn acquire(flag: &Arc<AtomicBool>) -> Result<Self, String> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "another GhostChat request is already in progress".to_string())?;
        Ok(Self(flag.clone()))
    }
}

impl Drop for InFlightLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct RoomReady {
    room: ActiveRoom,
    snapshot: RoomSnapshot,
    current_participant: Option<ParticipantId>,
    is_creator: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ErrorEvent {
    message: String,
    session_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct SessionEvent<T> {
    session_id: String,
    payload: T,
}

#[derive(Clone, Debug, Serialize)]
struct SessionEnded {
    session_id: String,
    state: &'static str,
    role: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct SendMessageResponse {
    message: ChatMessage,
    snapshot: RoomSnapshot,
}

#[derive(Clone, Debug, Serialize)]
struct AppStatus {
    /// `ready` means the private transport is bootstrapped; `stopped` means
    /// the Android-owned runtime is available to start for the first room.
    status: String,
    /// Internal transport state; the consumer UI exposes plain-language labels.
    tor: String,
    transport: String,
    connection_state: String,
    bootstrap_progress: Option<u8>,
}

#[tauri::command(rename_all = "snake_case")]
async fn app_status<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
) -> Result<AppStatus, String> {
    let lease = match InFlightLease::acquire(&state.status_check_in_flight) {
        Ok(lease) => lease,
        Err(_) => return Ok(status_check_in_progress()),
    };

    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        #[cfg(target_os = "android")]
        {
            android_status(&app)
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = app;
            status_blocking()
        }
    })
    .await
    .map_err(|_| "Tor status check failed".to_string())
}

#[tauri::command(rename_all = "snake_case")]
async fn create_room<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    display_name: String,
    room_name: Option<String>,
) -> Result<RoomSnapshot, String> {
    validate_display_name(&display_name)?;
    validate_room_name(room_name.as_deref())?;
    let shared = state.shared.clone();
    let operation = reserve_new_room(&shared, &state.operation_signal)?;

    tauri::async_runtime::spawn_blocking(move || {
        // The worker owns admission until ALL side effects and installation
        // finish, even if the IPC future is cancelled or its window disappears.
        let _operation = operation;
        prepare_new_room(&shared)?;
        #[cfg(target_os = "android")]
        let ready =
            create_room_blocking_android(&app, SessionConfig::default(), room_name, display_name)?;
        #[cfg(not(target_os = "android"))]
        let ready = create_room_blocking(SessionConfig::default(), room_name, display_name)?;
        install_room(&shared, &app, ready, SessionConfig::default())
    })
    .await
    .map_err(|_| "room creation task failed".to_string())?
}

/// Join a remote room through its signed Tor onion-service invitation.
#[tauri::command(rename_all = "snake_case")]
async fn join_room<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    display_name: String,
    invite_code: String,
) -> Result<RoomSnapshot, String> {
    validate_display_name(&display_name)?;
    validate_invitation_text(&invite_code)?;
    let shared = state.shared.clone();
    let operation = reserve_new_room(&shared, &state.operation_signal)?;

    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        prepare_new_room(&shared)?;
        #[cfg(target_os = "android")]
        let ready =
            join_room_blocking_android(&app, SessionConfig::default(), invite_code, display_name)?;
        #[cfg(not(target_os = "android"))]
        let ready = join_room_blocking(SessionConfig::default(), invite_code, display_name)?;
        install_room(&shared, &app, ready, SessionConfig::default())
    })
    .await
    .map_err(|_| "room join task failed".to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn get_session_snapshot(
    state: State<'_, AppState>,
    session_id: Option<String>,
) -> Result<RoomSnapshot, String> {
    let lease = InFlightLease::acquire(&state.snapshot_in_flight)?;
    let shared = state.shared.clone();
    let (room, participant) = clone_active_room(&shared, session_id.as_deref())?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        room.snapshot(participant.as_ref())
    })
    .await
    .map_err(|_| "snapshot task failed".to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn send_message<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    body: String,
    session_id: Option<String>,
) -> Result<SendMessageResponse, String> {
    validate_message_body(&body)?;
    let shared = state.shared.clone();
    let (operation, room, participant) = begin_room_operation(
        &shared,
        &state.operation_signal,
        session_id.as_deref(),
        false,
    )?;
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        let message = room.send_message(participant.as_ref(), &body)?;
        let snapshot = room.snapshot(participant.as_ref())?;
        emit_session_event(&app, "ghostchat://message", &snapshot.session_id, &message);
        emit_session_event(
            &app,
            "ghostchat://session-state",
            &snapshot.session_id,
            &snapshot,
        );
        Ok::<_, String>(SendMessageResponse { message, snapshot })
    })
    .await
    .map_err(|_| "message task failed; delivery is unknown".to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn advance_epoch<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    session_id: Option<String>,
) -> Result<RoomSnapshot, String> {
    let shared = state.shared.clone();
    let operation_signal = state.operation_signal.clone();
    let (operation, room, participant) =
        begin_room_operation(&shared, &operation_signal, session_id.as_deref(), true)?;

    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        if !room.is_creator()? {
            return Err("only the room owner can advance the MLS epoch".to_string());
        }
        room.advance_epoch()?;
        let snapshot = room.snapshot(participant.as_ref())?;
        emit_session_event(
            &app,
            "ghostchat://session-state",
            &snapshot.session_id,
            &snapshot,
        );
        Ok(snapshot)
    })
    .await
    .map_err(|_| "epoch task failed".to_string())?
}

#[tauri::command(rename_all = "snake_case")]
async fn remove_participant<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    participant_id: String,
    session_id: Option<String>,
) -> Result<RoomSnapshot, String> {
    validate_participant_id(&participant_id)?;
    let shared = state.shared.clone();
    let operation_signal = state.operation_signal.clone();
    let (operation, room, participant) =
        begin_room_operation(&shared, &operation_signal, session_id.as_deref(), true)?;

    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        if !room.is_creator()? {
            return Err("only the room owner can remove a participant".to_string());
        }
        if participant
            .as_ref()
            .is_some_and(|self_id| self_id.as_str() == participant_id)
        {
            return Err("the room owner cannot remove themselves".to_string());
        }
        room.remove_participant(&participant_id)?;
        let snapshot = room.snapshot(participant.as_ref())?;
        emit_session_event(
            &app,
            "ghostchat://session-state",
            &snapshot.session_id,
            &snapshot,
        );
        Ok(snapshot)
    })
    .await
    .map_err(|_| "participant removal task failed".to_string())?
}

/// End a room as its owner. Joiners must use `leave_session` so the UI and
/// lifecycle semantics remain explicit.
#[tauri::command(rename_all = "snake_case")]
async fn shutdown_session<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    session_id: Option<String>,
) -> Result<SessionEnded, String> {
    end_session(state, app, session_id, true).await
}

/// Leave a room as a joiner without presenting it as a host shutdown.
#[tauri::command(rename_all = "snake_case")]
async fn leave_session<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    session_id: Option<String>,
) -> Result<SessionEnded, String> {
    end_session(state, app, session_id, false).await
}

async fn end_session<R: Runtime>(
    state: State<'_, AppState>,
    app: AppHandle<R>,
    session_id: Option<String>,
    owner_action: bool,
) -> Result<SessionEnded, String> {
    let shared = state.shared.clone();
    let operation_signal = state.operation_signal.clone();
    let (operation, mut room, participant, scheduler, session_id) = take_room_for_end(
        &shared,
        &operation_signal,
        session_id.as_deref(),
        owner_action,
    )?;

    let role = if owner_action { "owner" } else { "joiner" };
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        stop_scheduler(scheduler);
        room.shutdown()?;
        // A NetworkRoom can expose its terminal, empty snapshot after close.
        // Emit it when available so consumers never retain stale participants
        // or messages. Local development rooms intentionally return closed
        // errors after teardown and use the SessionEnded event below.
        let terminal_snapshot = room.snapshot(participant.as_ref()).ok();
        let ended = SessionEnded {
            session_id,
            state: "closed",
            role,
        };
        if let Some(snapshot) = terminal_snapshot {
            emit_session_event(
                &app,
                "ghostchat://session-state",
                &ended.session_id,
                &snapshot,
            );
        }
        emit_session_event(&app, "ghostchat://session-state", &ended.session_id, &ended);
        Ok(ended)
    })
    .await
    .map_err(|_| "session shutdown task failed".to_string())?
}

#[cfg(not(target_os = "android"))]
fn create_room_blocking(
    config: SessionConfig,
    room_name: Option<String>,
    display_name: String,
) -> Result<RoomReady, String> {
    validate_display_name(&display_name)?;
    validate_room_name(room_name.as_deref())?;
    ensure_transport_allowed()?;
    if local_transport_enabled() {
        let room = LocalRoom::create(config, room_name, &display_name)
            .map_err(|error| error.to_string())?;
        let participant = room.creator_id();
        let snapshot = room
            .snapshot(&participant)
            .map_err(|error| error.to_string())?;
        return Ok(RoomReady {
            room: ActiveRoom::Local(Arc::new(Mutex::new(room))),
            snapshot,
            current_participant: Some(participant),
            is_creator: true,
        });
    }

    let tor = TorConfig::from_env().map_err(|error| error.to_string())?;
    let room = NetworkRoom::create_with_tor(config, tor, room_name, &display_name)
        .map_err(|error| error.to_string())?;
    let snapshot = room.snapshot().map_err(|error| error.to_string())?;
    Ok(RoomReady {
        room: ActiveRoom::Network {
            room,
            tor: TorLease::none(),
        },
        snapshot,
        current_participant: None,
        is_creator: true,
    })
}

#[cfg(not(target_os = "android"))]
fn join_room_blocking(
    config: SessionConfig,
    invite_code: String,
    display_name: String,
) -> Result<RoomReady, String> {
    validate_display_name(&display_name)?;
    ensure_transport_allowed()?;
    if local_transport_enabled() {
        return Err(
            "local development transport is host-only; unset GHOSTCHAT_TRANSPORT=local before joining"
                .to_string(),
        );
    }
    let invite_code = validate_invitation_text(&invite_code)?.to_string();
    let invitation = TorInvitation::decode_code(&invite_code).map_err(|error| error.to_string())?;
    let tor = TorConfig::from_env().map_err(|error| error.to_string())?;
    let room = NetworkRoom::join_with_tor(invitation, config, tor, &display_name)
        .map_err(|error| error.to_string())?;
    let snapshot = room.snapshot().map_err(|error| error.to_string())?;
    Ok(RoomReady {
        room: ActiveRoom::Network {
            room,
            tor: TorLease::none(),
        },
        snapshot,
        current_participant: None,
        is_creator: false,
    })
}

#[cfg(target_os = "android")]
fn create_room_blocking_android<R: Runtime>(
    app: &AppHandle<R>,
    config: SessionConfig,
    room_name: Option<String>,
    display_name: String,
) -> Result<RoomReady, String> {
    validate_display_name(&display_name)?;
    validate_room_name(room_name.as_deref())?;
    ensure_transport_allowed()?;
    if local_transport_enabled() {
        let room = LocalRoom::create(config, room_name, &display_name)
            .map_err(|error| error.to_string())?;
        let participant = room.creator_id();
        let snapshot = room
            .snapshot(&participant)
            .map_err(|error| error.to_string())?;
        return Ok(RoomReady {
            room: ActiveRoom::Local(Arc::new(Mutex::new(room))),
            snapshot,
            current_participant: Some(participant),
            is_creator: true,
        });
    }

    let (tor, lease) = android_tor::acquire(app)?;
    let room = NetworkRoom::create_with_tor(config, tor, room_name, &display_name)
        .map_err(|error| error.to_string())?;
    let snapshot = room.snapshot().map_err(|error| error.to_string())?;
    Ok(RoomReady {
        room: ActiveRoom::Network { room, tor: lease },
        snapshot,
        current_participant: None,
        is_creator: true,
    })
}

#[cfg(target_os = "android")]
fn join_room_blocking_android<R: Runtime>(
    app: &AppHandle<R>,
    config: SessionConfig,
    invite_code: String,
    display_name: String,
) -> Result<RoomReady, String> {
    validate_display_name(&display_name)?;
    ensure_transport_allowed()?;
    if local_transport_enabled() {
        return Err(
            "local development transport is host-only; unset GHOSTCHAT_TRANSPORT=local before joining"
                .to_string(),
        );
    }
    let invite_code = validate_invitation_text(&invite_code)?.to_string();
    let invitation = TorInvitation::decode_code(&invite_code).map_err(|error| error.to_string())?;
    let (tor, lease) = android_tor::acquire(app)?;
    let room = NetworkRoom::join_with_tor(invitation, config, tor, &display_name)
        .map_err(|error| error.to_string())?;
    let snapshot = room.snapshot().map_err(|error| error.to_string())?;
    Ok(RoomReady {
        room: ActiveRoom::Network { room, tor: lease },
        snapshot,
        current_participant: None,
        is_creator: false,
    })
}

fn install_room<R: Runtime>(
    shared: &SharedState,
    app: &AppHandle<R>,
    ready: RoomReady,
    config: SessionConfig,
) -> Result<RoomSnapshot, String> {
    let mut scheduler = Some(start_scheduler(
        shared.clone(),
        app.clone(),
        config.epoch_update_interval_secs,
    )?);
    let mut ready = Some(ready);
    let install_result = match shared.lock() {
        Err(_) => Err("application state lock poisoned".to_string()),
        Ok(mut inner) => {
            if inner.closing {
                Err("GhostChat is closing".to_string())
            } else if inner.room.is_some() {
                Err(
                    "a GhostChat room is already active; leave it before creating another"
                        .to_string(),
                )
            } else {
                let ready = ready.take().expect("room install value is present");
                inner.active_session_id = Some(ready.snapshot.session_id.clone());
                inner.active_is_creator = Some(ready.is_creator);
                inner.current_participant = ready.current_participant;
                let snapshot = ready.snapshot.clone();
                inner.room = Some(ready.room);
                inner.scheduler = scheduler.take();
                Ok(snapshot)
            }
        }
    };

    match install_result {
        Ok(snapshot) => Ok(snapshot),
        Err(error) => {
            stop_scheduler(scheduler.take());
            if let Some(mut ready) = ready {
                let _ = ready.room.shutdown();
            }
            Err(error)
        }
    }
}

fn reserve_new_room(shared: &SharedState, signal: &Arc<Condvar>) -> Result<OperationGuard, String> {
    let mut inner = shared
        .lock()
        .map_err(|_| "application state lock poisoned".to_string())?;
    if inner.closing {
        return Err("GhostChat is closing".to_string());
    }
    if inner.operation_in_flight {
        return Err("another GhostChat operation is already in progress".to_string());
    }
    inner.operation_in_flight = true;
    Ok(OperationGuard {
        shared: shared.clone(),
        signal: signal.clone(),
    })
}

/// Complete admission checks on the same blocking worker that owns the guard.
/// This keeps a cancelled IPC future from clearing `operation_in_flight` while
/// room teardown or a terminal-room probe is still running.
fn prepare_new_room(shared: &SharedState) -> Result<(), String> {
    let candidate = {
        let inner = shared
            .lock()
            .map_err(|_| "application state lock poisoned".to_string())?;
        if inner.closing {
            return Err("GhostChat is closing".to_string());
        }
        inner.room.as_ref().map(|room| {
            (
                room.clone(),
                inner.current_participant.clone(),
                inner.active_session_id.clone(),
            )
        })
    };

    if let Some((room, participant, session_id)) = candidate {
        let terminal = room
            .snapshot(participant.as_ref())
            .map(|snapshot| snapshot_is_terminal(&snapshot))
            .unwrap_or(false);
        if !terminal {
            return Err(
                "a GhostChat room is already active; leave it before creating another".to_string(),
            );
        }

        if let Some(session_id) = session_id {
            release_terminal_room(shared, &session_id);
        }
    }

    if let Some(scheduler) = take_scheduler_for_reap(shared) {
        stop_scheduler(Some(scheduler));
    }

    let inner = shared
        .lock()
        .map_err(|_| "application state lock poisoned".to_string())?;
    if inner.closing {
        Err("GhostChat is closing".to_string())
    } else if inner.room.is_some() {
        Err("a GhostChat room is already active; leave it before creating another".to_string())
    } else {
        Ok(())
    }
}

fn begin_room_operation(
    shared: &SharedState,
    signal: &Arc<Condvar>,
    session_id: Option<&str>,
    creator_action: bool,
) -> Result<(OperationGuard, ActiveRoom, Option<ParticipantId>), String> {
    let mut inner = shared
        .lock()
        .map_err(|_| "application state lock poisoned".to_string())?;
    if inner.closing {
        return Err("GhostChat is closing".to_string());
    }
    if inner.operation_in_flight {
        return Err("another GhostChat operation is already in progress".to_string());
    }
    validate_session_id(inner.active_session_id.as_deref(), session_id)?;
    if creator_action && inner.active_is_creator != Some(true) {
        return Err("only the room owner can perform this action".to_string());
    }
    let room = inner
        .room
        .as_ref()
        .ok_or_else(|| "no active GhostChat session".to_string())?
        .clone();
    let participant = inner.current_participant.clone();
    inner.operation_in_flight = true;
    Ok((
        OperationGuard {
            shared: shared.clone(),
            signal: signal.clone(),
        },
        room,
        participant,
    ))
}

fn clone_active_room(
    shared: &SharedState,
    session_id: Option<&str>,
) -> Result<(ActiveRoom, Option<ParticipantId>), String> {
    let inner = shared
        .lock()
        .map_err(|_| "application state lock poisoned".to_string())?;
    validate_session_id(inner.active_session_id.as_deref(), session_id)?;
    let room = inner
        .room
        .as_ref()
        .ok_or_else(|| "no active GhostChat session".to_string())?
        .clone();
    Ok((room, inner.current_participant.clone()))
}

type RoomEndOperation = (
    OperationGuard,
    ActiveRoom,
    Option<ParticipantId>,
    Option<Scheduler>,
    String,
);

fn take_room_for_end(
    shared: &SharedState,
    signal: &Arc<Condvar>,
    session_id: Option<&str>,
    owner_action: bool,
) -> Result<RoomEndOperation, String> {
    let mut inner = shared
        .lock()
        .map_err(|_| "application state lock poisoned".to_string())?;
    if inner.closing {
        return Err("GhostChat is closing".to_string());
    }
    if inner.operation_in_flight {
        return Err("another GhostChat operation is already in progress".to_string());
    }
    validate_session_id(inner.active_session_id.as_deref(), session_id)?;
    let is_creator = inner.active_is_creator.unwrap_or(false);
    if is_creator != owner_action {
        return Err(if owner_action {
            "only the room owner can end the room; use Leave room instead".to_string()
        } else {
            "the room owner must end the room; joiners use Leave room".to_string()
        });
    }
    let active_session_id = inner
        .active_session_id
        .clone()
        .ok_or_else(|| "no active GhostChat session".to_string())?;
    let room = inner
        .room
        .take()
        .ok_or_else(|| "no active GhostChat session".to_string())?;
    let participant = inner.current_participant.take();
    inner.active_is_creator = None;
    let scheduler = inner.scheduler.take();
    inner.active_session_id = None;
    inner.operation_in_flight = true;
    Ok((
        OperationGuard {
            shared: shared.clone(),
            signal: signal.clone(),
        },
        room,
        participant,
        scheduler,
        active_session_id,
    ))
}

fn validate_session_id(expected: Option<&str>, provided: Option<&str>) -> Result<(), String> {
    let provided = provided.ok_or_else(|| "session identifier is required".to_string())?;
    validate_session_id_value(provided)?;
    if expected != Some(provided) {
        return Err("session id does not match the active room".to_string());
    }
    Ok(())
}

fn start_scheduler<R: Runtime>(
    shared: SharedState,
    app: AppHandle<R>,
    interval_secs: u64,
) -> Result<Scheduler, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let signal: StopSignal = Arc::new((Mutex::new(false), Condvar::new()));
    let thread_stop = stop.clone();
    let thread_signal = signal.clone();
    let interval = Duration::from_secs(interval_secs.max(1));
    let handle = thread::Builder::new()
        .name("ghostchat-network-pump".to_string())
        .spawn(move || {
            let mut next_epoch = Instant::now() + interval;
            let mut last_snapshot_fingerprint = None;
            let mut last_snapshot_error = None;
            loop {
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                let wait = next_epoch
                    .saturating_duration_since(Instant::now())
                    .min(PUMP_TICK);
                let (lock, condvar) = &*thread_signal;
                let stopped = match lock.lock() {
                    Ok(stopped) => stopped,
                    Err(_) => break,
                };
                let (stopped, _) = match condvar.wait_timeout(stopped, wait) {
                    Ok(result) => result,
                    Err(_) => break,
                };
                if *stopped || thread_stop.load(Ordering::Acquire) {
                    break;
                }
                drop(stopped);

                let (Some(mut room), participant, Some(session_id)) =
                    (match clone_active_for_pump(&shared) {
                        Ok(value) => value,
                        Err(_) => break,
                    })
                else {
                    continue;
                };

                if !room.runtime_healthy() {
                    let _ = room.shutdown();
                    emit_session_error(&app, &session_id, "Tor runtime stopped");
                    if let Ok(snapshot) = room.snapshot(participant.as_ref()) {
                        emit_session_event(
                            &app,
                            "ghostchat://session-state",
                            &session_id,
                            &snapshot,
                        );
                    }
                    release_terminal_room(&shared, &session_id);
                    break;
                }

                match room.poll() {
                    Ok(events) => emit_network_events(&app, &session_id, events),
                    Err(error) => emit_session_error(&app, &session_id, error),
                }

                // A joiner's MLS Welcome can be processed without producing a
                // user-visible NetworkUiEvent. Compare UI metadata from the
                // complete snapshot so the UI still unlocks chat and clears
                // terminal participant/message lists promptly.
                match room.snapshot(participant.as_ref()) {
                    Ok(snapshot) => {
                        last_snapshot_error = None;
                        let fingerprint = snapshot_fingerprint(&snapshot);
                        if last_snapshot_fingerprint != Some(fingerprint) {
                            emit_session_event(
                                &app,
                                "ghostchat://session-state",
                                &session_id,
                                &snapshot,
                            );
                            last_snapshot_fingerprint = Some(fingerprint);
                        }
                        if snapshot_is_terminal(&snapshot) {
                            // The terminal snapshot is emitted before the
                            // room is detached so the UI can clear its view.
                            // Detachment only changes app state; the current
                            // pump exits and its handle is reaped by the next
                            // room operation or process shutdown.
                            release_terminal_room(&shared, &snapshot.session_id);
                            break;
                        }
                    }
                    Err(error) => {
                        if last_snapshot_error.as_deref() != Some(error.as_str()) {
                            emit_session_error(&app, &session_id, error.clone());
                            last_snapshot_error = Some(error);
                        }
                    }
                }

                if Instant::now() >= next_epoch {
                    let should_advance = room.is_creator().unwrap_or(false);
                    if should_advance {
                        match room.advance_epoch() {
                            Ok(_) => match room.snapshot(participant.as_ref()) {
                                Ok(snapshot) => {
                                    emit_session_event(
                                        &app,
                                        "ghostchat://session-state",
                                        &session_id,
                                        &snapshot,
                                    );
                                }
                                Err(error) => emit_session_error(&app, &session_id, error),
                            },
                            Err(error) => emit_session_error(&app, &session_id, error),
                        }
                    }
                    next_epoch = Instant::now() + interval;
                }
            }
        })
        .map_err(|error| format!("could not start GhostChat network pump: {error}"))?;

    Ok(Scheduler {
        stop,
        signal,
        handle: Some(handle),
    })
}

type PumpRoom = (Option<ActiveRoom>, Option<ParticipantId>, Option<String>);

fn clone_active_for_pump(shared: &SharedState) -> Result<PumpRoom, String> {
    let inner = shared
        .lock()
        .map_err(|_| "application state lock poisoned".to_string())?;
    Ok((
        inner.room.clone(),
        inner.current_participant.clone(),
        inner.active_session_id.clone(),
    ))
}

fn snapshot_is_terminal(snapshot: &RoomSnapshot) -> bool {
    [
        &snapshot.state,
        &snapshot.connection_state,
        &snapshot.tor_state,
    ]
    .iter()
    .any(|state| {
        matches!(
            state.trim().to_ascii_lowercase().as_str(),
            "closed" | "ended" | "shutdown" | "stopped" | "disconnected"
        )
    })
}

/// Release a terminal room without joining the pump from the pump thread.
/// The stopped scheduler remains in application state until a command or
/// process shutdown can reap its handle on a different thread.
fn release_terminal_room(shared: &SharedState, session_id: &str) -> bool {
    let room = match shared.lock() {
        Ok(mut inner) => {
            if inner.active_session_id.as_deref() != Some(session_id) {
                return false;
            }
            let room = inner.room.take();
            if room.is_none() {
                return false;
            }
            inner.active_session_id = None;
            inner.active_is_creator = None;
            inner.current_participant = None;
            if let Some(scheduler) = inner.scheduler.as_ref() {
                request_scheduler_stop(scheduler);
            }
            room
        }
        Err(_) => return false,
    };
    drop(room);
    true
}

fn take_scheduler_for_reap(shared: &SharedState) -> Option<Scheduler> {
    let mut inner = shared.lock().ok()?;
    if inner.room.is_none() {
        inner.scheduler.take()
    } else {
        None
    }
}

fn snapshot_fingerprint(snapshot: &RoomSnapshot) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    snapshot.state.hash(&mut hasher);
    snapshot.encryption_active.hash(&mut hasher);
    snapshot.connection_state.hash(&mut hasher);
    snapshot.transport.hash(&mut hasher);
    snapshot.tor_state.hash(&mut hasher);
    snapshot.invite_code.hash(&mut hasher);
    snapshot.epoch.hash(&mut hasher);
    snapshot.participants.len().hash(&mut hasher);
    for participant in &snapshot.participants {
        participant.id.hash(&mut hasher);
        participant.display_name.hash(&mut hasher);
        participant.state.hash(&mut hasher);
        participant.is_self.hash(&mut hasher);
    }
    snapshot.messages.len().hash(&mut hasher);
    if let Some(message) = snapshot.messages.last() {
        message.id.hash(&mut hasher);
        message.sender_id.hash(&mut hasher);
        message.body.hash(&mut hasher);
    }
    hasher.finish()
}

fn stop_scheduler(scheduler: Option<Scheduler>) {
    let Some(mut scheduler) = scheduler else {
        return;
    };
    request_scheduler_stop(&scheduler);
    if let Some(handle) = scheduler.handle.take() {
        // A future cleanup path may be reached from the pump itself. Never
        // self-join; the handle will be reaped by a later owner-thread path.
        if handle.thread().id() != thread::current().id() {
            let _ = handle.join();
        }
    }
}

fn request_scheduler_stop(scheduler: &Scheduler) {
    scheduler.stop.store(true, Ordering::Release);
    if let Ok(mut stopped) = scheduler.signal.0.lock() {
        *stopped = true;
        scheduler.signal.1.notify_one();
    }
}

fn emit_session_error<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    message: impl Into<String>,
) {
    let _ = app.emit(
        "ghostchat://error",
        ErrorEvent {
            message: message.into(),
            session_id: session_id.to_string(),
        },
    );
}

fn emit_network_events<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
    events: Vec<NetworkUiEvent>,
) {
    for event in events {
        match event {
            NetworkUiEvent::Message(message) => {
                emit_session_event(app, "ghostchat://message", session_id, &message);
            }
            NetworkUiEvent::Participant(participant) => {
                let is_offline = matches!(
                    participant.state.as_str(),
                    "offline" | "left" | "disconnected"
                );
                let event_name = if is_offline {
                    "ghostchat://participant-left"
                } else {
                    "ghostchat://participant-joined"
                };
                emit_session_event(app, event_name, session_id, &participant);
            }
            NetworkUiEvent::State(snapshot) => {
                if snapshot.session_id == session_id {
                    emit_session_event(app, "ghostchat://session-state", session_id, &snapshot);
                }
            }
            NetworkUiEvent::Error(message) => emit_session_error(app, session_id, message),
        }
    }
}

fn emit_session_event<R: Runtime, T: Serialize>(
    app: &AppHandle<R>,
    name: &str,
    session_id: &str,
    payload: &T,
) {
    let _ = app.emit(
        name,
        SessionEvent {
            session_id: session_id.to_string(),
            payload,
        },
    );
}

#[cfg(not(target_os = "android"))]
fn status_blocking() -> AppStatus {
    if local_transport_requested() && !local_transport_enabled() {
        return unavailable_status("local transport is disabled in release builds");
    }
    if local_transport_enabled() {
        return AppStatus {
            status: "ready".to_string(),
            tor: "disabled".to_string(),
            transport: "local-development".to_string(),
            connection_state: "ready".to_string(),
            bootstrap_progress: None,
        };
    }

    let config = match TorConfig::from_env() {
        Ok(config) => config,
        Err(error) => return unavailable_status(&error.to_string()),
    };
    let daemon = match TorDaemon::connect(config) {
        Ok(daemon) => daemon,
        Err(error) => return unavailable_status(&error.to_string()),
    };
    let progress = match daemon.bootstrap_progress() {
        Ok(progress) => progress,
        Err(error) => return unavailable_status(&error.to_string()),
    };
    if progress >= 100 {
        AppStatus {
            status: "ready".to_string(),
            tor: "available".to_string(),
            transport: "tor-onion-service".to_string(),
            connection_state: "ready".to_string(),
            bootstrap_progress: Some(progress),
        }
    } else {
        AppStatus {
            status: "connecting".to_string(),
            tor: "connecting".to_string(),
            transport: "tor-only".to_string(),
            connection_state: "waiting".to_string(),
            bootstrap_progress: Some(progress),
        }
    }
}

#[cfg(target_os = "android")]
fn android_status<R: Runtime>(app: &AppHandle<R>) -> AppStatus {
    if local_transport_requested() && !local_transport_enabled() {
        return unavailable_status("local transport is disabled in release builds");
    }
    if local_transport_enabled() {
        return AppStatus {
            status: "ready".to_string(),
            tor: "disabled".to_string(),
            transport: "local-development".to_string(),
            connection_state: "ready".to_string(),
            bootstrap_progress: None,
        };
    }
    match android_tor::status(app) {
        android_tor::AndroidTorStatus::Stopped => AppStatus {
            status: "stopped".to_string(),
            tor: "stopped".to_string(),
            transport: "tor-only".to_string(),
            connection_state: "stopped".to_string(),
            bootstrap_progress: None,
        },
        android_tor::AndroidTorStatus::Ready(progress) => AppStatus {
            status: "ready".to_string(),
            tor: "available".to_string(),
            transport: "tor-onion-service".to_string(),
            connection_state: "ready".to_string(),
            bootstrap_progress: Some(progress),
        },
        android_tor::AndroidTorStatus::Starting(progress) => AppStatus {
            status: "connecting".to_string(),
            tor: "connecting".to_string(),
            transport: "tor-only".to_string(),
            connection_state: "starting".to_string(),
            bootstrap_progress: progress,
        },
        android_tor::AndroidTorStatus::Unavailable => {
            unavailable_status("managed Android Tor runtime unavailable")
        }
    }
}

fn status_check_in_progress() -> AppStatus {
    if local_transport_requested() && !local_transport_enabled() {
        return unavailable_status("local transport is disabled in release builds");
    }
    if local_transport_enabled() {
        return AppStatus {
            status: "ready".to_string(),
            tor: "disabled".to_string(),
            transport: "local-development".to_string(),
            connection_state: "ready".to_string(),
            bootstrap_progress: None,
        };
    }
    AppStatus {
        status: "connecting".to_string(),
        tor: "connecting".to_string(),
        transport: "tor-only".to_string(),
        connection_state: "checking".to_string(),
        bootstrap_progress: None,
    }
}

fn unavailable_status(_message: &str) -> AppStatus {
    // Deliberately do not include daemon error text in the status payload. It
    // can mention local paths; the UI only needs the actionable state. Command
    // errors are still returned to the caller of the operation that failed.
    AppStatus {
        status: "unavailable".to_string(),
        tor: "unavailable".to_string(),
        transport: "tor-only".to_string(),
        connection_state: "unavailable".to_string(),
        bootstrap_progress: None,
    }
}

fn local_transport_enabled() -> bool {
    local_transport_allowed(
        cfg!(debug_assertions),
        cfg!(feature = "local-transport"),
        local_transport_requested(),
    )
}

fn local_transport_allowed(debug_build: bool, feature_enabled: bool, requested: bool) -> bool {
    requested && (debug_build || feature_enabled)
}

fn local_transport_requested() -> bool {
    env::var("GHOSTCHAT_TRANSPORT")
        .map(|value| value.trim().eq_ignore_ascii_case("local"))
        .unwrap_or(false)
}

fn ensure_transport_allowed() -> Result<(), String> {
    if local_transport_requested() && !local_transport_enabled() {
        return Err(
            "local development transport is disabled in release builds; use the Tor transport"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), String> {
    if value.len() > MAX_DISPLAY_NAME_BYTES || value.chars().any(char::is_control) {
        return Err("display name must be 1-32 non-control characters".to_string());
    }
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_DISPLAY_NAME_BYTES
        || value.chars().count() > 32
        || value.chars().any(char::is_control)
    {
        return Err("display name must be 1-32 non-control characters".to_string());
    }
    Ok(())
}

fn validate_room_name(value: Option<&str>) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() > MAX_ROOM_NAME_BYTES || value.chars().any(char::is_control) {
        return Err("room name must be 1-48 non-control characters".to_string());
    }
    let value = value.trim();
    if value.is_empty() {
        return Err("room name must not be empty when provided".to_string());
    }
    if value.len() > MAX_ROOM_NAME_BYTES
        || value.chars().count() > 48
        || value.chars().any(char::is_control)
    {
        return Err("room name must be 1-48 non-control characters".to_string());
    }
    Ok(())
}

fn validate_message_body(value: &str) -> Result<(), String> {
    if value.len() > MAX_MESSAGE_BYTES {
        return Err("message must be 16,000 bytes or fewer".to_string());
    }
    let value = value.trim();
    if value.is_empty() {
        return Err("message must not be empty".to_string());
    }
    if value.len() > MAX_MESSAGE_BYTES || value.chars().count() > MAX_MESSAGE_CHARS {
        return Err("message must be 4,000 characters or fewer".to_string());
    }
    if value.chars().any(char::is_control) {
        return Err("message must not contain control characters".to_string());
    }
    Ok(())
}

fn validate_participant_id(value: &str) -> Result<(), String> {
    if value.len() != PARTICIPANT_ID_BYTES
        || !value.starts_with("p-")
        || !value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("participant identifier is invalid".to_string());
    }
    Ok(())
}

fn validate_session_id_value(value: &str) -> Result<(), String> {
    if value.len() != SESSION_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("session identifier is invalid".to_string());
    }
    Ok(())
}

fn validate_invitation_text(value: &str) -> Result<&str, String> {
    if value.len() > MAX_INVITATION_TEXT_BYTES {
        return Err("invite codes must be 16 KiB or smaller".to_string());
    }
    let value = value.trim();
    if value.is_empty() {
        return Err("paste an invite code before joining".to_string());
    }
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invite codes must contain hexadecimal pairs".to_string());
    }
    Ok(value)
}

fn cleanup_on_exit(shared: &SharedState, operation_signal: &Arc<Condvar>) {
    cleanup_on_exit_with_budget(shared, operation_signal, EXIT_CLEANUP_BUDGET);
}

fn cleanup_on_exit_with_budget(
    shared: &SharedState,
    operation_signal: &Arc<Condvar>,
    budget: Duration,
) {
    let deadline = Instant::now() + budget;
    let Some(mut inner) = lock_until(shared, deadline) else {
        return;
    };
    if inner.closing {
        return;
    }
    inner.closing = true;
    inner.active_session_id = None;
    inner.active_is_creator = None;
    inner.current_participant = None;
    let scheduler = inner.scheduler.take();
    let room = inner.room.take();
    drop(inner);

    // Joining a pump or closing a Tor room can wait on room I/O. Keep those
    // waits off the exit callback and spend ONE total deadline, including the
    // in-flight operation wait. Process exit closes remaining Tor sockets.
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let _cleanup = thread::Builder::new()
        .name("ghostchat-exit-cleanup".to_string())
        .spawn(move || {
            stop_scheduler(scheduler);
            if let Some(mut room) = room {
                let _ = room.shutdown();
            }
            let _ = done_tx.send(());
        });
    let _ = done_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));

    // The worker still owns its operation guard if its IPC caller disappeared.
    // An in-progress create/join sees `closing` and tears down its own room.
    let Some(mut inner) = lock_until(shared, deadline) else {
        return;
    };
    while inner.operation_in_flight {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        inner = match operation_signal.wait_timeout(inner, remaining) {
            Ok((inner, _)) => inner,
            Err(_) => return,
        };
    }
}

fn lock_until(shared: &SharedState, deadline: Instant) -> Option<MutexGuard<'_, AppStateInner>> {
    loop {
        match shared.try_lock() {
            Ok(inner) => return Some(inner),
            Err(TryLockError::Poisoned(_)) => return None,
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => return None,
        }
    }
}

fn is_app_navigation(url: &tauri::Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return false;
    }
    matches!(
        (url.scheme(), url.host_str()),
        ("tauri", Some("localhost")) | ("http" | "https", Some("tauri.localhost"))
    )
}

fn configure_app<R: Runtime>(builder: tauri::Builder<R>, state: AppState) -> tauri::Builder<R> {
    let builder = builder.manage(state).plugin(
        tauri::plugin::Builder::<R>::new("local-navigation")
            .on_navigation(|_, url| is_app_navigation(url))
            .build(),
    );

    #[cfg(target_os = "android")]
    let builder = builder.plugin(android_tor::plugin());

    builder.invoke_handler(tauri::generate_handler![
        app_status,
        create_room,
        join_room,
        get_session_snapshot,
        send_message,
        advance_epoch,
        remove_participant,
        shutdown_session,
        leave_session
    ])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::default();
    let exit_shared = state.shared.clone();
    let exit_operation_signal = state.operation_signal.clone();

    let app = configure_app(tauri::Builder::default(), state)
        .build(tauri::generate_context!())
        .expect("error while running GhostChat");

    app.run(move |_app, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            cleanup_on_exit(&exit_shared, &exit_operation_signal);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    static TRANSPORT_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TransportEnv(Option<std::ffi::OsString>);

    impl TransportEnv {
        fn local() -> Self {
            let previous = env::var_os("GHOSTCHAT_TRANSPORT");
            env::set_var("GHOSTCHAT_TRANSPORT", "local");
            Self(previous)
        }
    }

    impl Drop for TransportEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => env::set_var("GHOSTCHAT_TRANSPORT", value),
                None => env::remove_var("GHOSTCHAT_TRANSPORT"),
            }
        }
    }

    #[test]
    fn navigation_is_restricted_to_the_packaged_app_origin() {
        for url in [
            "tauri://localhost/index.html",
            "http://tauri.localhost",
            "https://tauri.localhost",
        ] {
            assert!(is_app_navigation(&url.parse().unwrap()));
        }
        for url in [
            "https://example.com",
            "http://localhost:3000",
            "tauri://example.com",
            "data:text/html,hello",
            "http://tauri.localhost:1234",
            "https://tauri.localhost.example.com",
            "http://user@tauri.localhost",
        ] {
            assert!(!is_app_navigation(&url.parse().unwrap()));
        }
    }

    struct TestCleanup {
        shared: SharedState,
        signal: Arc<Condvar>,
    }

    impl Drop for TestCleanup {
        fn drop(&mut self) {
            cleanup_on_exit(&self.shared, &self.signal);
        }
    }

    fn ipc_app(state: AppState) -> (tauri::App<tauri::test::MockRuntime>, TestCleanup) {
        let cleanup = TestCleanup {
            shared: state.shared.clone(),
            signal: state.operation_signal.clone(),
        };
        let app = configure_app(tauri::test::mock_builder(), state)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        (app, cleanup)
    }

    fn ipc(
        window: &tauri::WebviewWindow<tauri::test::MockRuntime>,
        command: &str,
        args: Value,
    ) -> Result<Value, Value> {
        tauri::test::get_ipc_response(
            window,
            tauri::webview::InvokeRequest {
                cmd: command.to_string(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: if cfg!(any(windows, target_os = "android")) {
                    "http://tauri.localhost"
                } else {
                    "tauri://localhost"
                }
                .parse()
                .unwrap(),
                body: tauri::ipc::InvokeBody::Json(args),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.to_string(),
            },
        )
        .map(|body| body.deserialize::<Value>().unwrap())
    }

    #[test]
    fn generated_ipc_handler_rejects_invalid_inputs_stale_sessions_and_roles() {
        let state = AppState::default();
        let local = LocalRoom::create(SessionConfig::default(), None, "Alice").unwrap();
        let participant = local.creator_id();
        let session_id = local.session_id();
        {
            let mut inner = state.shared.lock().unwrap();
            inner.room = Some(ActiveRoom::Local(Arc::new(Mutex::new(local))));
            inner.active_session_id = Some(session_id.clone());
            inner.active_is_creator = Some(false);
            inner.current_participant = Some(participant);
        }
        let shared = state.shared.clone();
        let (app, _cleanup) = ipc_app(state);
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();

        assert!(ipc(
            &window,
            "create_room",
            json!({"display_name": "x".repeat(129)})
        )
        .is_err());
        assert!(ipc(
            &window,
            "join_room",
            json!({"display_name": "Bob", "invite_code": "x".repeat(MAX_INVITATION_TEXT_BYTES + 1)})
        )
        .is_err());
        assert!(ipc(&window, "send_message", json!({"body": "not sent"})).is_err());
        assert!(ipc(
            &window,
            "send_message",
            json!({"body": "not sent", "session_id": "0".repeat(32)})
        )
        .is_err());
        assert!(ipc(
            &window,
            "get_session_snapshot",
            json!({"session_id": "0".repeat(32)})
        )
        .is_err());
        assert!(ipc(&window, "advance_epoch", json!({"session_id": session_id})).is_err());
        assert!(ipc(
            &window,
            "shutdown_session",
            json!({"session_id": session_id})
        )
        .is_err());
        assert!(!shared.lock().unwrap().operation_in_flight);
        let snapshot = ipc(
            &window,
            "get_session_snapshot",
            json!({"session_id": session_id}),
        )
        .unwrap();
        assert!(snapshot["messages"].as_array().unwrap().is_empty());
        shared.lock().unwrap().active_is_creator = Some(true);
        assert!(ipc(&window, "leave_session", json!({"session_id": session_id})).is_err());
        assert!(ipc(
            &window,
            "shutdown_session",
            json!({"session_id": "0".repeat(32)})
        )
        .is_err());
        let ended = ipc(
            &window,
            "shutdown_session",
            json!({"session_id": session_id}),
        )
        .unwrap();
        assert_eq!(ended["state"], "closed");
        assert_eq!(ended["session_id"], session_id);
        assert!(shared.lock().unwrap().room.is_none());
    }

    #[test]
    fn invitation_text_is_trimmed_and_bounded() {
        assert_eq!(validate_invitation_text("  aabb  ").unwrap(), "aabb");
        assert!(validate_invitation_text("").is_err());
        assert!(validate_invitation_text(&"a".repeat(MAX_INVITATION_TEXT_BYTES)).is_ok());
        assert!(validate_invitation_text(&"x".repeat(MAX_INVITATION_TEXT_BYTES + 1)).is_err());
        assert!(validate_invitation_text("éé").is_err());
        assert!(validate_invitation_text("abc").is_err());
        assert!(validate_invitation_text(&format!(
            "{}aabb",
            " ".repeat(MAX_INVITATION_TEXT_BYTES)
        ))
        .is_err());
    }

    #[test]
    fn user_input_helpers_reject_control_and_oversized_values() {
        assert!(validate_display_name("Alice").is_ok());
        assert!(validate_display_name("\n").is_err());
        assert!(validate_display_name(&"a".repeat(33)).is_err());
        assert!(validate_display_name("é".repeat(32).as_str()).is_ok());
        assert!(validate_display_name("é".repeat(33).as_str()).is_err());
        assert!(validate_room_name(Some("Friday plans")).is_ok());
        assert!(validate_room_name(Some("\u{0000}")).is_err());
        assert!(validate_message_body("hello").is_ok());
        assert!(validate_message_body("hello\nworld").is_err());
        assert!(validate_message_body(&"a".repeat(MAX_MESSAGE_CHARS + 1)).is_err());
        assert!(validate_message_body("é".repeat(MAX_MESSAGE_CHARS).as_str()).is_ok());
        assert!(validate_message_body("é".repeat(MAX_MESSAGE_CHARS + 1).as_str()).is_err());
        assert!(validate_participant_id(&format!("p-{}", "a".repeat(64))).is_ok());
        assert!(validate_participant_id("p-123").is_err());
        assert!(validate_participant_id(&format!("p-{}", "a".repeat(65))).is_err());
        assert!(validate_participant_id(&format!("p-{}", "A".repeat(64))).is_err());
        assert!(
            validate_display_name(&format!("{}Alice", " ".repeat(MAX_DISPLAY_NAME_BYTES))).is_err()
        );
        assert!(validate_room_name(Some(&"🙂".repeat(49))).is_err());
        assert!(validate_display_name(&"🙂".repeat(32)).is_ok());
        assert!(validate_message_body(&"🙂".repeat(MAX_MESSAGE_CHARS)).is_ok());
        assert!(validate_message_body(&format!("{}hello", " ".repeat(MAX_MESSAGE_BYTES))).is_err());
    }

    #[test]
    fn session_id_validation_is_bounded_and_rejects_mismatches() {
        let session_id = "0123456789abcdef0123456789abcdef";
        assert!(validate_session_id(Some(session_id), None).is_err());
        assert!(validate_session_id(Some(session_id), Some(session_id)).is_ok());
        assert!(validate_session_id(Some(session_id), Some("other")).is_err());
        assert!(validate_session_id_value(&"a".repeat(SESSION_ID_BYTES + 1)).is_err());
        assert!(validate_session_id_value("room with spaces").is_err());
    }

    #[test]
    fn creator_only_actions_reject_joiners_before_room_io() {
        let room = LocalRoom::create(SessionConfig::default(), None, "Alice").unwrap();
        let participant = room.creator_id();
        let session_id = room.snapshot(&participant).unwrap().session_id;
        let shared = Arc::new(Mutex::new(AppStateInner {
            room: Some(ActiveRoom::Local(Arc::new(Mutex::new(room)))),
            current_participant: Some(participant),
            active_session_id: Some(session_id.clone()),
            active_is_creator: Some(false),
            scheduler: None,
            operation_in_flight: false,
            closing: false,
        }));
        let signal = Arc::new(Condvar::new());

        assert!(begin_room_operation(&shared, &signal, Some(&session_id), true).is_err());
        assert!(!shared.lock().unwrap().operation_in_flight);
        assert!(begin_room_operation(&shared, &signal, Some("bad"), false).is_err());
    }

    #[test]
    fn local_transport_release_gate_fails_closed_without_debug_or_feature() {
        assert!(!local_transport_allowed(false, false, true));
        assert!(local_transport_allowed(false, true, true));
        assert!(local_transport_allowed(true, false, true));
        assert!(!local_transport_allowed(false, false, false));
    }

    #[test]
    fn requested_local_transport_uses_the_compiled_build_gate() {
        let _lock = TRANSPORT_ENV_LOCK.lock().unwrap();
        let _env = TransportEnv::local();
        assert_eq!(
            local_transport_enabled(),
            cfg!(debug_assertions) || cfg!(feature = "local-transport")
        );
    }

    #[cfg(all(not(debug_assertions), not(feature = "local-transport")))]
    #[test]
    fn default_release_rejects_requested_local_before_network_work() {
        let _lock = TRANSPORT_ENV_LOCK.lock().unwrap();
        let _env = TransportEnv::local();
        assert_eq!(status_blocking().status, "unavailable");
        assert!(create_room_blocking(SessionConfig::default(), None, "Alice".to_string()).is_err());
        assert!(join_room_blocking(
            SessionConfig::default(),
            "aabb".to_string(),
            "Bob".to_string()
        )
        .is_err());
    }

    #[test]
    fn operation_guard_stays_busy_until_owned_worker_finishes() {
        let shared = Arc::new(Mutex::new(AppStateInner {
            room: None,
            current_participant: None,
            active_session_id: None,
            active_is_creator: None,
            scheduler: None,
            operation_in_flight: true,
            closing: false,
        }));
        let signal = Arc::new(Condvar::new());
        let guard = OperationGuard {
            shared: shared.clone(),
            signal: signal.clone(),
        };
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let worker_release = release.clone();
        let worker = thread::spawn(move || {
            let _guard = guard;
            worker_started.store(true, Ordering::Release);
            while !worker_release.load(Ordering::Acquire) {
                thread::yield_now();
            }
        });
        while !started.load(Ordering::Acquire) {
            thread::yield_now();
        }
        assert!(shared.lock().unwrap().operation_in_flight);
        release.store(true, Ordering::Release);
        worker.join().unwrap();
        assert!(!shared.lock().unwrap().operation_in_flight);
    }

    #[test]
    fn cancelling_async_caller_does_not_release_running_blocking_operation() {
        let state = AppState::default();
        let operation = reserve_new_room(&state.shared, &state.operation_signal).unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let caller = tauri::async_runtime::spawn(async move {
            tauri::async_runtime::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                drop(operation);
                finished_tx.send(()).unwrap();
            })
            .await
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        caller.abort();
        assert!(tauri::async_runtime::block_on(caller).is_err());
        assert!(reserve_new_room(&state.shared, &state.operation_signal).is_err());
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(reserve_new_room(&state.shared, &state.operation_signal).is_ok());
    }

    #[test]
    fn snapshot_requests_have_one_in_flight_lease() {
        let flag = Arc::new(AtomicBool::new(true));
        assert!(InFlightLease::acquire(&flag).is_err());
        flag.store(false, Ordering::Release);
        let lease = InFlightLease::acquire(&flag).unwrap();
        assert!(flag.load(Ordering::Acquire));
        drop(lease);
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn snapshot_ipc_rejects_extra_work_while_room_io_is_blocked() {
        let state = AppState::default();
        let room = LocalRoom::create(SessionConfig::default(), None, "Alice").unwrap();
        let participant = room.creator_id();
        let session_id = room.session_id();
        let room = Arc::new(Mutex::new(room));
        {
            let mut inner = state.shared.lock().unwrap();
            inner.room = Some(ActiveRoom::Local(room.clone()));
            inner.current_participant = Some(participant);
            inner.active_session_id = Some(session_id.clone());
            inner.active_is_creator = Some(true);
        }
        let flag = state.snapshot_in_flight.clone();
        let (app, _cleanup) = ipc_app(state);
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .unwrap();
        let held = room.lock().unwrap();
        let worker_window = window.clone();
        let worker_args = json!({"session_id": session_id});
        let reader =
            thread::spawn(move || ipc(&worker_window, "get_session_snapshot", worker_args));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !flag.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "snapshot worker must start");
            thread::yield_now();
        }
        assert!(ipc(
            &window,
            "get_session_snapshot",
            json!({"session_id": session_id})
        )
        .is_err());
        drop(held);
        assert!(reader.join().unwrap().is_ok());
        assert!(!flag.load(Ordering::Acquire));
    }

    #[test]
    fn exit_cleanup_is_bounded_when_a_worker_does_not_finish() {
        let shared = Arc::new(Mutex::new(AppStateInner {
            room: None,
            current_participant: None,
            active_session_id: None,
            active_is_creator: None,
            scheduler: None,
            operation_in_flight: true,
            closing: false,
        }));
        let signal = Arc::new(Condvar::new());
        let started = Instant::now();
        cleanup_on_exit_with_budget(&shared, &signal, Duration::from_millis(5));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(shared.lock().unwrap().closing);
        assert!(shared.lock().unwrap().operation_in_flight);
    }

    #[test]
    fn exit_cleanup_budget_also_bounds_stuck_scheduler_and_state_lock() {
        let state = AppState::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        });
        state.shared.lock().unwrap().scheduler = Some(Scheduler {
            stop,
            signal: Arc::new((Mutex::new(false), Condvar::new())),
            handle: Some(handle),
        });
        let started = Instant::now();
        cleanup_on_exit_with_budget(
            &state.shared,
            &state.operation_signal,
            Duration::from_millis(10),
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        release_tx.send(()).unwrap();

        let state = AppState::default();
        let held = state.shared.lock().unwrap();
        let started = Instant::now();
        cleanup_on_exit_with_budget(
            &state.shared,
            &state.operation_signal,
            Duration::from_millis(10),
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(held);
    }

    #[test]
    fn terminal_room_release_allows_a_fresh_reservation() {
        let room = LocalRoom::create(SessionConfig::default(), None, "Alice").unwrap();
        let participant = room.creator_id();
        let snapshot = room.snapshot(&participant).unwrap();
        let session_id = snapshot.session_id.clone();
        let shared = Arc::new(Mutex::new(AppStateInner {
            room: Some(ActiveRoom::Local(Arc::new(Mutex::new(room)))),
            current_participant: Some(participant),
            active_session_id: Some(session_id.clone()),
            active_is_creator: Some(true),
            scheduler: None,
            operation_in_flight: false,
            closing: false,
        }));
        let signal = Arc::new(Condvar::new());

        let mut terminal = snapshot;
        terminal.state = "closed".to_string();
        terminal.connection_state = "closed".to_string();
        terminal.tor_state = "closed".to_string();
        terminal.participants.clear();
        terminal.messages.clear();
        terminal.invite_code.clear();
        terminal.encryption_active = false;
        assert!(snapshot_is_terminal(&terminal));
        assert!(release_terminal_room(&shared, &session_id));
        assert!(shared.lock().unwrap().room.is_none());
        assert!(shared.lock().unwrap().active_session_id.is_none());

        let operation = reserve_new_room(&shared, &signal).unwrap();
        assert!(shared.lock().unwrap().operation_in_flight);
        drop(operation);
        assert!(!shared.lock().unwrap().operation_in_flight);
    }

    #[test]
    fn snapshot_fingerprint_tracks_security_and_transport_metadata() {
        let snapshot = RoomSnapshot {
            session_id: "room".to_string(),
            room_name: "Room".to_string(),
            invite_code: "invite".to_string(),
            owner_id: "owner".to_string(),
            state: "active".to_string(),
            epoch: 1,
            participants: Vec::new(),
            messages: Vec::new(),
            transport: "tor".to_string(),
            tor_state: "connected".to_string(),
            connection_state: "connected".to_string(),
            encryption_active: true,
        };
        let original = snapshot_fingerprint(&snapshot);
        for mutate in [
            |snapshot: &mut RoomSnapshot| snapshot.encryption_active = false,
            |snapshot: &mut RoomSnapshot| snapshot.connection_state = "waiting".to_string(),
            |snapshot: &mut RoomSnapshot| snapshot.transport = "local".to_string(),
            |snapshot: &mut RoomSnapshot| snapshot.tor_state = "closed".to_string(),
            |snapshot: &mut RoomSnapshot| snapshot.invite_code = "new-invite".to_string(),
        ] {
            let mut changed = snapshot.clone();
            mutate(&mut changed);
            assert_ne!(original, snapshot_fingerprint(&changed));
        }
    }

    #[test]
    #[ignore = "requires a running, bootstrapped Tor daemon and real onion networking"]
    fn real_tor_backend_create_join_send_poll_shutdown() {
        assert!(
            !local_transport_requested(),
            "run with GHOSTCHAT_TRANSPORT unset or tor"
        );
        let (owner_app, owner_cleanup) = ipc_app(AppState::default());
        let (joiner_app, joiner_cleanup) = ipc_app(AppState::default());
        let owner = tauri::WebviewWindowBuilder::new(&owner_app, "main", Default::default())
            .build()
            .unwrap();
        let joiner = tauri::WebviewWindowBuilder::new(&joiner_app, "main", Default::default())
            .build()
            .unwrap();
        let created = ipc(
            &owner,
            "create_room",
            json!({"display_name": "Alice", "room_name": "backend Tor test"}),
        )
        .expect("real Tor create_room IPC must succeed");
        assert_eq!(created["transport"], "tor");
        assert_eq!(created["tor_state"], "connected");
        let session_id = created["session_id"].as_str().unwrap().to_string();
        let invite = created["invite_code"].as_str().unwrap().to_string();
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if ipc(
                &joiner,
                "join_room",
                json!({"display_name": "Bob", "invite_code": invite}),
            )
            .is_ok()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "published Tor room must become reachable"
            );
            thread::sleep(Duration::from_secs(2));
        }

        let args = json!({"session_id": session_id});
        loop {
            let snapshot =
                ipc(&joiner, "get_session_snapshot", args.clone()).expect("joiner snapshot IPC");
            if snapshot["state"] == "active" && snapshot["encryption_active"] == true {
                assert_eq!(snapshot["participants"].as_array().unwrap().len(), 2);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Welcome and creator confirmation must arrive"
            );
            thread::sleep(Duration::from_millis(200));
        }
        assert!(ipc(&joiner, "shutdown_session", args.clone()).is_err());
        assert!(ipc(&owner, "leave_session", args.clone()).is_err());
        assert!(ipc(
            &owner,
            "send_message",
            json!({"session_id": "0".repeat(32), "body": "stale"})
        )
        .is_err());
        let sent = ipc(
            &owner,
            "send_message",
            json!({"session_id": session_id, "body": "real Tor owner message"}),
        )
        .expect("real Tor send_message IPC");
        assert_eq!(sent["snapshot"]["encryption_active"], true);
        wait_for_ipc_message(&joiner, &session_id, "real Tor owner message");
        ipc(
            &joiner,
            "send_message",
            json!({"session_id": session_id, "body": "real Tor joiner reply"}),
        )
        .expect("real Tor joiner send_message IPC");
        wait_for_ipc_message(&owner, &session_id, "real Tor joiner reply");

        let ended =
            ipc(&owner, "shutdown_session", args.clone()).expect("real Tor shutdown_session IPC");
        assert_eq!(ended["state"], "closed");
        assert_eq!(ended["session_id"], session_id);
        let terminal_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match ipc(&joiner, "get_session_snapshot", args.clone()) {
                Ok(snapshot) if snapshot["state"] == "closed" => {
                    assert!(snapshot["participants"].as_array().unwrap().is_empty());
                    assert!(snapshot["messages"].as_array().unwrap().is_empty());
                    assert_eq!(snapshot["encryption_active"], false);
                    break;
                }
                Err(_) if joiner_cleanup.shared.lock().unwrap().room.is_none() => break,
                _ => {}
            }
            assert!(
                Instant::now() < terminal_deadline,
                "joiner must close after owner shutdown"
            );
            thread::sleep(Duration::from_millis(100));
        }
        assert!(owner_cleanup.shared.lock().unwrap().room.is_none());
    }

    fn wait_for_ipc_message(
        window: &tauri::WebviewWindow<tauri::test::MockRuntime>,
        session_id: &str,
        body: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let snapshot = ipc(
                window,
                "get_session_snapshot",
                json!({"session_id": session_id}),
            )
            .unwrap();
            if snapshot["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| message["body"] == body)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "encrypted message must arrive via real Tor and app pump"
            );
            thread::sleep(Duration::from_millis(100));
        }
    }
}
