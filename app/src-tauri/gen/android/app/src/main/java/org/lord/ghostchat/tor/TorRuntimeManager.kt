package org.lord.ghostchat.tor

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.os.SystemClock
import app.tauri.plugin.Channel
import app.tauri.plugin.JSObject
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Owns one Tor generation and the private worker binding in the main app
 * process. Native startup is observed asynchronously; commands wait on the
 * state monitor from a background executor and never block Android's UI
 * thread.
 */
internal class TorRuntimeManager(context: Context) {
    private companion object {
        const val CONTROL_READY_TIMEOUT_MILLIS = 30_000L
        const val STOP_CLEANUP_TIMEOUT_MILLIS = 12_000L
        const val POLL_INTERVAL_MILLIS = 250L
        const val CONTROL_CONNECT_TIMEOUT_MILLIS = 250
        const val STOP_ESCALATION_INTERVAL_MILLIS = 2_000L
    }

    private data class Binding(
        val connection: ServiceConnection,
        var bound: Boolean,
    )

    private val appContext = context.applicationContext
    private val stateLock = Object()
    private val startupExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "GhostChat-Tor-Startup").apply { isDaemon = true }
    }
    private val poller: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "GhostChat-Tor-Supervisor").apply { isDaemon = true }
        }

    @Volatile
    private var snapshot = TorRuntimeSnapshot(
        state = TorRuntimeState.STOPPED,
        generation = null,
        controlHost = null,
        controlPort = 0,
        cookiePath = null,
        error = null,
    )

    @Volatile
    private var layout: TorRunLayout? = null

    @Volatile
    private var worker: IGhostChatTorWorker? = null

    private var binding: Binding? = null
    private var workerStartAccepted = false
    private var eventChannel: Channel? = null
    private var pollTask: ScheduledFuture<*>? = null
    private var cleanupTask: ScheduledFuture<*>? = null
    private var stopRequestedAt = 0L
    private var lastStopEscalationAt = 0L
    private var startRequestSequence = 0L
    private var pendingStartGeneration: String? = null

    fun startAsync(generation: String) {
        val requestSequence = synchronized(stateLock) {
            startRequestSequence += 1
            pendingStartGeneration = generation
            stateLock.notifyAll()
            startRequestSequence
        }
        startupExecutor.execute {
            try {
                start(generation, expectedRequestSequence = requestSequence)
            } catch (_: Exception) {
                // The command waiter observes FAILED or generation mismatch
                // through awaitControlReady; startup never blocks Android UI.
            }
        }
    }

    fun attachEventChannel(generation: String, channel: Channel) {
        require(generation.matches(Regex("[0-9a-f]{32}"))) { "invalid_generation" }
        synchronized(stateLock) {
            check(snapshot.generation == null || snapshot.generation == generation) {
                "another_generation_is_active"
            }
            eventChannel = channel
        }
    }

    fun start(
        generation: String,
        channel: Channel? = null,
        expectedRequestSequence: Long? = null,
    ): TorRuntimeSnapshot {
        require(generation.matches(Regex("[0-9a-f]{32}"))) {
            "invalid_generation"
        }

        val failedGeneration = synchronized(stateLock) {
            if (snapshot.state == TorRuntimeState.FAILED && snapshot.generation != generation) {
                snapshot.generation
            } else {
                null
            }
        }
        if (failedGeneration != null) {
            stopAndAwait(failedGeneration)
        }

        synchronized(stateLock) {
            if (expectedRequestSequence != null) {
                check(expectedRequestSequence == startRequestSequence &&
                    pendingStartGeneration == generation
                ) { "start_cancelled" }
                pendingStartGeneration = null
            }
            if (snapshot.generation == generation) {
                when (snapshot.state) {
                    TorRuntimeState.STARTING,
                    TorRuntimeState.CONTROL_READY,
                    -> {
                        if (channel != null) eventChannel = channel
                        return snapshot
                    }
                    TorRuntimeState.STOPPING -> throw IllegalStateException("generation_stopping")
                    TorRuntimeState.FAILED -> throw IllegalStateException("generation_failed")
                    TorRuntimeState.STOPPED -> Unit
                }
            } else if (snapshot.state == TorRuntimeState.STARTING ||
                snapshot.state == TorRuntimeState.CONTROL_READY ||
                snapshot.state == TorRuntimeState.STOPPING
            ) {
                throw IllegalStateException("another_generation_is_active")
            }

            val newLayout = try {
                TorRunLayout.create(appContext, generation)
            } catch (_: Exception) {
                snapshot = TorRuntimeSnapshot(
                    state = TorRuntimeState.FAILED,
                    generation = generation,
                    controlHost = null,
                    controlPort = 0,
                    cookiePath = null,
                    error = "private_storage_unavailable",
                )
                stateLock.notifyAll()
                throw IllegalStateException("private_storage_unavailable")
            }

            layout = newLayout
            worker = null
            workerStartAccepted = false
            if (channel != null) eventChannel = channel
            stopRequestedAt = 0L
            lastStopEscalationAt = 0L
            snapshot = TorRuntimeSnapshot(
                state = TorRuntimeState.STARTING,
                generation = generation,
                controlHost = null,
                controlPort = 0,
                cookiePath = newLayout.cookieFile.absolutePath,
                error = null,
            )

            val connection = createConnection(newLayout)
            val activeBinding = Binding(connection, bound = false)
            binding = activeBinding
            val bound = try {
                appContext.bindService(
                    Intent(appContext, GhostChatTorWorkerService::class.java),
                    connection,
                    Context.BIND_AUTO_CREATE or Context.BIND_IMPORTANT,
                )
            } catch (_: SecurityException) {
                false
            } catch (_: IllegalStateException) {
                false
            }
            activeBinding.bound = bound
            if (!bound) {
                snapshot = snapshot.copy(state = TorRuntimeState.FAILED, error = "worker_bind_failed")
                stateLock.notifyAll()
                scheduleCleanupLocked(newLayout)
                publishEventLocked(generation, "failed")
                throw IllegalStateException("worker_bind_failed")
            }

            pollTask?.cancel(false)
            pollTask = poller.scheduleWithFixedDelay(
                { poll(newLayout) },
                0L,
                POLL_INTERVAL_MILLIS,
                TimeUnit.MILLISECONDS,
            )
            stateLock.notifyAll()
            return snapshot
        }
    }

    /** Wait until Tor's loopback control listener and cookie are usable. */
    fun awaitControlReady(
        generation: String,
        timeoutMillis: Long = CONTROL_READY_TIMEOUT_MILLIS,
    ): TorRuntimeSnapshot {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        synchronized(stateLock) {
            while (true) {
                if (snapshot.generation != generation) {
                    // The foreground service schedules start() on a separate
                    // executor. It may not have published STARTING yet when
                    // the plugin command begins waiting for this generation.
                    // The service callback itself may not have queued that
                    // request yet. Wait while the manager is idle or retiring
                    // an old failed generation; reject a competing live or
                    // queued generation immediately.
                    val anotherGenerationActive = snapshot.generation != null &&
                        snapshot.state in setOf(
                            TorRuntimeState.STARTING,
                            TorRuntimeState.CONTROL_READY,
                            TorRuntimeState.STOPPING,
                        )
                    val anotherStartPending = pendingStartGeneration != null &&
                        pendingStartGeneration != generation
                    if (anotherGenerationActive || anotherStartPending) {
                        throw IllegalStateException("generation_changed")
                    }
                } else {
                    when (snapshot.state) {
                        TorRuntimeState.CONTROL_READY -> return snapshot
                        TorRuntimeState.FAILED -> throw IllegalStateException(snapshot.error ?: "tor_start_failed")
                        TorRuntimeState.STOPPED,
                        TorRuntimeState.STOPPING,
                        -> throw IllegalStateException("tor_stopped_during_startup")
                        TorRuntimeState.STARTING -> Unit
                    }
                }

                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0L) {
                    break
                }
                try {
                    stateLock.wait(minOf(remaining, POLL_INTERVAL_MILLIS * 2))
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw IllegalStateException("startup_interrupted")
                }
            }
        }

        stopAndAwait(generation, STOP_CLEANUP_TIMEOUT_MILLIS)
        throw IllegalStateException("control_ready_timeout")
    }

    /** Request shutdown and wait for the worker to return before deleting its files. */
    fun stopAndAwait(
        generation: String,
        timeoutMillis: Long = STOP_CLEANUP_TIMEOUT_MILLIS,
    ): Boolean {
        val activeWorker: IGhostChatTorWorker?
        val activeLayout: TorRunLayout?
        synchronized(stateLock) {
            if (pendingStartGeneration == generation) {
                startRequestSequence += 1
                pendingStartGeneration = null
                eventChannel = null
            }
            if (snapshot.generation != generation || snapshot.state == TorRuntimeState.STOPPED) {
                return true
            }
            if (snapshot.state != TorRuntimeState.STOPPING) {
                snapshot = snapshot.copy(state = TorRuntimeState.STOPPING, error = null)
                stopRequestedAt = SystemClock.elapsedRealtime()
                stateLock.notifyAll()
            }
            activeWorker = worker
            activeLayout = layout
            if (activeLayout != null) {
                scheduleCleanupLocked(activeLayout)
            } else {
                snapshot = TorRuntimeSnapshot(
                    state = TorRuntimeState.STOPPED,
                    generation = null,
                    controlHost = null,
                    controlPort = 0,
                    cookiePath = null,
                    error = null,
                )
                eventChannel = null
                stateLock.notifyAll()
                return true
            }
        }

        try {
            activeWorker?.stop()
        } catch (_: Exception) {
            // The worker has its own bounded process-exit escalation.
        }

        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        synchronized(stateLock) {
            while (snapshot.generation == generation &&
                snapshot.state != TorRuntimeState.STOPPED
            ) {
                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0L) return false
                try {
                    stateLock.wait(minOf(remaining, POLL_INTERVAL_MILLIS * 4))
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
            }
        }
        return true
    }

    /** Non-blocking stop used by Android lifecycle callbacks. */
    fun stop(generation: String? = null) {
        val activeWorker: IGhostChatTorWorker?
        synchronized(stateLock) {
            if (generation != null && pendingStartGeneration == generation) {
                startRequestSequence += 1
                pendingStartGeneration = null
                eventChannel = null
            }
            val activeGeneration = snapshot.generation ?: return
            if (generation != null && generation != activeGeneration) return
            if (snapshot.state == TorRuntimeState.STOPPED) return
            if (layout == null) {
                snapshot = TorRuntimeSnapshot(
                    state = TorRuntimeState.STOPPED,
                    generation = null,
                    controlHost = null,
                    controlPort = 0,
                    cookiePath = null,
                    error = null,
                )
                eventChannel = null
                stateLock.notifyAll()
                return
            }
            snapshot = snapshot.copy(state = TorRuntimeState.STOPPING, error = null)
            stopRequestedAt = SystemClock.elapsedRealtime()
            activeWorker = worker
            layout?.let(::scheduleCleanupLocked)
            stateLock.notifyAll()
        }
        try {
            activeWorker?.stop()
        } catch (_: Exception) {
            // The worker service applies its own bounded stop escalation.
        }
    }

    fun snapshot(): TorRuntimeSnapshot = snapshot

    fun startResponse(generation: String): JSObject {
        val activeLayout: TorRunLayout
        val activeWorker: IGhostChatTorWorker
        synchronized(stateLock) {
            check(snapshot.generation == generation &&
                snapshot.state == TorRuntimeState.CONTROL_READY
            ) { "control_not_ready" }
            activeLayout = layout ?: throw IllegalStateException("runtime_layout_unavailable")
            activeWorker = worker ?: throw IllegalStateException("worker_unavailable")
        }

        val workerUid = try {
            activeWorker.getUid()
        } catch (_: Exception) {
            throw IllegalStateException("worker_uid_unavailable")
        }
        return JSObject().apply {
            put("generation", generation)
            put("noBackupDir", appContext.noBackupFilesDir.canonicalPath)
            put("runDir", activeLayout.runDirectory.canonicalPath)
            put("controlPortFile", activeLayout.controlPortFile.canonicalPath)
            put("cookiePath", activeLayout.cookieFile.canonicalPath)
            put("appUid", Process.myUid())
            put("workerUid", workerUid)
        }
    }

    fun toJson(): JSObject {
        val current = snapshot
        val currentLayout = layout
        val currentWorker = worker
        val workerUid = try {
            currentWorker?.getUid()
        } catch (_: Exception) {
            null
        }
        return JSObject().apply {
            put("state", current.state.name.lowercase())
            put("generation", current.generation)
            put("controlHost", current.controlHost)
            put("controlPort", current.controlPort)
            put("cookiePath", current.cookiePath)
            put("noBackupDir", appContext.noBackupFilesDir.absolutePath)
            put("runDir", currentLayout?.runDirectory?.absolutePath)
            put("controlPortFile", currentLayout?.controlPortFile?.absolutePath)
            put("appUid", Process.myUid())
            put("workerUid", workerUid)
            put("error", current.error)
            put("torProviderVersion", TorNativeBridge.providerVersion())
        }
    }

    private fun createConnection(activeLayout: TorRunLayout): ServiceConnection =
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                val boundWorker = service?.let { IGhostChatTorWorker.Stub.asInterface(it) }
                if (boundWorker == null) {
                    fail(activeLayout, "worker_null_binding")
                    return
                }

                var shouldStart = false
                synchronized(stateLock) {
                    if (layout !== activeLayout ||
                        snapshot.generation != activeLayout.generation ||
                        snapshot.state != TorRuntimeState.STARTING
                    ) {
                        // A stop may win while Android is delivering the bind
                        // callback. The stale worker must not launch Tor.
                    } else {
                        worker = boundWorker
                        val launch = Bundle().apply {
                            putString("generation", activeLayout.generation)
                            putString("runDirectory", activeLayout.runDirectory.absolutePath)
                            putStringArray("commandLine", activeLayout.commandLine)
                        }
                        shouldStart = try {
                            boundWorker.start(launch).also { workerStartAccepted = it }
                        } catch (_: Exception) {
                            false
                        }
                        if (!shouldStart) {
                            workerStartAccepted = false
                        }
                        stateLock.notifyAll()
                    }
                }

                val isActive = synchronized(stateLock) {
                    layout === activeLayout && snapshot.generation == activeLayout.generation &&
                        snapshot.state == TorRuntimeState.STARTING
                }
                if (!isActive) {
                    unbindSpecific(this)
                } else if (!shouldStart) {
                    fail(activeLayout, "worker_start_rejected")
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                synchronized(stateLock) {
                    if (layout !== activeLayout || snapshot.generation != activeLayout.generation) return
                    worker = null
                    workerStartAccepted = false
                }
                if (snapshot.state == TorRuntimeState.STOPPING) {
                    scheduleCleanup(activeLayout)
                } else {
                    fail(activeLayout, "worker_disconnected")
                }
            }

            override fun onBindingDied(name: ComponentName?) {
                synchronized(stateLock) {
                    if (layout !== activeLayout || snapshot.generation != activeLayout.generation) return
                    worker = null
                    workerStartAccepted = false
                }
                if (snapshot.state == TorRuntimeState.STOPPING) {
                    scheduleCleanup(activeLayout)
                } else {
                    fail(activeLayout, "worker_binding_died")
                }
            }

            override fun onNullBinding(name: ComponentName?) {
                fail(activeLayout, "worker_null_binding")
            }
        }

    private fun poll(activeLayout: TorRunLayout) {
        val activeWorker: IGhostChatTorWorker?
        val shouldCheckControl: Boolean
        synchronized(stateLock) {
            if (layout !== activeLayout || snapshot.generation != activeLayout.generation) return
            if (snapshot.state == TorRuntimeState.STOPPING || snapshot.state == TorRuntimeState.FAILED ||
                snapshot.state == TorRuntimeState.STOPPED
            ) return
            activeWorker = worker
            shouldCheckControl = workerStartAccepted && snapshot.state == TorRuntimeState.STARTING
        }

        val workerState = try {
            activeWorker?.getState() ?: return
        } catch (_: Exception) {
            fail(activeLayout, "worker_state_unavailable")
            return
        }
        if (workerState == GhostChatTorWorkerService.STATE_FAILED) {
            fail(activeLayout, "tor_native_exit")
            return
        }
        if (workerState == GhostChatTorWorkerService.STATE_STOPPED) {
            val accepted = synchronized(stateLock) { workerStartAccepted }
            if (accepted) fail(activeLayout, "tor_stopped")
            return
        }

        if (shouldCheckControl) {
            val endpoint = activeLayout.controlEndpoint()
            if (endpoint != null && activeLayout.cookieReady() && controlSocketAccepts(endpoint)) {
                synchronized(stateLock) {
                    if (layout === activeLayout &&
                        snapshot.generation == activeLayout.generation &&
                        snapshot.state == TorRuntimeState.STARTING && workerStartAccepted
                    ) {
                        snapshot = snapshot.copy(
                            state = TorRuntimeState.CONTROL_READY,
                            controlHost = endpoint.first,
                            controlPort = endpoint.second,
                        )
                        publishEventLocked(activeLayout.generation, "controlReady")
                        stateLock.notifyAll()
                    }
                }
            }
        }
    }

    private fun controlSocketAccepts(endpoint: Pair<String, Int>): Boolean = try {
        Socket().use { socket ->
            socket.connect(
                InetSocketAddress(endpoint.first, endpoint.second),
                CONTROL_CONNECT_TIMEOUT_MILLIS,
            )
            true
        }
    } catch (_: Exception) {
        false
    }

    private fun fail(activeLayout: TorRunLayout, reason: String) {
        val activeWorker: IGhostChatTorWorker?
        synchronized(stateLock) {
            if (layout !== activeLayout || snapshot.generation != activeLayout.generation ||
                snapshot.state == TorRuntimeState.STOPPING ||
                snapshot.state == TorRuntimeState.STOPPED ||
                snapshot.state == TorRuntimeState.FAILED
            ) return
            snapshot = snapshot.copy(state = TorRuntimeState.FAILED, error = reason)
            activeWorker = worker
            publishEventLocked(activeLayout.generation, "failed")
            stateLock.notifyAll()
            scheduleCleanupLocked(activeLayout)
        }
        try {
            activeWorker?.stop()
        } catch (_: Exception) {
            // Cleanup continues by observing the worker's state and Binder death.
        }
    }

    private fun scheduleCleanup(activeLayout: TorRunLayout) {
        synchronized(stateLock) { scheduleCleanupLocked(activeLayout) }
    }

    private fun scheduleCleanupLocked(activeLayout: TorRunLayout) {
        if (cleanupTask?.isDone == false) return
        cleanupTask = poller.scheduleWithFixedDelay(
            { cleanupAttempt(activeLayout) },
            POLL_INTERVAL_MILLIS,
            POLL_INTERVAL_MILLIS,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun cleanupAttempt(activeLayout: TorRunLayout) {
        val activeWorker = synchronized(stateLock) {
            if (layout !== activeLayout || snapshot.generation != activeLayout.generation) {
                cleanupTask?.cancel(false)
                cleanupTask = null
                return
            }
            worker
        }
        val workerState = try {
            activeWorker?.getState()
        } catch (_: Exception) {
            null
        }
        // A Binder query error does not prove the worker process is dead.
        // Keep its generation files until Android reports disconnection or
        // the worker returns an authoritative terminal state.
        val stillRunning = (activeWorker != null && workerState == null) ||
            workerState == GhostChatTorWorkerService.STATE_STARTING ||
            workerState == GhostChatTorWorkerService.STATE_RUNNING ||
            workerState == GhostChatTorWorkerService.STATE_STOPPING
        if (stillRunning) {
            val shouldEscalate = synchronized(stateLock) {
                if (snapshot.state != TorRuntimeState.STOPPING) {
                    snapshot = snapshot.copy(state = TorRuntimeState.STOPPING, error = null)
                    stopRequestedAt = SystemClock.elapsedRealtime()
                    stateLock.notifyAll()
                }
                val now = SystemClock.elapsedRealtime()
                val stoppingFor = now - stopRequestedAt
                if (stoppingFor >= STOP_CLEANUP_TIMEOUT_MILLIS &&
                    now - lastStopEscalationAt >= STOP_ESCALATION_INTERVAL_MILLIS
                ) {
                    lastStopEscalationAt = now
                    true
                } else {
                    false
                }
            }
            if (shouldEscalate) {
                try {
                    activeWorker?.stop()
                } catch (_: Exception) {
                    // Keep polling; the worker process owns its kill escalation.
                }
            }
            return
        }

        val activeBinding = synchronized(stateLock) {
            if (layout !== activeLayout || snapshot.generation != activeLayout.generation) return
            val value = binding
            binding = null
            worker = null
            workerStartAccepted = false
            value
        }
        activeBinding?.let { unbindSpecific(it.connection, it) }
        activeLayout.deleteOwnedRun()

        synchronized(stateLock) {
            if (layout === activeLayout && snapshot.generation == activeLayout.generation) {
                pollTask?.cancel(false)
                pollTask = null
                cleanupTask?.cancel(false)
                cleanupTask = null
                snapshot = TorRuntimeSnapshot(
                    state = TorRuntimeState.STOPPED,
                    generation = null,
                    controlHost = null,
                    controlPort = 0,
                    cookiePath = null,
                    error = null,
                )
                layout = null
                eventChannel = null
                stateLock.notifyAll()
            }
        }
    }

    private fun unbindSpecific(connection: ServiceConnection, expected: Binding? = null) {
        val shouldUnbind = synchronized(stateLock) {
            val current = expected ?: binding?.takeIf { it.connection === connection }
            if (current == null || !current.bound) {
                false
            } else {
                current.bound = false
                if (binding === current) binding = null
                true
            }
        }
        if (shouldUnbind) {
            try {
                appContext.unbindService(connection)
            } catch (_: IllegalArgumentException) {
                // The binding can die between the state check and unbind.
            }
        }
    }

    private fun publishEventLocked(generation: String, event: String) {
        val channel = eventChannel ?: return
        val payload = JSObject().apply {
            put("generation", generation)
            put("event", event)
        }
        try {
            // Tauri's Android Channel.send(JSObject) wraps values in a
            // PluginResult envelope. Rust Channel expects the raw JSON body.
            channel.sendObject(payload)
        } catch (_: Exception) {
            // Channel delivery is diagnostic only; status and stop remain authoritative.
        }
    }
}

internal object TorRuntimeHolder {
    @Volatile
    private var instance: TorRuntimeManager? = null

    @Synchronized
    fun get(context: Context): TorRuntimeManager {
        val current = instance
        if (current != null) return current
        return TorRuntimeManager(context.applicationContext).also { instance = it }
    }
}
