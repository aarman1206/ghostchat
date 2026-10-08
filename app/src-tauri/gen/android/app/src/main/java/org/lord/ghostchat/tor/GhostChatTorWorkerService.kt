package org.lord.ghostchat.tor

import android.app.Service
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import android.util.Log
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The only Android component allowed to call tor_run_main.
 *
 * This service is placed in the private :tor process. It has the same UID as
 * the Tauri process, but it is not exported and does not expose a Tor control
 * protocol. The parent service authenticates Tor over its loopback TCP control
 * port using the cookie created by Tor itself.
 */
class GhostChatTorWorkerService : Service() {
    companion object {
        const val STATE_STOPPED = 0
        const val STATE_STARTING = 1
        const val STATE_RUNNING = 2
        const val STATE_STOPPING = 3
        const val STATE_FAILED = 4

        private const val KILL_GRACE_MILLIS = 2500L
    }

    @Volatile
    private var state: Int = STATE_STOPPED

    @Volatile
    private var exitCode: Int = Int.MIN_VALUE

    private val started = AtomicBoolean(false)
    private val hasRun = AtomicBoolean(false)
    private val stopping = AtomicBoolean(false)
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "GhostChat-Tor-Native").apply { isDaemon = true }
    }
    private val killScheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "GhostChat-Tor-Stop").apply { isDaemon = true }
        }

    private val binder = object : IGhostChatTorWorker.Stub() {
        override fun start(launch: Bundle?): Boolean {
            if (Binder.getCallingUid() != Process.myUid() || launch == null) {
                return false
            }
            return startNative(launch)
        }

        override fun stop() {
            if (Binder.getCallingUid() != Process.myUid()) {
                return
            }
            stopNative()
        }

        // The AIDL Stub synthesizes a Kotlin `state` property from getState().
        // Qualify the outer service field so this getter cannot dispatch back
        // to itself recursively.
        override fun getState(): Int =
            if (isSameUid()) this@GhostChatTorWorkerService.state else STATE_FAILED

        override fun getExitCode(): Int =
            if (isSameUid()) this@GhostChatTorWorkerService.exitCode else -1000

        override fun getUid(): Int = if (isSameUid()) Process.myUid() else -1000
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        stopNative()
        if (started.get()) {
            scheduleProcessTermination()
        } else {
            executor.shutdownNow()
            killScheduler.shutdownNow()
        }
        super.onDestroy()
    }

    private fun startNative(launch: Bundle): Boolean {
        if (!TorRunLayout.validateLaunch(this, launch)) {
            Log.e("GhostChatTor", "worker rejected an invalid launch layout")
            state = STATE_FAILED
            exitCode = -1000
            return false
        }
        if (hasRun.get() || !started.compareAndSet(false, true)) {
            Log.e("GhostChatTor", "worker rejected duplicate or concurrent native start")
            return false
        }
        hasRun.set(true)

        state = STATE_STARTING
        exitCode = Int.MIN_VALUE
        executor.execute {
            if (!TorNativeBridge.isAvailable()) {
                Log.e(
                    "GhostChatTor",
                    "embedded Tor API unavailable; JNI bridge or libtor.so could not be loaded",
                )
                exitCode = TorNativeBridge.BRIDGE_RUNTIME_UNAVAILABLE
                state = STATE_FAILED
                started.set(false)
                stopSelf()
                retireWorkerProcess()
                return@execute
            }

            state = STATE_RUNNING
            Log.i("GhostChatTor", "JNI bridge resolved libtor.so; starting embedded Tor")
            val commandLine = launch.getStringArray("commandLine") ?: emptyArray()
            val captureDiagnostics =
                applicationInfo.flags.and(ApplicationInfo.FLAG_DEBUGGABLE) != 0
            val result = TorNativeBridge.run(commandLine, captureDiagnostics)
            exitCode = result
            if (captureDiagnostics) {
                val runDirectory = launch.getString("runDirectory")?.let(::File)
                val diagnosticLog = runDirectory?.let { File(it, "tor-native.log") }
                if (diagnosticLog?.isFile == true) {
                    runCatching { diagnosticLog.readLines().takeLast(32) }
                        .getOrDefault(emptyList())
                        .forEach { line ->
                            Log.e("GhostChatTorDiag", line.take(1000))
                        }
                } else {
                    Log.e("GhostChatTorDiag", "Tor returned without creating tor.log")
                }
            }
            if (!stopping.get() && result != 0) {
                Log.e("GhostChatTor", "tor_run_main returned exit status $result")
            } else {
                Log.i("GhostChatTor", "tor_run_main returned exit status $result")
            }
            state = if (stopping.get() || result == 0) {
                STATE_STOPPED
            } else {
                STATE_FAILED
            }
            started.set(false)
            stopSelf()
            retireWorkerProcess()
        }
        return true
    }

    private fun stopNative() {
        stopping.set(true)
        if (state == STATE_RUNNING || state == STATE_STARTING) {
            state = STATE_STOPPING
        }
        stopSelf()
        if (started.get()) {
            scheduleProcessTermination()
        }
    }

    private fun scheduleProcessTermination() {
        killScheduler.schedule({
            if (started.get()) {
                // This PID is the dedicated, non-exported :tor worker. Tor
                // was first given its authenticated SIGNAL SHUTDOWN by the
                // Rust/native supervisor; this is only bounded escalation.
                Process.killProcess(Process.myPid())
            }
        }, KILL_GRACE_MILLIS, TimeUnit.MILLISECONDS)
    }

    private fun isSameUid(): Boolean = Binder.getCallingUid() == Process.myUid()

    private fun retireWorkerProcess() {
        // tor_run_main is one-shot per process. Do not leave a service process
        // around that could accidentally accept a second native run.
        Process.killProcess(Process.myPid())
    }
}
