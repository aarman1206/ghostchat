package org.lord.ghostchat.tor

import android.app.Activity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.concurrent.Executors

@InvokeArg
internal class NativeStartArgs {
    lateinit var generation: String
    lateinit var onEvent: Channel
}

@InvokeArg
internal class NativeStopArgs {
    lateinit var generation: String
}

/**
 * Tauri mobile-plugin seam consumed by the Android-only Rust runtime
 * provider. Startup completes asynchronously off the UI thread and resolves
 * only after the worker, control port, and cookie are ready.
 */
@TauriPlugin
class GhostChatTorPlugin(private val activity: Activity) : Plugin(activity) {
    companion object {
        private val commandExecutor = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "GhostChat-Tor-Plugin").apply { isDaemon = true }
        }
    }

    @Command
    fun start(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(NativeStartArgs::class.java)
        } catch (_: Exception) {
            invoke.reject("invalid_start_request", "invalid_start_request")
            return
        }
        if (!args.generation.matches(Regex("[0-9a-f]{32}"))) {
            invoke.reject("invalid_start_request", "invalid_start_request")
            return
        }

        val runtime = TorRuntimeHolder.get(activity)
        try {
            runtime.attachEventChannel(args.generation, args.onEvent)
            GhostChatSessionService.startFromVisibleContext(activity, args.generation)
        } catch (_: Exception) {
            commandExecutor.execute {
                try {
                    GhostChatSessionService.stopFromVisibleContext(activity, args.generation)
                } catch (_: Exception) {
                    // The runtime manager still performs generation-scoped cleanup.
                }
                runtime.stopAndAwait(args.generation)
                invoke.reject("tor_start_failed", "tor_start_failed")
            }
            return
        }

        // Do not block the main thread: startAndWait may cover Android service
        // binding, Tor's native startup, port publication, and cookie creation.
        commandExecutor.execute {
            try {
                runtime.awaitControlReady(args.generation)
                invoke.resolve(runtime.startResponse(args.generation))
            } catch (error: Exception) {
                try {
                    GhostChatSessionService.stopFromVisibleContext(activity, args.generation)
                } catch (_: Exception) {
                    // The runtime manager still performs generation-scoped cleanup.
                }
                runtime.stopAndAwait(args.generation)
                val code = (error as? IllegalStateException)?.message ?: "tor_start_failed"
                invoke.reject(code, code)
            }
        }
    }

    @Command
    fun status(invoke: Invoke) {
        invoke.resolve(TorRuntimeHolder.get(activity).toJson())
    }

    @Command
    fun stop(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(NativeStopArgs::class.java)
        } catch (_: Exception) {
            invoke.reject("invalid_stop_request", "invalid_stop_request")
            return
        }
        if (!args.generation.matches(Regex("[0-9a-f]{32}"))) {
            invoke.reject("invalid_stop_request", "invalid_stop_request")
            return
        }

        val runtime = TorRuntimeHolder.get(activity)
        try {
            GhostChatSessionService.stopFromVisibleContext(activity, args.generation)
        } catch (_: Exception) {
            // The runtime manager below still owns and synchronizes shutdown.
        }
        commandExecutor.execute {
            if (!runtime.stopAndAwait(args.generation)) {
                invoke.reject("tor_stop_timeout", "tor_stop_timeout")
                return@execute
            }
            invoke.resolve(JSObject().apply {
                put("generation", args.generation)
                put("stopped", true)
            })
        }
    }
}
