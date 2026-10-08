package org.lord.ghostchat.tor

import android.util.Log

/**
 * JNI surface for the single Tor run owned by GhostChatTorWorkerService.
 *
 * The bridge loads the packaged Tor library through the Android linker and
 * fails closed if either native library is unavailable. It never searches
 * writable storage and never starts an external/system process.
 */
internal object TorNativeBridge {
    const val BRIDGE_RUNTIME_UNAVAILABLE = -1001

    private var bridgeLoaded = false

    init {
        bridgeLoaded = try {
            System.loadLibrary("ghostchat_tor_bridge")
            true
        } catch (error: UnsatisfiedLinkError) {
            Log.e(
                "GhostChatTorNative",
                "GhostChat Tor JNI bridge failed to load (${error.javaClass.simpleName})",
            )
            false
        }
    }

    @JvmStatic
    private external fun nativeIsAvailable(): Boolean

    @JvmStatic
    private external fun nativeProviderVersion(): String?

    @JvmStatic
    private external fun nativeRun(args: Array<String>, captureDiagnostics: Boolean): Int

    fun isAvailable(): Boolean = bridgeLoaded && nativeIsAvailable()

    fun providerVersion(): String? {
        if (!bridgeLoaded) {
            return null
        }
        return nativeProviderVersion()
    }

    fun run(args: Array<String>, captureDiagnostics: Boolean): Int {
        if (!bridgeLoaded) {
            return BRIDGE_RUNTIME_UNAVAILABLE
        }
        return nativeRun(args, captureDiagnostics)
    }
}
