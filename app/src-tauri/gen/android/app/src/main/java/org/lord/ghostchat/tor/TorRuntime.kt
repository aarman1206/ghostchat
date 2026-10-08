package org.lord.ghostchat.tor

import android.content.Context
import android.system.Os
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.Charset

internal enum class TorRuntimeState {
    STOPPED,
    STARTING,
    CONTROL_READY,
    STOPPING,
    FAILED,
}

internal data class TorRuntimeSnapshot(
    val state: TorRuntimeState,
    val generation: String?,
    val controlHost: String?,
    val controlPort: Int,
    val cookiePath: String?,
    val error: String?,
)

/** Paths and command-line material for one private Tor generation. */
internal class TorRunLayout private constructor(
    val generation: String,
    val rootDirectory: File,
    val dataDirectory: File,
    val cacheDirectory: File,
    val runDirectory: File,
    val torrcFile: File,
    val controlPortFile: File,
    val cookieFile: File,
) {
    val commandLine: Array<String>
        get() = arrayOf(
            "tor",
            "--ignore-missing-torrc",
            "-f",
            torrcFile.absolutePath,
        )

    fun controlEndpoint(): Pair<String, Int>? {
        if (!controlPortFile.isFile || controlPortFile.length() > 512L) {
            return null
        }

        val text = try {
            controlPortFile.readText(Charsets.US_ASCII)
        } catch (_: IOException) {
            return null
        }

        for (line in text.split('\n')) {
            val value = line.trim().removePrefix("PORT=").removePrefix("ControlPort=")
            val endpoint = parseLoopbackEndpoint(value) ?: continue
            if (endpoint.second in 1..65535) {
                return endpoint
            }
        }
        return null
    }

    fun cookieReady(): Boolean = cookieFile.isFile && cookieFile.length() == 32L

    fun deleteOwnedRun() {
        val canonicalRoot = rootDirectory.canonicalFile
        val canonicalRun = runDirectory.canonicalFile
        val expectedRuns = File(canonicalRoot, "run").canonicalFile
        if (canonicalRun.parentFile?.canonicalFile != expectedRuns ||
            canonicalRun.name != generation
        ) {
            return
        }
        runDirectory.deleteRecursively()
    }

    companion object {
        private val ASCII: Charset = Charset.forName("US-ASCII")

        fun create(context: Context, generation: String): TorRunLayout {
            require(generation.matches(Regex("[0-9a-f]{32}"))) {
                "Invalid Android Tor generation"
            }
            val root = File(context.noBackupFilesDir, "tor")
            val data = File(root, "data")
            val cache = File(root, "cache")
            val runs = File(root, "run")
            ensurePrivateDirectory(root)
            ensurePrivateDirectory(data)
            ensurePrivateDirectory(cache)
            ensurePrivateDirectory(runs)

            val run = File(runs, generation)
            ensurePrivateDirectory(run)

            val layout = TorRunLayout(
                generation = generation,
                rootDirectory = root,
                dataDirectory = data,
                cacheDirectory = cache,
                runDirectory = run,
                torrcFile = File(run, "torrc"),
                controlPortFile = File(run, "control.port"),
                cookieFile = File(run, "control.cookie"),
            )
            layout.writeTorrc()
            return layout
        }

        fun expectedTorrc(runDirectory: File): File = File(runDirectory, "torrc")

        fun validateLaunch(context: Context, launch: android.os.Bundle): Boolean {
            val generation = launch.getString("generation") ?: return false
            val runPath = launch.getString("runDirectory") ?: return false
            val args = launch.getStringArray("commandLine") ?: return false
            if (!generation.matches(Regex("[0-9a-f]{32}"))) {
                return false
            }
            val torRoot = File(context.noBackupFilesDir, "tor").canonicalFile
            val expectedRuns = File(torRoot, "run").canonicalFile
            val run = File(runPath).canonicalFile
            val expected = expectedTorrc(run)
            val argsMatch = try {
                args.size == 4 && args[0] == "tor" &&
                    args[1] == "--ignore-missing-torrc" && args[2] == "-f" &&
                    File(args[3]).canonicalFile == expected.canonicalFile
            } catch (_: IOException) {
                false
            }
            val runMatches = run.name == generation && run.parentFile == expectedRuns
            val filesPresent = run.isDirectory && expected.isFile
            val valid = argsMatch && runMatches && filesPresent
            if (!valid) {
                Log.e(
                    "GhostChatTor",
                    "worker launch validation failed: argsMatch=$argsMatch, " +
                        "runMatches=$runMatches, filesPresent=$filesPresent, " +
                        "argCount=${args.size}",
                )
            }
            return valid
        }

        private fun parseLoopbackEndpoint(value: String): Pair<String, Int>? {
            val portText: String
            if (value.startsWith("127.0.0.1:")) {
                portText = value.substringAfter(':')
            } else if (value.matches(Regex("[0-9]+"))) {
                portText = value
            } else {
                return null
            }
            val port = portText.toIntOrNull() ?: return null
            return "127.0.0.1" to port
        }

        private fun ensurePrivateDirectory(directory: File) {
            if (!directory.exists() && !directory.mkdirs()) {
                throw IOException("Cannot create private Tor directory")
            }
            try {
                Os.chmod(directory.absolutePath, 448) // 0700
            } catch (_: Exception) {
                // Android's app sandbox is the authority; chmod is defense in
                // depth and is not allowed to turn a private path external.
            }
        }
    }

    private fun writeTorrc() {
        val text = buildString {
            appendLine("RunAsDaemon 0")
            appendLine("ClientOnly 1")
            appendLine("DataDirectory ${torPath(dataDirectory)}")
            appendLine("CacheDirectory ${torPath(cacheDirectory)}")
            appendLine("SocksPort 127.0.0.1:auto OnionTrafficOnly")
            appendLine("ControlPort 127.0.0.1:auto")
            appendLine("ControlPortWriteToFile ${torPath(controlPortFile)}")
            appendLine("CookieAuthentication 1")
            appendLine("CookieAuthFile ${torPath(cookieFile)}")
            appendLine("HiddenServiceNonAnonymousMode 0")
            appendLine("HiddenServiceSingleHopMode 0")
        }
        FileOutputStream(torrcFile, false).use { output ->
            output.write(text.toByteArray(ASCII))
            output.fd.sync()
        }
        try {
            Os.chmod(torrcFile.absolutePath, 384) // 0600
        } catch (_: Exception) {
            // The file is already in getNoBackupFilesDir()/tor/run/<generation>.
        }
    }

    private fun torPath(file: File): String {
        val path = file.absolutePath
        require(!path.contains('"') && !path.contains('\n') && !path.contains('\r'))
        return "\"${path.replace("\\", "\\\\")}\""
    }
}
