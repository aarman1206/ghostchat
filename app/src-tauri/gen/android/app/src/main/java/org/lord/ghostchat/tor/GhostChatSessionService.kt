package org.lord.ghostchat.tor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Main-process foreground owner for a user-started GhostChat Tor session.
 * Keeping this service in the Tauri process makes its importance cover the
 * Rust/OpenMLS session as well as the private :tor worker.
 */
class GhostChatSessionService : Service() {
    companion object {
        const val ACTION_START = "org.lord.ghostchat.tor.action.START_SESSION"
        const val ACTION_STOP = "org.lord.ghostchat.tor.action.STOP_SESSION"
        const val EXTRA_GENERATION = "org.lord.ghostchat.tor.extra.GENERATION"

        private const val CHANNEL_ID = "ghostchat_tor_session"
        private const val NOTIFICATION_ID = 1701

        fun startFromVisibleContext(context: Context, generation: String) {
            val intent = Intent(context, GhostChatSessionService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_GENERATION, generation)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            // Runtime startup is deferred to onStartCommand, after Android
            // has dispatched the foreground-service request and promotion.
        }

        fun stopFromVisibleContext(context: Context, generation: String) {
            val intent = Intent(context, GhostChatSessionService::class.java)
                .setAction(ACTION_STOP)
                .putExtra(EXTRA_GENERATION, generation)
            context.startService(intent)
        }
    }

    private val localBinder = LocalBinder()
    private var activeGeneration: String? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                val requestedGeneration = intent.getStringExtra(EXTRA_GENERATION)
                if (requestedGeneration != null && requestedGeneration == activeGeneration) {
                    activeGeneration = null
                    TorRuntimeHolder.get(this).stop(requestedGeneration)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelfResult(startId)
                }
            }
            ACTION_START, null -> {
                val generation = intent?.getStringExtra(EXTRA_GENERATION)
                if (generation != null) {
                    if (!generation.matches(Regex("[0-9a-f]{32}"))) {
                        stopSelfResult(startId)
                        return START_NOT_STICKY
                    }
                    val previousGeneration = activeGeneration
                    activeGeneration = generation
                    promoteToForeground(generation)
                    try {
                        TorRuntimeHolder.get(this).startAsync(generation)
                    } catch (_: Exception) {
                        // Restore an existing foreground session if a stale
                        // or overlapping start request was rejected.
                        activeGeneration = previousGeneration
                        if (previousGeneration != null) {
                            promoteToForeground(previousGeneration)
                        } else {
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelfResult(startId)
                        }
                    }
                } else {
                    // A null sticky restart has no in-memory room to restore.
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelfResult(startId)
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder = localBinder

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Privacy-first behavior: swiping the task ends the live room/runtime.
        activeGeneration?.let { TorRuntimeHolder.get(this).stop(it) }
        activeGeneration = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        activeGeneration?.let { TorRuntimeHolder.get(this).stop(it) }
        activeGeneration = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun promoteToForeground(generation: String) {
        val stopIntent = Intent(this, GhostChatSessionService::class.java)
            .setAction(ACTION_STOP)
            .putExtra(EXTRA_GENERATION, generation)
        val stopPendingIntent = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(org.lord.ghostchat.R.mipmap.ic_launcher)
                .setContentTitle("GhostChat session active")
                .setContentText("Tor-only private session")
                .setOngoing(true)
                .setCategory(Notification.CATEGORY_SERVICE)
                .addAction(
                    Notification.Action.Builder(
                        null,
                        "Stop",
                        stopPendingIntent,
                    ).build(),
                )
                .build()
        } else {
            @Suppress("DEPRECATION")
            val legacy = Notification.Builder(this)
                .setSmallIcon(org.lord.ghostchat.R.mipmap.ic_launcher)
                .setContentTitle("GhostChat session active")
                .setContentText("Tor-only private session")
                .setOngoing(true)
                .addAction(0, "Stop", stopPendingIntent)
            legacy.build()
        }

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val channel = NotificationChannel(
            CHANNEL_ID,
            "GhostChat session",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Ongoing private GhostChat Tor session"
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    inner class LocalBinder : android.os.Binder() {
        internal fun snapshot(): TorRuntimeSnapshot = TorRuntimeHolder.get(this@GhostChatSessionService).snapshot()
    }
}
