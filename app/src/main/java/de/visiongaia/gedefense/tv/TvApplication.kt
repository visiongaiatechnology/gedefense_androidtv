package de.visiongaia.gedefense.tv

import android.app.Application
import android.util.Log
import de.visiongaia.gedefense.tv.data.TvServicesBootstrap

/**
 * Application entry point. It establishes the process-wide service container exactly once.
 *
 * Startup is deliberately fail-fast: if the evidence/config bootstrap cannot be created the app
 * must not pretend to be a security app with missing state. The failure is logged without secrets
 * and the process terminates instead of running with a half-wired pipeline.
 */
class TvApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val startedAt = System.nanoTime()
        try {
            // The bootstrap wires every service and installs the container exactly once.
            val services = TvServicesBootstrap.create(this)
            // Apply the persisted, user-adjustable UI scale before the first screen is built.
            de.visiongaia.gedefense.tv.ui.TvTheme.userScale = services.settings.uiScale()
        } catch (t: Throwable) {
            Log.e(TAG, "GeDefense TV service bootstrap failed", t)
            throw t
        } finally {
            val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000L
            Log.i(TAG, "service bootstrap took ${elapsedMs}ms")
        }
    }

    companion object {
        private const val TAG = "GeDefenseTv"
    }
}
