package de.visiongaia.gedefense.tv.data

import android.content.Context
import android.content.SharedPreferences
import de.visiongaia.gedefense.tv.contract.ScanSummary
import de.visiongaia.gedefense.tv.contract.SettingsApi
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.PostureBand
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.core.model.TvEvent
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import java.security.SecureRandom

/**
 * SharedPreferences-backed settings for GeDefense TV.
 *
 * The store is deliberately tiny and local-only: no telemetry flags, no identifiers beyond the
 * pseudonymous device id. Every value is bounded and validated on read so a corrupted or
 * manipulated preferences file can never crash the app.
 */
class TvSettingsStore(context: Context) : SettingsApi {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    override fun tiAutoSyncEnabled(): Boolean = prefs.getBoolean(KEY_TI_AUTO_SYNC, true)

    override fun setTiAutoSyncEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_TI_AUTO_SYNC, enabled).apply()
    }

    override fun retentionDays(): Int = prefs.getInt(KEY_RETENTION_DAYS, DEFAULT_RETENTION_DAYS)
        .coerceIn(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)

    override fun setRetentionDays(days: Int) {
        prefs.edit().putInt(KEY_RETENTION_DAYS, days.coerceIn(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)).apply()
    }

    override fun lastScanAtMillis(): Long = prefs.getLong(KEY_LAST_SCAN_AT, 0L).coerceAtLeast(0L)

    override fun setLastScanAtMillis(millis: Long) {
        prefs.edit().putLong(KEY_LAST_SCAN_AT, millis.coerceAtLeast(0L)).apply()
    }

    /**
     * Reads the persisted last-scan summary.
     *
     * Every field is validated and enum names are parsed defensively: a corrupted, truncated or
     * foreign preferences file yields null instead of throwing or fabricating a scan outcome. The
     * summary timestamp is the same value as [lastScanAtMillis] so both stay consistent.
     */
    override fun lastScanSummary(): ScanSummary? {
        val stateName = prefs.getString(KEY_SUMMARY_STATE, null) ?: return null
        val coverageName = prefs.getString(KEY_SUMMARY_COVERAGE, null) ?: return null
        val bandName = prefs.getString(KEY_SUMMARY_BAND, null) ?: return null
        val completedAt = prefs.getLong(KEY_LAST_SCAN_AT, 0L)
        if (completedAt <= 0L) return null
        val state = parseEnum<ScanState>(stateName) ?: return null
        val coverage = parseEnum<DataVisibility>(coverageName) ?: return null
        val band = parseEnum<PostureBand>(bandName) ?: return null
        val findingsCount = prefs.getInt(KEY_SUMMARY_FINDINGS, -1)
        val collectorCount = prefs.getInt(KEY_SUMMARY_COLLECTORS, -1)
        if (findingsCount < 0 || collectorCount < 0) return null
        val scoreValue = if (prefs.contains(KEY_SUMMARY_SCORE)) {
            prefs.getInt(KEY_SUMMARY_SCORE, -1).takeIf { it in 0..100 } ?: return null
        } else {
            null
        }
        return try {
            ScanSummary(
                completedAtMillis = completedAt,
                state = state,
                coverage = coverage,
                band = band,
                scoreValue = scoreValue,
                findingsCount = findingsCount,
                collectorCount = collectorCount,
            )
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    override fun setLastScanSummary(summary: ScanSummary?) {
        if (summary == null) {
            prefs.edit()
                .remove(KEY_SUMMARY_STATE)
                .remove(KEY_SUMMARY_COVERAGE)
                .remove(KEY_SUMMARY_BAND)
                .remove(KEY_SUMMARY_SCORE)
                .remove(KEY_SUMMARY_FINDINGS)
                .remove(KEY_SUMMARY_COLLECTORS)
                .apply()
            return
        }
        val editor = prefs.edit()
            .putString(KEY_SUMMARY_STATE, summary.state.name)
            .putString(KEY_SUMMARY_COVERAGE, summary.coverage.name)
            .putString(KEY_SUMMARY_BAND, summary.band.name)
            .putInt(KEY_SUMMARY_FINDINGS, summary.findingsCount)
            .putInt(KEY_SUMMARY_COLLECTORS, summary.collectorCount)
            .putLong(KEY_LAST_SCAN_AT, summary.completedAtMillis)
        if (summary.scoreValue != null) {
            editor.putInt(KEY_SUMMARY_SCORE, summary.scoreValue)
        } else {
            editor.remove(KEY_SUMMARY_SCORE)
        }
        // commit() so the summary is durable before the scan thread reports completion to the UI and
        // before a possible process death; the value is tiny and written off the main thread.
        editor.commit()
    }

    private inline fun <reified T : Enum<T>> parseEnum(name: String): T? = try {
        enumValueOf<T>(name)
    } catch (_: IllegalArgumentException) {
        null
    }

    override fun onboardingDone(): Boolean = prefs.getBoolean(KEY_ONBOARDING_DONE, false)

    override fun setOnboardingDone(done: Boolean) {
        prefs.edit().putBoolean(KEY_ONBOARDING_DONE, done).apply()
    }

    /**
     * User-selected UI scaling factor (0.80..1.30, default 1.0).
     *
     * A corrupted or foreign preferences value (wrong type, NaN, infinity, out-of-range) is normalised
     * to the default instead of throwing or distorting every screen layout. Applied by
     * `TvTheme.userScale`; the settings screen writes it through [setUiScale].
     */
    override fun uiScale(): Float {
        val stored = try {
            prefs.getFloat(KEY_UI_SCALE, DEFAULT_UI_SCALE)
        } catch (_: ClassCastException) {
            DEFAULT_UI_SCALE
        } catch (_: RuntimeException) {
            DEFAULT_UI_SCALE
        }
        return normaliseUiScale(stored)
    }

    override fun setUiScale(scale: Float) {
        try {
            prefs.edit().putFloat(KEY_UI_SCALE, normaliseUiScale(scale)).apply()
        } catch (_: RuntimeException) {
            // A failing preferences write must never crash the settings screen or the app.
        }
    }

    private fun normaliseUiScale(value: Float): Float {
        if (!value.isFinite()) return DEFAULT_UI_SCALE
        return value.coerceIn(MIN_UI_SCALE, MAX_UI_SCALE)
    }

    // ------------------------------------------------------------------ V2 VPN settings

    override fun vpnAutoStart(): Boolean = try {
        prefs.getBoolean(KEY_VPN_AUTO_START, true)
    } catch (_: RuntimeException) {
        true
    }

    override fun setVpnAutoStart(enabled: Boolean) {
        try {
            prefs.edit().putBoolean(KEY_VPN_AUTO_START, enabled).apply()
        } catch (_: RuntimeException) {
            // Preferences failures must never crash the protection screen.
        }
    }

    override fun privacyProfile(): TvPrivacyProfile = try {
        TvPrivacyProfile.fromStorage(prefs.getString(KEY_PRIVACY_PROFILE, null))
    } catch (_: RuntimeException) {
        TvPrivacyProfile.BALANCED
    }

    override fun setPrivacyProfile(profile: TvPrivacyProfile) {
        try {
            prefs.edit().putString(KEY_PRIVACY_PROFILE, profile.storageKey).apply()
        } catch (_: RuntimeException) {
            // Preferences failures must never crash the protection screen.
        }
    }

    override fun protectionSetupDone(): Boolean = try {
        prefs.getBoolean(KEY_PROTECTION_SETUP_DONE, false)
    } catch (_: RuntimeException) {
        false
    }

    override fun setProtectionSetupDone(done: Boolean) {
        try {
            prefs.edit().putBoolean(KEY_PROTECTION_SETUP_DONE, done).apply()
        } catch (_: RuntimeException) {
            // Preferences failures must never crash the onboarding flow.
        }
    }

    override fun detailedTelemetryEnabled(): Boolean = try {
        prefs.getBoolean(KEY_DETAILED_TELEMETRY, false)
    } catch (_: RuntimeException) {
        false
    }

    override fun setDetailedTelemetryEnabled(enabled: Boolean) {
        try {
            prefs.edit().putBoolean(KEY_DETAILED_TELEMETRY, enabled).apply()
        } catch (_: RuntimeException) {
            // Preferences failures must never crash the protection screen.
        }
    }

    /** V2.1 opt-in for temporary outbound containments (strict profile only). */
    override fun containmentEnabled(): Boolean = try {
        prefs.getBoolean(KEY_CONTAINMENT_ENABLED, false)
    } catch (_: RuntimeException) {
        false
    }

    override fun setContainmentEnabled(enabled: Boolean) {
        try {
            prefs.edit().putBoolean(KEY_CONTAINMENT_ENABLED, enabled).apply()
        } catch (_: RuntimeException) {
            // Preferences failures must never crash the protection screen.
        }
    }

    /** Last completed threat-intel sync, or 0 when the app never synced on this device. */
    fun lastThreatIntelSyncAtMillis(): Long = prefs.getLong(KEY_TI_LAST_SYNC_AT, 0L).coerceAtLeast(0L)

    fun setThreatIntelSyncResult(atMillis: Long, healthy: Boolean) {
        prefs.edit()
            .putLong(KEY_TI_LAST_SYNC_AT, atMillis.coerceAtLeast(0L))
            .putBoolean(KEY_TI_LAST_SYNC_OK, healthy)
            .apply()
    }

    fun lastThreatIntelSyncHealthy(): Boolean = prefs.getBoolean(KEY_TI_LAST_SYNC_OK, false)

    /**
     * Last validated per-feed snapshot (opaque compact text, at most [MAX_TI_SNAPSHOT_CHARS]).
     *
     * This lets the first UI frame show the last known feed state with ages derived from timestamps
     * without hashing or parsing any feed file on the UI thread. Null means "never validated".
     */
    fun threatIntelSnapshot(): String? = try {
        prefs.getString(KEY_TI_SNAPSHOT, null)?.takeIf { it.isNotBlank() && it.length <= MAX_TI_SNAPSHOT_CHARS }
    } catch (_: RuntimeException) {
        null
    }

    fun setThreatIntelSnapshot(snapshot: String?) {
        try {
            val editor = prefs.edit()
            if (snapshot == null || snapshot.length > MAX_TI_SNAPSHOT_CHARS) {
                editor.remove(KEY_TI_SNAPSHOT)
            } else {
                editor.putString(KEY_TI_SNAPSHOT, snapshot)
            }
            editor.apply()
        } catch (_: RuntimeException) {
            // A failed snapshot write only costs the fast first-frame hint; validation still runs.
        }
    }

    /**
     * Returns the persistent pseudonymous device id (`tv_` + 32 lowercase hex), generating and
     * storing it on first use. Stored synchronously so a scan can never run with a different id than
     * the one persisted for reports.
     */
    fun ensureDeviceId(): String {
        val existing = prefs.getString(KEY_DEVICE_ID, null)
        if (existing != null && TvEvent.DEVICE_ID_PATTERN.matches(existing)) return existing
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val generated = "tv_" + random.joinToString("") { byte -> "%02x".format(byte) }
        prefs.edit().putString(KEY_DEVICE_ID, generated).commit()
        return generated
    }

    companion object {
        private const val PREFS_NAME = "gedefense_tv"
        private const val KEY_TI_AUTO_SYNC = "ti.auto_sync"
        private const val KEY_RETENTION_DAYS = "retention.days"
        private const val KEY_LAST_SCAN_AT = "scan.last_at"
        private const val KEY_ONBOARDING_DONE = "onboarding.done"
        private const val KEY_DEVICE_ID = "device.id"
        private const val KEY_TI_LAST_SYNC_AT = "ti.last_sync_at"
        private const val KEY_TI_LAST_SYNC_OK = "ti.last_sync_ok"
        private const val KEY_TI_SNAPSHOT = "ti.snapshot"
        private const val KEY_SUMMARY_STATE = "scan.summary.state"
        private const val KEY_SUMMARY_COVERAGE = "scan.summary.coverage"
        private const val KEY_SUMMARY_BAND = "scan.summary.band"
        private const val KEY_SUMMARY_SCORE = "scan.summary.score"
        private const val KEY_SUMMARY_FINDINGS = "scan.summary.findings"
        private const val KEY_SUMMARY_COLLECTORS = "scan.summary.collectors"
        private const val KEY_UI_SCALE = "ui_scale"
        private const val KEY_VPN_AUTO_START = "vpn.auto_start"
        private const val KEY_PRIVACY_PROFILE = "vpn.privacy_profile"
        private const val KEY_PROTECTION_SETUP_DONE = "vpn.protection_setup_done"
        private const val KEY_DETAILED_TELEMETRY = "vpn.detailed_telemetry"
        private const val KEY_CONTAINMENT_ENABLED = "vpn.containment_enabled"

        const val DEFAULT_RETENTION_DAYS = 30
        const val MIN_RETENTION_DAYS = 1
        const val MAX_RETENTION_DAYS = 365

        /** Default and hard bounds of the persisted UI scaling factor. */
        const val DEFAULT_UI_SCALE = 1.0f
        const val MIN_UI_SCALE = 0.80f
        const val MAX_UI_SCALE = 1.30f
        private const val MAX_TI_SNAPSHOT_CHARS = 2_048
    }
}
