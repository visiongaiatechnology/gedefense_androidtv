package de.visiongaia.gedefense.tv.contract

import android.app.Activity
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EvidenceHealth
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.PostureBand
import de.visiongaia.gedefense.tv.core.model.ScanProgress
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.core.model.SecurityReport
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus

/**
 * App-layer contracts between the UI, the scan controller and the data/platform layer.
 *
 * These interfaces exist so that the TV UI can be developed and reviewed against a stable API
 * without touching collector or persistence code. Implementations live in `scan/` and `data/`.
 */

data class ScanUiState(
    val running: Boolean,
    val lastCompletedAtMillis: Long,
    val lastState: ScanState?,
)

/**
 * Lightweight, persisted outcome of the most recent scan.
 *
 * The full [ScanResult] is intentionally not persisted: findings carry evidence details that should
 * not be rehydrated as if they were freshly verified. The summary keeps the honest statement "the
 * last run finished with X at time T" across process restarts, while the UI must state that detailed
 * findings are no longer in memory after a restart.
 */
data class ScanSummary(
    val completedAtMillis: Long,
    val state: ScanState,
    val coverage: DataVisibility,
    val band: PostureBand,
    val scoreValue: Int?,
    val findingsCount: Int,
    val collectorCount: Int,
) {
    init {
        require(completedAtMillis > 0L) { "invalid scan summary timestamp" }
        require(findingsCount >= 0) { "negative findings count" }
        require(collectorCount >= 0) { "negative collector count" }
        require(scoreValue == null || scoreValue in 0..100) { "score value out of range" }
    }
}

data class EvidenceRow(
    val atMillis: Long,
    val type: String,
    val severity: String,
    val subject: String,
)

data class ExportResult(
    val ok: Boolean,
    val fileName: String?,
    val message: MessageRef,
)

/** Receives scan lifecycle callbacks. Callbacks may arrive on a background thread. */
interface ScanListener {
    fun onStarted() {}

    fun onProgress(progress: ScanProgress) {}

    fun onCompleted(result: ScanResult) {}

    fun onFailed(error: MessageRef) {}
}

interface ScanControllerApi {
    fun state(): ScanUiState

    fun lastResult(): ScanResult?

    /**
     * Persisted summary of the most recent completed scan. Non-null across process restarts when a
     * scan finished successfully; full findings are explicitly not part of the summary.
     */
    fun lastSummary(): ScanSummary?

    /** Starts a scan. Returns false when a scan is already running. */
    fun start(listener: ScanListener): Boolean

    /** Requests cancellation. Returns false when no scan is running. */
    fun cancel(): Boolean
}

interface ThreatIntelSyncListener {
    /** Coarse progress while feeds are downloaded; called on a worker thread. */
    fun onProgress(completed: Int, total: Int, lastFeedId: String) {}

    fun onSyncFinished(ok: Boolean, message: MessageRef, status: ThreatIntelStatus)
}

interface ThreatIntelApi {
    fun status(): ThreatIntelStatus

    /** Starts a manual feed sync. Returns false when a sync is already running. */
    fun syncNow(listener: ThreatIntelSyncListener): Boolean

    fun schedulePeriodicSync(enabled: Boolean)
}

interface EvidenceApi {
    fun health(): EvidenceHealth

    /** Appends the scan findings/events to the local tamper-evident evidence ledger. */
    fun recordScan(result: ScanResult): Boolean

    /**
     * Appends one bounded operational security event (e.g. temporary containment applied/released)
     * to the local evidence ledger. Never accepts secrets; callers pass short ASCII metadata only.
     */
    fun recordSecurityEvent(type: String, severity: String, subject: String, detail: String): Boolean

    fun rows(limit: Int): List<EvidenceRow>

    /** Deletes local evidence data. Returns false when the deletion could not be completed. */
    fun clear(): Boolean
}

interface ReportApi {
    fun build(result: ScanResult): SecurityReport

    /**
     * Builds the report and writes it through the platform document picker (SAF) owned by
     * [activity]. Returns false when the export could not be started.
     */
    fun export(report: SecurityReport, activity: Activity, listener: (ExportResult) -> Unit): Boolean
}

interface SettingsApi {
    fun tiAutoSyncEnabled(): Boolean

    fun setTiAutoSyncEnabled(enabled: Boolean)

    fun retentionDays(): Int

    fun setRetentionDays(days: Int)

    fun lastScanAtMillis(): Long

    fun setLastScanAtMillis(millis: Long)

    /** Persisted summary of the last completed scan (see [ScanSummary]); null when never scanned. */
    fun lastScanSummary(): ScanSummary?

    fun setLastScanSummary(summary: ScanSummary?)

    /** User-adjustable UI scale (1.0 = normal); persisted and applied process-wide. */
    fun uiScale(): Float

    fun setUiScale(scale: Float)

    fun onboardingDone(): Boolean

    fun setOnboardingDone(done: Boolean)

    /** Start the local loopback VPN automatically after boot/app start when consent exists. */
    fun vpnAutoStart(): Boolean

    fun setVpnAutoStart(enabled: Boolean)

    /** Persisted privacy/filter profile for the local VPN policy. */
    fun privacyProfile(): de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile

    fun setPrivacyProfile(profile: de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile)

    /** True once the user completed the first-run protection onboarding. */
    fun protectionSetupDone(): Boolean

    fun setProtectionSetupDone(done: Boolean)

    /** Detailed local telemetry (flow-level rows) toggle; off by default on low-end TVs. */
    fun detailedTelemetryEnabled(): Boolean

    fun setDetailedTelemetryEnabled(enabled: Boolean)

    /** Opt-in for temporary outbound containments; only effective in the strict profile. */
    fun containmentEnabled(): Boolean

    fun setContainmentEnabled(enabled: Boolean)
}
