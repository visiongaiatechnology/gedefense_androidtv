package de.visiongaia.gedefense.tv.scan

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import de.visiongaia.gedefense.tv.contract.ScanControllerApi
import de.visiongaia.gedefense.tv.contract.ScanListener
import de.visiongaia.gedefense.tv.contract.ScanSummary
import de.visiongaia.gedefense.tv.contract.ScanUiState
import de.visiongaia.gedefense.tv.contract.SettingsApi
import de.visiongaia.gedefense.tv.contract.ThreatIntelApi
import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.Collector
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.EvidenceHealth
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.PatchPolicy
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import de.visiongaia.gedefense.tv.core.scan.DefaultScanEngine
import de.visiongaia.gedefense.tv.data.TvEvidenceRepository
import de.visiongaia.gedefense.tv.platform.AppInventoryCollector
import de.visiongaia.gedefense.tv.platform.ConnectivityCollector
import de.visiongaia.gedefense.tv.platform.HardeningCollector
import de.visiongaia.gedefense.tv.platform.PlatformCollector
import de.visiongaia.gedefense.tv.platform.SensorHealthCollector
import de.visiongaia.gedefense.tv.platform.ThreatIntelCollector
import de.visiongaia.gedefense.tv.platform.TvCollector
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Default TV scan controller.
 *
 * Runs one scan at a time on a single bounded background thread: collect the platform identity and
 * patch assessment first, then let the tv-core [DefaultScanEngine] execute the collectors in the
 * datasheet order (platform, app-inventory, hardening, connectivity, threat-intel, sensor-health).
 *
 * UI safety: every listener callback is posted to the main thread and wrapped so a throwing observer
 * can never take the scan pipeline or the app down. The last completed result is kept in memory, the
 * completion time is persisted through [SettingsApi], and the evidence repository receives the
 * finding and event records. [cancel] only requests cancellation; the engine and collectors poll the
 * signal between steps.
 */
class DefaultScanController(
    context: Context,
    private val settings: SettingsApi,
    private val deviceId: String,
    private val evidence: TvEvidenceRepository,
    private val threatIntel: ThreatIntelApi,
) : ScanControllerApi {
    private val appContext = context.applicationContext
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "gedefense-tv-scan").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val running = AtomicBoolean(false)
    private val cancelRequested = AtomicBoolean(false)

    @Volatile
    private var lastResult: ScanResult? = null

    @Volatile
    private var lastState: ScanState? = null

    @Volatile
    private var lastCompletedAtMillis = 0L

    @Volatile
    private var lastSummary: ScanSummary? = null

    init {
        // Restore the persisted outcome so the UI can state "last run completed at T" after a process
        // restart or reboot without pretending the detailed findings are still in memory.
        try {
            val persisted = settings.lastScanSummary()
            if (persisted != null) {
                lastSummary = persisted
                lastState = persisted.state
                lastCompletedAtMillis = persisted.completedAtMillis
            }
        } catch (_: Throwable) {
            // A corrupt preferences file must never prevent the controller from starting.
        }
    }

    override fun state(): ScanUiState = ScanUiState(
        running = running.get(),
        lastCompletedAtMillis = maxOf(lastCompletedAtMillis, settings.lastScanAtMillis()),
        lastState = lastState,
    )

    override fun lastResult(): ScanResult? = lastResult

    override fun lastSummary(): ScanSummary? =
        lastSummary ?: try {
            settings.lastScanSummary()
        } catch (_: Throwable) {
            null
        }

    override fun start(listener: ScanListener): Boolean {
        if (!running.compareAndSet(false, true)) return false
        cancelRequested.set(false)
        dispatch { listener.onStarted() }
        return try {
            executor.execute { runScan(listener) }
            true
        } catch (_: RejectedExecutionException) {
            running.set(false)
            dispatch { listener.onFailed(MessageRef(KEY_SCAN_FAILED)) }
            false
        }
    }

    override fun cancel(): Boolean {
        if (!running.get()) return false
        cancelRequested.set(true)
        return true
    }

    private fun runScan(listener: ScanListener) {
        try {
            val startedAt = System.currentTimeMillis()
            val identity = PlatformCollector.readIdentity(appContext)
            val patch = PatchPolicy.assess(identity.securityPatch, startedAt)
            val environment = CollectorEnvironment(
                collectedAtMillis = startedAt,
                deviceId = deviceId,
                platform = identity,
                patch = patch,
            )
            val appInventoryCollector = AppInventoryCollector(appContext)
            val collectors: List<Collector> = listOf(
                PlatformCollector(appContext),
                appInventoryCollector,
                HardeningCollector(appContext),
                ConnectivityCollector(appContext),
                ThreatIntelCollector { statusSafely() },
                SensorHealthCollector(appContext) { evidenceHealthSafely() },
            )
            val engine = DefaultScanEngine()
            val outcome = engine.run(
                collectors = collectors,
                environment = environment,
                cancel = CancelSignal { cancelRequested.get() },
                onProgress = { progress -> dispatch { listener.onProgress(progress) } },
            )
            val result = ScanResult.compose(
                outcome = outcome,
                platform = identity,
                patch = patch,
                inventory = appInventoryCollector.lastInventory,
                inventoryDelta = appInventoryCollector.lastDelta,
            )
            publish(result)
            persistSummary(result)
            persist(result, collectors)
            dispatch { listener.onCompleted(result) }
        } catch (_: InterruptedException) {
            // Clear the pool worker's interrupt flag so the next scan is not falsely cancelled.
            Thread.interrupted()
            lastState = ScanState.CANCELLED
            lastCompletedAtMillis = System.currentTimeMillis()
            running.set(false)
            cancelRequested.set(false)
            dispatch { listener.onFailed(MessageRef(KEY_SCAN_CANCELLED)) }
        } catch (error: Throwable) {
            // Never log collector payloads or exception messages: only the class name is stable and safe.
            Log.e(TAG, "scan failed type=${error::class.java.simpleName}")
            lastState = ScanState.FAILED
            lastCompletedAtMillis = System.currentTimeMillis()
            running.set(false)
            cancelRequested.set(false)
            dispatch { listener.onFailed(MessageRef(KEY_SCAN_FAILED)) }
        } finally {
            running.set(false)
            cancelRequested.set(false)
        }
    }

    private fun publish(result: ScanResult) {
        lastResult = result
        lastState = result.state
        lastCompletedAtMillis = result.completedAtMillis
        try {
            settings.setLastScanAtMillis(result.completedAtMillis)
        } catch (_: Throwable) {
            // A failing settings write must not destroy a completed scan.
        }
    }

    /**
     * Persists the lightweight outcome of a successfully finished scan (COMPLETED/PARTIAL).
     *
     * Failed and cancelled runs are deliberately not persisted as "last successful run": the
     * datasheet requires the last *successful* state to stay correct after reboot/Doze, and a failed
     * attempt must not overwrite an older honest summary.
     */
    private fun persistSummary(result: ScanResult) {
        if (result.state != ScanState.COMPLETED && result.state != ScanState.PARTIAL) return
        val summary = ScanSummary(
            completedAtMillis = result.completedAtMillis,
            state = result.state,
            coverage = result.coverage,
            band = result.score.band,
            scoreValue = result.score.value,
            findingsCount = result.findings.size,
            collectorCount = result.collectorResults.size,
        )
        lastSummary = summary
        try {
            settings.setLastScanSummary(summary)
        } catch (_: Throwable) {
            // In-memory lastSummary still serves the running process; persistence is best effort.
        }
    }

    private fun persist(result: ScanResult, collectors: List<Collector>) {
        try {
            evidence.recordScan(result)
        } catch (_: Throwable) {
            // The evidence health state surfaces the failure; the scan result stays valid.
        }
        val events = try {
            collectors.mapNotNull { it as? TvCollector }.flatMap { it.lastEvents }
        } catch (_: Throwable) {
            emptyList()
        }
        try {
            evidence.recordEvents(events)
        } catch (_: Throwable) {
            // Event persistence is best effort; findings are already recorded above.
        }
    }

    private fun statusSafely(): ThreatIntelStatus = try {
        threatIntel.status()
    } catch (_: Throwable) {
        ThreatIntelStatus.EMPTY
    }

    private fun evidenceHealthSafely(): EvidenceHealth = try {
        evidence.health()
    } catch (_: Throwable) {
        EvidenceHealth.UNAVAILABLE
    }

    private fun dispatch(action: () -> Unit) {
        mainHandler.post {
            try {
                action()
            } catch (_: Throwable) {
                // UI observers have no authority over the scan pipeline.
            }
        }
    }

    companion object {
        private const val TAG = "GeDefenseTvScan"
        private const val KEY_SCAN_CANCELLED = "scan.cancelled"
        private const val KEY_SCAN_FAILED = "scan.failed"
    }
}
