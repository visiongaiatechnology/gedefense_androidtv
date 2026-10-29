package de.visiongaia.gedefense.tv.data

import android.content.Context
import android.util.Log
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.EvidenceLedger
import de.visiongaia.gedefense.mobile.core.EvidencePayloadProtector
import de.visiongaia.gedefense.mobile.core.EvidenceStore
import de.visiongaia.gedefense.mobile.core.LedgerHealth
import de.visiongaia.gedefense.mobile.core.UnavailableEvidenceStore
import de.visiongaia.gedefense.tv.contract.EvidenceApi
import de.visiongaia.gedefense.tv.contract.EvidenceRow
import de.visiongaia.gedefense.tv.core.model.EvidenceHealth
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.TvEvent
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.SecretKey

/**
 * Tamper-evident local evidence store for GeDefense TV.
 *
 * Key custody is fail-closed and provided by [TvKeyCustody]: a random root is wrapped with an Android
 * Keystore AES-GCM key and domain-separated HMAC-SHA256 (ledger chain) plus AES-256-GCM (per-record
 * payload, bound to sequence + timestamp) subkeys are derived in memory. If custody cannot be
 * established, the repository falls back to [UnavailableEvidenceStore] and never reports a healthy
 * empty ledger, never writes plaintext and never accepts records.
 *
 * Keystore access is asynchronous because AndroidKeystoreGate rejects main-thread provider calls;
 * [health] reports an honest "initializing" state until the background bootstrap finished.
 */
class TvEvidenceRepository(context: Context) : EvidenceApi {
    private val appContext = context.applicationContext
    private val lock = Any()
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "gedefense-tv-evidence").apply { isDaemon = true }
    }
    private val ready = CountDownLatch(1)

    @Volatile
    private var initialized = false

    @Volatile
    private var unavailableReason: String? = null

    private var hmacKey: SecretKey? = null
    private var protector: EvidencePayloadProtector? = null
    private var ledger: EvidenceStore? = null
    private var cachedHealth: LedgerHealth = LedgerHealth(false, 0L, REASON_INITIALIZING)
    private var lastVerifyMillis = 0L
    private var verifyScheduled = false
    private var stateGeneration = 0L

    init {
        executor.execute { bootstrap() }
    }

    /**
     * Waits until key custody and ledger verification finished (or timed out).
     *
     * Startup components that also use the protected keyring (threat-intel cache) call this first so
     * key custody is established exactly once before other stores ask for their subkeys.
     */
    fun awaitStartup(timeoutMillis: Long = 15_000L): Boolean = try {
        ready.await(timeoutMillis.coerceIn(1L, 60_000L), TimeUnit.MILLISECONDS)
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }

    private fun bootstrap() {
        val startedAt = System.currentTimeMillis()
        try {
            val custody = TvKeyCustody.ensureLoaded(appContext)
            val material = custody.material
                ?: return markUnavailable(custody.failureCode ?: TvKeyCustody.CODE_CUSTODY_UNAVAILABLE)
            val file = ledgerFile()
            var activeProtector = AesGcmEvidenceProtector(material.evidenceAes)
            var store = EvidenceLedger(file, material.evidenceHmac, MAX_LEDGER_BYTES, activeProtector)
            var openHealth = store.open()
            if (!openHealth.ok && custody.createdNow && file.isFile && file.length() > 0L) {
                // Upgrade path only: the file predates the Keystore-wrapped keyring (it was written with
                // the earlier per-store Keystore aliases and cannot be authenticated with the new
                // subkeys). Preserve the bytes in an archive and start a fresh authenticated chain;
                // with an already existing keyring an unhealthy ledger is treated as tampering and
                // stays fail-closed.
                archiveUnverifiedLedger(file)
                activeProtector = AesGcmEvidenceProtector(material.evidenceAes)
                store = EvidenceLedger(file, material.evidenceHmac, MAX_LEDGER_BYTES, activeProtector)
                openHealth = store.open()
            }
            if (!openHealth.ok) {
                Log.w(TAG, "evidence ledger opened degraded: ${openHealth.reason.orEmpty().take(120)}")
            }
            synchronized(lock) {
                hmacKey = material.evidenceHmac
                protector = activeProtector
                ledger = store
                cachedHealth = openHealth
                lastVerifyMillis = System.currentTimeMillis()
                initialized = true
            }
            Log.i(
                PERF_TAG,
                "evidence.bootstrap ms=${System.currentTimeMillis() - startedAt} " +
                    "records=${openHealth.records} healthy=${openHealth.ok}",
            )
        } catch (error: Throwable) {
            Log.w(TAG, "evidence bootstrap failed: ${describe(error)}")
            markUnavailable("bootstrap failed")
        } finally {
            ready.countDown()
        }
    }

    /**
     * Moves an unverified legacy ledger into `evidence/legacy/` without deleting it. This is only used
     * once, when the keyring is created for the first time (alpha upgrade path), never for a ledger
     * that was written under the current keyring.
     */
    private fun archiveUnverifiedLedger(file: File) {
        try {
            val archiveDirectory = File(File(appContext.noBackupFilesDir, "evidence"), "legacy")
            if (!archiveDirectory.mkdirs() && !archiveDirectory.isDirectory) return
            val archive = File(archiveDirectory, "events.v3-${System.currentTimeMillis()}.log")
            try {
                Files.move(file.toPath(), archive.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (_: Throwable) {
                Files.move(file.toPath(), archive.toPath())
            }
            Log.w(TAG, "archived unverified legacy evidence ledger as ${archive.name} (${archive.length()} bytes)")
        } catch (error: Throwable) {
            // If the archive fails, the new ledger creation below still fails closed on the old file.
            Log.w(TAG, "legacy evidence archive failed: ${describe(error)}")
        }
    }

    private fun markUnavailable(reason: String) {
        Log.w(TAG, "evidence store unavailable: $reason")
        synchronized(lock) {
            unavailableReason = REASON_KEY_UNAVAILABLE
            hmacKey = null
            protector = null
            ledger = UnavailableEvidenceStore(REASON_KEY_UNAVAILABLE)
            cachedHealth = LedgerHealth(false, 0L, REASON_KEY_UNAVAILABLE)
            initialized = true
        }
    }

    override fun health(): EvidenceHealth = synchronized(lock) {
        val startedAt = System.nanoTime()
        if (!initialized) return EvidenceHealth(false, 0L, MessageRef(KEY_EVIDENCE_INITIALIZING))
        if (unavailableReason != null) return EvidenceHealth(false, 0L, MessageRef(KEY_EVIDENCE_UNAVAILABLE))
        if (!cachedHealth.ok && !verifyScheduled) {
            // A degraded flag can be transient (Keystore provider warm-up, interrupted verification).
            // Force a fresh verification at most once per in-flight check so a stale flag cannot stick
            // forever; a genuinely broken ledger still verifies unhealthy and keeps reporting so.
            lastVerifyMillis = 0L
        }
        scheduleVerifyLocked()
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000L
        if (elapsedMs > HEALTH_WARN_MILLIS) Log.w(PERF_TAG, "evidence.health slow ms=$elapsedMs")
        if (cachedHealth.ok) {
            EvidenceHealth(healthy = true, records = cachedHealth.records)
        } else {
            EvidenceHealth(
                healthy = false,
                records = cachedHealth.records,
                reason = MessageRef(KEY_EVIDENCE_DEGRADED),
            )
        }
    }

    override fun recordScan(result: ScanResult): Boolean {
        awaitReady()
        val events = buildScanEvents(result)
        return appendEvents(events)
    }

    override fun recordSecurityEvent(type: String, severity: String, subject: String, detail: String): Boolean {
        awaitReady()
        val safeType = type.take(64)
        if (!EVENT_TYPE_PATTERN.matches(safeType)) return false
        val safeSeverity = severity.take(16)
        if (!EVENT_SEVERITY_PATTERN.matches(safeSeverity)) return false
        return appendEvents(
            listOf(
                EvidenceEvent(
                    type = safeType,
                    severity = safeSeverity,
                    subject = oneLine(subject, 200),
                    detail = oneLine(detail, 600),
                    atMillis = System.currentTimeMillis(),
                ),
            ),
        )
    }


    override fun rows(limit: Int): List<EvidenceRow> {
        val startedAt = System.currentTimeMillis()
        val effective = limit.coerceIn(1, MAX_ROWS)
        val activeProtector: EvidencePayloadProtector
        val activeHmac: SecretKey
        val file: File
        synchronized(lock) {
            if (!initialized || unavailableReason != null) return emptyList()
            if (!cachedHealth.ok) return emptyList()
            activeProtector = protector ?: return emptyList()
            activeHmac = hmacKey ?: return emptyList()
            file = ledgerFile()
            if (!file.isFile) return emptyList()
        }
        val events = try {
            EvidenceTailReader.readLast(file, effective, activeHmac, activeProtector)
        } catch (error: Throwable) {
            Log.w(TAG, "evidence row read failed: ${describe(error)}")
            emptyList()
        }
        val elapsedMs = System.currentTimeMillis() - startedAt
        if (elapsedMs > ROWS_WARN_MILLIS) {
            Log.w(PERF_TAG, "evidence.rows slow ms=$elapsedMs requested=$effective returned=${events.size}")
        }
        // Newest first: the evidence screen shows the latest events without scrolling.
        return events.asReversed().map { event ->
            EvidenceRow(
                atMillis = event.atMillis,
                type = event.type,
                severity = event.severity,
                subject = event.subject,
            )
        }
    }

    override fun clear(): Boolean {
        awaitReady()
        return synchronized(lock) {
        val file = ledgerFile()
        try {
            if (file.exists() && !file.delete()) return false
            val activeHmac = hmacKey
            val activeProtector = protector
            if (activeHmac != null && activeProtector != null) {
                val fresh = EvidenceLedger(file, activeHmac, MAX_LEDGER_BYTES, activeProtector)
                ledger = fresh
                cachedHealth = fresh.open()
                unavailableReason = null
                stateGeneration++
            } else {
                cachedHealth = LedgerHealth(false, 0L, unavailableReason ?: REASON_KEY_UNAVAILABLE)
                // Key custody is unavailable (for example after a Keystore reset): the user-requested
                // deletion also drops the wrapped keyring so the next app start can establish fresh
                // key custody instead of staying unusable forever.
                if (unavailableReason != null) TvKeyCustody.deleteKeyring(appContext)
            }
            lastVerifyMillis = System.currentTimeMillis()
            file.parentFile?.let { parent -> runCatching { SecureFiles.fsyncDirectory(parent) } }
            true
        } catch (error: Throwable) {
            Log.w(TAG, "evidence clear failed: ${describe(error)}")
            false
        }
        }
    }

    /**
     * Persists real XDR-lite events (device state, app inventory, connectivity, sensor health) as
     * authenticated evidence rows. The event schema stays exactly [TvEvent]; this method only adds
     * the evidence sink that the read-only contract does not model.
     */
    fun recordEvents(events: List<TvEvent>): Boolean {
        if (events.isEmpty()) return true
        awaitReady()
        val records = events.map { event ->
            EvidenceEvent(
                type = EVENT_TYPE,
                severity = event.severity?.name?.lowercase() ?: SEVERITY_INFO,
                subject = oneLine(event.subject, 200),
                detail = buildEventDetail(event),
                atMillis = event.eventTimeMillis,
            )
        }
        return appendEvents(records)
    }

    private fun awaitReady() {
        if (!initialized) ready.await(KEY_CUSTODY_WAIT_SECONDS, TimeUnit.SECONDS)
    }

    private fun appendEvents(events: List<EvidenceEvent>): Boolean {
        if (events.isEmpty()) return true
        if (!initialized || unavailableReason != null) return false
        synchronized(lock) {
            val store = ledger ?: return false
            if (unavailableReason != null) return false
            return try {
                for (event in events) store.append(event)
                if (cachedHealth.ok) {
                    cachedHealth = cachedHealth.copy(records = cachedHealth.records + events.size)
                }
                lastVerifyMillis = System.currentTimeMillis()
                true
            } catch (error: Throwable) {
                // The ledger may be degraded or full; health will surface the degraded state.
                Log.w(TAG, "evidence append failed: ${describe(error)}")
                cachedHealth = cachedHealth.copy(ok = false, reason = "evidence append failed")
                false
            }
        }
    }

    private fun scheduleVerifyLocked() {
        if (!initialized || unavailableReason != null || verifyScheduled) return
        val now = System.currentTimeMillis()
        if (now - lastVerifyMillis < VERIFY_INTERVAL_MILLIS) return
        val store = ledger ?: return
        val generation = stateGeneration
        verifyScheduled = true
        executor.execute {
            val verified = try {
                store.verify()
            } catch (error: Throwable) {
                Log.w(TAG, "evidence verification failed: ${describe(error)}")
                LedgerHealth(false, cachedHealth.records, "evidence verify failed")
            }
            synchronized(lock) {
                // A concurrent clear() replaces the ledger; a stale verification result must not
                // overwrite the fresh, healthy state.
                if (stateGeneration == generation) {
                    cachedHealth = verified
                    lastVerifyMillis = System.currentTimeMillis()
                }
                verifyScheduled = false
            }
        }
    }

    private fun buildScanEvents(result: ScanResult): List<EvidenceEvent> {
        val summary = EvidenceEvent(
            type = "scan.completed",
            severity = when (result.state.name) {
                "COMPLETED" -> SEVERITY_INFO
                "PARTIAL" -> SEVERITY_WARNING
                else -> SEVERITY_WARNING
            },
            subject = "scan",
            detail = oneLine(
                "scanId=${result.scanId} state=${result.state.name} collectors=${result.collectorResults.size} " +
                    "findings=${result.findings.size} coverage=${result.coverage.name} " +
                    "score=${result.score.value?.toString() ?: "unknown"} band=${result.score.band.name}",
                1_500,
            ),
            atMillis = result.completedAtMillis,
        )
        val findingEvents = result.findings
            .sortedWith(compareByDescending<Finding> { it.severity.rank }.thenBy { it.firstSeenMillis })
            .take(MAX_FINDING_EVENTS)
            .map { finding -> findingEvent(finding, result.completedAtMillis) }
        return listOf(summary) + findingEvents
    }

    private fun findingEvent(finding: Finding, atMillis: Long): EvidenceEvent = EvidenceEvent(
        type = "scan.finding",
        severity = finding.severity.name.lowercase(),
        subject = oneLine(finding.component, 200),
        detail = oneLine(
            "rule=${finding.ruleId} findingId=${finding.id} confidence=${finding.confidence.name} " +
                "visibility=${finding.visibility.name} policy=${finding.policyAction.name} " +
                "evidence=${finding.evidence.source} titleKey=${finding.title.key}",
            1_500,
        ),
        atMillis = atMillis,
    )

    private fun buildEventDetail(event: TvEvent): String {
        val builder = StringBuilder(256)
        builder.append("class=").append(event.eventClass.name)
        builder.append(" id=").append(event.eventId)
        builder.append(" collector=").append(event.collectorId)
        builder.append(" dq=").append(event.dataQuality.name)
        event.ruleId?.let { builder.append(" rule=").append(it) }
        event.severity?.let { builder.append(" sev=").append(it.name) }
        event.confidence?.let { builder.append(" conf=").append(it.name) }
        var included = 0
        for ((key, value) in event.attributes) {
            val addition = " $key=${oneLine(value, 200)}"
            if (builder.length + addition.length > MAX_DETAIL_CHARS) break
            builder.append(addition)
            included++
        }
        val omitted = event.attributes.size - included
        if (omitted > 0) builder.append(" attrs_omitted=").append(omitted)
        return oneLine(builder.toString(), MAX_DETAIL_CHARS)
    }

    private fun ledgerFile(): File = File(File(appContext.noBackupFilesDir, "evidence"), "events.v3.log")

    private fun oneLine(value: String, max: Int): String {
        val sanitized = value.map { character ->
            if (character == '\n' || character == '\r' || character == '\t') ' ' else character
        }.joinToString("").trim()
        return if (sanitized.length <= max) sanitized else sanitized.take(max - 1) + "\u2026"
    }

    /** Short, secret-free diagnostic form for logs: exception type plus a sanitised message prefix. */
    private fun describe(error: Throwable): String {
        val message = error.message.orEmpty()
            .map { character -> if (character == '\n' || character == '\r') ' ' else character }
            .joinToString("")
            .trim()
            .take(120)
        return "${error::class.java.simpleName}: $message"
    }

    companion object {
        private const val TAG = "GeDefenseTv"
        private const val PERF_TAG = "GeDefenseTvPerf"
        private const val MAX_LEDGER_BYTES = 16L shl 20
        private const val MAX_ROWS = 500
        private const val MAX_FINDING_EVENTS = 200
        private const val MAX_DETAIL_CHARS = 1_900
        private const val VERIFY_INTERVAL_MILLIS = 30_000L
        private const val HEALTH_WARN_MILLIS = 10L
        private const val ROWS_WARN_MILLIS = 50L
        private const val KEY_CUSTODY_WAIT_SECONDS = 5L
        private const val REASON_INITIALIZING = "evidence_initializing"
        private const val REASON_KEY_UNAVAILABLE = "evidence_key_custody_unavailable"
        private const val KEY_EVIDENCE_INITIALIZING = "evidence.initializing"
        private const val KEY_EVIDENCE_UNAVAILABLE = "evidence.unavailable"
        private const val KEY_EVIDENCE_DEGRADED = "evidence.degraded"
        private const val EVENT_TYPE = "tv.event"
        private const val SEVERITY_INFO = "info"
        private val EVENT_TYPE_PATTERN = Regex("[a-z][a-z0-9_.]{2,63}")
        private val EVENT_SEVERITY_PATTERN = Regex("[a-z]{3,16}")
        private const val SEVERITY_WARNING = "warning"
    }
}
