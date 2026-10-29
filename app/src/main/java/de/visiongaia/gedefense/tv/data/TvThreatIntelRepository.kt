package de.visiongaia.gedefense.tv.data

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import de.visiongaia.gedefense.mobile.core.ThreatCacheStore
import de.visiongaia.gedefense.mobile.core.ThreatFeed
import de.visiongaia.gedefense.mobile.core.ThreatFeedCatalog
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.contract.ThreatIntelApi
import de.visiongaia.gedefense.tv.contract.ThreatIntelSyncListener
import de.visiongaia.gedefense.tv.core.model.FeedSnapshot
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.SecretKey

/**
 * Threat-intelligence client for GeDefense TV.
 *
 * Reuses the vendored core ([ThreatFeedCatalog], [ThreatCacheStore]) instead of a second IOC engine.
 * The integrity key is a process-keyring HMAC subkey ([TvKeyCustody]); the store never accepts a
 * generation without a valid HMAC-authenticated metadata pair.
 *
 * Performance contract (TV UI, debug build):
 *  - [status] never touches the file system, hashes or parses a feed. It returns the last validated
 *    [ThreatIntelStatus] snapshot immediately.
 *  - Validation (which does run `sha256` + full feed parsing inside the vendored store) happens on the
 *    single background sync executor at start-up, after a sync, and lazily when the cached snapshot is
 *    older than [VALIDATION_TTL_MILLIS]. Refreshes are coalesced by [refreshing].
 *  - Until the first validation finished, the cached status honestly reports every feed as unavailable
 *    ("never synchronised"); it never pretends to be clean.
 *
 * Sync behaviour:
 *  - manual and periodic syncs share one bounded background pipeline (max 3 parallel downloads);
 *  - each feed is skipped while its `minRefreshMinutes` budget is still open (based on the cached
 *    snapshot, not on a fresh parse);
 *  - feeds are downloaded TLS-only through [TvFeedDownloader] and committed only after size, digest,
 *    format and HMAC verification;
 *  - no destination address, package list or usage data is ever uploaded.
 */
class TvThreatIntelRepository(
    context: Context,
    private val settings: TvSettingsStore,
    /**
     * Called once before the first Keystore/cache operation. It lets the process bootstrap serialize
     * the cold Android Keystore path (evidence key custody) ahead of the cache verification, because
     * concurrent first-use calls against an opaque provider can trip the core's bounded-crypto
     * circuit and would then make unrelated stores fail closed for the rest of the process.
     */
    private val startupGate: () -> Unit = {},
    /**
     * Called on the background sync thread with the freshly validated threat index after a
     * successful sync so the VPN policy can be refreshed. Default: no-op (JVM/test construction).
     */
    private val onPolicyIndexUpdated: (ThreatIndex) -> Unit = {},
) : ThreatIntelApi {
    private val appContext = context.applicationContext
    private val root = File(appContext.filesDir, "threat-intel")
    private val store = ThreatCacheStore(root, null) { integrityKeyOrNull() }
    private val syncing = AtomicBoolean(false)
    private val refreshing = AtomicBoolean(false)
    private val immediateResyncScheduled = AtomicBoolean(false)
    private val syncExecutor = Executors.newSingleThreadExecutor { runnable ->
        // Background priority for the (CPU-heavy) cache validation so it cannot compete with the TV
        // UI thread for first-frame rendering.
        Thread(runnable, "gedefense-tv-ti-sync").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }
    }
    private val downloadPool = Executors.newFixedThreadPool(MAX_PARALLEL_DOWNLOADS) { runnable ->
        Thread(runnable, "gedefense-tv-ti-download").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile
    private var cachedKey: SecretKey? = null

    @Volatile
    private var keyState: KeyState = KeyState.UNKNOWN

    /** Validated per-feed snapshots; null until the first background validation completed. */
    @Volatile
    private var validatedFeeds: List<FeedSnapshot>? = null

    @Volatile
    private var lastValidationMillis = 0L

    /**
     * True until [warmUp] queued its startup validation. While set, [status] must not start a competing
     * validation pass (the UI calls status() on the first frame, before warm-up finished).
     */
    @Volatile
    private var startupValidationQueued = true

    /** Always safe to read from the UI thread; starts as an honest "never synchronised" status. */
    @Volatile
    private var cachedStatus: ThreatIntelStatus = initialStatus()

    init {
        syncExecutor.execute { warmUp() }
    }

    override fun status(): ThreatIntelStatus {
        val startedAt = System.nanoTime()
        val now = System.currentTimeMillis()
        val status = cachedStatus
        val neverValidated = validatedFeeds == null
        if (neverValidated) {
            if (!startupValidationQueued) scheduleValidation(force = true)
        } else if (now - lastValidationMillis > VALIDATION_TTL_MILLIS) {
            scheduleValidation(force = false)
        }
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000L
        if (elapsedMs > STATUS_WARN_MILLIS) {
            Log.w(PERF_TAG, "threatintel.status exceeded UI budget: ${elapsedMs}ms")
        }
        return status
    }

    override fun syncNow(listener: ThreatIntelSyncListener): Boolean {
        if (!syncing.compareAndSet(false, true)) return false
        syncExecutor.execute {
            val startedAt = System.currentTimeMillis()
            val result = try {
                performSync()
            } catch (_: Throwable) {
                SyncResult(ok = false, message = MessageRef(KEY_TI_SYNCFAILED))
            } finally {
                syncing.set(false)
            }
            Log.i(
                PERF_TAG,
                "threatintel.sync ms=${System.currentTimeMillis() - startedAt} ok=${result.ok} " +
                    "available=${cachedStatus.availableCount}",
            )
            mainHandler.post {
                try {
                    listener.onSyncFinished(result.ok, result.message, cachedStatus)
                } catch (_: Throwable) {
                    // A UI observer must never be able to break the sync pipeline.
                }
            }
        }
        return true
    }

    /**
     * Schedules or cancels the periodic feed sync.
     *
     * The job is deliberately **not** persisted across reboots: `JobInfo.Builder.setPersisted(true)`
     * requires `android.permission.RECEIVE_BOOT_COMPLETED`, and the TV app intentionally requests no
     * permission beyond INTERNET and ACCESS_NETWORK_STATE. Instead, [warmUp] re-schedules the job on
     * every app start while auto-sync is enabled, so a device that runs the app keeps its periodic
     * refresh without an extra boot receiver or privilege.
     */
    override fun schedulePeriodicSync(enabled: Boolean) {
        val scheduler = appContext.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
        try {
            if (!enabled) {
                scheduler.cancel(THREAT_INTEL_JOB_ID)
                return
            }
            if (scheduler.getPendingJob(THREAT_INTEL_JOB_ID) != null) return
            val component = ComponentName(
                appContext,
                de.visiongaia.gedefense.tv.platform.TvThreatIntelJobService::class.java,
            )
            val job = JobInfo.Builder(THREAT_INTEL_JOB_ID, component)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPeriodic(PERIODIC_MILLIS, FLEX_MILLIS)
                .build()
            scheduler.schedule(job)
        } catch (_: Throwable) {
            // Job scheduling is enrichment: the manual sync path stays fully functional without it.
        }
    }

    private fun warmUp() {
        try {
            startupGate()
        } catch (_: Throwable) {
            // A failing gate must not block the feed cache; the cache fails closed on its own.
        }
        integrityKeyOrNull()
        // No feed parsing/hashing here on the caller; the validated snapshot is produced on this same
        // background thread by the coalesced refresh below. When a persisted snapshot exists it already
        // drives the first UI frame, so validation is deferred slightly to keep first-frame latency low.
        val hasPersistedSnapshot = try {
            settings.threatIntelSnapshot() != null
        } catch (_: Throwable) {
            false
        }
        startupValidationQueued = false
        scheduleValidation(
            force = true,
            delayMillis = if (hasPersistedSnapshot) STARTUP_VALIDATION_DELAY_MILLIS else 0L,
        )
        if (settings.tiAutoSyncEnabled()) schedulePeriodicSync(true)
    }

    /**
     * Queues one background validation of the authenticated feed cache. Coalesced: while a validation
     * is queued/running no second one is started.
     */
    private fun scheduleValidation(force: Boolean, delayMillis: Long = 0L) {
        if (!force && refreshing.get()) return
        if (!refreshing.compareAndSet(false, true)) return
        syncExecutor.execute {
            try {
                if (delayMillis > 0L) {
                    try {
                        Thread.sleep(delayMillis)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        return@execute
                    }
                }
                validateAndPublishStatus()
            } catch (_: Throwable) {
                // Keep the last validated status; a later refresh retries.
            } finally {
                refreshing.set(false)
            }
        }
    }

    /**
     * Canonical validation pass. This is the ONLY place that calls into the vendored cache store's
     * `latestInfo`, i.e. the only place that hashes and parses feed generations. Runs on the sync
     * executor, never on the UI thread.
     */
    private fun validateAndPublishStatus() {
        val startedAt = System.currentTimeMillis()
        val now = startedAt
        val feeds = ThreatFeedCatalog.all.map { feed ->
            val info = try {
                store.latestInfo(feed, now)
            } catch (_: Throwable) {
                null
            }
            FeedSnapshot(
                id = feed.id,
                name = feed.name,
                available = info != null,
                fresh = info?.fresh == true,
                records = info?.records ?: 0,
                fetchedAtMillis = info?.fetchedAt ?: 0L,
                enforcement = feed.enforcement.name.lowercase(),
            )
        }
        validatedFeeds = feeds
        lastValidationMillis = System.currentTimeMillis()
        cachedStatus = composeStatus(feeds, lastValidationMillis)
        settings.setThreatIntelSnapshot(encodeSnapshot(feeds))
        Log.i(
            PERF_TAG,
            "threatintel.validate ms=${lastValidationMillis - startedAt} feeds=${feeds.size} " +
                "available=${feeds.count { it.available }} fresh=${feeds.count { it.fresh }}",
        )
        // After a keyring/cache migration the previously HMAC-authenticated generations can no longer
        // be verified, so a previously synced cache looks empty: rebuild it in the near future instead
        // of waiting for the periodic window.
        if (feeds.none { it.available } && settings.lastThreatIntelSyncAtMillis() > 0L &&
            settings.tiAutoSyncEnabled() && immediateResyncScheduled.compareAndSet(false, true)
        ) {
            scheduleImmediateSync()
        }
    }

    /**
     * Refreshes the time-derived freshness of the cached snapshots without any file I/O. Called from
     * the background validation only; [status] just returns the already composed snapshot.
     */
    private fun composeStatus(validated: List<FeedSnapshot>, now: Long): ThreatIntelStatus {
        val feedById = ThreatFeedCatalog.all.associateBy { it.id }
        val feeds = validated.map { snapshot ->
            val feed = feedById[snapshot.id]
            val maxAge = (feed?.maxStaleMinutes ?: 0L) * 60_000L
            val fresh = snapshot.available && snapshot.fetchedAtMillis > 0L && maxAge > 0L &&
                now - snapshot.fetchedAtMillis in 0..maxAge
            snapshot.copy(fresh = fresh)
        }
        val lastSync = try {
            settings.lastThreatIntelSyncAtMillis().takeIf { it > 0L }
        } catch (_: Throwable) {
            null
        }
        val note = when {
            keyState == KeyState.UNAVAILABLE -> MessageRef(KEY_TI_KEY_UNAVAILABLE)
            feeds.none { it.available } && lastSync != null -> MessageRef(KEY_TI_SYNCFAILED)
            feeds.any { it.available && !it.fresh } -> MessageRef(KEY_TI_STALE)
            else -> null
        }
        return ThreatIntelStatus(
            feeds = feeds,
            lastSyncMillis = lastSync,
            syncHealthy = settings.lastThreatIntelSyncHealthy() && feeds.any { it.available },
            note = note,
        )
    }

    /** Honest initial state: no feed has been validated yet, so nothing is reported as clean. */
    private fun initialStatus(): ThreatIntelStatus {
        // Fast first frame: reuse the last validated snapshot from preferences (no feed file I/O,
        // no hashing, no parsing). Freshness is derived from the stored timestamps at read time and a
        // missing snapshot means "never synchronised" and stays explicitly unavailable.
        val persisted = persistedSnapshotFeeds()
        Log.i(PERF_TAG, "threatintel.initial restoredFeeds=${persisted?.size ?: 0}")
        if (persisted != null) {
            return try {
                composeStatus(persisted, System.currentTimeMillis())
            } catch (_: Throwable) {
                unavailableStatus()
            }
        }
        return unavailableStatus()
    }

    private fun unavailableStatus(): ThreatIntelStatus {
        val feeds = ThreatFeedCatalog.all.map { feed ->
            FeedSnapshot(
                id = feed.id,
                name = feed.name,
                available = false,
                fresh = false,
                records = 0,
                fetchedAtMillis = 0L,
                enforcement = feed.enforcement.name.lowercase(),
            )
        }
        val lastSync = try {
            settings.lastThreatIntelSyncAtMillis().takeIf { it > 0L }
        } catch (_: Throwable) {
            null
        }
        return ThreatIntelStatus(
            feeds = feeds,
            lastSyncMillis = lastSync,
            syncHealthy = false,
            note = if (lastSync != null) MessageRef(KEY_TI_SYNCFAILED) else null,
        )
    }

    /** Parses the persisted compact snapshot; null when missing/corrupt/incompatible. */
    private fun persistedSnapshotFeeds(): List<FeedSnapshot>? {
        val raw = settings.threatIntelSnapshot() ?: return null
        val feedById = ThreatFeedCatalog.all.associateBy { it.id }
        val feeds = ArrayList<FeedSnapshot>(ThreatFeedCatalog.all.size)
        for (rawLine in raw.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            val fields = line.split('|')
            if (fields.size != 4) return null
            val feed = feedById[fields[0]] ?: return null
            val available = when (fields[1]) {
                "1" -> true
                "0" -> false
                else -> return null
            }
            val records = fields[2].toIntOrNull()?.takeIf { it >= 0 } ?: return null
            val fetchedAt = fields[3].toLongOrNull()?.takeIf { it >= 0L } ?: return null
            val snapshot = try {
                FeedSnapshot(
                    id = feed.id,
                    name = feed.name,
                    available = available,
                    fresh = false,
                    records = records,
                    fetchedAtMillis = fetchedAt,
                    enforcement = feed.enforcement.name.lowercase(),
                )
            } catch (_: IllegalArgumentException) {
                return null
            }
            feeds.add(snapshot)
        }
        return feeds.ifEmpty { null }
    }

    private fun encodeSnapshot(feeds: List<FeedSnapshot>): String = buildString {
        for (feed in feeds) {
            append(feed.id).append('|')
            append(if (feed.available) '1' else '0').append('|')
            append(feed.records).append('|')
            append(feed.fetchedAtMillis).append('\n')
        }
    }

    /** One-off background sync (network-constrained, short deadline) used to rebuild a cache. */
    private fun scheduleImmediateSync() {
        val scheduler = appContext.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
        try {
            val component = ComponentName(
                appContext,
                de.visiongaia.gedefense.tv.platform.TvThreatIntelJobService::class.java,
            )
            val job = JobInfo.Builder(IMMEDIATE_SYNC_JOB_ID, component)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setMinimumLatency(IMMEDIATE_SYNC_MIN_LATENCY_MILLIS)
                .setOverrideDeadline(IMMEDIATE_SYNC_DEADLINE_MILLIS)
                .build()
            scheduler.schedule(job)
            Log.i(PERF_TAG, "threatintel.immediate_sync_scheduled")
        } catch (_: Throwable) {
            // Without the immediate job the periodic job or a manual sync still refreshes the cache.
        }
    }

    private fun performSync(): SyncResult {
        if (integrityKeyOrNull() == null) {
            settings.setThreatIntelSyncResult(System.currentTimeMillis(), false)
            val now = System.currentTimeMillis()
            val base = validatedFeeds?.let { composeStatus(it, now) } ?: initialStatus()
            cachedStatus = base.copy(note = MessageRef(KEY_TI_KEY_UNAVAILABLE))
            return SyncResult(ok = false, message = MessageRef(KEY_TI_KEY_UNAVAILABLE))
        }
        val feeds = ThreatFeedCatalog.all
        val results = arrayOfNulls<FeedSyncResult>(feeds.size)
        val futures = feeds.mapIndexed { index, feed ->
            downloadPool.submit(Callable { index to syncOne(feed) })
        }
        try {
            for (future in futures) {
                try {
                    val (index, result) = future.get()
                    results[index] = result
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    break
                } catch (_: Throwable) {
                    // A single worker failure is represented as a failed feed below.
                }
            }
        } finally {
            futures.forEach { if (!it.isDone) it.cancel(true) }
        }
        val finalResults = results.mapIndexed { index, result ->
            result ?: FeedSyncResult(feeds[index].id, ok = false)
        }
        val successCount = finalResults.count { it.ok }
        val healthy = successCount == finalResults.size
        val atMillis = System.currentTimeMillis()
        settings.setThreatIntelSyncResult(atMillis, healthy)
        // Re-validate the committed cache directly on this background thread so the listener and every
        // later status() call see the new generations without ever parsing on the UI thread.
        validateAndPublishStatus()
        // Refresh the VPN policy context with the same validated index (background thread only).
        try {
            onPolicyIndexUpdated(policyIndexSnapshot())
        } catch (_: Throwable) {
            // Policy handover is enrichment; the next app start / manual refresh retries it.
        }
        val message = when {
            healthy -> MessageRef(KEY_TI_SYNCOK)
            successCount > 0 -> MessageRef(KEY_TI_SYNCPARTIAL)
            else -> MessageRef(KEY_TI_SYNCFAILED)
        }
        return SyncResult(ok = healthy, message = message)
    }

    private fun syncOne(feed: ThreatFeed): FeedSyncResult {
        val now = System.currentTimeMillis()
        // Rate limiting uses the already validated snapshot (no hashing/parsing here).
        val cachedFetchedAt = validatedFeeds
            ?.firstOrNull { it.id == feed.id }
            ?.fetchedAtMillis
            ?: 0L
        val minAge = feed.minRefreshMinutes * 60_000L
        if (cachedFetchedAt > 0L && now - cachedFetchedAt < minAge) {
            return FeedSyncResult(feed.id, ok = true, skipped = true)
        }
        val downloaded = try {
            TvFeedDownloader.download(feed, root)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return FeedSyncResult(feed.id, ok = false)
        } catch (_: Throwable) {
            return FeedSyncResult(feed.id, ok = false)
        }
        return try {
            val commit = store.commit(feed, downloaded.file, downloaded.sha256, downloaded.bytes, now)
            FeedSyncResult(feed.id, commit.ok)
        } catch (_: Throwable) {
            FeedSyncResult(feed.id, ok = false)
        } finally {
            downloaded.file.delete()
        }
    }

    /**
     * Loads the authenticated threat index for the VPN data plane.
     *
     * This performs the full cache validation/hash/parse of the vendored store and MUST only be
     * called from a background thread (the VpnService control thread). It never touches the UI and
     * returns an honest empty index (no threat rules, only the privacy policy remains effective)
     * when the cache cannot be validated.
     */
    fun policyIndexSnapshot(): ThreatIndex {
        integrityKeyOrNull()
        return try {
            store.loadSnapshot()
        } catch (_: Throwable) {
            ThreatIndex.empty()
        }
    }

    /**
     * Resolves the cache integrity key from the process keyring ([TvKeyCustody]).
     *
     * The keyring subkey is an in-memory software key, so the cache does not run per-record opaque
     * Keystore operations. Key custody itself is established by the evidence bootstrap first
     * ([startupGate]); a cold status read before that honestly reports "feed cache unavailable"
     * instead of blocking the TV UI.
     */
    private fun integrityKeyOrNull(): SecretKey? {
        cachedKey?.let { return it }
        val key = TvKeyCustody.cached()?.threatIntelHmac
        if (key == null) {
            keyState = KeyState.UNAVAILABLE
            return null
        }
        cachedKey = key
        keyState = KeyState.READY
        return key
    }

    private enum class KeyState { UNKNOWN, READY, UNAVAILABLE }

    private data class FeedSyncResult(val id: String, val ok: Boolean, val skipped: Boolean = false)

    private data class SyncResult(val ok: Boolean, val message: MessageRef)

    companion object {
        /**
         * Stable job id of the periodic feed sync. Shared with
         * [de.visiongaia.gedefense.tv.platform.TvThreatIntelJobService]; do not change without
         * migrating persisted jobs.
         */
        const val THREAT_INTEL_JOB_ID = 7301

        /** One-off cache rebuild job id; distinct from the periodic sync job. */
        const val IMMEDIATE_SYNC_JOB_ID = 7302

        private const val PERF_TAG = "GeDefenseTvPerf"
        private const val MAX_PARALLEL_DOWNLOADS = 3
        private const val VALIDATION_TTL_MILLIS = 60_000L
        private const val STARTUP_VALIDATION_DELAY_MILLIS = 2_500L
        private const val STATUS_WARN_MILLIS = 10L
        private const val PERIODIC_MILLIS = 12L * 60L * 60L * 1_000L
        private const val FLEX_MILLIS = 60L * 60L * 1_000L
        private const val IMMEDIATE_SYNC_MIN_LATENCY_MILLIS = 5_000L
        private const val IMMEDIATE_SYNC_DEADLINE_MILLIS = 120_000L
        private const val KEY_TI_SYNCOK = "ti.syncok"
        private const val KEY_TI_SYNCPARTIAL = "ti.syncpartial"
        private const val KEY_TI_SYNCFAILED = "ti.syncfailed"
        private const val KEY_TI_KEY_UNAVAILABLE = "ti.keyunavailable"
        private const val KEY_TI_STALE = "ti.stale"
    }
}
