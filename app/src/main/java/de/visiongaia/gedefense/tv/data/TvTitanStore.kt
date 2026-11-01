package de.visiongaia.gedefense.tv.data

import android.content.Context
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.FimBaseline
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanVaultEntry
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus

/**
 * Persisted counters of the last socket-provenance pass.
 *
 * The observation rows themselves are deliberately NOT persisted: a socket table is valid for
 * seconds only, so a restart shows "last known counts" plus an explicit "no live data" state instead
 * of stale rows that look freshly collected. Live rows exist only while a scan result is held in
 * memory by the controller.
 */
data class TitanSocketSummary(
    val totalSockets: Int,
    val attributableSockets: Int,
    val suspiciousCount: Int,
    val capturedAtMillis: Long,
    val visibility: DataVisibility,
    val truncated: Boolean,
    val note: MessageRef?,
)

/** Persisted counters of the last FIM pass (observation rows are not persisted, see [TitanSocketSummary]). */
data class TitanFimSummary(
    val baselineCreated: Boolean,
    val newFiles: Int,
    val modifiedFiles: Int,
    val unreadableFiles: Int,
    val scannedFiles: Int,
    val capturedAtMillis: Long,
    val baselineAtMillis: Long?,
    val visibility: DataVisibility,
    val truncated: Boolean,
    val note: MessageRef?,
)

/**
 * App-private persistence of the Titan Engine state.
 *
 * Scope and honesty rules:
 *  - only a compact, bounded summary is stored - never live `/proc` rows, never raw shell output;
 *  - the store is a convenience cache for a cold start: [loadStatus] reconstructs the privilege
 *    evidence and counters, but `sockets`/`fim` are always `null` because the observation lists are
 *    not persisted (the UI must show counts plus "no live data", never a fabricated clean state);
 *  - every read is defensive: type mismatches, truncated values, out-of-range numbers and unknown
 *    enum names yield `null`/defaults instead of throwing or inventing data;
 *  - every write is bounded and fail-soft; a failed write only costs the cache, never a scan;
 *  - records are bounded and injection-safe (one value per line, no JSON, hex-encoded catalog args).
 *
 * The store is thread-safe for the controller pattern (one scan worker plus UI-thread reads).
 * Threading: all methods are cheap; [saveStatus], [saveFimBaseline] and [addVaultEntry] do a small
 * synchronous commit so the state is durable before the scan reports completion.
 */
class TvTitanStore internal constructor(
    private val prefs: TitanPrefs,
    deviceId: String = "",
) {
    /** Production constructor: wraps the app-private Titan preferences file of [context]. */
    constructor(context: Context, deviceId: String = "") : this(TitanPrefs(context), deviceId)

    private val lock = Any()
    private val witnessCodec = TitanWitnessCodec(prefs)
    private val statusCodec = TitanStatusCodec(prefs, deviceId, witnessCodec)
    private val baselineCodec = TitanFimBaselineCodec(prefs)
    private val vaultCodec = TitanVaultCodec(prefs)

    // -------------------------------------------------------------------- status

    /**
     * Reconstructs the last persisted Titan status for [deviceId], or `null` when nothing valid is
     * stored. `sockets` and `fim` are always `null` (see class contract).
     *
     * A persisted status whose device binding, privilege evidence or required fields are invalid is
     * rejected completely - a partial status would let the UI claim a level or capability the device
     * never confirmed.
     */
    fun loadStatus(deviceId: String): TitanStatus? = synchronized(lock) {
        statusCodec.load(deviceId)
    }

    /** Persists one composed status. Never throws; a failure only costs the cold-start cache. */
    fun saveStatus(status: TitanStatus) {
        synchronized(lock) {
            statusCodec.save(status)
        }
    }

    /** Last persisted socket counters, or `null` when the device never completed a socket pass. */
    fun loadSocketSummary(): TitanSocketSummary? = synchronized(lock) {
        statusCodec.loadSocketSummary()
    }

    /** Last persisted FIM counters, or `null` when the device never completed a FIM pass. */
    fun loadFimSummary(): TitanFimSummary? = synchronized(lock) {
        statusCodec.loadFimSummary()
    }

    // -------------------------------------------------------------------- FIM baseline

    /**
     * Persists a complete FIM baseline. A baseline that would exceed the char cap is not written at
     * all (a partial baseline would fabricate `NEW_FILE` deltas). Never throws.
     */
    fun saveFimBaseline(baseline: FimBaseline) {
        synchronized(lock) {
            baselineCodec.save(baseline)
        }
    }

    /** Loads the persisted FIM baseline, or `null` when absent/corrupt. */
    fun loadFimBaseline(): FimBaseline? = synchronized(lock) {
        baselineCodec.load()
    }

    // -------------------------------------------------------------------- witness

    /** Highest allocated witness sequence (0 when none was allocated on this device). */
    fun witnessSequence(): Long = synchronized(lock) {
        witnessCodec.sequence()
    }

    /**
     * Atomically reserves the next witness sequence and persists it before returning. Returns 0 when
     * the counter is exhausted or the write failed; the caller must then report the witness as
     * unavailable instead of issuing a checkpoint with a guessed number.
     */
    fun allocateWitnessSequence(): Long = synchronized(lock) {
        witnessCodec.allocate()
    }

    fun saveWitness(status: TitanWitnessStatus) {
        synchronized(lock) {
            witnessCodec.save(status)
        }
    }

    fun loadWitness(): TitanWitnessStatus = synchronized(lock) {
        witnessCodec.load()
    }

    // -------------------------------------------------------------------- vault

    /** Quarantine metadata rows, newest first. Never throws. */
    fun vaultEntries(): List<TitanVaultEntry> = synchronized(lock) {
        vaultCodec.load()
    }

    /**
     * Adds one validated quarantine row (newest first, capped) and persists it synchronously.
     * Duplicate ids/file names are ignored; a failed write only loses the vault row, never the
     * quarantined file itself. Never throws.
     */
    fun addVaultEntry(entry: TitanVaultEntry) {
        synchronized(lock) {
            vaultCodec.add(entry)
        }
    }
}
