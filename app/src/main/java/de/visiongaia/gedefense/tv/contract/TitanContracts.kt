package de.visiongaia.gedefense.tv.contract

import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionRequest
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionResult
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanVaultEntry
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessCheckpoint
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus

/**
 * UI-facing contract of the Titan Engine.
 *
 * Threading contract:
 *  - [status], [state], [vaultEntries], [witnessStatus] and [latestCheckpoint] are cheap cached reads
 *    and may be called on the UI thread at any time;
 *  - [scanNow], [refreshPrivilege] and [activate] run the actual work on a bounded background worker
 *    and report through their listener on the main thread;
 *  - [contain] validates first, then executes the allow-listed command on the background worker.
 *
 * Honesty contract: a scan never starts a new activation probe and never escalates on its own. Only
 * [activate] runs the root confirmation probe. After a scan reuse of a channel confirmed in this
 * process, each privileged command may still be subject to the root manager's own grant policy (for
 * example a per-request Superuser dialog); that device policy is outside the app's control and is
 * documented as an alpha limit. If the user does not grant the probe, the level stays STANDARD and
 * every elevated capability reports unavailable.
 */
interface TitanApi {

    /** Latest composed Titan status. Never null, never blocking. */
    fun status(): TitanStatus

    fun state(): TitanUiState

    /**
     * Runs one passive Titan pass: privilege re-detection (passive), socket provenance and FIM delta
     * (only for the guards the user enabled). Returns false when a pass is already running.
     */
    fun scanNow(listener: TitanScanListener): Boolean

    /**
     * Passive re-detection only (no `su` prompt): root binaries, root managers, SELinux state,
     * Shizuku presence, build hardening. Updates the cached status and reports the snapshot.
     */
    fun refreshPrivilege(listener: TitanActivationListener): Boolean

    /**
     * Explicit, user-consented activation: runs the passive detection and then the root confirmation
     * probe through the allow-listed command channel. This is the ONLY method that may trigger a
     * Superuser prompt. It never escalates silently.
     */
    fun activate(listener: TitanActivationListener): Boolean

    /**
     * Requests one containment action. The policy gate decides first; when it refuses, the listener
     * receives a structured result with the failure code and no command is executed.
     */
    fun contain(request: TitanActionRequest, listener: TitanActionResultListener): Boolean

    fun vaultEntries(): List<TitanVaultEntry>

    fun witnessStatus(): TitanWitnessStatus

    fun latestCheckpoint(): TitanWitnessCheckpoint?

    /** Recomputes the local witness checkpoint from the current evidence ledger tail (background). */
    fun refreshWitnessCheckpoint(listener: TitanWitnessListener? = null): Boolean
}

/** Coarse scan state for the Titan screen. */
data class TitanUiState(
    val scanning: Boolean,
    val lastScanAtMillis: Long,
)

/** Scan lifecycle callbacks. Delivered on the main thread. */
interface TitanScanListener {
    fun onStarted() {}

    /** [step] is 1-based; [total] is at least 1. */
    fun onProgress(step: Int, total: Int) {}

    fun onCompleted(status: TitanStatus) {}

    fun onFailed(message: MessageRef) {}
}

/** Result of a privilege detection/activation pass. Delivered on the main thread. */
interface TitanActivationListener {
    fun onResult(snapshot: TitanPrivilegeSnapshot?, message: MessageRef)
}

/** Result of one containment action or witness checkpoint refresh. Delivered on the main thread. */
interface TitanActionResultListener {
    fun onResult(result: TitanActionResult)
}

/** Result of a local witness checkpoint refresh. Delivered on the main thread. */
interface TitanWitnessListener {
    fun onResult(ok: Boolean, status: TitanWitnessStatus, message: MessageRef)
}
