package de.visiongaia.gedefense.tv.core.titan

import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.FimSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.SocketRisk
import de.visiongaia.gedefense.tv.core.titan.model.SocketSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanScanOutcome
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus

/**
 * Composes the single [TitanStatus] snapshot from the individual module results.
 *
 * The composer is intentionally pure and deterministic: it never invents a result for a module that
 * did not run, it derives the effective capability set from the confirmed privilege snapshot, and it
 * collects the user-facing notes in a stable order.
 */
object TitanStatusComposer {

    fun compose(
        privilege: TitanPrivilegeSnapshot?,
        sockets: SocketSnapshot?,
        fim: FimSnapshot?,
        witness: TitanWitnessStatus = TitanWitnessStatus.UNAVAILABLE,
        activeContainments: Int = 0,
        lastScanAtMillis: Long = 0L,
        lastScanOutcome: TitanScanOutcome = TitanScanOutcome.NEVER,
        extraNotes: List<MessageRef> = emptyList(),
        nowMillis: Long = System.currentTimeMillis(),
    ): TitanStatus {
        val capabilities = TitanCapabilityMatrix.effectiveCapabilities(privilege)
        // Honest overall visibility: a privileged channel alone does not make a PARTIAL module pass
        // "full visibility". The weakest successfully-collected module wins.
        val privilegeVisibility = TitanCapabilityMatrix.effectiveVisibility(privilege)
        val visibility = when {
            sockets != null && sockets.visibility != DataVisibility.FULL -> sockets.visibility
            fim != null && fim.visibility != DataVisibility.FULL -> fim.visibility
            else -> privilegeVisibility
        }
        val notes = LinkedHashSet<MessageRef>()
        privilege?.notes?.let(notes::addAll)
        sockets?.note?.let(notes::add)
        fim?.note?.let(notes::add)
        witness.note?.let(notes::add)
        notes.addAll(extraNotes.take(MAX_EXTRA_NOTES))
        val boundedNotes = notes.toList().take(TitanStatus.MAX_NOTES)
        val attention = (sockets?.observations?.any {
            it.risk == SocketRisk.THREAT_FEED_MATCH
        } == true) || (fim?.deltaCount ?: 0) > 0 || (privilege?.dirtyRootSuspected == true)
        return TitanStatus(
            level = privilege?.level ?: TitanPrivilegeLevel.STANDARD,
            visibility = visibility,
            capabilities = capabilities,
            privilege = privilege,
            sockets = sockets,
            fim = fim,
            witness = witness,
            activeContainments = activeContainments.coerceAtLeast(0),
            lastScanAtMillis = lastScanAtMillis.coerceAtLeast(0L),
            lastScanOutcome = lastScanOutcome,
            notes = boundedNotes,
            attentionRequired = attention,
        )
    }

    /**
     * Marks a running scan without dropping the previously collected evidence.
     *
     * The status keeps the last module snapshots (they are stale but explicitly still labelled with
     * their own capture timestamp); the outcome is [TitanScanOutcome.RUNNING].
     */
    fun running(previous: TitanStatus?, nowMillis: Long): TitanStatus {
        val base = previous ?: TitanStatus.empty(nowMillis)
        return base.copy(lastScanOutcome = TitanScanOutcome.RUNNING)
    }

    /** Honest empty state used before the first scan and when key custody/data is unavailable. */
    fun empty(nowMillis: Long): TitanStatus = TitanStatus.empty(nowMillis)

    /** DataVisibility of the socket module if it ran, else the privilege-derived visibility. */
    fun socketVisibility(status: TitanStatus): DataVisibility =
        status.sockets?.visibility ?: status.visibility

    fun capabilityLabelId(capability: TitanCapability): String = capability.id

    private const val MAX_EXTRA_NOTES = 8
}
