package de.visiongaia.gedefense.tv.data.titan

import android.util.Log
import de.visiongaia.gedefense.tv.contract.EvidenceApi
import de.visiongaia.gedefense.tv.core.model.TvEvent
import de.visiongaia.gedefense.tv.core.titan.events.TitanEventFactory
import de.visiongaia.gedefense.tv.core.titan.model.FimFileObservation
import de.visiongaia.gedefense.tv.core.titan.model.FimSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.FimStatus
import de.visiongaia.gedefense.tv.core.titan.model.SocketRisk
import de.visiongaia.gedefense.tv.core.titan.model.SocketSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionResult
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessCheckpoint

/**
 * Bounded evidence writer for Titan engine events.
 *
 * The Titan scan can observe hundreds of sockets and FIM deltas; the evidence ledger must stay
 * readable and bounded, so this recorder only appends the most important rows (privilege state,
 * threat matches, unattributed sockets, ADB exposure, FIM deltas, containment results and witness
 * checkpoints) with a hard per-scan cap. It never throws into the scan path: a degraded ledger is
 * surfaced through the normal evidence health UI.
 */
class TitanEvidenceRecorder(
    private val deviceId: String,
    private val osApiLevel: Int,
    private val evidence: EvidenceApi,
) {

    fun recordScan(
        privilege: TitanPrivilegeSnapshot,
        sockets: SocketSnapshot,
        fim: FimSnapshot,
        nowMillis: Long,
    ) {
        try {
            val events = ArrayList<TvEvent>(MAX_EVENTS)
            TitanEventFactory.privilegeEvent(deviceId, osApiLevel, privilege, nowMillis)?.let(events::add)
            sockets.observations.filter { it.risk == SocketRisk.THREAT_FEED_MATCH }.take(MAX_THREAT_EVENTS).forEach {
                events += TitanEventFactory.threatSocketEvent(deviceId, osApiLevel, it, nowMillis)
            }
            sockets.observations.filter { it.risk == SocketRisk.UNATTRIBUTED }.take(MAX_UNATTRIBUTED_EVENTS).forEach {
                events += TitanEventFactory.unattributedSocketEvent(deviceId, osApiLevel, it, nowMillis)
            }
            sockets.observations.filter { it.risk == SocketRisk.ADB_EXPOSED }.take(1).forEach {
                events += TitanEventFactory.adbExposureEvent(deviceId, osApiLevel, it, nowMillis)
            }
            fim.observations.filter { it.isDelta() }.take(MAX_FIM_EVENTS).forEach { observation ->
                TitanEventFactory.fimDeltaEvent(deviceId, osApiLevel, observation, nowMillis)?.let(events::add)
            }
            append(events)
        } catch (error: Throwable) {
            logFailure("scan", error)
        }
    }

    fun recordPrivilege(snapshot: TitanPrivilegeSnapshot, nowMillis: Long) {
        try {
            TitanEventFactory.privilegeEvent(deviceId, osApiLevel, snapshot, nowMillis)?.let { append(listOf(it)) }
        } catch (error: Throwable) {
            logFailure("privilege", error)
        }
    }

    fun recordActionResult(result: TitanActionResult, reason: String, nowMillis: Long) {
        try {
            append(listOf(TitanEventFactory.containmentEvent(deviceId, osApiLevel, result, reason, nowMillis)))
        } catch (error: Throwable) {
            logFailure("containment", error)
        }
    }

    fun recordWitness(checkpoint: TitanWitnessCheckpoint, nowMillis: Long) {
        try {
            append(listOf(TitanEventFactory.witnessCheckpointEvent(deviceId, osApiLevel, checkpoint, nowMillis)))
        } catch (error: Throwable) {
            logFailure("witness", error)
        }
    }

    private fun append(events: List<TvEvent>) {
        if (events.isEmpty()) return
        evidence.recordEvents(events.take(MAX_EVENTS))
    }

    private fun logFailure(area: String, error: Throwable) {
        Log.w(TAG, "titan evidence ($area) failed: ${error.javaClass.simpleName}")
    }

    private fun FimFileObservation.isDelta(): Boolean =
        status == FimStatus.NEW_FILE || status == FimStatus.MODIFIED

    private companion object {
        const val TAG = "GeDefenseTvTitan"
        const val MAX_EVENTS = 32
        const val MAX_THREAT_EVENTS = 8
        const val MAX_UNATTRIBUTED_EVENTS = 4
        const val MAX_FIM_EVENTS = 12
    }
}
