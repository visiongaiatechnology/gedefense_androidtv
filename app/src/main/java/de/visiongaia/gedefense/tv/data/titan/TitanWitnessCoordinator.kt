package de.visiongaia.gedefense.tv.data.titan

import android.util.Log
import de.visiongaia.gedefense.tv.contract.EvidenceApi
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessCheckpoint
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessState
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus
import de.visiongaia.gedefense.tv.core.titan.witness.TitanWitnessCheckpointFactory
import de.visiongaia.gedefense.tv.data.TvKeyCustody
import de.visiongaia.gedefense.tv.data.TvTitanStore

/** One witness refresh result: the persisted status plus the checkpoint when one was produced. */
data class TitanWitnessRefresh(
    val status: TitanWitnessStatus,
    val checkpoint: TitanWitnessCheckpoint?,
)

/**
 * Produces and persists the local Witness checkpoints.
 *
 * Alpha scope: the checkpoint is an HMAC-SHA256 over the current evidence-ledger tail, stored in the
 * app-private Titan store and appended to the ledger as its own event. It is the artifact a paired
 * second device would verify; mobile pairing/transport is not part of this alpha, so the status is
 * always [TitanWitnessState.READY] without ever claiming [TitanWitnessState.PAIRED].
 *
 * Fail-soft: a missing key custody or an empty ledger returns the last persisted witness status and
 * never invents a checkpoint.
 */
class TitanWitnessCoordinator(
    private val deviceId: String,
    private val evidence: EvidenceApi,
    private val store: TvTitanStore,
    private val recorder: TitanEvidenceRecorder,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    fun refresh(nowMillis: Long = clock()): TitanWitnessRefresh {
        val now = nowMillis.coerceAtLeast(1L)
        val hmac = TvKeyCustody.cached()?.evidenceHmac ?: return TitanWitnessRefresh(store.loadWitness(), null)
        val rows = try {
            evidence.rows(ROW_LIMIT).take(ROW_LIMIT).map { row ->
                TitanWitnessCheckpointFactory.LedgerRow(
                    atMillis = row.atMillis.coerceAtLeast(0L),
                    type = canonicalType(row.type),
                    subject = canonicalSubject(row.subject),
                )
            }
        } catch (error: Throwable) {
            Log.w(TAG, "titan witness rows failed: ${error.javaClass.simpleName}")
            return TitanWitnessRefresh(store.loadWitness(), null)
        }
        if (rows.isEmpty()) return TitanWitnessRefresh(store.loadWitness(), null)
        return try {
            val sequence = store.allocateWitnessSequence()
            if (sequence <= 0L) return TitanWitnessRefresh(store.loadWitness(), null)
            val checkpoint = TitanWitnessCheckpointFactory.create(deviceId, sequence, now, rows, hmac)
            val status = TitanWitnessStatus.ready(sequence, now, checkpoint.ledgerDigestHex.take(16))
            store.saveWitness(status)
            recorder.recordWitness(checkpoint, now)
            TitanWitnessRefresh(status, checkpoint)
        } catch (error: Throwable) {
            Log.w(TAG, "titan witness checkpoint failed: ${error.javaClass.simpleName}")
            TitanWitnessRefresh(store.loadWitness(), null)
        }
    }

    /**
     * Canonical ASCII rendering of the ledger tail covered by a checkpoint.
     *
     * The evidence ledger may contain localized text or punctuation in a subject; the checkpoint
     * covers the exact canonical rendering so the same transformation can be applied by a verifier.
     * Replacing a non-printable/non-ASCII rune with '?' is deterministic and keeps the digest stable.
     */
    private fun canonicalType(raw: String): String {
        val mapped = raw.take(64).lowercase().map { character ->
            if (character in 'a'..'z' || character in '0'..'9' || character == '.' || character == '-' ||
                character == '_'
            ) {
                character
            } else {
                '-'
            }
        }.joinToString("")
        return when {
            mapped.isNotEmpty() && mapped[0] in 'a'..'z' -> mapped
            else -> "event" + mapped.take(0)
        }
    }

    private fun canonicalSubject(raw: String): String {
        val mapped = raw.take(160).map { character ->
            if (character.code in 0x20..0x7e) character else '?'
        }.joinToString("").trim()
        return mapped.ifEmpty { "-" }
    }

    private companion object {
        const val TAG = "GeDefenseTvTitan"
        const val ROW_LIMIT = 64
    }
}
