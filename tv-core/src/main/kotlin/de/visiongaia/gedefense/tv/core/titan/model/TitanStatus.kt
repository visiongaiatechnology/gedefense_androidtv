package de.visiongaia.gedefense.tv.core.titan.model

import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef

/** Outcome state of the most recent Titan scan. */
enum class TitanScanOutcome { NEVER, RUNNING, COMPLETED, PARTIAL, FAILED }

/**
 * Second-device trust (Witness Protocol) local state.
 *
 * Alpha scope: the TV produces signed, local checkpoints of its evidence ledger. Mobile push
 * delivery is not part of this alpha, so [PAIRED] is never claimed without a real counterpart.
 */
enum class TitanWitnessState { UNAVAILABLE, READY, PAIRED, DEGRADED }

/** One locally produced, HMAC-authenticated witness checkpoint. */
data class TitanWitnessCheckpoint(
    val sequence: Long,
    val issuedAtMillis: Long,
    val ledgerDigestHex: String,
    val macHex: String,
) {
    init {
        require(sequence >= 1L) { "invalid witness sequence" }
        require(issuedAtMillis > 0L) { "invalid witness timestamp" }
        require(ledgerDigestHex.matches(HEX_64)) { "invalid witness ledger digest" }
        require(macHex.matches(HEX_64)) { "invalid witness mac" }
    }

    companion object {
        private val HEX_64 = Regex("[0-9a-f]{64}")
    }
}

/** Honest status of the witness protocol: what exists locally, what does not. */
data class TitanWitnessStatus(
    val state: TitanWitnessState,
    val checkpointsCreated: Long,
    val lastCheckpointAtMillis: Long?,
    val lastLedgerDigestPrefix: String?,
    val note: MessageRef? = null,
) {
    init {
        require(checkpointsCreated >= 0L) { "negative witness checkpoint count" }
        require(lastCheckpointAtMillis == null || lastCheckpointAtMillis > 0L) { "invalid witness timestamp" }
        require(lastLedgerDigestPrefix == null || lastLedgerDigestPrefix.matches(Regex("[0-9a-f]{8,16}"))) {
            "invalid witness digest prefix"
        }
    }

    companion object {
        val UNAVAILABLE = TitanWitnessStatus(
            state = TitanWitnessState.UNAVAILABLE,
            checkpointsCreated = 0L,
            lastCheckpointAtMillis = null,
            lastLedgerDigestPrefix = null,
        )

        fun ready(checkpointsCreated: Long, lastAtMillis: Long?, prefix: String?): TitanWitnessStatus =
            TitanWitnessStatus(
                state = TitanWitnessState.READY,
                checkpointsCreated = checkpointsCreated,
                lastCheckpointAtMillis = lastAtMillis,
                lastLedgerDigestPrefix = prefix,
                note = MessageRef(TitanTextKeys.NOTE_WITNESS_UNPAIRED),
            )
    }
}

/**
 * Complete Titan state as consumed by the UI, report and evidence layer.
 *
 * This snapshot is the single source of truth for "what Titan can actually do right now". It is a
 * pure value object: it never implies that an unavailable capability is protected or clean.
 */
data class TitanStatus(
    val level: TitanPrivilegeLevel,
    val visibility: DataVisibility,
    val capabilities: Set<TitanCapability>,
    val privilege: TitanPrivilegeSnapshot?,
    val sockets: SocketSnapshot?,
    val fim: FimSnapshot?,
    val witness: TitanWitnessStatus,
    val activeContainments: Int,
    val lastScanAtMillis: Long,
    val lastScanOutcome: TitanScanOutcome,
    val notes: List<MessageRef> = emptyList(),
    /** True when the most recent containment/scan surfaced a critical condition. */
    val attentionRequired: Boolean = false,
) {
    init {
        require(activeContainments >= 0) { "negative containment count" }
        require(lastScanAtMillis >= 0L) { "invalid last scan timestamp" }
        require(notes.size <= MAX_NOTES) { "too many Titan notes" }
        require(capabilities.size <= TitanCapability.values().size) { "invalid capability set" }
        require(level != TitanPrivilegeLevel.STANDARD || capabilities.isEmpty()) {
            "standard level cannot carry elevated capabilities"
        }
    }

    fun has(capability: TitanCapability): Boolean = capability in capabilities

    /** Local, honest one-liner used by the report and the Home status strip. */
    val capabilityCount: Int get() = capabilities.size

    companion object {
        const val MAX_NOTES = 16

        fun empty(nowMillis: Long): TitanStatus = TitanStatus(
            level = TitanPrivilegeLevel.STANDARD,
            visibility = DataVisibility.PARTIAL,
            capabilities = emptySet(),
            privilege = null,
            sockets = null,
            fim = null,
            witness = TitanWitnessStatus.UNAVAILABLE,
            activeContainments = 0,
            lastScanAtMillis = 0L,
            lastScanOutcome = TitanScanOutcome.NEVER,
        )
    }
}
