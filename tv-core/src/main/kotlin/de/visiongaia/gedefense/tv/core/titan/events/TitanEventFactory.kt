package de.visiongaia.gedefense.tv.core.titan.events

import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.TvEvent
import de.visiongaia.gedefense.tv.core.titan.model.FimFileObservation
import de.visiongaia.gedefense.tv.core.titan.model.FimStatus
import de.visiongaia.gedefense.tv.core.titan.model.SocketObservation
import de.visiongaia.gedefense.tv.core.titan.model.SocketRisk
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionResult
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessCheckpoint
import java.util.UUID

/**
 * Builds the XDR-lite [TvEvent]s of the Titan Engine.
 *
 * Every factory method is deterministic for a given input (except the event UUID), bounded and
 * secret-free: no file contents, no full socket tables and no user data leave the model. The events
 * are appended to the local HMAC evidence ledger by the platform layer.
 */
object TitanEventFactory {
    const val COLLECTOR_GATE = "titan-gate"
    const val COLLECTOR_SOCKET = "titan-socket"
    const val COLLECTOR_FIM = "titan-fim"
    const val COLLECTOR_RESPONSE = "titan-response"
    const val COLLECTOR_WITNESS = "titan-witness"

    const val RULE_ROOT_AUDIT = "titan-root-audit"
    const val RULE_C2_SOCKET = "titan-c2-socket"
    const val RULE_UNATTRIBUTED_SOCKET = "titan-unattributed-socket"
    const val RULE_ADB_EXPOSED = "titan-adb-exposed"
    const val RULE_FIM_DELTA = "titan-fim-delta"
    const val RULE_CONTAINMENT = "titan-containment"
    const val RULE_WITNESS_CHECKPOINT = "titan-witness-checkpoint"

    /** Emitted when the passive audit found an elevated channel, dirty root or weakened kernel. */
    fun privilegeEvent(
        deviceId: String,
        osApiLevel: Int,
        snapshot: TitanPrivilegeSnapshot,
        nowMillis: Long = System.currentTimeMillis(),
    ): TvEvent? {
        val dirty = snapshot.dirtyRootSuspected
        val permissive = snapshot.build.selinuxEnforcing == false
        val testKeys = snapshot.build.testKeys
        val exposed = snapshot.build.adbTcpExposed == true
        if (snapshot.level == de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel.STANDARD &&
            !dirty && !permissive && !testKeys && !exposed
        ) {
            return null
        }
        val severity = when {
            dirty || permissive -> Severity.HIGH
            snapshot.level != de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel.STANDARD -> Severity.MEDIUM
            else -> Severity.LOW
        }
        val attributes = linkedMapOf(
            "level" to snapshot.level.name.lowercase(),
            "root_kind" to snapshot.rootKind.name.lowercase(),
            "selinux" to when (snapshot.build.selinuxEnforcing) {
                true -> "enforcing"
                false -> "permissive"
                null -> "unknown"
            },
            "test_keys" to testKeys.toString(),
        )
        if (exposed) attributes["adb_tcp"] = "exposed"
        return build(
            eventClass = EventClass.TV_DEVICE_STATE,
            deviceId = deviceId,
            osApiLevel = osApiLevel,
            collectorId = COLLECTOR_GATE,
            subject = "titan-privilege",
            ruleId = RULE_ROOT_AUDIT,
            severity = severity,
            confidence = Confidence.HIGH,
            policyAction = PolicyAction.ESCALATE_TO_USER,
            atMillis = nowMillis,
            attributes = attributes,
        )
    }

    /** Emitted when a live socket matched a ThreatIndex record (C2/botnet/proxy). */
    fun threatSocketEvent(
        deviceId: String,
        osApiLevel: Int,
        observation: SocketObservation,
        nowMillis: Long = System.currentTimeMillis(),
    ): TvEvent = build(
        eventClass = EventClass.TV_TI_MATCH,
        deviceId = deviceId,
        osApiLevel = osApiLevel,
        collectorId = COLLECTOR_SOCKET,
        subject = observation.subject,
        ruleId = RULE_C2_SOCKET,
        severity = Severity.CRITICAL,
        confidence = Confidence.HIGH,
        policyAction = PolicyAction.ESCALATE_TO_USER,
        atMillis = nowMillis,
        attributes = linkedMapOf(
            "remote" to observation.remoteEndpoint,
            "protocol" to observation.protocol.name.lowercase(),
            "pkg" to (observation.packageName ?: "unattributed"),
            "uid" to observation.uid.toString(),
            "feeds" to observation.threatFeedIds.take(4).joinToString(","),
        ),
    )

    /** Emitted when a socket cannot be attributed to an app at the current privilege level. */
    fun unattributedSocketEvent(
        deviceId: String,
        osApiLevel: Int,
        observation: SocketObservation,
        nowMillis: Long = System.currentTimeMillis(),
    ): TvEvent = build(
        eventClass = EventClass.TV_DEVICE_STATE,
        deviceId = deviceId,
        osApiLevel = osApiLevel,
        collectorId = COLLECTOR_SOCKET,
        subject = observation.subject,
        ruleId = RULE_UNATTRIBUTED_SOCKET,
        severity = Severity.MEDIUM,
        confidence = Confidence.MEDIUM,
        policyAction = PolicyAction.RECOMMEND_MANUAL,
        atMillis = nowMillis,
        attributes = linkedMapOf(
            "remote" to observation.remoteEndpoint,
            "protocol" to observation.protocol.name.lowercase(),
            "uid" to observation.uid.toString(),
            "inode" to observation.inode.toString(),
        ),
    )

    /** Emitted when the classic ADB-over-network port is exposed/listening. */
    fun adbExposureEvent(
        deviceId: String,
        osApiLevel: Int,
        observation: SocketObservation,
        nowMillis: Long = System.currentTimeMillis(),
    ): TvEvent = build(
        eventClass = EventClass.TV_DEVICE_STATE,
        deviceId = deviceId,
        osApiLevel = osApiLevel,
        collectorId = COLLECTOR_SOCKET,
        subject = "adb-port",
        ruleId = RULE_ADB_EXPOSED,
        severity = Severity.HIGH,
        confidence = Confidence.MEDIUM,
        policyAction = PolicyAction.RECOMMEND_MANUAL,
        atMillis = nowMillis,
        attributes = linkedMapOf(
            "local_port" to observation.localPort.toString(),
            "protocol" to observation.protocol.name.lowercase(),
            "state" to observation.state.name.lowercase(),
        ),
    )

    /** Emitted for each new/changed file in a watched persistence location. */
    fun fimDeltaEvent(
        deviceId: String,
        osApiLevel: Int,
        observation: FimFileObservation,
        nowMillis: Long = System.currentTimeMillis(),
    ): TvEvent? {
        if (observation.status != FimStatus.NEW_FILE && observation.status != FimStatus.MODIFIED) return null
        return build(
            eventClass = EventClass.TV_ENFORCEMENT,
            deviceId = deviceId,
            osApiLevel = osApiLevel,
            collectorId = COLLECTOR_FIM,
            subject = observation.path,
            ruleId = RULE_FIM_DELTA,
            severity = if (observation.status == FimStatus.NEW_FILE) Severity.HIGH else Severity.MEDIUM,
            confidence = Confidence.MEDIUM,
            policyAction = PolicyAction.RECOMMEND_MANUAL,
            atMillis = nowMillis,
            attributes = linkedMapOf(
                "status" to observation.status.name.lowercase(),
                "hash" to (observation.sha256?.take(16) ?: "unreadable"),
                "size" to observation.sizeBytes.toString(),
            ),
        )
    }

    /** Emitted for every executed or refused containment action. */
    fun containmentEvent(
        deviceId: String,
        osApiLevel: Int,
        result: TitanActionResult,
        reason: String,
        nowMillis: Long = System.currentTimeMillis(),
    ): TvEvent = build(
        eventClass = EventClass.TV_ENFORCEMENT,
        deviceId = deviceId,
        osApiLevel = osApiLevel,
        collectorId = COLLECTOR_RESPONSE,
        subject = "${result.action.name.lowercase()}:${result.target.identity()}",
        ruleId = RULE_CONTAINMENT,
        severity = if (result.ok) Severity.MEDIUM else Severity.HIGH,
        confidence = if (result.verified) Confidence.HIGH else Confidence.MEDIUM,
        policyAction = PolicyAction.ESCALATE_TO_USER,
        atMillis = nowMillis,
        attributes = linkedMapOf(
            "action" to result.action.name.lowercase(),
            "reason" to reason.lowercase().take(32),
            "ok" to result.ok.toString(),
            "verified" to result.verified.toString(),
            "failure" to (result.failure?.name?.lowercase() ?: "none"),
        ),
    )

    /** Emitted when a local witness checkpoint of the evidence ledger was produced. */
    fun witnessCheckpointEvent(
        deviceId: String,
        osApiLevel: Int,
        checkpoint: TitanWitnessCheckpoint,
        nowMillis: Long = System.currentTimeMillis(),
    ): TvEvent = build(
        eventClass = EventClass.TV_DEVICE_STATE,
        deviceId = deviceId,
        osApiLevel = osApiLevel,
        collectorId = COLLECTOR_WITNESS,
        subject = "witness-checkpoint",
        ruleId = RULE_WITNESS_CHECKPOINT,
        severity = Severity.INFO,
        confidence = Confidence.HIGH,
        policyAction = PolicyAction.NONE,
        atMillis = nowMillis,
        attributes = linkedMapOf(
            "seq" to checkpoint.sequence.toString(),
            "digest" to checkpoint.ledgerDigestHex.take(16),
        ),
    )

    fun isThreatRisk(observation: SocketObservation): Boolean = observation.risk == SocketRisk.THREAT_FEED_MATCH

    private fun build(
        eventClass: EventClass,
        deviceId: String,
        osApiLevel: Int,
        collectorId: String,
        subject: String,
        ruleId: String,
        severity: Severity,
        confidence: Confidence,
        policyAction: PolicyAction,
        atMillis: Long,
        attributes: Map<String, String>,
    ): TvEvent = TvEvent(
        eventClass = eventClass,
        eventId = UUID.randomUUID().toString(),
        deviceId = deviceId,
        eventTimeMillis = atMillis.coerceAtLeast(1L),
        collectorId = collectorId,
        osApiLevel = osApiLevel.coerceAtLeast(1),
        subject = sanitize(subject, 160),
        dataQuality = DataQuality.FRESH,
        severity = severity,
        confidence = confidence,
        ruleId = ruleId,
        policyAction = policyAction,
        attributes = attributes.mapValues { (_, value) -> sanitize(value, 256) },
    )

    private fun sanitize(value: String, max: Int): String {
        val oneLine = value.map { character ->
            if (character == '\n' || character == '\r' || character == '\t') ' ' else character
        }.joinToString("").trim()
        return if (oneLine.length <= max) oneLine.ifEmpty { "-" } else oneLine.take(max - 1) + "\u2026"
    }
}
