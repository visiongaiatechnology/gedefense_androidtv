package de.visiongaia.gedefense.tv.core

import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.mobile.core.ThreatRecord
import de.visiongaia.gedefense.tv.core.model.*
import de.visiongaia.gedefense.tv.core.titan.TitanCapabilityMatrix
import de.visiongaia.gedefense.tv.core.titan.TitanStatusComposer
import de.visiongaia.gedefense.tv.core.titan.events.TitanEventFactory
import de.visiongaia.gedefense.tv.core.titan.fim.FimComparison
import de.visiongaia.gedefense.tv.core.titan.fim.FimEngine
import de.visiongaia.gedefense.tv.core.titan.model.*
import de.visiongaia.gedefense.tv.core.titan.proc.ProcNetParser
import de.visiongaia.gedefense.tv.core.titan.proc.SocketProvenanceEngine
import de.visiongaia.gedefense.tv.core.titan.response.*
import de.visiongaia.gedefense.tv.core.titan.witness.TitanWitnessCheckpointFactory
import de.visiongaia.gedefense.tv.core.titan.witness.TitanWitnessCheckpointFactory.LedgerRow
import java.io.File
import javax.crypto.SecretKey
import kotlin.system.exitProcess

// --- fixtures ----------------------------------------------------------------------------------

internal const val TITAN_NOW = 1_700_000_000_000L
internal const val TITAN_DEVICE_ID = "tv_0123456789abcdef0123456789abcdef"
internal const val TITAN_TMP_ROOT = "/data/local/tmp"
internal const val TITAN_VAULT = "/data/local/gedefense_vault"

internal fun fakeHash(seed: Int): String = seed.toString(16).padStart(8, '0').repeat(8)

internal fun rawSocket(
    inode: Long,
    remoteAddress: String = "45.33.32.7",
    remotePort: Int = 443,
    localPort: Int = 40_000,
    state: SocketState = SocketState.ESTABLISHED,
    uid: Int = 10_050,
    protocol: SocketProtocol = SocketProtocol.TCP,
): RawSocket = RawSocket(protocol, "10.0.0.5", localPort, remoteAddress, remotePort, state, uid, inode)

internal fun scannedFile(
    path: String,
    seed: Int,
    size: Long = 100L,
    readable: Boolean = true,
    root: String = TITAN_TMP_ROOT,
): FimScannedFile = FimScannedFile(
    path = path,
    sha256 = if (readable) fakeHash(seed) else null,
    sizeBytes = size,
    modifiedAtMillis = TITAN_NOW - 1_000L,
    permissions = "0644",
    watchedRoot = root,
    readable = readable,
)

internal fun fimObservation(
    path: String,
    seed: Int,
    status: FimStatus = FimStatus.NEW_FILE,
    readable: Boolean = true,
): FimFileObservation = FimFileObservation(
    path = path,
    sha256 = if (readable) fakeHash(seed) else null,
    sizeBytes = 100L,
    modifiedAtMillis = TITAN_NOW - 1_000L,
    permissions = "0644",
    status = status,
    watchedRoot = TITAN_TMP_ROOT,
)

internal val inodeToPid = mapOf(1L to 1_000, 2L to 2_000, 50L to 5_000)
internal val uidByPid = mapOf(1_000 to 10_050, 2_000 to 10_100, 5_000 to 0)
internal val packagesByUid = mapOf(10_050 to listOf("com.example.app"), 10_100 to listOf("com.example.two"))
/** Deterministic HMAC key fixture; avoids provider-specific key implementations in the harness. */
internal class FixedHmacKey(private val rawKey: ByteArray) : SecretKey {
    override fun getAlgorithm(): String = "HmacSHA256"
    override fun getFormat(): String = "RAW"
    override fun getEncoded(): ByteArray = rawKey.copyOf()
}

internal val witnessKey: SecretKey = FixedHmacKey(ByteArray(32) { index -> index.toByte() })
internal val otherKey: SecretKey = FixedHmacKey(ByteArray(32) { index -> (index + 1).toByte() })
internal val ledgerRow1 = LedgerRow(1_700_000_000_000L, "titan-socket", "com.example.app|45.33.32.7:443|TCP")
internal val ledgerRow2 = LedgerRow(1_700_000_000_001L, "titan-fim", "/data/local/tmp/evil.sh")

internal fun titanC2Index(vararg prefixes: String): ThreatIndex =
    ThreatIndex.build(prefixes.map { prefix -> ThreatRecord("feodo", IpPrefix.parse(prefix)!!) })

internal class FakeClock(var now: Long = TITAN_NOW) { fun read(): Long = now }

internal fun actionTarget(action: TitanContainmentAction): TitanActionTarget = when (action) {
    TitanContainmentAction.FREEZE_APP, TitanContainmentAction.RESTORE_APP ->
        TitanActionTarget(packageName = "com.example.app")

    TitanContainmentAction.ISOLATE_NETWORK_UID, TitanContainmentAction.RELEASE_NETWORK_UID ->
        TitanActionTarget(uid = 10_050)

    TitanContainmentAction.KILL_PROCESS -> TitanActionTarget(pid = 4_242)
    TitanContainmentAction.CLOSE_ADB_PORT -> TitanActionTarget()
}

internal fun actionRequest(
    action: TitanContainmentAction,
    target: TitanActionTarget = actionTarget(action),
): TitanActionRequest = TitanActionRequest(action, target, TitanActionReason.USER_INITIATED, TITAN_NOW)

internal fun actionResult(ok: Boolean, verified: Boolean, failure: TitanActionFailure? = null): TitanActionResult =
    TitanActionResult(
        action = TitanContainmentAction.FREEZE_APP,
        target = TitanActionTarget(packageName = "com.example.app"),
        executedAtMillis = TITAN_NOW,
        ok = ok,
        verified = verified,
        failure = failure,
    )

internal fun expectedCapability(action: TitanContainmentAction): TitanCapability = when (action) {
    TitanContainmentAction.FREEZE_APP, TitanContainmentAction.RESTORE_APP -> TitanCapability.APP_FREEZE
    TitanContainmentAction.ISOLATE_NETWORK_UID, TitanContainmentAction.RELEASE_NETWORK_UID ->
        TitanCapability.NETWORK_QUARANTINE

    TitanContainmentAction.KILL_PROCESS -> TitanCapability.PROCESS_KILL
    TitanContainmentAction.CLOSE_ADB_PORT -> TitanCapability.ADB_LOCKDOWN
}

internal fun checkEventInvariants(event: TvEvent, label: String) {
    titanCheckTrue(event.eventId.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")), "$label event id")
    titanCheckTrue(event.subject.length in 1..160, "$label subject bound")
    titanCheckTrue(event.attributes.size <= 12, "$label attribute count")
    titanCheckTrue(event.attributes.all { (key, value) ->
        key.matches(Regex("[a-z][a-z0-9_]{1,31}")) && value.length <= 256 && value.none { it == '\n' || it == '\r' }
    }, "$label attribute validity")
    titanCheckTrue(event.collectorId.matches(Regex("[a-z][a-z0-9-]{1,63}")), "$label collector id")
    titanCheckTrue(event.osApiLevel >= 1 && event.eventTimeMillis > 0L, "$label time/api")
}


internal fun allCapabilities(): Set<TitanCapability> = TitanCapability.values().toSet()
