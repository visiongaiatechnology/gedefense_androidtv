package de.visiongaia.gedefense.tv.core.titan.model

import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.Severity

/** Kernel socket table a raw row came from. */
enum class SocketProtocol(val procFile: String) {
    TCP("tcp"),
    TCP6("tcp6"),
    UDP("udp"),
    UDP6("udp6"),
    ;

    val isV6: Boolean get() = this == TCP6 || this == UDP6
    val isStream: Boolean get() = this == TCP || this == TCP6
}

/** Kernel socket state decoded from the two-hex-digit `st` column. */
enum class SocketState {
    ESTABLISHED,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT1,
    FIN_WAIT2,
    TIME_WAIT,
    CLOSE,
    CLOSE_WAIT,
    LAST_ACK,
    LISTEN,
    CLOSING,
    UNKNOWN,
    ;

    val isConnected: Boolean
        get() = this == ESTABLISHED || this == SYN_SENT || this == SYN_RECV ||
            this == FIN_WAIT1 || this == FIN_WAIT2 || this == CLOSE_WAIT || this == LAST_ACK
}

/**
 * Why a socket is listed as conspicuous.
 *
 * [THREAT_FEED_MATCH] is the only verdict backed by the ThreatIndex; [UNATTRIBUTED] means the
 * process could not be mapped to a package (hidden or inaccessible process), which is evidence of
 * missing visibility, not a malware verdict. [ADB_EXPOSED] flags a listening/active ADB port.
 */
enum class SocketRisk { NONE, THREAT_FEED_MATCH, UNATTRIBUTED, ADB_EXPOSED }

/**
 * One decoded row of `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp` or `/proc/net/udp6`.
 *
 * Addresses are already canonicalised by the parser (dotted quad / compressed IPv6). Ports are
 * decimal. The inode is the join key to `/proc/<pid>/fd` socket entries.
 */
data class RawSocket(
    val protocol: SocketProtocol,
    val localAddress: String,
    val localPort: Int,
    val remoteAddress: String,
    val remotePort: Int,
    val state: SocketState,
    val uid: Int,
    val inode: Long,
) {
    init {
        require(localAddress.isNotEmpty() && localAddress.length <= 64) { "invalid local address" }
        require(remoteAddress.isNotEmpty() && remoteAddress.length <= 64) { "invalid remote address" }
        require(localPort in 0..MAX_PORT) { "invalid local port" }
        require(remotePort in 0..MAX_PORT) { "invalid remote port" }
        require(uid in 0..MAX_UID) { "invalid socket uid" }
        require(inode >= 0L) { "invalid socket inode" }
    }

    companion object {
        const val MAX_PORT = 65_535
        const val MAX_UID = 2_000_000_000
    }
}

/**
 * A raw socket with its process/package provenance and risk classification.
 *
 * [packageName] is null when the process could not be resolved at the confirmed privilege level.
 * [pid] is null when the kernel inode could not be mapped to a process (normal at Level 1 for
 * sockets of other apps). The UI must render those rows as "app unknown", never as trusted.
 */
data class SocketObservation(
    val protocol: SocketProtocol,
    val state: SocketState,
    val localAddress: String,
    val localPort: Int,
    val remoteAddress: String,
    val remotePort: Int,
    val inode: Long,
    val pid: Int?,
    val uid: Int,
    val packageName: String?,
    val risk: SocketRisk,
    val threatFeedIds: List<String> = emptyList(),
    val severity: Severity? = null,
    val observedAtMillis: Long,
) {
    init {
        require(observedAtMillis > 0L) { "invalid socket observation timestamp" }
        require(pid == null || pid in 1..MAX_PID) { "invalid socket pid" }
        require(packageName == null || packageName.matches(PACKAGE_PATTERN)) { "invalid socket package" }
        require(threatFeedIds.size <= MAX_FEEDS) { "too many threat feeds" }
        require(threatFeedIds.all { it.matches(FEED_ID_PATTERN) }) { "invalid threat feed id" }
        require(threatFeedIds.isEmpty() || risk == SocketRisk.THREAT_FEED_MATCH) {
            "threat feeds require a feed-match risk"
        }
    }

    /** Stable, compact target string used by UI and evidence (`remote:port`). */
    val remoteEndpoint: String get() = "$remoteAddress:$remotePort"

    /** Value used for evidence subject and de-duplication. */
    val subject: String get() = "$packageName|$remoteEndpoint|${protocol.name}"

    companion object {
        const val MAX_PID = 4_194_304
        const val MAX_FEEDS = 8
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+){1,15}")
        private val FEED_ID_PATTERN = Regex("[a-z0-9][a-z0-9_-]{1,31}")
    }
}

/** Bounded result of one socket provenance pass. */
data class SocketSnapshot(
    val observations: List<SocketObservation>,
    val totalSockets: Int,
    val attributableSockets: Int,
    val suspiciousCount: Int,
    val capturedAtMillis: Long,
    val visibility: DataVisibility,
    /** True when one of the bounded caps dropped rows (socket/observation/process cap). */
    val truncated: Boolean = false,
    val note: MessageRef? = null,
) {
    init {
        require(totalSockets >= 0) { "negative socket count" }
        require(attributableSockets in 0..totalSockets) { "invalid attributable socket count" }
        require(suspiciousCount >= 0) { "negative suspicious count" }
        require(observations.size <= MAX_OBSERVATIONS) { "too many socket observations" }
        require(capturedAtMillis > 0L) { "invalid socket snapshot timestamp" }
    }

    companion object {
        const val MAX_OBSERVATIONS = 512

        fun empty(nowMillis: Long, visibility: DataVisibility, note: MessageRef? = null): SocketSnapshot =
            SocketSnapshot(
                observations = emptyList(),
                totalSockets = 0,
                attributableSockets = 0,
                suspiciousCount = 0,
                capturedAtMillis = nowMillis.coerceAtLeast(1L),
                visibility = visibility,
                note = note,
            )
    }
}

/** Tunable bounds of the socket provenance pass. All values are hard caps, no unbounded growth. */
data class SocketProvenanceConfig(
    val maxSockets: Int = 4_096,
    val maxObservations: Int = SocketSnapshot.MAX_OBSERVATIONS,
    val maxProcessEntries: Int = 4_096,
    val adbPort: Int = 5555,
) {
    init {
        require(maxSockets in 1..65_536) { "invalid socket cap" }
        require(maxObservations in 1..SocketSnapshot.MAX_OBSERVATIONS) { "invalid observation cap" }
        require(maxProcessEntries in 1..65_536) { "invalid process cap" }
        require(adbPort in 1..65_535) { "invalid ADB port" }
    }

    companion object {
        val DEFAULT = SocketProvenanceConfig()
    }
}
