package de.visiongaia.gedefense.mobile.core

// STATUS: DIAMANT VGT SUPREME

enum class SentinelRisk { INFO, REVIEW, HIGH, CRITICAL }

data class SentinelAssessment(
    val code: String,
    val risk: SentinelRisk,
    val riskPoints: Int,
    val suspicious: Boolean,
)

/**
 * Pure, bounded classifier for local passive-sentinel connection attempts.
 * It never inspects payload bytes. Classification depends only on destination port and the
 * number of distinct protected ports contacted by the same source within the caller's window.
 */
object PortSentinelClassifier {
    const val SCAN_WINDOW_MILLIS = 30_000L
    const val MAX_TRACKED_DISTINCT_PORTS = 6

    val monitoredPorts: Set<Int> = setOf(1080, 2222, 2323, 5555, 8080, 8443)

    fun assess(targetPort: Int, distinctPortsInWindow: Int): SentinelAssessment {
        require(targetPort in monitoredPorts) { "target port is not monitored" }
        val distinct = distinctPortsInWindow.coerceIn(1, MAX_TRACKED_DISTINCT_PORTS)
        if (distinct >= 3) {
            val critical = targetPort == 5555 || distinct >= 5
            return SentinelAssessment(
                code = "LAN_PORT_SCAN_DETECTED",
                risk = if (critical) SentinelRisk.CRITICAL else SentinelRisk.HIGH,
                riskPoints = if (critical) 82 else 58,
                suspicious = true,
            )
        }
        return when (targetPort) {
            5555 -> SentinelAssessment("LAN_ADB_PROBE_DETECTED", SentinelRisk.CRITICAL, 78, true)
            2323 -> SentinelAssessment("LAN_TELNET_PROBE_DETECTED", SentinelRisk.HIGH, 56, true)
            2222 -> SentinelAssessment("LAN_SSH_ALT_PROBE_DETECTED", SentinelRisk.REVIEW, 28, true)
            1080 -> SentinelAssessment("LAN_SOCKS_PROBE_DETECTED", SentinelRisk.REVIEW, 30, true)
            8080, 8443 -> SentinelAssessment("LAN_WEB_PROXY_PROBE_DETECTED", SentinelRisk.REVIEW, 24, true)
            else -> SentinelAssessment("LAN_SENTINEL_HIT", SentinelRisk.INFO, 4, false)
        }
    }
}
