package de.visiongaia.gedefense.tv.core.model

/** Health of the local tamper-evident evidence ledger. */
data class EvidenceHealth(
    val healthy: Boolean,
    val records: Long,
    val reason: MessageRef? = null,
) {
    init {
        require(records >= 0L) { "negative evidence record count" }
        require(healthy || reason != null) { "unhealthy evidence store needs a reason" }
    }

    companion object {
        val UNAVAILABLE = EvidenceHealth(healthy = false, records = 0L, reason = MessageRef("evidence.unavailable"))
    }
}

/**
 * Complete, self-contained report input. Everything a report claims must come from this object;
 * the renderer may format but never invent content.
 */
data class SecurityReport(
    val reportId: String,
    val generatedAtMillis: Long,
    val deviceId: String,
    val scan: ScanResult,
    val evidence: EvidenceHealth,
    val threatIntel: ThreatIntelStatus,
) {
    init {
        require(reportId.matches(Regex("[a-z0-9-]{8,64}"))) { "invalid report id" }
        require(generatedAtMillis > 0L) { "invalid report timestamp" }
        require(deviceId.matches(TvEvent.DEVICE_ID_PATTERN)) { "invalid report device id" }
    }
}
