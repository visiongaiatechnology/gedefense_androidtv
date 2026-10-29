package de.visiongaia.gedefense.tv.core.model

/**
 * TV outbound anomaly kinds (V2.1 "Kinetic-Lite").
 *
 * These are local, explainable heuristics over observed outbound traffic. They are never malware
 * verdicts and never auto-enforce on their own: the containment policy requires an explicit opt-in
 * (strict profile), multiple independent signals and a known destination.
 */
enum class AnomalyKind {
    DNS_BURST,
    DESTINATION_FANOUT,
    BEACON_PATTERN,
    VOLUME_SPIKE,
    REPEATED_BLOCK,
    TRACKER_CATEGORY,
    C2_MATCH,
    HIGH_RISK_CORRIDOR,
}

/** One explainable score contribution of an anomaly. */
data class AnomalySignal(
    val kind: AnomalyKind,
    val score: Int,
    val detail: String,
    val count: Int = 0,
) {
    init {
        require(score in -100..100) { "invalid anomaly signal score" }
        require(detail.length <= 160) { "anomaly signal detail too long" }
        require(count >= 0) { "invalid anomaly signal count" }
    }
}

/**
 * A bounded, deterministic outbound anomaly. IDs are stable for one evaluation window so the UI and
 * evidence layer can dedupe without inventing incidents.
 */
data class OutboundAnomaly(
    val id: String,
    val kind: AnomalyKind,
    val packageName: String?,
    val appLabel: String?,
    val countryCode: String?,
    val destinationPrefix: String?,
    val score: Int,
    val severity: Severity,
    val confidence: Confidence,
    val signals: List<AnomalySignal>,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long,
    val observationCount: Int,
) {
    init {
        require(id.isNotBlank() && id.length <= 128) { "invalid anomaly id" }
        require(packageName == null || packageName.length <= 255) { "anomaly package too long" }
        require(appLabel == null || appLabel.length <= 120) { "anomaly label too long" }
        require(countryCode == null || countryCode.matches(Regex("[A-Z]{2}"))) { "invalid anomaly country" }
        require(destinationPrefix == null || destinationPrefix.length <= 64) { "invalid anomaly destination" }
        require(score in 0..100) { "invalid anomaly score" }
        require(signals.isNotEmpty() && signals.size <= 8) { "invalid anomaly signals" }
        require(firstSeenMillis > 0L && lastSeenMillis >= firstSeenMillis) { "invalid anomaly timestamps" }
        require(observationCount >= 1) { "invalid anomaly count" }
    }

    val isKnownCountry: Boolean get() = countryCode != null && countryCode != "ZZ" && countryCode != "UNKNOWN"
}
