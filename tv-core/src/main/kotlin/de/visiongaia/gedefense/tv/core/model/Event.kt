package de.visiongaia.gedefense.tv.core.model

/**
 * XDR-lite event as defined by the TV datasheet (section 6).
 *
 * Unknown values stay null; the app never guesses network fields it could not observe. Timestamps
 * are serialised as ISO-8601 UTC strings in the event log, while internal models keep epoch millis
 * for deterministic ordering.
 */
data class TvEvent(
    val eventClass: EventClass,
    val eventId: String,
    val deviceId: String,
    val eventTimeMillis: Long,
    val collectorId: String,
    val platform: String = PLATFORM,
    val osApiLevel: Int,
    val subject: String,
    val dataQuality: DataQuality,
    val severity: Severity? = null,
    val confidence: Confidence? = null,
    val evidenceRef: String? = null,
    val ruleId: String? = null,
    val policyAction: PolicyAction? = null,
    val firstSeenMillis: Long? = null,
    val lastSeenMillis: Long? = null,
    val attributes: Map<String, String> = emptyMap(),
) {
    init {
        require(eventId.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))) {
            "invalid event id"
        }
        require(deviceId.matches(DEVICE_ID_PATTERN)) { "invalid pseudonymous device id" }
        require(eventTimeMillis > 0L) { "invalid event timestamp" }
        require(collectorId.matches(Regex("[a-z][a-z0-9-]{1,63}"))) { "invalid event collector" }
        require(osApiLevel >= 1) { "invalid event api level" }
        require(subject.length in 1..160) { "invalid event subject" }
        require(evidenceRef == null || evidenceRef.length <= 200) { "event evidence reference too long" }
        require(ruleId == null || ruleId.matches(Regex("[a-z][a-z0-9-]{2,63}"))) { "invalid event rule id" }
        require(firstSeenMillis == null || firstSeenMillis > 0L) { "invalid first seen" }
        require(lastSeenMillis == null || lastSeenMillis > 0L) { "invalid last seen" }
        require(firstSeenMillis == null || lastSeenMillis == null || lastSeenMillis >= firstSeenMillis) {
            "event lastSeen before firstSeen"
        }
        require(attributes.size <= 12) { "too many event attributes" }
        require(attributes.all { (key, value) ->
            key.matches(Regex("[a-z][a-z0-9_]{1,31}")) && value.length <= 256 && value.none { it == '\n' || it == '\r' }
        }) { "invalid event attribute" }
    }

    companion object {
        const val PLATFORM = "android-tv"
        val DEVICE_ID_PATTERN = Regex("tv_[0-9a-f]{32}")
    }
}

/** Tri-state wrapper used by collectors for platform values that may be unreadable. */
data class Observed<T>(val value: T?, val readable: Boolean) {
    init {
        require(value == null || readable) { "unreadable observation cannot carry a value" }
    }

    companion object {
        fun <T> of(value: T): Observed<T> = Observed(value, readable = true)
        fun <T> unreadable(): Observed<T> = Observed(null, readable = false)
    }
}
