package de.visiongaia.gedefense.tv.core.model

/**
 * Local threat-intelligence status for one configured feed.
 *
 * The TV app can only use feeds it actually downloaded and verified. [fresh] is derived from the
 * feed's staleness budget; stale data stays usable but is always labelled as stale.
 */
data class FeedSnapshot(
    val id: String,
    val name: String,
    val available: Boolean,
    val fresh: Boolean,
    val records: Int,
    val fetchedAtMillis: Long,
    val enforcement: String,
) {
    init {
        require(id.matches(Regex("[a-z0-9][a-z0-9-]{1,47}"))) { "invalid feed id" }
        require(name.length in 1..96) { "invalid feed name" }
        require(records >= 0) { "negative feed record count" }
        require(fetchedAtMillis >= 0L) { "invalid feed timestamp" }
        require(enforcement.length <= 32) { "invalid enforcement label" }
    }

    val ageMillis: Long get() = if (fetchedAtMillis <= 0L) 0L else (System.currentTimeMillis() - fetchedAtMillis).coerceAtLeast(0L)
}

/** Aggregated threat-intelligence state shown in the UI and report. */
data class ThreatIntelStatus(
    val feeds: List<FeedSnapshot>,
    val lastSyncMillis: Long?,
    val syncHealthy: Boolean,
    val note: MessageRef? = null,
) {
    init {
        require(feeds.size <= 64) { "too many feeds" }
        require(feeds.map { it.id }.toSet().size == feeds.size) { "duplicate feed" }
    }

    val availableCount: Int get() = feeds.count { it.available }
    val freshCount: Int get() = feeds.count { it.fresh }
    val staleCount: Int get() = feeds.count { it.available && !it.fresh }

    companion object {
        val EMPTY = ThreatIntelStatus(feeds = emptyList(), lastSyncMillis = null, syncHealthy = false)
    }
}

/**
 * A threat-intelligence match that the TV app actually observed. V1 has no system-wide flow
 * visibility, so matches can only be derived from data the collectors legitimately hold (for
 * example the app's own TLS endpoints). Never invent matches from unavailable telemetry.
 */
data class ThreatMatch(
    val indicator: String,
    val feedId: String,
    val feedName: String,
    val matchedAtMillis: Long,
    val confidence: Confidence,
    val evidenceRef: String,
) {
    init {
        require(indicator.length in 3..128) { "invalid threat indicator" }
        require(feedId.matches(Regex("[a-z0-9][a-z0-9-]{1,47}"))) { "invalid feed id" }
        require(matchedAtMillis > 0L) { "invalid match timestamp" }
        require(evidenceRef.length in 1..200) { "invalid match evidence" }
    }
}
