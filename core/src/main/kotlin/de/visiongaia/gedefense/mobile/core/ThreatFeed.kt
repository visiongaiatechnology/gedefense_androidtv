package de.visiongaia.gedefense.mobile.core

import java.net.URI

enum class FeedFormat { PLAIN, SPAMHAUS_JSONL, IPSUM_SCORE }
enum class FeedSemantics { MALICIOUS_C2, DROP_NETWORK, HOSTILE_SCANNER, AGGREGATED_RISK, ANONYMIZER }
enum class EnforcementClass { ROUTE_BLOCK, CORRELATE_ONLY, ANNOTATE_ONLY }

data class ThreatFeed(
    val id: String,
    val name: String,
    val url: String,
    val format: FeedFormat,
    val semantics: FeedSemantics,
    val enforcement: EnforcementClass,
    val minRefreshMinutes: Long,
    val maxStaleMinutes: Long,
    val maxDownloadBytes: Long,
    val maxEntries: Int,
    val minIpsumScore: Int = 0,
    val attribution: String? = null,
) {
    init {
        require(id.matches(Regex("[a-z0-9][a-z0-9-]{1,47}"))) { "invalid feed id" }
        require(name.length in 1..96) { "invalid feed name" }
        val uri = URI(url)
        require(uri.scheme == "https" && uri.host != null && uri.userInfo == null && uri.fragment == null) { "feed must use plain HTTPS" }
        require(minRefreshMinutes in 5..(7L * 24L * 60L)) { "invalid refresh budget" }
        require(maxStaleMinutes >= minRefreshMinutes && maxStaleMinutes <= 14L * 24L * 60L) { "invalid staleness budget" }
        require(maxDownloadBytes in 1024L..(32L shl 20)) { "invalid feed size bound" }
        require(maxEntries in 1..500_000) { "invalid feed entry bound" }
        require(minIpsumScore in 0..100) { "invalid IPsum threshold" }
        require(attribution == null || attribution.length <= 160) { "attribution too long" }
    }
}

object ThreatFeedCatalog {
    const val POLICY_ABI_VERSION = 2
    private val POLICY_ABI_IDS = listOf(
        "feodo", "spamhaus-drop-v4", "spamhaus-drop-v6",
        "cins", "blocklist-de", "emerging-threats", "ipsum", "firehol-level1", "tor-exits",
    )

    val all: List<ThreatFeed> = listOf(
        ThreatFeed(
            "feodo", "Feodo Tracker C2", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            FeedFormat.PLAIN, FeedSemantics.MALICIOUS_C2, EnforcementClass.ROUTE_BLOCK,
            15, 6 * 60, 2L shl 20, 20_000, attribution = "abuse.ch Feodo Tracker"
        ),
        ThreatFeed(
            "spamhaus-drop-v4", "Spamhaus DROP IPv4", "https://www.spamhaus.org/drop/drop_v4.json",
            FeedFormat.SPAMHAUS_JSONL, FeedSemantics.DROP_NETWORK, EnforcementClass.ROUTE_BLOCK,
            24 * 60, 3 * 24 * 60, 4L shl 20, 30_000, attribution = "The Spamhaus Project - DROP"
        ),
        ThreatFeed(
            "spamhaus-drop-v6", "Spamhaus DROP IPv6", "https://www.spamhaus.org/drop/drop_v6.json",
            FeedFormat.SPAMHAUS_JSONL, FeedSemantics.DROP_NETWORK, EnforcementClass.ROUTE_BLOCK,
            24 * 60, 3 * 24 * 60, 4L shl 20, 30_000, attribution = "The Spamhaus Project - DROPv6"
        ),
        ThreatFeed(
            "cins", "CINS Army Badguys", "https://cinsscore.com/list/ci-badguys.txt",
            FeedFormat.PLAIN, FeedSemantics.HOSTILE_SCANNER, EnforcementClass.CORRELATE_ONLY,
            6 * 60, 48 * 60, 4L shl 20, 50_000
        ),
        ThreatFeed(
            "blocklist-de", "blocklist.de", "https://lists.blocklist.de/lists/all.txt",
            FeedFormat.PLAIN, FeedSemantics.HOSTILE_SCANNER, EnforcementClass.CORRELATE_ONLY,
            60, 48 * 60, 4L shl 20, 50_000, attribution = "blocklist.de"
        ),
        ThreatFeed(
            "emerging-threats", "Emerging Threats Block IPs", "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
            FeedFormat.PLAIN, FeedSemantics.AGGREGATED_RISK, EnforcementClass.CORRELATE_ONLY,
            6 * 60, 48 * 60, 8L shl 20, 80_000, attribution = "Emerging Threats"
        ),
        ThreatFeed(
            "ipsum", "IPsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            FeedFormat.IPSUM_SCORE, FeedSemantics.AGGREGATED_RISK, EnforcementClass.CORRELATE_ONLY,
            6 * 60, 48 * 60, 8L shl 20, 150_000, minIpsumScore = 3, attribution = "stamparm/ipsum"
        ),
        ThreatFeed(
            "firehol-level1", "FireHOL Level 1", "https://iplists.firehol.org/files/firehol_level1.netset",
            FeedFormat.PLAIN, FeedSemantics.AGGREGATED_RISK, EnforcementClass.ROUTE_BLOCK,
            6 * 60, 48 * 60, 8L shl 20, 80_000, attribution = "FireHOL blocklist-ipsets"
        ),
        ThreatFeed(
            "tor-exits", "Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist",
            FeedFormat.PLAIN, FeedSemantics.ANONYMIZER, EnforcementClass.ANNOTATE_ONLY,
            6 * 60, 24 * 60, 2L shl 20, 20_000, attribution = "The Tor Project - bulk exit list"
        ),
    )

    init {
        require(all.map { it.id } == POLICY_ABI_IDS) { "threat feed order changed without native policy ABI migration" }
        require(all.map { it.id }.toSet().size == all.size) { "duplicate threat feed id" }
        require(all.map { it.url }.toSet().size == all.size) { "duplicate threat feed URL" }
        require(all.size < 63) { "feed bitset exhausted" }
    }

    private val byId = all.associateBy { it.id }
    private val indexById = all.mapIndexed { index, feed -> feed.id to index }.toMap()
    fun require(id: String): ThreatFeed = byId[id] ?: error("unknown feed id: $id")
    fun indexOf(id: String): Int = indexById[id] ?: error("unknown feed id: $id")
}
