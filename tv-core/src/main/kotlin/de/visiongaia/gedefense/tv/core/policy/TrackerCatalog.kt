package de.visiongaia.gedefense.tv.core.policy

import de.visiongaia.gedefense.mobile.core.canonicalPrivacyDomain
import de.visiongaia.gedefense.tv.core.model.Confidence

/**
 * Local tracker/discovery categories relevant to smart TVs.
 *
 * Category assignment is a review signal, never a malware verdict:
 *  - [TELEMETRY] device diagnostics and crash/usage telemetry;
 *  - [ACR] automatic content recognition (Samba TV, Inscape, Alphonso, TVision);
 *  - [ADS] advertising delivery/measurement;
 *  - [ANALYTICS] app analytics and attribution;
 *  - [C2] command-and-control infrastructure, normally derived from signed threat intelligence
 *    rather than from a hand-maintained name list.
 */
enum class TrackerCategory { TELEMETRY, ACR, ADS, ANALYTICS, C2 }

/**
 * One curated local tracker rule. [sourceId] documents where the entry came from so UI/report can
 * explain the match. Domains are matched exactly (or as a suffix when [includeSubdomains]).
 */
data class TrackerRule(
    val id: String,
    val domain: String,
    val includeSubdomains: Boolean,
    val category: TrackerCategory,
    val confidence: Confidence,
    val sourceId: String = DEFAULT_SOURCE_ID,
) {
    init {
        require(id.matches(Regex("[a-z0-9][a-z0-9._-]{2,95}"))) { "invalid tracker rule id: $id" }
        require(sourceId.matches(Regex("[a-z0-9][a-z0-9._-]{2,63}"))) { "invalid tracker source id: $sourceId" }
    }

    val canonicalDomain: String = requireNotNull(canonicalPrivacyDomain(domain)) {
        "invalid tracker domain: $domain"
    }

    companion object {
        const val DEFAULT_SOURCE_ID = "local-tv-trackers-v1"
    }
}

/**
 * Bounded, immutable local tracker catalog.
 *
 * Matching is deterministic: highest confidence wins, then the longest matched domain, then the
 * lexicographically smallest rule id. A domain without a rule is not classified at all.
 */
class TrackerCatalog private constructor(
    private val exact: Map<String, List<TrackerRule>>,
    private val suffix: Map<String, List<TrackerRule>>,
    val rules: List<TrackerRule>,
) {

    /** Total number of curated rules. */
    val size: Int get() = rules.size

    fun match(rawDomain: String): TrackerRule? {
        val domain = canonicalPrivacyDomain(rawDomain) ?: return null
        val candidates = ArrayList<TrackerRule>(4)
        exact[domain]?.let(candidates::addAll)
        var cursor = domain
        while (true) {
            suffix[cursor]?.let(candidates::addAll)
            val dot = cursor.indexOf('.')
            if (dot < 0 || dot + 1 >= cursor.length) break
            cursor = cursor.substring(dot + 1)
        }
        if (candidates.isEmpty()) return null
        return candidates.maxWithOrNull(PRECEDENCE)
    }

    /** Convenience classification used by the XDR engine. */
    fun categoryOf(rawDomain: String): TrackerCategory? = match(rawDomain)?.category

    companion object {
        const val MAX_RULES = 4096

        private val PRECEDENCE = compareBy<TrackerRule>(
            { it.confidence.ordinal },
            { it.canonicalDomain.length },
            { it.id },
        )

        /**
         * Builds a catalog. Duplicate ids and duplicate (domain, includeSubdomains, category) keys
         * are rejected so the table cannot silently drift.
         */
        fun build(rules: Collection<TrackerRule>, maxRules: Int = MAX_RULES): TrackerCatalog {
            require(maxRules in 1..MAX_RULES) { "invalid tracker rule bound" }
            require(rules.size <= maxRules) { "tracker rule bound exceeded: ${rules.size} > $maxRules" }
            val ids = HashSet<String>(rules.size)
            val keys = HashSet<String>(rules.size)
            val sorted = rules.sortedWith(compareBy<TrackerRule>({ it.canonicalDomain }, { it.id }))
            val exact = LinkedHashMap<String, MutableList<TrackerRule>>()
            val suffix = LinkedHashMap<String, MutableList<TrackerRule>>()
            for (rule in sorted) {
                require(ids.add(rule.id)) { "duplicate tracker rule id: ${rule.id}" }
                require(keys.add("${rule.canonicalDomain}|${rule.includeSubdomains}|${rule.category.name}")) {
                    "duplicate tracker rule classification: ${rule.id}"
                }
                val target = if (rule.includeSubdomains) suffix else exact
                target.getOrPut(rule.canonicalDomain) { ArrayList(1) }.add(rule)
            }
            return TrackerCatalog(
                exact = exact.mapValues { it.value.toList() },
                suffix = suffix.mapValues { it.value.toList() },
                rules = sorted.toList(),
            )
        }

        /** Curated TV tracker/telemetry table. C2 entries are intentionally supplied by threat intel. */
        val TV_DEFAULT: TrackerCatalog by lazy { build(defaultRules()) }

        private fun defaultRules(): List<TrackerRule> {
            fun rule(
                id: String,
                domain: String,
                includeSubdomains: Boolean,
                category: TrackerCategory,
                confidence: Confidence,
            ) = TrackerRule(id, domain, includeSubdomains, category, confidence)

            return listOf(
                // Automatic content recognition (well-known TV ACR providers).
                rule("acr-samba", "samba.tv", true, TrackerCategory.ACR, Confidence.HIGH),
                rule("acr-sambatv", "sambatv.com", true, TrackerCategory.ACR, Confidence.HIGH),
                rule("acr-inscape", "inscape.tv", true, TrackerCategory.ACR, Confidence.HIGH),
                rule("acr-alphonso", "alphonso.tv", true, TrackerCategory.ACR, Confidence.HIGH),
                rule("acr-tvision", "tvisioninsights.com", true, TrackerCategory.ACR, Confidence.HIGH),

                // Advertising delivery and measurement.
                rule("ads-doubleclick", "doubleclick.net", true, TrackerCategory.ADS, Confidence.HIGH),
                rule("ads-googlesyndication", "googlesyndication.com", true, TrackerCategory.ADS, Confidence.HIGH),
                rule("ads-googleadservices", "googleadservices.com", true, TrackerCategory.ADS, Confidence.HIGH),
                rule("ads-adservice-google", "adservice.google.com", false, TrackerCategory.ADS, Confidence.HIGH),
                rule("ads-amazon", "amazon-adsystem.com", true, TrackerCategory.ADS, Confidence.HIGH),
                rule("ads-adsrvr", "adsrvr.org", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-rubiconproject", "rubiconproject.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-pubmatic", "pubmatic.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-openx", "openx.net", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-criteo", "criteo.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-criteo-net", "criteo.net", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-adnxs", "adnxs.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-taboola", "taboola.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-outbrain", "outbrain.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-smartadserver", "smartadserver.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-moatads", "moatads.com", true, TrackerCategory.ADS, Confidence.MEDIUM),
                rule("ads-imasdk", "imasdk.googleapis.com", false, TrackerCategory.ADS, Confidence.MEDIUM),

                // App analytics, crash reporting and attribution.
                rule("analytics-google", "google-analytics.com", true, TrackerCategory.ANALYTICS, Confidence.HIGH),
                rule("analytics-google-com", "analytics.google.com", false, TrackerCategory.ANALYTICS, Confidence.HIGH),
                rule("analytics-appmeasurement", "app-measurement.com", true, TrackerCategory.ANALYTICS, Confidence.HIGH),
                rule("analytics-firebaseinstallations", "firebaseinstallations.googleapis.com", false, TrackerCategory.ANALYTICS, Confidence.HIGH),
                rule("analytics-appanalytics", "app-analytics-services.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-segment-io", "segment.io", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-segment-com", "segment.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-mixpanel", "mixpanel.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-amplitude", "amplitude.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-heap", "heap.io", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-hotjar", "hotjar.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-fullstory", "fullstory.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-newrelic", "newrelic.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-nrdata", "nr-data.net", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-bugsnag", "bugsnag.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-sentry", "sentry.io", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-datadog", "datadoghq.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-appsflyer", "appsflyer.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-adjust", "adjust.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-branch", "branch.io", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),
                rule("analytics-kochava", "kochava.com", true, TrackerCategory.ANALYTICS, Confidence.MEDIUM),

                // Device telemetry / crash telemetry.
                rule("telemetry-crashlytics", "crashlytics.com", true, TrackerCategory.TELEMETRY, Confidence.HIGH),
                rule("telemetry-firebase-settings-crashlytics", "firebase-settings.crashlytics.com", false, TrackerCategory.TELEMETRY, Confidence.HIGH),
                rule("telemetry-amazon-device-metrics", "device-metrics-us.amazon.com", false, TrackerCategory.TELEMETRY, Confidence.MEDIUM),
            )
        }
    }
}
