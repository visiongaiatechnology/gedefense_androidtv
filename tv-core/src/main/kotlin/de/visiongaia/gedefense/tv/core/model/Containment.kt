package de.visiongaia.gedefense.tv.core.model

/** What a containment targets. V2.1 restricts enforcement to destination prefixes (no app kills). */
enum class ContainmentTargetType { DESTINATION_PREFIX }

/**
 * A validated containment target. Destination prefixes are canonical CIDR strings; the policy engine
 * rejects anything broader than /16 (IPv4) or /48 (IPv6) to avoid CDN/ASN collateral damage.
 */
data class ContainmentTarget(
    val type: ContainmentTargetType,
    val value: String,
) {
    init {
        require(value.matches(Regex("[0-9a-fA-F:.]{3,64}/[0-9]{1,3}"))) { "invalid containment target" }
    }
}

enum class ContainmentState { ACTIVE, RELEASED, EXPIRED }

enum class ContainmentOrigin { AUTO, MANUAL }

/** A proposal to temporarily contain outbound traffic; only produced under the strict profile. */
data class ContainmentProposal(
    val id: String,
    val target: ContainmentTarget,
    val reasonCode: String,
    val anomalyKind: AnomalyKind,
    val anomalyScore: Int,
    val confidence: Confidence,
    val packageName: String?,
    val appLabel: String?,
    val countryCode: String?,
    val signals: List<AnomalySignal>,
    val proposedTtlMillis: Long,
) {
    init {
        require(id.isNotBlank() && id.length <= 128) { "invalid containment proposal id" }
        require(reasonCode.isNotBlank() && reasonCode.length <= 120) { "invalid containment reason" }
        require(anomalyScore in 0..100) { "invalid containment score" }
        require(proposedTtlMillis in MIN_TTL_MILLIS..MAX_TTL_MILLIS) { "invalid containment ttl" }
        require(signals.size >= 2) { "containment requires at least two independent signals" }
    }

    companion object {
        const val MIN_TTL_MILLIS: Long = 60_000L
        const val MAX_TTL_MILLIS: Long = 30L * 60L * 1_000L
    }
}

/** One active/expired containment; the UI and evidence layer render exactly this state. */
data class ContainmentRecord(
    val id: String,
    val target: ContainmentTarget,
    val reasonCode: String,
    val anomalyKind: AnomalyKind,
    val anomalyScore: Int,
    val confidence: Confidence,
    val packageName: String?,
    val appLabel: String?,
    val countryCode: String?,
    val signals: List<AnomalySignal>,
    val origin: ContainmentOrigin,
    val state: ContainmentState,
    val createdAtMillis: Long,
    val expiresAtMillis: Long,
    val releasedAtMillis: Long? = null,
) {
    init {
        require(id.isNotBlank() && id.length <= 128) { "invalid containment record id" }
        require(reasonCode.isNotBlank() && reasonCode.length <= 120) { "invalid containment reason" }
        require(anomalyScore in 0..100) { "invalid containment score" }
        require(createdAtMillis > 0L) { "invalid containment creation time" }
        require(expiresAtMillis > createdAtMillis) { "invalid containment expiry" }
        require(releasedAtMillis == null || releasedAtMillis >= createdAtMillis) { "invalid release time" }
        require(signals.size >= 2) { "containment requires at least two independent signals" }
    }

    val isActive: Boolean get() = state == ContainmentState.ACTIVE
    val remainingMillis: Long get() = (expiresAtMillis - createdAtMillis).coerceAtLeast(0L)
}

/**
 * Bounded containment policy. Defaults are OBSERVE-only: no proposal is enforced until the user
 * explicitly enables containment in the strict profile.
 */
data class ContainmentPolicy(
    val enabled: Boolean = false,
    val maxActive: Int = 4,
    val minSignals: Int = 2,
    val minScore: Int = 60,
    val defaultTtlMillis: Long = 10L * 60L * 1_000L,
    val maxTtlMillis: Long = ContainmentProposal.MAX_TTL_MILLIS,
    val requireKnownCountry: Boolean = true,
    /** Never contain these packages (system, launcher, Play services, store, TV shell). */
    val protectedPackagePrefixes: Set<String> = DEFAULT_PROTECTED_PACKAGE_PREFIXES,
    /** Never contain these destination prefixes (platform/CDN essentials). */
    val allowlistedPrefixes: Set<String> = DEFAULT_ALLOWLISTED_PREFIXES,
) {
    init {
        require(maxActive in 1..16) { "invalid containment bound" }
        require(minSignals in 2..8) { "containment requires at least two signals" }
        require(minScore in 0..100) { "invalid containment score" }
        require(defaultTtlMillis in ContainmentProposal.MIN_TTL_MILLIS..ContainmentProposal.MAX_TTL_MILLIS) {
            "invalid default containment ttl"
        }
        require(maxTtlMillis in defaultTtlMillis..ContainmentProposal.MAX_TTL_MILLIS) { "invalid max containment ttl" }
        require(protectedPackagePrefixes.size <= 64 && allowlistedPrefixes.size <= 256) { "containment lists too large" }
    }

    companion object {
        /**
         * Exact package names that must never be contained. Matching is exact, not a prefix, so a
         * sideloaded `com.google.android.gms.helper` cannot inherit platform protection (SECV2-05).
         */
        val DEFAULT_PROTECTED_PACKAGE_PREFIXES: Set<String> = setOf(
            "android",
            "com.android.systemui",
            "com.android.settings",
            "com.android.shell",
            "com.android.vending",
            "com.android.tv.settings",
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.google.android.apps.tv.launcherx",
            "com.google.android.tvlauncher",
            "com.google.android.play.games",
            "com.google.android.leanbacklauncher",
            "com.google.android.inputmethod.latin",
            "de.visiongaia.gedefense.tv",
        )
        /** Google/YouTube/Play CDN ranges and platform resolvers must never be contained. */
        val DEFAULT_ALLOWLISTED_PREFIXES: Set<String> = setOf(
            "8.8.8.8/32",
            "8.8.4.4/32",
            "1.1.1.1/32",
            "9.9.9.9/32",
            "142.250.0.0/15",
            "172.217.0.0/16",
            "216.58.192.0/19",
            "74.125.0.0/16",
            "173.194.0.0/16",
            "209.85.128.0/17",
            "34.96.0.0/12",
            "35.190.0.0/17",
            "64.233.160.0/19",
            // Never contain private, loopback, link-local, multicast or documentation ranges (SECV2-04).
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
            "224.0.0.0/4", "240.0.0.0/4", "0.0.0.0/8",
            "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
        )
    }
}
