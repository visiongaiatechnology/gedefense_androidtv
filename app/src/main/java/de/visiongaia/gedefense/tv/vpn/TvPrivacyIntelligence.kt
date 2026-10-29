package de.visiongaia.gedefense.tv.vpn

import android.content.Context
import de.visiongaia.gedefense.mobile.core.PrivacyBreakageRisk
import de.visiongaia.gedefense.mobile.core.PrivacyCategory
import de.visiongaia.gedefense.mobile.core.PrivacyConfidence
import de.visiongaia.gedefense.mobile.core.PrivacyIntelligenceRegistry
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.mobile.core.PrivacyProvenance
import de.visiongaia.gedefense.mobile.core.PrivacyRule
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.core.policy.TrackerCatalog
import de.visiongaia.gedefense.tv.core.policy.TrackerCategory
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Builds the immutable local privacy policy that the GaiaNet helper enforces.
 *
 * Sources, merged locally without any network request:
 *  1. the signed APK asset `privacy_intelligence_v1.tsv` (same schema/provenance as the mobile
 *     dossier) — never granted blocking authority beyond the profile/confidence/breakage rules;
 *  2. the curated TV tracker catalog (`TrackerCatalog.TV_DEFAULT` from tv-core), translated into
 *     privacy rules so smart-TV telemetry/ACR/ad domains are actually blocked by the data plane.
 *
 * Tracker rules are translated per profile because the vendored core derives actions from
 * category/confidence/breakage (it has no explicit action field):
 *  - OFF: tracker rules are not merged at all;
 *  - CONSERVATIVE: only HIGH-confidence tracker rules are encoded as blockable, the rest observe;
 *  - BALANCED: every non-LOW-confidence tracker rule is blockable;
 *  - STRICT: every tracker rule is blockable.
 *
 * Category mapping: TELEMETRY→DEVICE_TELEMETRY, ACR→ATTRIBUTION, ADS→ADS, ANALYTICS→ANALYTICS,
 * C2→ADS (the vendored privacy category set has no dedicated malicious-C2 category; C2 prefixes are
 * primarily enforced by the signed threat index, this mapping is the local-domain fallback).
 */
class TvPrivacyIntelligence(
    context: Context,
    trackerCatalog: TrackerCatalog = TrackerCatalog.TV_DEFAULT,
) {
    private val appContext = context.applicationContext
    private val trackerRules: List<de.visiongaia.gedefense.tv.core.policy.TrackerRule> =
        trackerCatalog.rules + SUPPLEMENTARY_TV_TRACKERS
    private val assetState: AssetState by lazy { loadAsset() }
    private val registries = arrayOfNulls<PrivacyIntelligenceRegistry>(TvPrivacyProfile.entries.size)

    /** Registry for [profile], cached per profile. Safe to call from any thread. */
    fun registry(profile: TvPrivacyProfile): PrivacyIntelligenceRegistry {
        val index = profile.ordinal
        registries[index]?.let { return it }
        return synchronized(registries) {
            registries[index] ?: buildRegistry(profile).also { registries[index] = it }
        }
    }

    /** Convenience for callers that do not know the active profile (defaults to BALANCED). */
    fun registry(): PrivacyIntelligenceRegistry = registry(TvPrivacyProfile.BALANCED)

    fun healthy(): Boolean {
        val asset = assetState
        return (asset is AssetState.Ready) || trackerRules.isNotEmpty()
    }

    fun failureReason(): String? = (assetState as? AssetState.Failed)?.reason

    fun trackerRuleCount(): Int = trackerRules.size

    private fun buildRegistry(profile: TvPrivacyProfile): PrivacyIntelligenceRegistry {
        val assetRules = (assetState as? AssetState.Ready)?.rules.orEmpty()
        val rules = ArrayList<PrivacyRule>(assetRules.size + trackerRules.size)
        rules += assetRules
        if (profile != TvPrivacyProfile.OFF) {
            val blockableIds = when (profile) {
                TvPrivacyProfile.CONSERVATIVE -> trackerRules
                    .filter { it.confidence == Confidence.HIGH }
                    .mapTo(HashSet()) { it.id }

                TvPrivacyProfile.BALANCED -> trackerRules
                    .filter { it.confidence != Confidence.LOW }
                    .mapTo(HashSet()) { it.id }

                TvPrivacyProfile.STRICT -> trackerRules.mapTo(HashSet()) { it.id }
                TvPrivacyProfile.OFF -> emptySet()
            }
            val usedIds = assetRules.mapTo(HashSet()) { it.id }
            for (rule in trackerRules) {
                val id = ("tvtrk." + rule.id).take(96)
                if (!usedIds.add(id)) continue
                val blockable = rule.id in blockableIds
                val coreConfidence = when {
                    !blockable -> PrivacyConfidence.LOW
                    profile == TvPrivacyProfile.CONSERVATIVE -> PrivacyConfidence.HIGH
                    else -> PrivacyConfidence.MEDIUM
                }
                val category = when (rule.category) {
                    TrackerCategory.TELEMETRY -> PrivacyCategory.DEVICE_TELEMETRY
                    TrackerCategory.ACR -> PrivacyCategory.ATTRIBUTION
                    TrackerCategory.ADS -> PrivacyCategory.ADS
                    TrackerCategory.ANALYTICS -> PrivacyCategory.ANALYTICS
                    TrackerCategory.C2 -> PrivacyCategory.ADS
                }
                val privacyRule = try {
                    PrivacyRule(
                        id = id,
                        domain = rule.domain,
                        includeSubdomains = true,
                        category = category,
                        confidence = coreConfidence,
                        breakageRisk = PrivacyBreakageRisk.LOW,
                        essential = false,
                        provenance = TRACKER_PROVENANCE,
                    )
                } catch (_: IllegalArgumentException) {
                    // A malformed/duplicate tracker entry is skipped; the rest of the table stays usable.
                    continue
                }
                rules += privacyRule
            }
        }
        return PrivacyIntelligenceRegistry.build(rules, MAX_RULES)
    }

    private fun loadAsset(): AssetState = try {
        val rules = ArrayList<PrivacyRule>(128)
        appContext.assets.open(ASSET_NAME).use { input ->
            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            BufferedReader(InputStreamReader(input, decoder), 16 * 1024).use { reader ->
                var lineNumber = 0
                var totalChars = 0
                while (true) {
                    val line = reader.readLine() ?: break
                    lineNumber++
                    totalChars += line.length + 1
                    require(lineNumber <= MAX_LINES && totalChars <= MAX_CHARS) {
                        "privacy intelligence asset bound exceeded"
                    }
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith('#')) continue
                    val fields = line.split('\t')
                    require(fields.size == FIELD_COUNT) { "privacy intelligence field count invalid" }
                    rules += PrivacyRule(
                        id = fields[0],
                        domain = fields[1],
                        includeSubdomains = parseBoolean(fields[2]),
                        category = PrivacyCategory.valueOf(fields[3]),
                        confidence = PrivacyConfidence.valueOf(fields[4]),
                        breakageRisk = PrivacyBreakageRisk.valueOf(fields[5]),
                        essential = parseBoolean(fields[6]),
                        provenance = PrivacyProvenance(
                            sourceId = fields[7],
                            sourceUrl = fields[8],
                            licenseId = fields[9],
                            observedAt = fields[10],
                        ),
                    )
                }
            }
        }
        if (rules.isEmpty()) AssetState.Failed("privacy_intelligence_asset_empty") else AssetState.Ready(rules)
    } catch (_: Exception) {
        AssetState.Failed("privacy_intelligence_asset_invalid")
    }

    private fun parseBoolean(value: String): Boolean = when (value) {
        "true" -> true
        "false" -> false
        else -> throw IllegalArgumentException("invalid privacy intelligence boolean")
    }

    private sealed interface AssetState {
        data class Ready(val rules: List<PrivacyRule>) : AssetState
        data class Failed(val reason: String) : AssetState
    }

    companion object {
        private const val ASSET_NAME = "privacy_intelligence_v1.tsv"
        private const val FIELD_COUNT = 11
        private const val MAX_RULES = 8_192
        private const val MAX_LINES = 16_384
        private const val MAX_CHARS = 4 * 1024 * 1024

        /** Attribution for locally curated tracker rules; source ids match TrackerRule's default. */
        private val TRACKER_PROVENANCE = PrivacyProvenance(
            sourceId = "local-tv-trackers-v1",
            sourceUrl = "https://visiongaiatechnology.de/gedefense/privacy-intelligence",
            licenseId = "VGT-1.0",
            observedAt = "2026-10-29",
        )

        /**
         * Supplementary TV-specific tracker domains that the vendored catalog does not list yet
         * (Samsung Ads / Samsung ACR). Kept local and conservative: only dedicated ad/ACR domains,
         * never app-store, firmware-update or support endpoints.
         */
        private val SUPPLEMENTARY_TV_TRACKERS = listOf(
            de.visiongaia.gedefense.tv.core.policy.TrackerRule(
                id = "ads-samsungads",
                domain = "samsungads.com",
                includeSubdomains = true,
                category = TrackerCategory.ADS,
                confidence = Confidence.HIGH,
            ),
            de.visiongaia.gedefense.tv.core.policy.TrackerRule(
                id = "acr-samsungacr",
                domain = "samsungacr.com",
                includeSubdomains = true,
                category = TrackerCategory.ACR,
                confidence = Confidence.HIGH,
            ),
        )
    }
}
