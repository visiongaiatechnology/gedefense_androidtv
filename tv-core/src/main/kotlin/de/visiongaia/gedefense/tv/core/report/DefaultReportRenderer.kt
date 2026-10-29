package de.visiongaia.gedefense.tv.core.report

import de.visiongaia.gedefense.tv.core.model.CapabilityState
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EvidenceHealth
import de.visiongaia.gedefense.tv.core.model.FeedSnapshot
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.InstalledApp
import de.visiongaia.gedefense.tv.core.model.InventoryDelta
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.PatchAssessment
import de.visiongaia.gedefense.tv.core.model.PlatformIdentity
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.PostureBand
import de.visiongaia.gedefense.tv.core.model.PostureScore
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.core.model.SecurityReport
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.TextCatalog
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import java.time.Instant
import java.time.format.DateTimeFormatter

/**
 * Default report renderer.
 *
 * Text output is a German plain-text report for the TV display and local file export. It resolves
 * every label and every model message through the supplied [TextCatalog] (the Android app passes
 * [de.visiongaia.gedefense.tv.core.text.DeCatalog]), states scope, limitations and data freshness,
 * labels partial/stale/unknown data and repeats the full score explanation.
 *
 * JSON output is locale-independent, deterministically ordered and machine readable: no localized
 * labels, canonical ISO-8601 UTC timestamps and enum names as stable identifiers.
 */
object DefaultReportRenderer : ReportRenderer {

    private const val JSON_SCHEMA = "gedefense-tv-report/1"

    private val LIMITATION_KEYS = listOf(
        "report.limit.nosystemwideflows",
        "report.limit.noprivilegedsensor",
        "report.limit.packagevisibility",
        "report.limit.patchnotvulnerability",
        "report.limit.nointegrity",
        "report.limit.localonly",
        "report.limit.observeonly",
    )

    private val JSON_SCOPE = listOf(
        "local_visible_data_only",
        "observe_only_v1",
        "no_telemetry_upload_v1",
    )

    private val JSON_LIMITATIONS = listOf(
        "package_visibility_may_restrict_app_inventory",
        "no_system_wide_flow_visibility",
        "no_privileged_endpoint_sensor",
        "build_fingerprint_is_not_integrity_proof",
        "patch_age_is_not_vulnerability_proof",
        "collector_coverage_may_be_unknown",
        "no_automated_enforcement",
    )

    // --- text report ---------------------------------------------------------------------------

    override fun renderText(report: SecurityReport, catalog: TextCatalog): String {
        val scan = report.scan
        val out = StringBuilder(4_096)

        fun t(key: String, vararg args: String): String = catalog.resolve(MessageRef(key, args.toList()))
        fun resolved(ref: MessageRef): String = catalog.resolve(ref)
        fun label(key: String, value: String) {
            out.append(t("report.line", t(key), value)).append('\n')
        }

        fun section(key: String) {
            out.append('\n').append(t(key)).append('\n')
        }

        out.append(t("report.title")).append('\n')
        out.append(t("report.subject")).append('\n')

        section("report.section.scope")
        out.append(t("report.scope.text")).append('\n')

        section("report.section.limitations")
        LIMITATION_KEYS.forEach { out.append("- ").append(t(it)).append('\n') }

        section("report.section.freshness")
        out.append(
            t(
                "report.freshness.text",
                utc(report.generatedAtMillis),
                utc(scan.completedAtMillis),
                resolved(scan.patch.summary),
            ),
        ).append('\n')

        section("report.section.metadata")
        label("report.label.reportid", report.reportId)
        label("report.label.generated", utc(report.generatedAtMillis))
        label("report.label.device", report.deviceId)
        label("report.label.scanid", scan.scanId)
        label("report.label.started", utc(scan.startedAtMillis))
        label("report.label.completed", utc(scan.completedAtMillis))
        label("report.label.scanstate", t("report.scanstate." + scan.state.name.lowercase()))
        label("report.label.platform", scan.platform.displayModel)
        label("report.label.android", scan.platform.androidRelease)
        label("report.label.api", scan.platform.sdkInt.toString())
        label("report.label.patch", resolved(scan.patch.summary))
        label("report.label.coverage", t("report.visibility." + visibilityKey(scan.coverage)))
        out.append(t(coverageKey(scan.coverage))).append('\n')

        section("report.section.posture")
        val bandLabel = t("score.band." + bandKey(scan.score.band))
        if (scan.score.value != null) {
            out.append(
                t("report.line", t("report.label.score"), t("report.score.value", scan.score.value.toString(), bandLabel)),
            ).append('\n')
        } else {
            out.append(
                t("report.line", t("report.label.score"), t("report.score.none", bandLabel)),
            ).append('\n')
        }
        label("report.label.band", bandLabel)
        scan.score.capReason?.let { label("report.label.capreason", resolved(it)) }
        out.append('\n').append(t("report.score.contributions")).append('\n')
        scan.score.contributions.forEach { contribution ->
            out.append("- ")
                .append(t("report.score.contribution", contribution.delta.toString(), resolved(contribution.message)))
                .append('\n')
        }

        section("report.section.collectors")
        scan.collectorResults.forEach { result ->
            out.append("- ")
                .append(
                    t(
                        "report.collector.line",
                        result.collectorId,
                        t("report.capability." + capabilityKey(result.capability)),
                        t("report.visibility." + visibilityKey(result.visibility)),
                        result.findings.size.toString(),
                    ),
                )
                .append('\n')
            result.errorKey?.let {
                out.append("  ").append(t("report.line", t("report.label.error"), resolved(it))).append('\n')
            }
        }

        section("report.section.findings")
        if (scan.findings.isEmpty()) {
            out.append(t("report.findings.none")).append('\n')
        } else {
            scan.findings.forEach { finding ->
                out.append(t("report.finding.header", t("report.severity." + finding.severity.name.lowercase()), resolved(finding.title)))
                    .append('\n')
                out.append("  ").append(t("report.finding.component", finding.component)).append('\n')
                out.append("  ").append(t("report.finding.why", resolved(finding.why))).append('\n')
                out.append("  ")
                    .append(t("report.finding.evidence", finding.evidence.source, utc(finding.evidence.collectedAtMillis)))
                    .append('\n')
                out.append("  ")
                    .append(t("report.finding.confidence", t("report.confidence." + finding.confidence.name.lowercase())))
                    .append('\n')
                out.append("  ")
                    .append(t("report.finding.visibility", t("report.visibility." + visibilityKey(finding.visibility))))
                    .append('\n')
                out.append("  ")
                    .append(t("report.finding.policy", t("report.policy." + policyKey(finding.policyAction))))
                    .append('\n')
                finding.recommendation?.let {
                    out.append("  ").append(t("report.finding.recommendation", resolved(it))).append('\n')
                }
                out.append('\n')
            }
        }

        section("report.section.inventory")
        val inventory = scan.inventory
        if (inventory == null) {
            out.append(t("report.inventory.unavailable")).append('\n')
        } else {
            label("report.label.coverage", t("report.visibility." + visibilityKey(inventory.visibility)))
            out.append(t("report.inventory.visible", inventory.apps.size.toString())).append('\n')
            if (inventory.packageVisibilityRestricted) {
                out.append(t("report.inventory.restricted")).append('\n')
            }
            val delta = scan.inventoryDelta
            if (delta.baselineAvailable) {
                out.append(
                    t(
                        "report.inventory.delta",
                        delta.newPackages.size.toString(),
                        delta.changedPackages.size.toString(),
                        delta.removedPackages.size.toString(),
                    ),
                ).append('\n')
            } else {
                out.append(t("report.inventory.nobaseline")).append('\n')
            }
        }

        section("report.section.threatintel")
        val threatIntel = report.threatIntel
        out.append(
            t(
                "report.threatintel.feeds",
                threatIntel.feeds.size.toString(),
                threatIntel.availableCount.toString(),
                threatIntel.freshCount.toString(),
                threatIntel.staleCount.toString(),
            ),
        ).append('\n')
        val lastSync = threatIntel.lastSyncMillis
        if (lastSync != null) {
            label("report.label.lastsync", utc(lastSync))
        } else {
            out.append(t("report.threatintel.never")).append('\n')
        }
        if (!threatIntel.syncHealthy) {
            out.append(t("report.threatintel.unhealthy")).append('\n')
        }
        threatIntel.note?.let { out.append(t("report.threatintel.note", resolved(it))).append('\n') }

        section("report.section.evidence")
        if (report.evidence.healthy) {
            out.append(t("report.evidence.healthy", report.evidence.records.toString())).append('\n')
        } else {
            val reason = report.evidence.reason?.let { resolved(it) } ?: t("report.value.never")
            out.append(t("report.evidence.unhealthy", reason)).append('\n')
        }

        out.append('\n').append(t("report.footer.disclaimer")).append('\n')
        return out.toString()
    }

    // --- JSON report ---------------------------------------------------------------------------

    override fun renderJson(report: SecurityReport): String {
        val scan = report.scan
        return obj(
            "schema" to str(JSON_SCHEMA),
            "report_id" to str(report.reportId),
            "generated_at_utc" to str(utc(report.generatedAtMillis)),
            "device_id" to str(report.deviceId),
            "scan" to obj(
                "scan_id" to str(scan.scanId),
                "started_at_utc" to str(utc(scan.startedAtMillis)),
                "completed_at_utc" to str(utc(scan.completedAtMillis)),
                "state" to str(scan.state.name),
                "coverage" to str(scan.coverage.name),
                "platform" to platformJson(scan.platform),
                "patch" to patchJson(scan.patch),
                "score" to scoreJson(scan.score),
                "collectors" to arr(scan.collectorResults.map(::collectorJson)),
                "findings" to arr(scan.findings.map(::findingJson)),
                "inventory" to (scan.inventory?.let(::inventoryJson) ?: "null"),
                "inventory_delta" to deltaJson(scan.inventoryDelta),
            ),
            "evidence" to evidenceJson(report.evidence),
            "threat_intel" to threatIntelJson(report.threatIntel),
            "scope" to arr(JSON_SCOPE.map(::str)),
            "limitations" to arr(JSON_LIMITATIONS.map(::str)),
        )
    }

    private fun platformJson(platform: PlatformIdentity): String = obj(
        "sdk_int" to platform.sdkInt.toString(),
        "android_release" to str(platform.androidRelease),
        "manufacturer" to str(platform.manufacturer),
        "model" to str(platform.model),
        "device" to str(platform.device),
        "fingerprint" to str(platform.fingerprint),
        "security_patch" to nullable(platform.securityPatch?.let(::str)),
        "build_time_utc" to nullable(platform.buildTimeMillis?.let { str(utc(it)) }),
        "abis" to arr(platform.supportedAbis.map(::str)),
        "app_version_name" to str(platform.appVersionName),
        "app_version_code" to platform.appVersionCode.toString(),
        "app_debuggable" to bool(platform.appDebuggable),
    )

    private fun patchJson(patch: PatchAssessment): String = obj(
        "status" to str(patch.status.name),
        "patch_date_utc" to nullable(patch.patchDateMillis?.let { str(utc(it)) }),
        "age_days" to nullable(patch.ageDays?.toString()),
        "summary" to str(patch.summary.key),
    )

    private fun scoreJson(score: PostureScore): String = obj(
        "value" to nullable(score.value?.toString()),
        "band" to str(score.band.name),
        "visibility" to str(score.visibility.name),
        "cap_reason" to nullable(score.capReason?.key?.let(::str)),
        "contributions" to arr(
            score.contributions.map { contribution ->
                obj(
                    "rule_id" to str(contribution.ruleId),
                    "delta" to contribution.delta.toString(),
                    "message" to str(contribution.message.key),
                )
            },
        ),
    )

    private fun collectorJson(result: CollectorResult): String = obj(
        "collector_id" to str(result.collectorId),
        "category" to str(result.category.name),
        "capability" to str(result.capability.name),
        "visibility" to str(result.visibility.name),
        "data_quality" to str(result.dataQuality.name),
        "started_at_utc" to str(utc(result.startedAtMillis)),
        "completed_at_utc" to str(utc(result.completedAtMillis)),
        "findings_count" to result.findings.size.toString(),
        "coverage" to (
            result.coverage?.let { coverage ->
                obj(
                    "observed" to coverage.observed.toString(),
                    "total" to nullable(coverage.total?.toString()),
                    "complete" to bool(coverage.complete),
                )
            } ?: "null"
            ),
        "error" to nullable(result.errorKey?.key?.let(::str)),
    )

    private fun findingJson(finding: Finding): String = obj(
        "id" to str(finding.id),
        "rule_id" to str(finding.ruleId),
        "severity" to str(finding.severity.name),
        "confidence" to str(finding.confidence.name),
        "category" to str(finding.category.name),
        "title" to str(finding.title.key),
        "why" to str(finding.why.key),
        "component" to str(finding.component),
        "evidence" to obj(
            "source" to str(finding.evidence.source),
            "collected_at_utc" to str(utc(finding.evidence.collectedAtMillis)),
            "digest" to nullable(finding.evidence.digest?.let(::str)),
        ),
        "recommendation" to nullable(finding.recommendation?.key?.let(::str)),
        "visibility" to str(finding.visibility.name),
        "first_seen_utc" to str(utc(finding.firstSeenMillis)),
        "last_seen_utc" to str(utc(finding.lastSeenMillis)),
        "policy_action" to str(finding.policyAction.name),
    )

    private fun inventoryJson(inventory: de.visiongaia.gedefense.tv.core.model.AppInventory): String = obj(
        "visibility" to str(inventory.visibility.name),
        "scanned_at_utc" to str(utc(inventory.scannedAtMillis)),
        "visible_apps" to inventory.apps.size.toString(),
        "package_visibility_restricted" to bool(inventory.packageVisibilityRestricted),
        "declared_query_packages" to inventory.declaredQueryPackages.toString(),
        "launcher_candidates" to inventory.launcherCandidates.toString(),
        "apps" to arr(inventory.apps.sortedBy { it.packageName }.map(::appJson)),
    )

    private fun appJson(app: InstalledApp): String = obj(
        "package" to str(app.packageName),
        "label" to str(app.label),
        "version_name" to nullable(app.versionName?.let(::str)),
        "version_code" to app.versionCode.toString(),
        "system" to bool(app.isSystemApp),
        "installer" to nullable(app.installerPackage?.let(::str)),
        "first_install_utc" to str(utc(app.firstInstallTimeMillis)),
        "last_update_utc" to str(utc(app.lastUpdateTimeMillis)),
        "signature_sha256" to arr(app.signatureSha256.sorted().map(::str)),
        "enabled" to bool(app.enabled),
    )

    private fun deltaJson(delta: InventoryDelta): String = obj(
        "baseline_available" to bool(delta.baselineAvailable),
        "baseline_at_utc" to nullable(delta.baselineAtMillis?.let { str(utc(it)) }),
        "new_packages" to arr(delta.newPackages.sorted().map(::str)),
        "changed_packages" to arr(delta.changedPackages.sorted().map(::str)),
        "removed_packages" to arr(delta.removedPackages.sorted().map(::str)),
    )

    private fun evidenceJson(evidence: EvidenceHealth): String = obj(
        "healthy" to bool(evidence.healthy),
        "records" to evidence.records.toString(),
        "reason" to nullable(evidence.reason?.key?.let(::str)),
    )

    private fun threatIntelJson(status: ThreatIntelStatus): String = obj(
        "feeds" to arr(status.feeds.sortedBy { it.id }.map(::feedJson)),
        "last_sync_utc" to nullable(status.lastSyncMillis?.let { str(utc(it)) }),
        "sync_healthy" to bool(status.syncHealthy),
        "available" to status.availableCount.toString(),
        "fresh" to status.freshCount.toString(),
        "stale" to status.staleCount.toString(),
        "note" to nullable(status.note?.key?.let(::str)),
    )

    private fun feedJson(feed: FeedSnapshot): String = obj(
        "id" to str(feed.id),
        "name" to str(feed.name),
        "available" to bool(feed.available),
        "fresh" to bool(feed.fresh),
        "records" to feed.records.toString(),
        "fetched_at_utc" to str(utc(feed.fetchedAtMillis)),
        "enforcement" to str(feed.enforcement),
    )

    // --- JSON building helpers -----------------------------------------------------------------

    private fun obj(vararg fields: Pair<String, String>): String =
        fields.joinToString(separator = ",", prefix = "{", postfix = "}") { (key, value) -> "${str(key)}:$value" }

    private fun arr(items: List<String>): String = items.joinToString(separator = ",", prefix = "[", postfix = "]")

    private fun str(value: String): String {
        val out = StringBuilder(value.length + 2)
        out.append('"')
        value.forEach { character ->
            when (character) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> {
                    val code = character.code
                    if (code < 0x20 || code == 0x7F) {
                        out.append("\\u").append(code.toString(16).padStart(4, '0'))
                    } else {
                        out.append(character)
                    }
                }
            }
        }
        out.append('"')
        return out.toString()
    }

    private fun nullable(raw: String?): String = raw ?: "null"

    private fun bool(value: Boolean): String = if (value) "true" else "false"

    private fun utc(millis: Long): String = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(millis))

    // --- model-to-key mapping ------------------------------------------------------------------

    private fun visibilityKey(visibility: DataVisibility): String = visibility.name.lowercase()

    private fun coverageKey(coverage: DataVisibility): String = when (coverage) {
        DataVisibility.FULL -> "report.coverage.full"
        DataVisibility.PARTIAL -> "report.coverage.partial"
        DataVisibility.STALE -> "report.coverage.stale"
        DataVisibility.NONE -> "report.coverage.none"
    }

    private fun capabilityKey(state: CapabilityState): String = when (state) {
        CapabilityState.SUPPORTED -> "supported"
        CapabilityState.PERMISSION_REQUIRED -> "permissionrequired"
        CapabilityState.UNSUPPORTED -> "unsupported"
        CapabilityState.FAILED -> "failed"
    }

    private fun bandKey(band: PostureBand): String = when (band) {
        PostureBand.STRONG -> "strong"
        PostureBand.MODERATE -> "moderate"
        PostureBand.WEAK -> "weak"
        PostureBand.UNKNOWN -> "unknown"
        PostureBand.INSUFFICIENT_COVERAGE -> "insufficientcoverage"
    }

    private fun policyKey(action: PolicyAction): String = when (action) {
        PolicyAction.NONE -> "none"
        PolicyAction.OBSERVE -> "observe"
        PolicyAction.RECOMMEND_MANUAL -> "recommendmanual"
        PolicyAction.ESCALATE_TO_USER -> "escalate"
    }
}
