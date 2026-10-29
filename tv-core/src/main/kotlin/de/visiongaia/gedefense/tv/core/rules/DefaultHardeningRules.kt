package de.visiongaia.gedefense.tv.core.rules

import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EvidenceRef
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.HardeningObservations
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.Observed
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.Severity

/**
 * Default hardening rule engine.
 *
 * The engine is pure and deterministic: identical observations plus identical evidence always yield
 * the same findings in the same order. Rules follow the datasheet's hardening assistant:
 *
 *  - active risk indicators produce severity-graded findings with a manual recommendation;
 *  - unreadable platform values produce an explicit visibility finding and never a "secure" claim;
 *  - list-valued observations are deduplicated and sorted so input order cannot change the result.
 */
object DefaultHardeningRules : HardeningRuleEvaluator {

    override fun evaluate(observations: HardeningObservations, evidence: EvidenceRef): List<Finding> {
        val findings = mutableListOf<Finding>()
        val seenAt = observations.collectedAtMillis

        fun add(
            ruleId: String,
            severity: Severity,
            confidence: Confidence,
            component: String,
            titleKey: String,
            whyKey: String,
            recommendationKey: String,
            titleArgs: List<String> = emptyList(),
            visibility: DataVisibility = DataVisibility.FULL,
            action: PolicyAction = PolicyAction.RECOMMEND_MANUAL,
        ) {
            val safeComponent = component.trim().take(160).ifEmpty { "unknown" }
            findings += Finding(
                id = Finding.identity(ruleId, safeComponent),
                ruleId = ruleId,
                severity = severity,
                confidence = confidence,
                category = CollectorCategory.HARDENING,
                title = MessageRef(titleKey, titleArgs),
                why = MessageRef(whyKey),
                component = safeComponent,
                evidence = evidence,
                recommendation = MessageRef(recommendationKey),
                visibility = visibility,
                firstSeenMillis = seenAt,
                lastSeenMillis = seenAt,
                policyAction = action,
            )
        }

        fun evaluateFlag(
            flag: Observed<Boolean>,
            ruleId: String,
            component: String,
            severity: Severity,
            enabledTitle: String,
            enabledWhy: String,
            enabledRecommendation: String,
            unknownTitle: String,
            unknownWhy: String,
            unknownRecommendation: String,
        ) {
            if (!flag.readable) {
                add(
                    ruleId = "$ruleId-unreadable",
                    severity = Severity.INFO,
                    confidence = Confidence.LOW,
                    component = component,
                    titleKey = unknownTitle,
                    whyKey = unknownWhy,
                    recommendationKey = unknownRecommendation,
                    visibility = DataVisibility.NONE,
                    action = PolicyAction.OBSERVE,
                )
            } else if (flag.value == true) {
                add(
                    ruleId = ruleId,
                    severity = severity,
                    confidence = Confidence.HIGH,
                    component = component,
                    titleKey = enabledTitle,
                    whyKey = enabledWhy,
                    recommendationKey = enabledRecommendation,
                )
            }
        }

        evaluateFlag(
            flag = observations.adbEnabled,
            ruleId = "hardening-adb",
            component = "adb",
            severity = Severity.HIGH,
            enabledTitle = "hardening.adb.enabled.title",
            enabledWhy = "hardening.adb.enabled.why",
            enabledRecommendation = "hardening.adb.enabled.recommendation",
            unknownTitle = "hardening.adb.unknown.title",
            unknownWhy = "hardening.adb.unknown.why",
            unknownRecommendation = "hardening.adb.unknown.recommendation",
        )

        evaluateFlag(
            flag = observations.developerOptionsEnabled,
            ruleId = "hardening-devoptions",
            component = "developer-options",
            severity = Severity.MEDIUM,
            enabledTitle = "hardening.devoptions.enabled.title",
            enabledWhy = "hardening.devoptions.enabled.why",
            enabledRecommendation = "hardening.devoptions.enabled.recommendation",
            unknownTitle = "hardening.devoptions.unknown.title",
            unknownWhy = "hardening.devoptions.unknown.why",
            unknownRecommendation = "hardening.devoptions.unknown.recommendation",
        )

        evaluateFlag(
            flag = observations.ownAppCanInstallUnknownApps,
            ruleId = "hardening-unknownsources",
            component = "own-app-install-unknown",
            severity = Severity.HIGH,
            enabledTitle = "hardening.unknownsources.enabled.title",
            enabledWhy = "hardening.unknownsources.enabled.why",
            enabledRecommendation = "hardening.unknownsources.enabled.recommendation",
            unknownTitle = "hardening.unknownsources.unknown.title",
            unknownWhy = "hardening.unknownsources.unknown.why",
            unknownRecommendation = "hardening.unknownsources.unknown.recommendation",
        )

        if (observations.testKeysBuild) {
            add(
                ruleId = "hardening-testkeys",
                severity = Severity.HIGH,
                confidence = Confidence.HIGH,
                component = "build",
                titleKey = "hardening.testkeys.detected.title",
                whyKey = "hardening.testkeys.detected.why",
                recommendationKey = "hardening.testkeys.detected.recommendation",
            )
        }

        observations.activeDeviceAdminPackages
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .sorted()
            .forEach { adminPackage ->
                add(
                    ruleId = "hardening-deviceadmin",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.MEDIUM,
                    component = adminPackage,
                    titleKey = "hardening.deviceadmin.detected.title",
                    whyKey = "hardening.deviceadmin.detected.why",
                    recommendationKey = "hardening.deviceadmin.detected.recommendation",
                    titleArgs = listOf(adminPackage),
                )
            }

        observations.accessibilityEnabledServices
            .asSequence()
            .filter { service ->
                !service.isSystemPackage && service.packageName !in observations.accessibilityKnownSystemPackages
            }
            .distinctBy { it.packageName }
            .sortedBy { it.packageName }
            .forEach { service ->
                add(
                    ruleId = "hardening-accessibility",
                    severity = Severity.HIGH,
                    confidence = Confidence.MEDIUM,
                    component = service.packageName,
                    titleKey = "hardening.accessibility.detected.title",
                    whyKey = "hardening.accessibility.detected.why",
                    recommendationKey = "hardening.accessibility.detected.recommendation",
                    titleArgs = listOf(service.packageName),
                )
            }

        observations.visibleNonStoreInstallers
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .sorted()
            .forEach { installer ->
                add(
                    ruleId = "hardening-installer",
                    severity = Severity.LOW,
                    confidence = Confidence.MEDIUM,
                    component = installer,
                    titleKey = "hardening.installer.detected.title",
                    whyKey = "hardening.installer.detected.why",
                    recommendationKey = "hardening.installer.detected.recommendation",
                    titleArgs = listOf(installer),
                )
            }

        return findings.sortedWith(
            compareByDescending<Finding> { it.severity.rank }.thenBy { it.id },
        )
    }
}
