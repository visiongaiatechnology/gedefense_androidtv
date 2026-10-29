package de.visiongaia.gedefense.tv.ui.screens

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.model.CapabilityState
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.FindingRow
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.addSpacer
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.capabilityGlyph
import de.visiongaia.gedefense.tv.ui.components.capabilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.capabilityTone
import de.visiongaia.gedefense.tv.ui.components.severityGlyph
import de.visiongaia.gedefense.tv.ui.components.severityLabelRes
import de.visiongaia.gedefense.tv.ui.components.severityTone
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * Hardening assistant (2026 redesign): checklist cards with explicit status.
 *
 * Status is derived from the hardening findings of the last scan (stable rule ids) plus the
 * collector capability. Unreadable values are "Nicht prüfbar"; the absence of a finding is
 * explicitly not presented as a secure setting. After a restart the detail states are gone and the
 * screen says so instead of inventing checks.
 */
internal class HardeningScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.HARDENING

    private var firstFocusRow: View? = null
    private var lastFocusRow: View? = null

    private data class HardeningCheck(
        val titleRes: Int,
        val guidanceRes: Int,
        val ruleKeywords: List<String>,
    )

    private val checks = listOf(
        HardeningCheck(R.string.hardening_check_adb_title, R.string.hardening_check_adb_guidance, listOf("adb", "debug")),
        HardeningCheck(
            R.string.hardening_check_developer_title,
            R.string.hardening_check_developer_guidance,
            listOf("developer", "devoption"),
        ),
        HardeningCheck(
            R.string.hardening_check_unknown_sources_title,
            R.string.hardening_check_unknown_sources_guidance,
            listOf("unknown-source", "unknown_source", "unknownsources", "unknown-sources", "sideload"),
        ),
        HardeningCheck(
            R.string.hardening_check_test_keys_title,
            R.string.hardening_check_test_keys_guidance,
            listOf("test-key", "testkey", "userdebug", "debug-build", "build-type"),
        ),
        HardeningCheck(
            R.string.hardening_check_device_admin_title,
            R.string.hardening_check_device_admin_guidance,
            listOf("device-admin", "deviceadmin", "admin"),
        ),
        HardeningCheck(
            R.string.hardening_check_accessibility_title,
            R.string.hardening_check_accessibility_guidance,
            listOf("accessibility", "a11y"),
        ),
        HardeningCheck(
            R.string.hardening_check_installers_title,
            R.string.hardening_check_installers_guidance,
            listOf("installer"),
        ),
    )

    override fun build(scaffold: ScreenScaffold) {
        val result = lastResult()
        val summary = if (result == null) lastSummary() else null
        val hardeningFindings = result?.findingsFor(CollectorCategory.HARDENING).orEmpty()
        val collectors = result?.collectorResults?.filter { it.category == CollectorCategory.HARDENING }.orEmpty()

        scaffold.setEyebrow(text(R.string.hardening_eyebrow))
        scaffold.setTitle(text(R.string.hardening_title))
        scaffold.setSubtitle(text(R.string.hardening_subtitle))

        if (collectors.isNotEmpty()) {
            val capability = aggregateCapability(collectors)
            scaffold.addStatus(pill(capabilityGlyph(capability), capabilityLabelRes(capability), capabilityTone(capability)))
            scaffold.addStatus(
                StatusPill(
                    context,
                    TvFormat.findingsCount(context, hardeningFindings.size),
                    TvTone.NEUTRAL,
                    TvGlyph.ALERT,
                ),
            )
        } else if (summary != null) {
            scaffold.addStatus(pill(scanStateSummaryGlyph(summary), scanStateSummaryLabel(summary), TvTone.NEUTRAL))
        } else {
            scaffold.addStatus(pill(TvGlyph.QUESTION, R.string.hardening_check_not_readable, TvTone.NEUTRAL))
        }

        if (result == null) {
            val empty = EmptyState(context, TvGlyph.LOCK)
            if (summary != null) {
                empty.set(
                    TvGlyph.LOCK,
                    text(R.string.hardening_summary_empty_title),
                    text(R.string.hardening_summary_empty_message),
                )
            } else {
                empty.set(
                    TvGlyph.LOCK,
                    text(R.string.empty_no_check_title),
                    text(R.string.empty_no_check_message),
                    text(R.string.hardening_no_collector),
                )
            }
            scaffold.content.addView(empty, matchParams())
        } else {
            scaffold.addSection(text(R.string.hardening_section_checks))
            buildCheckList(scaffold, hardeningFindings, collectors)
            scaffold.addFullWidth(bodyText(context, text(R.string.hardening_note_absence), TvTheme.textSecondary))
            if (hardeningFindings.isNotEmpty()) {
                scaffold.addSection(
                    text(R.string.hardening_section_findings),
                    TvFormat.findingsCount(context, hardeningFindings.size),
                )
                for (finding in hardeningFindings) {
                    val row = FindingRow(context)
                    row.bind(finding, services.catalog)
                    row.setOnClickListener { host.navigate(TvRoute.FINDING_DETAIL, finding.id) }
                    scaffold.content.addView(row, matchParams())
                    if (firstFocusRow == null) firstFocusRow = row
                    lastFocusRow = row
                    scaffold.content.addSpacer(10)
                }
            }
        }

        val labelRes = if (result == null && summary != null) {
            R.string.action_rerun_check
        } else if (result == null) {
            R.string.action_start_check
        } else {
            R.string.action_rerun_check
        }
        scaffold.addAction(
            primaryAction(labelRes, TvGlyph.REFRESH) { host.navigate(TvRoute.CHECK) },
            primary = true,
        )
        if (result != null) {
            scaffold.addAction(
                secondaryAction(R.string.action_open_findings, TvGlyph.ALERT) { host.navigate(TvRoute.FINDINGS) },
            )
        }
        scaffold.linkFocusChain(firstFocusRow, lastFocusRow)
    }

    private fun scanStateSummaryGlyph(summary: de.visiongaia.gedefense.tv.contract.ScanSummary) =
        de.visiongaia.gedefense.tv.ui.components.scanStateGlyph(summary.state)

    private fun scanStateSummaryLabel(summary: de.visiongaia.gedefense.tv.contract.ScanSummary): Int =
        de.visiongaia.gedefense.tv.ui.components.scanStateLabelRes(summary.state)

    private fun buildCheckList(
        scaffold: ScreenScaffold,
        findings: List<Finding>,
        collectors: List<CollectorResult>,
    ) {
        val readable = collectors.any { it.capability == CapabilityState.SUPPORTED && it.visibility != DataVisibility.NONE }
        for (check in checks) {
            val matched = findings
                .filter { finding ->
                    check.ruleKeywords.any { keyword -> finding.ruleId.contains(keyword, ignoreCase = true) }
                }
                .maxByOrNull { it.severity.rank }

            val row = FocusableRow(context, interactive = matched != null)
            row.setCard(true)
            val title = text(check.titleRes)
            row.setTitle(title)
            row.setSubtitle(text(R.string.hardening_manual_step, text(check.guidanceRes)))

            if (matched != null) {
                val tone = severityTone(matched.severity)
                row.setLeading(severityGlyph(matched.severity), toneColor(context, tone))
                row.setTrailing(
                    StatusPill(
                        context,
                        text(R.string.hardening_check_finding, text(severityLabelRes(matched.severity))),
                        tone,
                        severityGlyph(matched.severity),
                    ),
                )
                row.setChevronVisible(true)
                row.contentDescription = "$title: ${text(severityLabelRes(matched.severity))}"
                val findingId = matched.id
                row.setOnClickListener { host.navigate(TvRoute.FINDING_DETAIL, findingId) }
            } else if (!readable) {
                row.setLeading(TvGlyph.QUESTION, toneColor(context, TvTone.NEUTRAL))
                row.setTrailing(
                    StatusPill(context, text(R.string.hardening_check_not_readable), TvTone.NEUTRAL, TvGlyph.QUESTION),
                )
            } else {
                row.setLeading(TvGlyph.DOT, toneColor(context, TvTone.NEUTRAL))
                row.setTrailing(
                    StatusPill(context, text(R.string.hardening_check_no_finding), TvTone.NEUTRAL, TvGlyph.DOT),
                )
            }
            scaffold.content.addView(
                row,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
            )
            if (firstFocusRow == null) firstFocusRow = row
            lastFocusRow = row
            scaffold.content.addSpacer(10)
        }
    }

    /** Worst capability wins: a failed or permission-bound collector must not look supported. */
    private fun aggregateCapability(collectors: List<CollectorResult>): CapabilityState {
        val order = listOf(
            CapabilityState.FAILED,
            CapabilityState.PERMISSION_REQUIRED,
            CapabilityState.UNSUPPORTED,
            CapabilityState.SUPPORTED,
        )
        return order.firstOrNull { candidate -> collectors.any { it.capability == candidate } }
            ?: CapabilityState.UNSUPPORTED
    }
}
