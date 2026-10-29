package de.visiongaia.gedefense.tv.ui.screens

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.ScanSummary
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.FindingRow
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.SectionHeader
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.scanStateGlyph
import de.visiongaia.gedefense.tv.ui.components.scanStateLabelRes
import de.visiongaia.gedefense.tv.ui.components.scanStateTone
import de.visiongaia.gedefense.tv.ui.components.visibilityGlyph
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityTone

/**
 * TV Findings list — 2-column dashboard layout:
 * - Header: Standardized top action button [Erneut prüfen]
 * - Left column: Severity breakdown card (Critical, High, Medium, Low), coverage notice, link to evidence
 * - Right column: Scrollable finding cards with immediate visibility of top findings
 */
internal class FindingsScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.FINDINGS

    private var firstFocusRow: View? = null
    private var lastFocusRow: View? = null

    private companion object {
        const val MAX_ROWS = 60
    }

    override fun build(scaffold: ScreenScaffold) {
        val result = lastResult()
        val summary = if (result == null) lastSummary() else null
        val findings = result?.findings.orEmpty()
        val coverage = result?.coverage ?: summary?.coverage ?: DataVisibility.NONE

        scaffold.setEyebrow(text(R.string.findings_eyebrow))
        scaffold.setTitle(text(R.string.findings_title))
        scaffold.setSubtitle(
            when {
                result != null && coverage == DataVisibility.FULL -> text(R.string.findings_subtitle_full)
                result != null -> text(R.string.findings_subtitle_partial)
                summary != null -> text(R.string.findings_summary_message)
                else -> text(R.string.findings_subtitle_partial)
            },
        )

        if (result != null) {
            scaffold.addStatus(
                pill(scanStateGlyph(result.state), scanStateLabelRes(result.state), scanStateTone(result.state)),
            )
            scaffold.addStatus(
                pill(visibilityGlyph(coverage), visibilityLabelRes(coverage), visibilityTone(coverage)),
            )
        } else if (summary != null) {
            scaffold.addStatus(
                pill(scanStateGlyph(summary.state), scanStateLabelRes(summary.state), scanStateTone(summary.state)),
            )
            scaffold.addStatus(
                pill(visibilityGlyph(summary.coverage), visibilityLabelRes(summary.coverage), visibilityTone(summary.coverage)),
            )
        }

        val labelRes = if (result == null && summary == null) R.string.action_start_check else R.string.action_rerun_check
        scaffold.addAction(
            primaryAction(labelRes, TvGlyph.REFRESH) { host.navigate(TvRoute.CHECK) },
            primary = true,
        )

        when {
            result == null && summary != null -> {
                val empty = EmptyState(context, TvGlyph.CLOCK)
                empty.set(
                    TvGlyph.CLOCK,
                    text(R.string.findings_summary_title),
                    text(R.string.findings_summary_message),
                    text(R.string.home_summary_details_note),
                )
                scaffold.content.addView(empty, matchParams())
            }

            result == null -> {
                val empty = EmptyState(context, TvGlyph.ALERT)
                empty.set(
                    TvGlyph.ALERT,
                    text(R.string.empty_no_check_title),
                    text(R.string.empty_no_check_message),
                )
                scaffold.content.addView(empty, matchParams())
            }

            findings.isEmpty() -> {
                val empty = EmptyState(context, TvGlyph.SHIELD)
                empty.set(
                    if (coverage == DataVisibility.FULL) TvGlyph.SHIELD else TvGlyph.EYE_OFF,
                    if (coverage == DataVisibility.FULL) {
                        text(R.string.empty_no_findings_full_title)
                    } else {
                        text(R.string.empty_no_findings_partial_title)
                    },
                    if (coverage == DataVisibility.FULL) {
                        text(R.string.empty_no_findings_full_message)
                    } else {
                        text(R.string.empty_no_findings_partial_message)
                    },
                    text(R.string.findings_visibility_note, text(visibilityLabelRes(coverage))),
                )
                scaffold.content.addView(empty, matchParams())
            }

            else -> {
                buildTwoColumnFindings(scaffold, findings, coverage)
            }
        }

        scaffold.linkFocusChain(firstFocusRow, lastFocusRow)
    }

    private fun buildTwoColumnFindings(
        scaffold: ScreenScaffold,
        findings: List<Finding>,
        coverage: DataVisibility,
    ) {
        val twoColRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }

        // Left Column (32% width): Severity Overview Card & Coverage Notice
        val leftCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.32f).apply {
                rightMargin = TvTheme.scaledDp(context, 14)
            }
        }

        val statCard = GlassPanel(context).apply {
            compact()
            addView(TvTheme.textView(context, findings.size.toString(), TvTheme.TEXT_SCORE_SP, TvTheme.warning, bold = true))
            addView(
                TvTheme.textView(context, text(R.string.findings_title).uppercase(), TvTheme.TEXT_MICRO_SP, TvTheme.textSecondary, bold = true).apply {
                    letterSpacing = 0.12f
                },
            )
            addView(
                captionText(context, severitySummary(findings.map { it.severity })),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.scaledDp(context, 4)
                },
            )
        }
        leftCol.addView(statCard, matchParams())

        if (coverage != DataVisibility.FULL) {
            val notice = noticePanel(
                TvGlyph.EYE_OFF,
                TvTone.WARNING,
                null,
                text(R.string.findings_visibility_note, text(visibilityLabelRes(coverage))),
            )
            leftCol.addView(
                notice,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.scaledDp(context, 8)
                },
            )
        }

        val viewEvidenceAction = FocusableAction.secondary(context, R.string.action_open_evidence, TvGlyph.EXPORT).apply {
            setOnClickListener { host.navigate(TvRoute.EVIDENCE) }
        }
        leftCol.addView(
            viewEvidenceAction,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 8)
            },
        )

        // Right Column (68% width): List of Findings
        val rightCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.68f)
        }

        rightCol.addView(
            SectionHeader(
                context,
                text(R.string.home_top_findings),
                TvFormat.findingsCount(context, findings.size),
            ),
        )

        for (finding in findings.take(MAX_ROWS)) {
            val row = FindingRow(context)
            row.bind(finding, services.catalog)
            row.setOnClickListener { host.navigate(TvRoute.FINDING_DETAIL, finding.id) }
            rightCol.addView(
                row,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    bottomMargin = TvTheme.scaledDp(context, 6)
                },
            )
            if (firstFocusRow == null) firstFocusRow = row
            lastFocusRow = row
        }

        if (findings.size > MAX_ROWS) {
            rightCol.addView(
                captionText(context, text(R.string.findings_limit_note, MAX_ROWS)),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.scaledDp(context, 6)
                },
            )
        }

        twoColRow.addView(leftCol)
        twoColRow.addView(rightCol)
        scaffold.content.addView(twoColRow)
    }

    private fun severitySummary(severities: List<Severity>): String {
        val high = severities.count { it == Severity.HIGH || it == Severity.CRITICAL }
        val medium = severities.count { it == Severity.MEDIUM }
        val low = severities.count { it == Severity.LOW || it == Severity.INFO }
        return text(R.string.findings_severity_summary, high, medium, low)
    }
}
