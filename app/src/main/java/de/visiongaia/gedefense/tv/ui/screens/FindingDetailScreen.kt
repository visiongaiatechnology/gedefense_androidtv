package de.visiongaia.gedefense.tv.ui.screens

import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.categoryLabelRes
import de.visiongaia.gedefense.tv.ui.components.confidenceLabelRes
import de.visiongaia.gedefense.tv.ui.components.confidenceTone
import de.visiongaia.gedefense.tv.ui.components.policyActionLabelRes
import de.visiongaia.gedefense.tv.ui.components.policyActionTone
import de.visiongaia.gedefense.tv.ui.components.severityGlyph
import de.visiongaia.gedefense.tv.ui.components.severityLabelRes
import de.visiongaia.gedefense.tv.ui.components.severityTone
import de.visiongaia.gedefense.tv.ui.components.visibilityGlyph
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityTone

/**
 * Finding detail: why it matters, affected component, evidence source/time, confidence, visibility
 * and the manual recommendation. Read-only by design - V1 never enforces anything automatically.
 */
internal class FindingDetailScreen(
    services: TvServices,
    private val findingId: String?,
) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.FINDING_DETAIL

    override fun build(scaffold: ScreenScaffold) {
        scaffold.setEyebrow(text(R.string.finding_detail_eyebrow))

        val result = lastResult()
        val finding = result?.findings?.firstOrNull { it.id == findingId }
        if (finding == null) {
            scaffold.setTitle(text(R.string.finding_detail_missing_title))
            scaffold.setSubtitle(text(R.string.finding_detail_missing_message))
            val empty = EmptyState(context, TvGlyph.QUESTION)
            empty.set(
                TvGlyph.QUESTION,
                text(R.string.finding_detail_missing_title),
                text(R.string.finding_detail_missing_message),
            )
            scaffold.content.addView(empty, matchParams())
            scaffold.addAction(
                primaryAction(R.string.action_back_to_list, TvGlyph.CHEVRON) { host.goBack() },
                primary = true,
            )
            scaffold.addAction(
                secondaryAction(R.string.action_rerun_check, TvGlyph.REFRESH) { host.navigate(TvRoute.CHECK) },
            )
            return
        }
        bindFinding(scaffold, finding)
    }

    private fun bindFinding(scaffold: ScreenScaffold, finding: Finding) {
        scaffold.setEyebrow(
            text(
                R.string.finding_detail_eyebrow_format,
                text(severityLabelRes(finding.severity)),
                text(categoryLabelRes(finding.category)),
            ),
        )
        scaffold.setTitle(resolve(finding.title) ?: finding.title.key)
        scaffold.setSubtitle(finding.component)

        scaffold.addStatus(pill(severityGlyph(finding.severity), severityLabelRes(finding.severity), severityTone(finding.severity)))
        scaffold.addStatus(
            pill(TvGlyph.HALF, confidenceLabelRes(finding.confidence), confidenceTone(finding.confidence)),
        )
        scaffold.addStatus(
            pill(visibilityGlyph(finding.visibility), visibilityLabelRes(finding.visibility), visibilityTone(finding.visibility)),
        )
        scaffold.addStatus(
            pill(TvGlyph.INFO, policyActionLabelRes(finding.policyAction), policyActionTone(finding.policyAction)),
        )

        scaffold.addSection(text(R.string.finding_detail_section_why))
        scaffold.content.addView(
            bodyText(context, resolve(finding.why) ?: finding.why.key, TvTheme.textSecondary),
            matchParams(),
        )

        scaffold.addSection(text(R.string.finding_detail_section_recommendation))
        val recommendation = resolve(finding.recommendation)
        scaffold.content.addView(
            bodyText(
                context,
                recommendation ?: text(R.string.finding_detail_no_recommendation),
                if (recommendation == null) TvTheme.textSecondary else TvTheme.textSecondary,
            ),
            matchParams(),
        )

        scaffold.addSection(text(R.string.finding_detail_section_evidence))
        val digest = finding.evidence.digest
        val rows = mutableListOf(
            infoRow(text(R.string.finding_detail_label_source), finding.evidence.source),
            infoRow(
                text(R.string.finding_detail_label_collected),
                TvFormat.dateTime(context, finding.evidence.collectedAtMillis),
            ),
            infoRow(
                text(R.string.finding_detail_label_digest),
                if (digest == null) {
                    text(R.string.finding_detail_digest_none)
                } else {
                    text(R.string.finding_detail_digest_short, digest.take(24))
                },
            ),
        )
        scaffold.content.addView(parameterPanel(*rows.toTypedArray()), matchParams())

        scaffold.addSection(text(R.string.finding_detail_section_meta))
        val metaRows = mutableListOf(
            infoRow(text(R.string.finding_detail_label_category), text(categoryLabelRes(finding.category))),
            infoRow(text(R.string.finding_detail_label_first_seen), TvFormat.dateTime(context, finding.firstSeenMillis)),
            infoRow(text(R.string.finding_detail_label_last_seen), TvFormat.dateTime(context, finding.lastSeenMillis)),
            infoRowPill(
                text(R.string.finding_detail_label_policy),
                pill(TvGlyph.INFO, policyActionLabelRes(finding.policyAction), policyActionTone(finding.policyAction)),
            ),
        )
        scaffold.content.addView(parameterPanel(*metaRows.toTypedArray()), matchParams())

        scaffold.addAction(
            primaryAction(R.string.action_back_to_list, TvGlyph.CHEVRON) { host.goBack() },
            primary = true,
        )
        val areaRoute = routeFor(finding.category)
        if (areaRoute != null) {
            scaffold.addAction(
                secondaryAction(R.string.action_open_area, TvGlyph.SHIELD) { host.navigate(areaRoute) },
            )
        }
    }

    private fun routeFor(category: CollectorCategory): TvRoute? = when (category) {
        CollectorCategory.PLATFORM -> TvRoute.CHECK
        CollectorCategory.APPS -> TvRoute.APPS
        CollectorCategory.HARDENING -> TvRoute.HARDENING
        CollectorCategory.THREAT_INTEL -> TvRoute.THREAT_INTEL
        CollectorCategory.CONNECTIVITY -> null
        CollectorCategory.SENSOR_HEALTH -> null
    }
}
