package de.visiongaia.gedefense.tv.ui.screens

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.EvidenceRow
import de.visiongaia.gedefense.tv.contract.ExportResult
import de.visiongaia.gedefense.tv.core.model.EvidenceHealth
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.eventClassLabelResOrNull
import de.visiongaia.gedefense.tv.ui.components.findHostActivity
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.severityGlyph
import de.visiongaia.gedefense.tv.ui.components.severityLabelRes
import de.visiongaia.gedefense.tv.ui.components.severityLabelResOrNull
import de.visiongaia.gedefense.tv.ui.components.severityTone
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * Evidence and report screen.
 *
 * Shows the tamper-evident ledger health and the latest local events, exports the report through the
 * platform document picker (SAF) and deletes local evidence only after an explicit two-step D-pad
 * confirmation.
 */
internal class EvidenceScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.EVIDENCE

    private var firstFocusRow: View? = null
    private var lastFocusRow: View? = null

    private companion object {
        const val MAX_EVENTS = 50
    }

    private var confirmPanel: GlassPanel? = null
    private var deleteAction: FocusableAction? = null
    private var confirmCancel: FocusableAction? = null
    private var exportAction: FocusableAction? = null
    private var exportStatusView: TextView? = null
    private var lastExportMessage: String? = null

    override fun build(scaffold: ScreenScaffold) {
        val health = readService { services.evidence.health() } ?: EvidenceHealth.UNAVAILABLE
        val events = readService { services.evidence.rows(MAX_EVENTS) } ?: emptyList()
        val result = lastResult()

        scaffold.setEyebrow(text(R.string.evidence_eyebrow))
        scaffold.setTitle(text(R.string.evidence_title))
        scaffold.setSubtitle(text(R.string.evidence_subtitle))

        if (health.healthy) {
            scaffold.addStatus(pill(TvGlyph.CHECK, R.string.evidence_health_ok, TvTone.SUCCESS))
        } else {
            scaffold.addStatus(pill(TvGlyph.ALERT, R.string.evidence_health_bad, TvTone.DANGER))
        }
        scaffold.addStatus(
            StatusPill(
                context,
                TvFormat.evidenceRecordsCount(context, health.records),
                TvTone.NEUTRAL,
                TvGlyph.INFO,
            ),
        )

        val confirm = buildConfirmPanel()
        confirmPanel = confirm
        scaffold.content.addView(confirm, matchParams())
        confirm.visibility = View.GONE

        scaffold.content.addView(buildHealthPanel(health), matchParams())
        scaffold.content.addView(
            captionText(context, text(R.string.evidence_ledger_note)),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 10)
            },
        )

        val exportStatus = captionText(context, lastExportMessage.orEmpty(), TvTheme.textSecondary)
        exportStatus.visibility = if (lastExportMessage == null) View.GONE else View.VISIBLE
        exportStatusView = exportStatus
        scaffold.content.addView(
            exportStatus,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 12)
            },
        )

        if (result == null) {
            scaffold.content.addView(
                noticePanel(TvGlyph.INFO, TvTone.NEUTRAL, null, text(R.string.evidence_export_needs_scan)),
                matchParams(),
            )
        }

        scaffold.addSection(text(R.string.evidence_section_events), TvFormat.eventsCount(context, events.size))
        if (events.isEmpty()) {
            val empty = EmptyState(context, TvGlyph.SHIELD)
            empty.set(
                TvGlyph.SHIELD,
                text(R.string.evidence_no_events_title),
                text(R.string.evidence_no_events_message),
            )
            scaffold.content.addView(empty, matchParams())
        } else {
            for (event in events) {
                val row = buildEventRow(event)
                scaffold.content.addView(row, matchParams())
                if (firstFocusRow == null) firstFocusRow = row
                lastFocusRow = row
            }
            if (events.size >= MAX_EVENTS) {
                scaffold.addFullWidth(captionText(context, text(R.string.evidence_events_limit, MAX_EVENTS)))
            }
        }

        val export = primaryAction(R.string.action_export_report, TvGlyph.EXPORT) { exportReport() }
        exportAction = export
        scaffold.addAction(export, primary = true)
        val delete = dangerAction(R.string.action_delete_evidence, TvGlyph.TRASH) { showDeleteConfirmation() }
        deleteAction = delete
        scaffold.addAction(delete)
        scaffold.linkFocusChain(firstFocusRow, lastFocusRow)
    }

    // ------------------------------------------------------------------ health

    private fun buildHealthPanel(health: EvidenceHealth): View {
        val panel = GlassPanel(context, soft = true)
        panel.compact()
        panel.addView(
            infoRowPill(
                text(R.string.label_state),
                if (health.healthy) {
                    pill(TvGlyph.CHECK, R.string.evidence_health_ok, TvTone.SUCCESS)
                } else {
                    pill(TvGlyph.ALERT, R.string.evidence_health_bad, TvTone.DANGER)
                },
            ),
        )
        panel.addView(infoRow(text(R.string.evidence_records_label), TvFormat.evidenceRecordsCount(context, health.records)))
        val reason = resolve(health.reason)
        if (reason != null) {
            panel.addView(captionText(context, text(R.string.evidence_health_reason, reason), TvTheme.textSecondary))
        }
        return panel
    }

    // ------------------------------------------------------------------ events

    private fun buildEventRow(event: EvidenceRow): FocusableRow {
        val row = FocusableRow(context, interactive = false)
        val severity = runCatching { Severity.valueOf(event.severity) }.getOrNull()
        val tone = severity?.let { severityTone(it) } ?: TvTone.NEUTRAL
        row.setLeading(severity?.let { severityGlyph(it) } ?: TvGlyph.DOT, toneColor(context, tone))
        row.setTitle(event.subject)
        val typeLabel = eventClassLabelResOrNull(event.type)?.let { text(it) } ?: event.type
        val severityLabel = severityLabelResOrNull(event.severity)?.let { text(it) }
            ?: event.severity.ifBlank { text(R.string.evidence_severity_none) }
        row.setSubtitle(text(R.string.evidence_row_meta, typeLabel, severityLabel))
        row.setTrailing(captionText(context, TvFormat.relative(context, event.atMillis)))
        return row
    }

    // --------------------------------------------------------------- confirm step

    private fun buildConfirmPanel(): GlassPanel {
        val panel = GlassPanel(context)
        panel.addView(
            TvTheme.textView(
                context,
                text(R.string.evidence_confirm_title),
                TvTheme.TEXT_HEADING_SP,
                TvTheme.danger,
                bold = true,
            ),
        )
        panel.addView(
            bodyText(context, text(R.string.evidence_confirm_body)),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 10)
            },
        )
        val actions = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val cancel = secondaryAction(R.string.action_cancel, null) { hideDeleteConfirmation() }
        confirmCancel = cancel
        val confirm = dangerAction(R.string.action_confirm_delete, TvGlyph.TRASH) { deleteEvidence() }
        actions.addView(cancel)
        actions.addView(
            confirm,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                leftMargin = TvTheme.scaledDp(context, 16)
            },
        )
        panel.addView(
            actions,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 18)
            },
        )
        return panel
    }

    private fun showDeleteConfirmation() {
        val panel = confirmPanel ?: return
        panel.visibility = View.VISIBLE
        notify(text(R.string.evidence_confirm_title))
        panel.post { confirmCancel?.requestFocus() }
    }

    private fun hideDeleteConfirmation() {
        confirmPanel?.visibility = View.GONE
        val delete = deleteAction
        if (delete != null) {
            delete.post { delete.requestFocus() }
        }
    }

    private fun deleteEvidence() {
        val rows = readService { services.evidence.rows(1) }.orEmpty()
        if (rows.isEmpty()) {
            hideDeleteConfirmation()
            notify(text(R.string.evidence_delete_empty))
            return
        }
        val cleared = readService { services.evidence.clear() } ?: false
        hideDeleteConfirmation()
        notify(text(if (cleared) R.string.evidence_delete_ok else R.string.evidence_delete_failed))
        refreshIfVisible()
    }

    // ------------------------------------------------------------------ export

    private fun exportReport() {
        val result = lastResult()
        if (result == null) {
            showExportMessage(text(R.string.evidence_export_needs_scan))
            return
        }
        val report = readService { services.reports.build(result) }
        if (report == null) {
            showExportMessage(text(R.string.evidence_export_failed))
            return
        }
        val activity = context.findHostActivity()
        if (activity == null) {
            showExportMessage(text(R.string.evidence_export_unavailable))
            return
        }
        val started = readService {
            services.reports.export(report, activity) { exportResult -> handleExportResult(exportResult) }
        } ?: false
        if (!started) {
            showExportMessage(text(R.string.evidence_export_failed))
        } else {
            showExportMessage(text(R.string.evidence_export_started))
        }
    }

    private fun handleExportResult(result: ExportResult) {
        if (!scaffoldReady()) return
        scaffold.post {
            val message = if (result.ok) {
                text(R.string.evidence_export_ok, result.fileName ?: text(R.string.value_unknown))
            } else {
                resolve(result.message) ?: text(R.string.evidence_export_failed)
            }
            showExportMessage(message)
        }
    }

    private fun showExportMessage(message: String) {
        lastExportMessage = message
        val view = exportStatusView
        if (view != null) {
            view.text = message
            view.visibility = View.VISIBLE
        }
        notify(message)
    }
}
