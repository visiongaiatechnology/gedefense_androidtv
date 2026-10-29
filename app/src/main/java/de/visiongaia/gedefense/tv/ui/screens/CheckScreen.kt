package de.visiongaia.gedefense.tv.ui.screens

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.ScanListener
import de.visiongaia.gedefense.tv.contract.ScanSummary
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ScanProgress
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.RingGaugeView
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.SectionHeader
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.capabilityGlyph
import de.visiongaia.gedefense.tv.ui.components.capabilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.capabilityTone
import de.visiongaia.gedefense.tv.ui.components.categoryLabelRes
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.dataQualityLabelRes
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.scanStateGlyph
import de.visiongaia.gedefense.tv.ui.components.scanStateLabelRes
import de.visiongaia.gedefense.tv.ui.components.scanStateTone
import de.visiongaia.gedefense.tv.ui.components.severityGlyph
import de.visiongaia.gedefense.tv.ui.components.severityTone
import de.visiongaia.gedefense.tv.ui.components.toneColor
import de.visiongaia.gedefense.tv.ui.components.visibilityGlyph
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityTone

/**
 * TV System check screen — 2-column dashboard layout:
 * - Header: Standardized top action buttons [Prüfung starten / abbrechen] and [Befunde ansehen]
 * - Left column: Progress / status ring (82dp), state context, honest limitations
 * - Right column: 6 Collector checklist cards (Platform, Packages, Hardening, Network, TI, Evidence)
 */
internal class CheckScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.CHECK

    private var progressRing: RingGaugeView? = null
    private var progressCountView: TextView? = null
    private var progressCurrentView: TextView? = null
    private var progressFindingsView: TextView? = null
    private var listenerFailure: String? = null

    private val scanListener = object : ScanListener {
        override fun onProgress(progress: ScanProgress) {
            val ring = progressRing ?: return
            ring.post { applyProgress(progress) }
        }

        override fun onCompleted(result: ScanResult) {
            val view = scaffold
            view.post {
                listenerFailure = null
                notify(text(R.string.scan_state_completed))
                if (view.isAttachedToWindow) host.refreshCurrent()
            }
        }

        override fun onFailed(error: MessageRef) {
            val view = scaffold
            view.post {
                listenerFailure = resolve(error)
                if (view.isAttachedToWindow) {
                    notify(listenerFailure ?: text(R.string.check_failed_message))
                    host.refreshCurrent()
                }
            }
        }
    }

    override fun build(scaffold: ScreenScaffold) {
        val result = lastResult()
        val summary = if (result == null) lastSummary() else null
        val uiState = scanUiState()
        val running = uiState?.running == true

        scaffold.setEyebrow(text(R.string.check_eyebrow))
        scaffold.setTitle(text(R.string.check_title))

        if (running) {
            scaffold.addStatus(pill(TvGlyph.CLOCK, R.string.scan_state_running, TvTone.INFO))
        } else when {
            result != null -> scaffold.addStatus(
                pill(scanStateGlyph(result.state), scanStateLabelRes(result.state), scanStateTone(result.state)),
            )

            summary != null -> scaffold.addStatus(
                pill(scanStateGlyph(summary.state), scanStateLabelRes(summary.state), scanStateTone(summary.state)),
            )

            else -> scaffold.addStatus(pill(TvGlyph.QUESTION, R.string.scan_state_idle, TvTone.NEUTRAL))
        }
        val coverage = result?.coverage ?: summary?.coverage
        if (coverage != null) {
            scaffold.addStatus(
                pill(visibilityGlyph(coverage), visibilityLabelRes(coverage), visibilityTone(coverage)),
            )
        }

        // Header Actions: Clean buttons at the top-right
        if (running) {
            scaffold.addAction(
                dangerAction(R.string.action_cancel_check, TvGlyph.CROSS) { cancelScan() },
                primary = true,
            )
        } else {
            val labelRes = if (result == null) R.string.action_start_check else R.string.action_rerun_check
            scaffold.addAction(
                primaryAction(labelRes, TvGlyph.REFRESH) { startScan() },
                primary = true,
            )
        }
        if (result != null && result.findings.isNotEmpty()) {
            scaffold.addAction(
                secondaryAction(R.string.action_open_findings, TvGlyph.ALERT) { host.navigate(TvRoute.FINDINGS) },
            )
        }

        // Two-Column Layout: Left = Status & Ring, Right = Collector Checklist
        val twoColRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }

        // Left Column (36% width): Status Card, Ring, Context
        val leftCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.36f).apply {
                rightMargin = TvTheme.scaledDp(context, 14)
            }
        }

        leftCol.addView(buildStatusHead(result, summary, running), matchParams())

        when {
            running -> leftCol.addView(
                captionText(context, text(R.string.check_running_hint)),
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = TvTheme.scaledDp(context, 8) },
            )

            result != null -> {
                if (result.state == ScanState.FAILED) {
                    leftCol.addView(
                        noticePanel(TvGlyph.ALERT, TvTone.DANGER, text(R.string.check_failed_title), failureBody()),
                        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                            topMargin = TvTheme.scaledDp(context, 8)
                        },
                    )
                } else if (result.state == ScanState.CANCELLED) {
                    leftCol.addView(
                        noticePanel(TvGlyph.CROSS, TvTone.NEUTRAL, null, text(R.string.check_cancelled_note)),
                        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                            topMargin = TvTheme.scaledDp(context, 8)
                        },
                    )
                } else if (result.state == ScanState.PARTIAL) {
                    leftCol.addView(
                        noticePanel(TvGlyph.HALF, TvTone.WARNING, null, text(R.string.check_partial_note)),
                        LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                            topMargin = TvTheme.scaledDp(context, 8)
                        },
                    )
                }
            }

            summary != null -> leftCol.addView(
                noticePanel(TvGlyph.INFO, TvTone.NEUTRAL, null, text(R.string.home_summary_details_note)),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.scaledDp(context, 8)
                },
            )

            else -> {
                val empty = EmptyState(context, TvGlyph.SHIELD)
                empty.set(
                    TvGlyph.SHIELD,
                    text(R.string.empty_no_check_title),
                    text(R.string.empty_no_check_message),
                )
                leftCol.addView(
                    empty,
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                        topMargin = TvTheme.scaledDp(context, 8)
                    },
                )
            }
        }

        // Right Column (64% width): 6 Collector cards
        val rightCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.64f)
        }

        val collectorMeta = result?.let { TvFormat.collectorsCount(context, it.collectorResults.size) }
            ?: summary?.let { TvFormat.collectorsCount(context, it.collectorCount) }
        rightCol.addView(SectionHeader(context, text(R.string.check_section_collectors), collectorMeta))

        buildCollectorList(rightCol, result, summary != null)

        twoColRow.addView(leftCol)
        twoColRow.addView(rightCol)
        scaffold.content.addView(twoColRow)
    }

    // --------------------------------------------------------------- status head

    private fun buildStatusHead(result: ScanResult?, summary: ScanSummary?, running: Boolean): View {
        val head = GlassPanel(context)
        head.compact()
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
        }

        val uiScale = TvTheme.userScale.coerceAtLeast(0.1f)
        val ringDp = (82f / uiScale).toInt()
        val ring = RingGaugeView(context, ringDp)
        progressRing = ring
        row.addView(
            ring,
            LinearLayout.LayoutParams(TvTheme.dp(context, ringDp), TvTheme.dp(context, ringDp)).apply {
                rightMargin = TvTheme.scaledDp(context, 12)
            },
        )

        val column = column()
        val stateTitle = when {
            running -> text(R.string.scan_state_running)
            result != null -> text(scanStateLabelRes(result.state))
            summary != null -> text(scanStateLabelRes(summary.state))
            else -> text(R.string.scan_state_idle)
        }
        column.addView(
            TvTheme.textView(context, stateTitle, TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true).apply {
                maxLines = 2
                ellipsize = android.text.TextUtils.TruncateAt.END
            },
        )

        val count = TvTheme.textView(
            context,
            if (running) text(R.string.check_progress_unknown) else text(R.string.check_progress_idle),
            TvTheme.TEXT_MICRO_SP,
            TvTheme.textSecondary,
        )
        progressCountView = count
        column.addView(
            count,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 4)
            },
        )

        val current = captionText(context, "")
        current.visibility = View.GONE
        progressCurrentView = current
        column.addView(
            current,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 4)
            },
        )

        val findings = captionText(context, "")
        findings.visibility = View.GONE
        progressFindingsView = findings
        column.addView(
            findings,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 4)
            },
        )
        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        head.addView(row)

        val findingsCount = result?.findings?.size ?: summary?.findingsCount
        if (running) {
            val total = lastKnownTotal()
            if (total > 0) {
                ring.setProgress(
                    0f,
                    "0/$total",
                    text(R.string.check_ring_caption_collectors),
                    TvTheme.electricBlue,
                    TvTheme.goldBright,
                )
            } else {
                ring.setProgress(
                    null,
                    text(R.string.check_ring_unknown),
                    text(R.string.check_ring_caption_running),
                    TvTheme.electricBlue,
                    TvTheme.goldBright,
                )
            }
        } else if (findingsCount != null) {
            val tone = result?.let { toneColor(context, scanStateTone(it.state)) }
                ?: summary?.let { toneColor(context, scanStateTone(it.state)) }
                ?: TvTheme.accent
            ring.setProgress(1f, findingsCount.toString(), text(R.string.check_ring_caption_findings), tone, TvTheme.goldBright)
        } else {
            ring.setProgress(0f, text(R.string.value_dash), text(R.string.check_ring_caption_state), TvTheme.textSecondary, TvTheme.textSecondary)
        }
        return head
    }

    private fun lastKnownTotal(): Int = progressTotal

    @Volatile
    private var progressTotal: Int = 0

    private fun applyProgress(progress: ScanProgress) {
        if (progress.totalCollectors > 0) {
            progressTotal = progress.totalCollectors
            progressRing?.setProgress(
                progress.fraction,
                "${progress.completedCollectors}/${progress.totalCollectors}",
                text(R.string.check_ring_caption_collectors),
                TvTheme.electricBlue,
                TvTheme.goldBright,
            )
            progressCountView?.text = text(
                R.string.check_progress_count,
                progress.completedCollectors,
                progress.totalCollectors,
            )
        } else {
            progressRing?.setProgress(
                null,
                text(R.string.check_ring_unknown),
                text(R.string.check_ring_caption_running),
                TvTheme.electricBlue,
                TvTheme.goldBright,
            )
            progressCountView?.text = text(R.string.check_progress_unknown)
        }
        val current = resolve(progress.currentTitle) ?: progress.currentCollectorId
        if (current == null) {
            progressCurrentView?.visibility = View.GONE
        } else {
            progressCurrentView?.visibility = View.VISIBLE
            progressCurrentView?.text = text(R.string.check_progress_current, current)
        }
        progressFindingsView?.visibility = View.VISIBLE
        progressFindingsView?.text = text(R.string.check_progress_findings, progress.findingsSoFar)
    }

    private fun failureBody(): String {
        val extra = listenerFailure
        val base = text(R.string.check_failed_message)
        return if (extra.isNullOrBlank()) base else "$base\n$extra"
    }

    // -------------------------------------------------------------- collectors

    private fun buildCollectorList(container: LinearLayout, result: ScanResult?, summaryOnly: Boolean) {
        val collectors = result?.collectorResults.orEmpty()
        if (collectors.isEmpty()) {
            val pending = result == null && scanUiState()?.running == true
            val message = when {
                pending -> text(R.string.check_collectors_pending)
                summaryOnly -> text(R.string.check_collectors_after_restart)
                else -> text(R.string.check_no_collectors)
            }
            container.addView(bodyText(context, message))
            return
        }
        val panel = GlassPanel(context, soft = true).apply {
            compact()
        }
        for ((index, collector) in collectors.withIndex()) {
            val row = FocusableRow(context, interactive = false)
            row.setLeading(capabilityGlyph(collector.capability), toneColor(context, capabilityTone(collector.capability)))
            row.setTitle(text(categoryLabelRes(collector.category)))
            row.setSubtitle(collectorMeta(collector))
            val worstFinding = collector.findings.maxByOrNull { it.severity.rank }
            val findingsText = if (collector.findings.isEmpty()) {
                text(R.string.check_collector_no_findings)
            } else {
                TvFormat.collectorFindingsCount(context, collector.findings.size)
            }
            row.setTrailing(
                StatusPill(
                    context,
                    findingsText,
                    worstFinding?.let { severityTone(it.severity) } ?: TvTone.NEUTRAL,
                    worstFinding?.let { severityGlyph(it.severity) } ?: TvGlyph.DOT,
                ),
            )
            panel.addView(row, matchParams())
            if (index < collectors.size - 1) {
                panel.addView(
                    View(context).apply {
                        setBackgroundColor(android.graphics.Color.argb(30, 160, 190, 220))
                    },
                    LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        TvTheme.scaledDp(context, 1),
                    ).apply {
                        topMargin = TvTheme.scaledDp(context, 2)
                        bottomMargin = TvTheme.scaledDp(context, 2)
                    },
                )
            }
        }
        container.addView(panel, matchParams())
    }

    private fun collectorMeta(collector: de.visiongaia.gedefense.tv.core.model.CollectorResult): String {
        val capability = text(capabilityLabelRes(collector.capability))
        val visibility = text(visibilityLabelRes(collector.visibility))
        val quality = text(dataQualityLabelRes(collector.dataQuality))
        val meta = text(R.string.check_collector_meta, collector.collectorId, capability, visibility, quality)
        val coverage = collector.coverage
        val coverageText = when {
            coverage == null -> null
            coverage.total != null && coverage.total!! > 0 -> text(R.string.check_coverage, coverage.observed, coverage.total!!)
            else -> text(R.string.check_coverage_no_denominator, coverage.observed)
        }
        val errorText = readerError(collector.errorKey)
        return listOfNotNull(meta, coverageText, errorText).joinToString(" · ")
    }

    private fun readerError(errorKey: MessageRef?): String? {
        val resolved = resolve(errorKey) ?: return null
        return text(R.string.check_collector_error, resolved)
    }

    // ----------------------------------------------------------------- actions

    private fun startScan() {
        val started = readService { services.scan.start(scanListener) } ?: false
        if (started) {
            notify(text(R.string.check_started))
        } else {
            notify(text(R.string.check_already_running))
        }
        host.refreshCurrent()
    }

    private fun cancelScan() {
        val cancelled = readService { services.scan.cancel() } ?: false
        notify(if (cancelled) text(R.string.check_cancel_requested) else text(R.string.check_cancel_unavailable))
        host.refreshCurrent()
    }
}
