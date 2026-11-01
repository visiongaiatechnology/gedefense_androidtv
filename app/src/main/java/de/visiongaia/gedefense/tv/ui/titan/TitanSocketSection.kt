package de.visiongaia.gedefense.tv.ui.titan

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.titan.model.SocketObservation
import de.visiongaia.gedefense.tv.core.titan.model.SocketRisk
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionTarget
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanScanOutcome
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.addSpacer
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.severityLabelRes
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * Socket radar section of the Titan screen.
 *
 * Shows only what the last provenance pass actually observed. A missing observation list is explained
 * with its real cause (no elevated channel, guard disabled, no pass yet, live rows not persisted) and
 * never rendered as a clean result. Containment controls appear only for conspicuous rows, only with
 * the matching effective capability, and always behind the confirmation step of the screen.
 */
internal object TitanSocketSection {

    private const val MAX_ROWS = 6

    fun build(
        container: LinearLayout,
        status: TitanStatus,
        socketGuardEnabled: Boolean,
        onScan: () -> Unit,
        onFreeze: (SocketObservation) -> Unit,
        onIsolate: (SocketObservation) -> Unit,
    ): List<View> {
        val context = container.context
        val snapshot = status.sockets
        val meta = snapshot?.let { context.getString(R.string.titan_socket_meta, it.totalSockets, it.suspiciousCount) }
        TitanLayout.addSection(container, context.getString(R.string.titan_socket_section), meta)

        if (snapshot == null) {
            val reasonRes = when {
                !status.has(TitanCapability.SOCKET_PROVENANCE) -> R.string.titan_socket_empty_unavailable
                !socketGuardEnabled -> R.string.titan_socket_empty_guard
                status.lastScanOutcome == TitanScanOutcome.NEVER -> R.string.titan_empty_never
                else -> R.string.titan_empty_restart
            }
            val action = TitanLayout.addEmptyState(
                container,
                TvGlyph.EYE_OFF,
                context.getString(R.string.titan_socket_empty_title),
                context.getString(reasonRes),
                actionLabelRes = R.string.titan_action_start_check,
                onAction = onScan,
            )
            return listOfNotNull(action)
        }

        TitanLayout.addMetricRow(
            container,
            listOf(
                TitanMetric(
                    TvGlyph.EYE,
                    TvTone.INFO,
                    snapshot.totalSockets.toString(),
                    context.getString(R.string.titan_socket_metric_connections),
                ),
                TitanMetric(
                    TvGlyph.CHECK,
                    TvTone.SUCCESS,
                    snapshot.attributableSockets.toString(),
                    context.getString(R.string.titan_socket_metric_attributed),
                ),
                TitanMetric(
                    TvGlyph.ALERT,
                    if (snapshot.suspiciousCount > 0) TvTone.WARNING else TvTone.NEUTRAL,
                    snapshot.suspiciousCount.toString(),
                    context.getString(R.string.titan_socket_metric_suspicious),
                ),
            ),
        )
        TitanLayout.addCaption(
            container,
            context.getString(R.string.titan_captured, TvFormat.relative(context, snapshot.capturedAtMillis)),
            topDp = 6,
        )

        if (snapshot.observations.isEmpty()) {
            TitanLayout.addBody(container, context.getString(R.string.titan_socket_none_title), topDp = 10)
            TitanLayout.addCaption(container, context.getString(R.string.titan_socket_none_note), topDp = 4)
            val action = TitanLayout.addScanAction(container, R.string.titan_action_start_check, onScan)
            return listOf(action)
        }

        val focusables = mutableListOf<View>()
        for (observation in snapshot.observations.take(MAX_ROWS)) {
            focusables += observationRow(container, status, observation, onFreeze, onIsolate)
        }
        if (snapshot.observations.size > MAX_ROWS) {
            TitanLayout.addCaption(
                container,
                context.getString(R.string.titan_socket_truncated, snapshot.observations.size - MAX_ROWS),
                topDp = 2,
            )
        }
        TitanLayout.addCaption(container, context.getString(R.string.titan_socket_none_note), topDp = 4)
        return focusables
    }

    private fun observationRow(
        container: LinearLayout,
        status: TitanStatus,
        observation: SocketObservation,
        onFreeze: (SocketObservation) -> Unit,
        onIsolate: (SocketObservation) -> Unit,
    ): List<View> {
        val context = container.context
        val focusables = mutableListOf<View>()
        val row = FocusableRow(context, interactive = false)
        row.setLeading(TitanText.riskGlyph(observation.risk), toneColor(context, TitanText.riskTone(observation.risk)))
        val title = observation.packageName ?: context.getString(R.string.titan_socket_unknown_app)
        row.setTitle(title)
        val detail = context.getString(
            R.string.titan_socket_detail,
            observation.remoteEndpoint,
            observation.protocol.name,
            observation.state.name,
        )
        val extra = when (observation.risk) {
            SocketRisk.THREAT_FEED_MATCH -> {
                val severity = observation.severity?.let { context.getString(severityLabelRes(it)) }
                    ?: context.getString(R.string.titan_socket_risk_threat)
                context.getString(R.string.titan_socket_threat_detail, severity, observation.threatFeedIds.size)
            }

            SocketRisk.UNATTRIBUTED -> context.getString(R.string.titan_socket_uid, observation.uid)
            SocketRisk.ADB_EXPOSED -> context.getString(R.string.titan_socket_risk_adb)
            SocketRisk.NONE -> context.getString(R.string.titan_socket_uid, observation.uid)
        }
        row.setSubtitle("$detail · $extra")
        row.setTrailing(
            StatusPill(
                context,
                context.getString(TitanText.riskLabelRes(observation.risk)),
                TitanText.riskTone(observation.risk),
                TitanText.riskGlyph(observation.risk),
            ),
        )
        row.contentDescription = "$title: ${context.getString(TitanText.riskLabelRes(observation.risk))}"
        TitanLayout.addRow(container, row, gapDp = 6)
        focusables += row

        if (observation.risk == SocketRisk.NONE) return focusables

        val canFreeze = observation.packageName != null && status.has(TitanCapability.APP_FREEZE)
        val canIsolate = observation.uid in 1..TitanActionTarget.MAX_UID &&
            status.has(TitanCapability.NETWORK_QUARANTINE)
        if (!canFreeze && !canIsolate) {
            TitanLayout.addCaption(container, context.getString(R.string.titan_socket_no_containment), topDp = 0)
            return focusables
        }

        val actionRow = horizontalRow(context)
        if (canFreeze) {
            val freeze = FocusableAction.danger(context, R.string.titan_action_freeze, TvGlyph.LOCK).apply {
                setOnClickListener { onFreeze(observation) }
            }
            actionRow.addView(freeze)
            focusables += freeze
        }
        if (canIsolate) {
            val isolate = FocusableAction.danger(context, R.string.titan_action_isolate, TvGlyph.CROSS).apply {
                setOnClickListener { onIsolate(observation) }
            }
            actionRow.addView(
                isolate,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { leftMargin = TvTheme.scaledDp(context, 12) },
            )
            focusables += isolate
        }
        container.addView(actionRow, TitanLayout.matchWidth())
        container.addSpacer(10)
        return focusables
    }
}
