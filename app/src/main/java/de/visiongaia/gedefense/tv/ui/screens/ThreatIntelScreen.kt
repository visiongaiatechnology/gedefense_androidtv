package de.visiongaia.gedefense.tv.ui.screens

import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.ThreatIntelSyncListener
import de.visiongaia.gedefense.tv.core.model.FeedSnapshot
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * Threat-intelligence status. Feed freshness is always labelled; stale data stays visible but is
 * explicitly marked. The V1 scope note states that there is no system-wide flow monitoring, so the
 * screen never implies traffic-based detection.
 */
internal class ThreatIntelScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.THREAT_INTEL

    private var firstFocusRow: android.view.View? = null
    private var lastFocusRow: android.view.View? = null

    private var syncing: Boolean = false
    private var syncAction: FocusableAction? = null

    private val syncListener = object : ThreatIntelSyncListener {
        override fun onProgress(completed: Int, total: Int, lastFeedId: String) {
            if (!scaffoldReady()) return
            scaffold.post { host.updateSyncOverlay(completed, total) }
        }

        override fun onSyncFinished(ok: Boolean, message: MessageRef, status: ThreatIntelStatus) {
            if (!scaffoldReady()) {
                syncing = false
                return
            }
            val view = scaffold
            view.post {
                syncing = false
                host.hideSyncOverlay()
                val detail = resolve(message)
                notify(detail ?: text(if (ok) R.string.ti_sync_ok else R.string.ti_sync_failed))
                if (view.isAttachedToWindow) host.refreshCurrent()
            }
        }
    }

    override fun onHidden() {
        host.hideSyncOverlay()
    }

    override fun build(scaffold: ScreenScaffold) {
        val status = readService { services.threatIntel.status() } ?: ThreatIntelStatus.EMPTY

        scaffold.setEyebrow(text(R.string.ti_eyebrow))
        scaffold.setTitle(text(R.string.ti_title))
        scaffold.setSubtitle(text(R.string.ti_subtitle))

        // Honest fresh-install state: if no sync was ever attempted, never claim "gestört".
        val lastSync = status.lastSyncMillis
        if (lastSync == null) {
            scaffold.addStatus(
                StatusPill(context, text(R.string.ti_never_synced), TvTone.NEUTRAL, TvGlyph.CLOCK),
            )
        } else {
            // A sync was attempted: "gestört" only if that attempt failed or no feed is available
            // at all; otherwise the sync state is healthy (stale feeds keep their own gold label).
            val allFeedsUnavailable = status.feeds.isNotEmpty() && status.availableCount == 0
            if (status.syncHealthy && !allFeedsUnavailable) {
                scaffold.addStatus(pill(TvGlyph.CHECK, R.string.ti_sync_healthy, TvTone.SUCCESS))
            } else {
                scaffold.addStatus(pill(TvGlyph.ALERT, R.string.ti_sync_unhealthy, TvTone.WARNING))
            }
            scaffold.addStatus(
                StatusPill(
                    context,
                    text(R.string.ti_last_sync, TvFormat.relative(context, lastSync)),
                    TvTone.NEUTRAL,
                    TvGlyph.CLOCK,
                ),
            )
        }

        if (status.feeds.isEmpty()) {
            val empty = EmptyState(context, TvGlyph.REFRESH)
            empty.set(
                TvGlyph.REFRESH,
                text(R.string.ti_no_feeds_title),
                text(R.string.ti_no_feeds_message),
                text(R.string.ti_scope_note),
            )
            scaffold.content.addView(empty, matchParams())
        } else {
            scaffold.content.addView(
                bodyText(
                    context,
                    text(R.string.ti_status_value, status.freshCount, status.feeds.size, status.staleCount),
                ),
                matchParams(),
            )
            val note = resolve(status.note)
            if (note != null) {
                scaffold.content.addView(
                    captionText(context, text(R.string.ti_feed_note, note)),
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                        topMargin = TvTheme.scaledDp(context, 10)
                    },
                )
            }
            scaffold.addSection(text(R.string.ti_section_feeds), TvFormat.feedsCount(context, status.feeds.size))
            for (feed in status.feeds) {
                val row = buildFeedRow(feed)
                scaffold.content.addView(row, matchParams())
                if (firstFocusRow == null) firstFocusRow = row
                lastFocusRow = row
            }
        }

        scaffold.addSection(text(R.string.ti_section_scope))
        scaffold.content.addView(bodyText(context, text(R.string.ti_scope_note)), matchParams())
        scaffold.content.addView(
            captionText(context, text(R.string.ti_scope_matches)),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 10)
            },
        )
        scaffold.content.addView(
            captionText(context, text(R.string.ti_auto_sync_hint), TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 10)
            },
        )

        val action = primaryAction(
            if (syncing) R.string.action_syncing else R.string.action_sync_now,
            TvGlyph.REFRESH,
        ) { syncNow() }
        action.setActionEnabled(!syncing)
        syncAction = action
        scaffold.addAction(action, primary = true)
        scaffold.addAction(secondaryAction(R.string.action_open_settings, TvGlyph.SHIELD) { host.navigate(TvRoute.SETTINGS) })
        scaffold.linkFocusChain(firstFocusRow, lastFocusRow)
    }

    private fun buildFeedRow(feed: FeedSnapshot): FocusableRow {
        val row = FocusableRow(context, interactive = false)
        val (glyph, tone) = when {
            feed.available && feed.fresh -> TvGlyph.CHECK to TvTone.SUCCESS
            feed.available -> TvGlyph.CLOCK to TvTone.WARNING
            else -> TvGlyph.CROSS to TvTone.NEUTRAL
        }
        row.setLeading(glyph, toneColor(context, tone))
        row.setTitle(feed.name)
        val fetched = if (feed.fetchedAtMillis <= 0L) {
            text(R.string.ti_never_synced)
        } else {
            text(R.string.ti_feed_fetched, TvFormat.relative(context, feed.fetchedAtMillis))
        }
        val enforcement = if (feed.enforcement.isBlank()) null else text(R.string.ti_feed_enforcement, feed.enforcement)
        row.setSubtitle(
            listOfNotNull(
                text(R.string.ti_feed_records, feed.records),
                fetched,
                enforcement,
            ).joinToString(" · "),
        )
        val labelRes = when {
            feed.available && feed.fresh -> R.string.ti_feed_fresh
            feed.available -> R.string.ti_feed_stale
            else -> R.string.ti_feed_unavailable
        }
        row.setTrailing(StatusPill(context, text(labelRes), tone, glyph))
        return row
    }

    private fun syncNow() {
        if (syncing) return
        syncing = true
        host.showSyncOverlay(text(R.string.ti_title))
        val started = readService { services.threatIntel.syncNow(syncListener) } ?: false
        if (!started) {
            syncing = false
            host.hideSyncOverlay()
            notify(text(R.string.ti_sync_already))
            return
        }
        // Update the control in place instead of rebuilding: a fast sync may already have finished and
        // the completion listener recreates the screen with fresh data.
        syncAction?.setActionEnabled(false)
        syncAction?.setLabel(text(R.string.action_syncing))
    }
}
