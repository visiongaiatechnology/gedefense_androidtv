package de.visiongaia.gedefense.tv.ui.screens

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.model.AppInventory
import de.visiongaia.gedefense.tv.core.model.InstalledApp
import de.visiongaia.gedefense.tv.core.model.InventoryDelta
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.EmptyState
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.InitialsBadge
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.SectionHeader
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.visibilityGlyph
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.visibilityTone

/**
 * TV App inventory screen — 2-column dashboard layout:
 * - Left column: App count overview, TV package visibility constraint, baseline timestamp
 * - Right column: Interactive, scrollable app catalog with immediate visibility of top items
 * - Header: Standardized top action button [Erneut prüfen] with no clipped bottom bars
 */
internal class AppsScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.APPS

    private var firstFocusRow: View? = null
    private var lastFocusRow: View? = null

    private companion object {
        const val MAX_ROWS = 100
    }

    override fun build(scaffold: ScreenScaffold) {
        val result = lastResult()
        val inventory = result?.inventory
        val summary = if (result == null) lastSummary() else null

        scaffold.setEyebrow(text(R.string.apps_eyebrow))
        scaffold.setTitle(text(R.string.apps_title))
        scaffold.setSubtitle(text(R.string.apps_subtitle))

        if (inventory != null) {
            val delta = result.inventoryDelta
            scaffold.addStatus(
                pill(visibilityGlyph(inventory.visibility), visibilityLabelRes(inventory.visibility), visibilityTone(inventory.visibility)),
            )
            scaffold.addStatus(
                StatusPill(
                    context,
                    text(
                        R.string.apps_counts_short,
                        inventory.apps.size,
                        delta.newPackages.size,
                        delta.changedPackages.size,
                    ),
                    TvTone.NEUTRAL,
                    TvGlyph.INFO,
                ),
            )
        }

        if (result == null || inventory == null) {
            val empty = EmptyState(context, TvGlyph.INFO)
            if (summary != null && result == null) {
                empty.set(
                    TvGlyph.INFO,
                    text(R.string.apps_summary_empty_title),
                    text(R.string.apps_summary_empty_message),
                )
            } else {
                empty.set(
                    TvGlyph.INFO,
                    text(R.string.apps_empty_title),
                    text(R.string.apps_empty_message),
                    text(R.string.apps_no_inventory),
                )
            }
            scaffold.content.addView(empty, matchParams())
        } else {
            buildTwoColumnDashboard(scaffold, inventory, result.inventoryDelta)
        }

        val labelRes = if (result == null && summary == null) R.string.action_start_check else R.string.action_rerun_check
        scaffold.addAction(
            primaryAction(labelRes, TvGlyph.REFRESH) { host.navigate(TvRoute.CHECK) },
            primary = true,
        )

        scaffold.linkFocusChain(firstFocusRow, lastFocusRow)
    }

    private fun buildTwoColumnDashboard(
        scaffold: ScreenScaffold,
        inventory: AppInventory,
        delta: InventoryDelta,
    ) {
        val twoColRow = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }

        // Left Column (32% width): Context, total count, TV visibility note
        val leftCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.32f).apply {
                rightMargin = TvTheme.scaledDp(context, 14)
            }
        }

        // Card 1: App Count Stat Card
        val statCard = GlassPanel(context).apply {
            compact()
            addView(TvTheme.textView(context, inventory.apps.size.toString(), TvTheme.TEXT_SCORE_SP, TvTheme.accent, bold = true))
            addView(
                TvTheme.textView(context, text(R.string.home_metric_apps).uppercase(), TvTheme.TEXT_MICRO_SP, TvTheme.textSecondary, bold = true).apply {
                    letterSpacing = 0.12f
                },
            )
            val deltaText = text(
                R.string.apps_counts_short,
                inventory.apps.size,
                delta.newPackages.size,
                delta.changedPackages.size,
            )
            addView(
                TvTheme.textView(context, deltaText, TvTheme.TEXT_MICRO_SP, TvTheme.textDim),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.scaledDp(context, 4)
                },
            )
        }
        leftCol.addView(statCard, matchParams())

        // Card 2: TV Visibility Notice
        if (inventory.packageVisibilityRestricted) {
            val notice = noticePanel(
                TvGlyph.EYE_OFF,
                TvTone.WARNING,
                text(R.string.apps_visibility_title),
                text(R.string.apps_visibility_body),
            )
            leftCol.addView(
                notice,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.scaledDp(context, 8)
                },
            )
        } else {
            val scopeNotice = noticePanel(
                TvGlyph.EYE,
                TvTone.INFO,
                null,
                text(R.string.apps_visibility_scope, text(visibilityLabelRes(inventory.visibility))),
            )
            leftCol.addView(
                scopeNotice,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = TvTheme.scaledDp(context, 8)
                },
            )
        }

        // Card 3: Baseline timestamp
        val baselineText = if (delta.baselineAvailable && delta.baselineAtMillis != null) {
            text(R.string.apps_baseline_time, TvFormat.dateTime(context, delta.baselineAtMillis!!))
        } else {
            text(R.string.apps_baseline_missing)
        }
        leftCol.addView(
            captionText(context, baselineText),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 6)
            },
        )

        // Right Column (68% width): Scrollable App Catalog
        val rightCol = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.68f)
        }

        rightCol.addView(
            SectionHeader(
                context,
                text(R.string.apps_section_list),
                TvFormat.appsCount(context, inventory.apps.size),
            ),
        )

        val newSet = delta.newPackages.toHashSet()
        val changedSet = delta.changedPackages.toHashSet()
        val sorted = inventory.apps.sortedWith(
            compareBy<InstalledApp> { app ->
                when (app.packageName) {
                    in newSet -> 0
                    in changedSet -> 1
                    else -> 2
                }
            }.thenBy { it.label.lowercase() },
        )

        if (sorted.isEmpty()) {
            rightCol.addView(captionText(context, text(R.string.apps_no_inventory)))
        } else {
            val listPanel = GlassPanel(context, soft = true).apply {
                compact()
            }
            for ((index, app) in sorted.take(MAX_ROWS).withIndex()) {
                val row = buildAppRow(app, app.packageName in newSet, app.packageName in changedSet)
                listPanel.addView(row, matchParams())
                if (firstFocusRow == null) firstFocusRow = row
                lastFocusRow = row
                if (index < minOf(sorted.size, MAX_ROWS) - 1) {
                    listPanel.addView(
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
            rightCol.addView(listPanel, matchParams())

            if (inventory.apps.size > MAX_ROWS) {
                rightCol.addView(
                    captionText(context, text(R.string.apps_list_limit, MAX_ROWS)),
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                        topMargin = TvTheme.scaledDp(context, 6)
                    },
                )
            }
            if (delta.removedPackages.isNotEmpty()) {
                rightCol.addView(
                    captionText(context, TvFormat.removedPackagesCount(context, delta.removedPackages.size)),
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                        topMargin = TvTheme.scaledDp(context, 4)
                    },
                )
            }
        }

        twoColRow.addView(leftCol)
        twoColRow.addView(rightCol)
        scaffold.content.addView(twoColRow)
    }

    private fun buildAppRow(app: InstalledApp, isNew: Boolean, isChanged: Boolean): View {
        val row = horizontalRow(context)
        row.minimumHeight = TvTheme.scaledDp(context, 44)
        row.setPadding(
            TvTheme.scaledDp(context, 10),
            TvTheme.scaledDp(context, 5),
            TvTheme.scaledDp(context, 10),
            TvTheme.scaledDp(context, 5),
        )
        row.isFocusable = true
        row.isFocusableInTouchMode = false
        row.isClickable = false
        row.setDefaultFocusHighlightEnabled(false)
        row.setBackgroundResource(R.drawable.sel_row)

        val badge = InitialsBadge(context, 28)
        badge.bind(app.label.ifBlank { app.packageName }, app.packageName)
        row.addView(
            badge,
            LinearLayout.LayoutParams(TvTheme.scaledDp(context, 28), TvTheme.scaledDp(context, 28)).apply {
                rightMargin = TvTheme.scaledDp(context, 10)
            },
        )

        val column = column()
        column.addView(
            TvTheme.textView(context, app.label.ifBlank { app.packageName }, TvTheme.TEXT_BODY_SP, TvTheme.textPrimary, bold = true),
        )
        column.addView(
            captionText(context, appMeta(app)),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = TvTheme.scaledDp(context, 1)
            },
        )
        row.addView(column, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        val badgeText = when {
            isNew -> text(R.string.apps_badge_new) to R.drawable.bg_badge_new
            isChanged -> text(R.string.apps_badge_changed) to R.drawable.bg_badge_changed
            !app.enabled -> text(R.string.apps_disabled) to R.drawable.bg_pill_neutral
            else -> null
        }
        if (badgeText != null) {
            val label = TvTheme.textView(context, badgeText.first, TvTheme.TEXT_MICRO_SP, TvTheme.textPrimary, bold = true).apply {
                letterSpacing = 0.08f
                isAllCaps = true
                setBackgroundResource(badgeText.second)
                setPadding(
                    TvTheme.scaledDp(context, 10),
                    TvTheme.scaledDp(context, 4),
                    TvTheme.scaledDp(context, 10),
                    TvTheme.scaledDp(context, 4),
                )
            }
            row.addView(
                label,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    leftMargin = TvTheme.scaledDp(context, 10)
                },
            )
        }
        return row
    }

    private fun appMeta(app: InstalledApp): String {
        val versionName = app.versionName
        val version = if (versionName.isNullOrBlank()) {
            text(R.string.apps_version_unknown)
        } else {
            text(R.string.apps_version, versionName, app.versionCode)
        }
        val flags = mutableListOf(app.packageName, version)
        flags += if (app.isSystemApp) text(R.string.apps_system_app) else text(R.string.apps_user_app)
        return flags.joinToString(" · ")
    }
}
