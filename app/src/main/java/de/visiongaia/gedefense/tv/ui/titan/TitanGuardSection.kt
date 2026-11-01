package de.visiongaia.gedefense.tv.ui.titan

import android.view.View
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone

/**
 * Guard switches. The preference is persisted immediately, but a switch is rendered as an unusable
 * reading row when the effective capability set does not contain the required capability: a stored
 * "on" that can never take effect would be a false promise.
 */
internal object TitanGuardSection {

    fun build(
        container: LinearLayout,
        status: TitanStatus,
        socketGuardEnabled: Boolean,
        fimGuardEnabled: Boolean,
        onToggleSocket: (Boolean) -> Unit,
        onToggleFim: (Boolean) -> Unit,
    ): List<View> {
        val context = container.context
        TitanLayout.addSection(container, context.getString(R.string.titan_guard_section))

        val socketRow = guardRow(
            container,
            titleRes = R.string.titan_guard_socket_title,
            descRes = R.string.titan_guard_socket_desc,
            enabled = socketGuardEnabled,
            capabilityAvailable = status.has(TitanCapability.SOCKET_PROVENANCE),
            onToggle = onToggleSocket,
        )
        val fimRow = guardRow(
            container,
            titleRes = R.string.titan_guard_fim_title,
            descRes = R.string.titan_guard_fim_desc,
            enabled = fimGuardEnabled,
            capabilityAvailable = status.has(TitanCapability.DEEP_INVENTORY_FIM),
            onToggle = onToggleFim,
        )
        return listOf(socketRow, fimRow)
    }

    private fun guardRow(
        container: LinearLayout,
        titleRes: Int,
        descRes: Int,
        enabled: Boolean,
        capabilityAvailable: Boolean,
        onToggle: (Boolean) -> Unit,
    ): View {
        val context = container.context
        val row = FocusableRow(context, interactive = capabilityAvailable)
        row.setCard(true)
        row.setLeading(
            if (enabled && capabilityAvailable) TvGlyph.CHECK else TvGlyph.LOCK,
            if (capabilityAvailable) TvTheme.accent else TvTheme.textSecondary,
        )
        row.setTitle(context.getString(titleRes))
        row.setSubtitle(
            if (capabilityAvailable) {
                context.getString(descRes)
            } else {
                context.getString(descRes) + "\n" + context.getString(R.string.titan_guard_unavailable)
            },
        )
        row.setSubtitleMaxLines(3)
        if (capabilityAvailable) {
            row.setTrailing(
                StatusPill(
                    context,
                    context.getString(
                        if (enabled) R.string.settings_state_enabled else R.string.settings_state_disabled,
                    ),
                    if (enabled) TvTone.SUCCESS else TvTone.NEUTRAL,
                    if (enabled) TvGlyph.CHECK else TvGlyph.CROSS,
                ),
            )
            row.setOnClickListener { onToggle(!enabled) }
        } else {
            row.setTrailing(
                StatusPill(
                    context,
                    context.getString(R.string.titan_capability_inactive),
                    TvTone.NEUTRAL,
                    TvGlyph.CROSS,
                ),
            )
        }
        TitanLayout.addRow(container, row, gapDp = 8)
        return row
    }
}
