package de.visiongaia.gedefense.tv.ui.titan

import android.view.View
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessState
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.toneColor

/**
 * Witness protocol section: local, HMAC-authenticated checkpoints of the evidence ledger.
 *
 * The alpha produces and stores checkpoints locally only. Mobile push pairing is not implemented, so
 * the section states that gap instead of offering a pairing button.
 */
internal object TitanWitnessSection {

    fun build(
        container: LinearLayout,
        witness: TitanWitnessStatus,
        checkpointEnabled: Boolean,
        onCheckpoint: () -> Unit,
    ): List<View> {
        val context = container.context
        TitanLayout.addSection(container, context.getString(R.string.titan_witness_section))

        val row = FocusableRow(context, interactive = false)
        row.setLeading(
            TitanText.witnessStateGlyph(witness.state),
            toneColor(context, TitanText.witnessStateTone(witness.state)),
        )
        row.setTitle(context.getString(TitanText.witnessStateLabelRes(witness.state)))
        val parts = mutableListOf(
            context.getString(R.string.titan_witness_checkpoints, witness.checkpointsCreated),
        )
        val lastCheckpointAt = witness.lastCheckpointAtMillis
        parts += if (lastCheckpointAt != null && lastCheckpointAt > 0L) {
            context.getString(
                R.string.titan_witness_last,
                TvFormat.relative(context, lastCheckpointAt),
            )
        } else {
            context.getString(R.string.titan_witness_last, context.getString(R.string.value_never))
        }
        row.setSubtitle(parts.joinToString(" · "))
        row.setTrailing(
            StatusPill(
                context,
                context.getString(TitanText.witnessStateLabelRes(witness.state)),
                TitanText.witnessStateTone(witness.state),
                TitanText.witnessStateGlyph(witness.state),
            ),
        )
        TitanLayout.addRow(container, row, gapDp = 6)

        val focusables = mutableListOf<View>()
        val digestPrefix = witness.lastLedgerDigestPrefix
        if (digestPrefix != null) {
            TitanLayout.addCaption(
                container,
                context.getString(R.string.titan_witness_digest, digestPrefix),
                topDp = 0,
            )
        } else if (witness.checkpointsCreated == 0L) {
            TitanLayout.addCaption(container, context.getString(R.string.titan_witness_empty), topDp = 0)
        }

        if (witness.state == TitanWitnessState.UNAVAILABLE) {
            TitanLayout.addCaption(container, context.getString(R.string.titan_witness_unavailable_note), topDp = 4)
        } else if (checkpointEnabled) {
            val action = FocusableAction.secondary(context, R.string.titan_action_checkpoint, TvGlyph.REFRESH).apply {
                setOnClickListener { onCheckpoint() }
            }
            container.addView(
                action,
                TitanLayout.wrapWidth().apply {
                    topMargin = TvTheme.scaledDp(context, 8)
                },
            )
            focusables += action
        }

        TitanLayout.addCaption(container, context.getString(R.string.titan_witness_note), topDp = 6)
        return focusables
    }
}
