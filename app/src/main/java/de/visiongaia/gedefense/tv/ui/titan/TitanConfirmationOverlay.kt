package de.visiongaia.gedefense.tv.ui.titan

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow

/**
 * Two-step D-pad confirmation for destructive or privilege-relevant Titan actions.
 *
 * The panel is part of the screen content (Z2 raised surface), hidden by default and shown directly
 * above the reading area. Default focus always sits on "Abbrechen"; BACK closes the step instead of
 * leaving the screen. The consequence text names the real effect - never a generic "sind Sie sicher".
 */
internal class TitanConfirmationOverlay(context: Context) : GlassPanel(context) {

    private val titleView = TvTheme.textView(
        context,
        "",
        TvTheme.TEXT_HEADING_SP,
        TvTheme.danger,
        bold = true,
    )
    private val bodyView = bodyText(context, "")
    private val consequenceView = captionText(context, "").apply {
        setTextColor(TvTheme.textPrimary)
        visibility = GONE
    }
    private val cancelAction = FocusableAction.secondary(context, R.string.action_cancel)
    private val confirmAction = FocusableAction.danger(
        context,
        R.string.titan_confirm_proceed,
        TvGlyph.ALERT,
    )
    private var confirmHandler: (() -> Unit)? = null
    private var returnFocus: View? = null
    private var open: Boolean = false

    init {
        orientation = VERTICAL
        visibility = GONE
        // Z4 modal surface: opaque scrim fill with the brand-danger edge, never pure colour signalling.
        background = TvTheme.glassPanelBackground(
            context,
            fill = TvTheme.scrimHeavy,
            stroke = TvTheme.danger,
        )
        addView(titleView, matchWidth())
        addView(
            bodyView,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 10) },
        )
        addView(
            consequenceView,
            matchWidth().apply { topMargin = TvTheme.scaledDp(context, 10) },
        )
        val actions = horizontalRow(context)
        actions.addView(cancelAction)
        actions.addView(
            confirmAction,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { leftMargin = TvTheme.scaledDp(context, 16) },
        )
        addView(
            actions,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = TvTheme.scaledDp(context, 18) },
        )
        cancelAction.setOnClickListener { hide() }
        confirmAction.setOnClickListener {
            val handler = confirmHandler
            hide()
            handler?.invoke()
        }
    }

    /**
     * Opens the confirmation step. [consequence] is the concrete target/effect line; [returnTo] is the
     * control that receives focus again after cancel/confirm.
     */
    fun show(
        titleRes: Int,
        bodyRes: Int,
        consequence: CharSequence?,
        confirmLabelRes: Int,
        returnTo: View?,
        onConfirm: () -> Unit,
    ) {
        titleView.text = context.getString(titleRes)
        bodyView.text = context.getString(bodyRes)
        if (consequence.isNullOrBlank()) {
            consequenceView.text = ""
            consequenceView.visibility = GONE
        } else {
            consequenceView.text = consequence
            consequenceView.visibility = VISIBLE
        }
        confirmAction.setLabel(context.getString(confirmLabelRes))
        confirmHandler = onConfirm
        returnFocus = returnTo
        open = true
        visibility = VISIBLE
        // Requesting focus also scrolls the reading viewport to the confirmation panel.
        post { cancelAction.requestFocus() }
    }

    /** Closes the step and restores focus to the triggering control (never a dead focus). */
    fun hide() {
        if (!open) return
        open = false
        visibility = GONE
        confirmHandler = null
        val target = returnFocus ?: cancelAction
        returnFocus = null
        target.post { if (target.isAttachedToWindow) target.requestFocus() }
    }

    fun isOpen(): Boolean = open

    private fun matchWidth(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )
}
