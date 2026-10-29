package de.visiongaia.gedefense.tv.ui.screens

import android.content.Context
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.ScanSummary
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.ui.ScreenHost
import de.visiongaia.gedefense.tv.ui.TvScreen
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.GlyphView
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.horizontalRow
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.resolveText
import de.visiongaia.gedefense.tv.ui.components.spacer
import de.visiongaia.gedefense.tv.ui.components.toneColor
import de.visiongaia.gedefense.tv.ui.components.verticalColumn

/**
 * Shared base for all TV screens.
 *
 * Screens are pure view builders: the service layer is read once while [build] composes the view
 * tree, live updates are pushed by listeners, and a full reload is performed by the shell through
 * `refreshCurrent()` (which calls [createView] again). Screens never start activities or manipulate
 * the back stack themselves.
 */
internal abstract class ScaffoldScreen(protected val services: TvServices) : TvScreen {

    protected lateinit var host: ScreenHost
    protected lateinit var scaffold: ScreenScaffold
    private var hostingContext: Context? = null

    protected val context: Context get() = hostingContext ?: services.appContext

    final override fun createView(host: ScreenHost): View {
        this.host = host
        hostingContext = host as? Context
        scaffold = ScreenScaffold(context)
        build(scaffold)
        return scaffold
    }

    protected abstract fun build(scaffold: ScreenScaffold)

    override fun initialFocus(): View? = scaffold.primaryFocus()

    /** True once [createView] has built the current view tree. */
    protected fun scaffoldReady(): Boolean = this::scaffold.isInitialized

    // ---------------------------------------------------------------- helpers

    protected fun text(resId: Int): String = context.getString(resId)

    protected fun text(resId: Int, vararg args: Any): String = context.getString(resId, *args)

    protected fun lastResult(): ScanResult? = readService { services.scan.lastResult() }

    /** Persisted summary of the last completed scan (survives process restarts). */
    protected fun lastSummary(): ScanSummary? = readService { services.scan.lastSummary() }

    protected fun scanUiState() = readService { services.scan.state() }

    protected fun resolve(ref: MessageRef?): String? = resolveText(services.catalog, ref)

    /** Small status pill helper. */
    protected fun pill(glyph: TvGlyph, labelRes: Int, tone: TvTone): StatusPill =
        StatusPill(context, text(labelRes), tone, glyph)

    /** Label/value line for structured detail blocks. */
    protected fun infoRow(label: CharSequence, value: CharSequence): LinearLayout {
        val row = horizontalRow(context)
        row.setPadding(0, TvTheme.scaledDp(context, 6), 0, TvTheme.scaledDp(context, 6))
        row.addView(
            TvTheme.textView(context, label, TvTheme.TEXT_LABEL_SP, TvTheme.textSecondary),
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                rightMargin = TvTheme.scaledDp(context, 16)
            },
        )
        row.addView(
            TvTheme.textView(context, value, TvTheme.TEXT_LABEL_SP, TvTheme.textSecondary).apply {
                gravity = Gravity.END
                maxLines = 2
            },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        return row
    }

    /** Label/value line where the value is a status pill (status is never colour-only). */
    protected fun infoRowPill(label: CharSequence, value: StatusPill): LinearLayout {
        val row = horizontalRow(context)
        row.setPadding(0, TvTheme.scaledDp(context, 6), 0, TvTheme.scaledDp(context, 6))
        row.addView(
            TvTheme.textView(context, label, TvTheme.TEXT_LABEL_SP, TvTheme.textSecondary),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        row.addView(value)
        return row
    }

    /** Compact structured information block on a soft glass surface. */
    protected fun parameterPanel(vararg rows: View): GlassPanel {
        val panel = GlassPanel(context, soft = true)
        panel.compact()
        for (row in rows) {
            panel.addView(row, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        return panel
    }

    /** Honest notice panel: limitation, permission or failure context - never a fake success box. */
    protected fun noticePanel(glyph: TvGlyph, tone: TvTone, title: CharSequence?, body: CharSequence): GlassPanel {
        val panel = GlassPanel(context)
        panel.compact()
        if (title != null) {
            val row = horizontalRow(context)
            row.addView(
                GlyphView(context, glyph, toneColor(context, tone), 22),
                LinearLayout.LayoutParams(TvTheme.scaledDp(context, 22), TvTheme.scaledDp(context, 22)).apply {
                    rightMargin = TvTheme.scaledDp(context, 10)
                },
            )
            row.addView(TvTheme.textView(context, title, TvTheme.TEXT_LABEL_SP, toneColor(context, tone), bold = true))
            panel.addView(row)
            panel.addView(spacer(context, 8))
        }
        panel.addView(bodyText(context, body))
        return panel
    }

    /** Primary action wired to a click handler. */
    protected fun primaryAction(labelRes: Int, glyph: TvGlyph, onClick: () -> Unit): FocusableAction =
        FocusableAction.primary(context, labelRes, glyph).apply {
            setOnClickListener { onClick() }
        }

    /** Secondary action wired to a click handler. */
    protected fun secondaryAction(labelRes: Int, glyph: TvGlyph?, onClick: () -> Unit): FocusableAction =
        FocusableAction.secondary(context, labelRes, glyph).apply {
            setOnClickListener { onClick() }
        }

    /** Destructive action wired to a click handler (must open an explicit confirmation step). */
    protected fun dangerAction(labelRes: Int, glyph: TvGlyph?, onClick: () -> Unit): FocusableAction =
        FocusableAction.danger(context, labelRes, glyph).apply {
            setOnClickListener { onClick() }
        }

    /** Recreates the current screen when it is still the visible one. */
    protected fun refreshIfVisible() {
        val view: View = scaffold
        if (view.isAttachedToWindow) host.refreshCurrent()
    }

    protected fun notify(message: CharSequence) = host.notifyUser(message.toString())

    /** Small caption view helper used by several screens. */
    protected fun caption(text: CharSequence, color: Int = TvTheme.textSecondary): TextView = captionText(context, text, color)

    /** Vertical column helper. */
    protected fun column(): LinearLayout = verticalColumn(context)

    /** Layout params for a full-width row inside the scaffold content column. */
    protected fun matchParams(): LinearLayout.LayoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )
}
