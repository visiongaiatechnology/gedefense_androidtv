package de.visiongaia.gedefense.tv.ui.components

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.TextCatalog
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Small, dependency-free helpers shared by all TV screens.
 *
 * These functions deliberately contain no user-facing copy: every label comes from `strings.xml`.
 */

/** Resolves the hosting [Activity] for a context (used as the SAF owner for report export). */
fun Context.findHostActivity(): Activity? {
    var context: Context = this
    while (context is ContextWrapper) {
        if (context is Activity) return context
        context = context.baseContext
    }
    return null
}

/**
 * Executes a read against the local service layer. A failing service must never crash the TV UI:
 * the screen shows an honest error state instead of pretending the data exists.
 */
inline fun <T> readService(block: () -> T): T? =
    try {
        block()
    } catch (t: Throwable) {
        null
    }

/** Resolves a [MessageRef] through the active catalog; never throws on unknown keys. */
fun resolveText(catalog: TextCatalog, ref: MessageRef?): String? {
    if (ref == null) return null
    return try {
        catalog.resolve(ref)
    } catch (t: Throwable) {
        null
    }
}

/** Resolves the optional user-facing text of a message ref, falling back to [fallback]. */
fun resolveTextOr(catalog: TextCatalog, ref: MessageRef?, fallback: String): String =
    resolveText(catalog, ref)?.takeIf { it.isNotBlank() } ?: fallback

/** Theme-consistent body text with restrained line spacing for 10-foot reading. */
fun bodyText(context: Context, text: CharSequence, color: Int = TvTheme.textSecondary): TextView =
    TvTheme.textView(context, text, TvTheme.TEXT_BODY_SP, color).apply {
        setLineSpacing(0f, 1.14f)
    }

/** Theme-consistent caption text (secondary technical detail, timestamps, identifiers). */
fun captionText(context: Context, text: CharSequence, color: Int = TvTheme.textSecondary): TextView =
    TvTheme.textView(context, text, TvTheme.TEXT_CAPTION_SP, color)

/** Vertical spacer for the screen composition rhythm. */
fun spacer(context: Context, heightDp: Int): View = View(context).apply {
    layoutParams = LinearLayout.LayoutParams(1, TvTheme.scaledDp(context, heightDp))
}

/** Adds a vertical spacer to a vertical [LinearLayout]. */
fun LinearLayout.addSpacer(heightDp: Int) {
    addView(spacer(context, heightDp))
}

/** Thin mineral divider - grouping by rule instead of by card. */
fun divider(context: Context): View = View(context).apply {
    setBackgroundColor(context.getColor(R.color.tv_divider))
    layoutParams = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        TvTheme.scaledDp(context, 1).coerceAtLeast(1),
    )
}

/** Horizontal row with centred vertical alignment. */
fun horizontalRow(context: Context): LinearLayout = LinearLayout(context).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
}

/** Vertical column. */
fun verticalColumn(context: Context): LinearLayout = LinearLayout(context).apply {
    orientation = LinearLayout.VERTICAL
}

/** Applies standard row layout params to a child of a vertical column. */
fun LinearLayout.LayoutParams.matchWidth(): LinearLayout.LayoutParams = apply {
    width = ViewGroup.LayoutParams.MATCH_PARENT
}

/** Sets a weight-based width for a child inside a horizontal row. */
fun LinearLayout.LayoutParams.weighted(weight: Float): LinearLayout.LayoutParams = apply {
    width = 0
    this.weight = weight
}
