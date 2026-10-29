package de.visiongaia.gedefense.tv.ui

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Design tokens for GeDefense TV (VGT GLASS 2100, 2026 redesign).
 *
 * Brand DNA is taken from the original GeDefense identity: obsidian/graphite mineral surfaces,
 * metallic-gold brand accent, electric-blue protection light from the shield gem, green reserved
 * for verified health and signal red reserved for critical attention. Glass is a material language
 * for functional surfaces - no decorative background grids, no neon cyberpunk, no card inflation.
 *
 * This file is the runtime source of truth for programmatic views. Res XML colors mirror these
 * values for state-list drawables.
 */
object TvTheme {
    // Environment / canvas - obsidian mineral
    val bgDeep: Int = Color.rgb(4, 7, 10)
    val bg: Int = Color.rgb(8, 12, 17)
    val canvas: Int = Color.rgb(11, 16, 22)
    val canvasRaised: Int = Color.rgb(14, 20, 27)

    // Glass surfaces (functional layers with restrained opacity)
    val glassPanel: Int = Color.argb(222, 19, 26, 34)
    val glassPanelSoft: Int = Color.argb(184, 15, 21, 28)
    val glassStroke: Int = Color.argb(82, 201, 162, 75)
    val glassStrokeCool: Int = Color.argb(64, 120, 156, 190)
    val glassHighlight: Int = Color.argb(38, 244, 236, 214)
    val scrimHeavy: Int = Color.argb(236, 6, 9, 13)

    // Brand pigment: metallic gold (logo, primary actions, brand rules)
    val accent: Int = Color.rgb(230, 185, 92)
    val accentSoft: Int = Color.rgb(164, 126, 52)
    val accentDim: Int = Color.rgb(58, 45, 20)
    val goldBright: Int = Color.rgb(247, 214, 138)

    // Protection light: electric blue from the shield gem / live state
    val electricBlue: Int = Color.rgb(90, 169, 230)
    val gemBlue: Int = Color.rgb(64, 140, 230)
    val blueDim: Int = Color.rgb(24, 44, 64)

    // Typography. Product rule: text on dark surfaces is always white-family (>=82% white);
    // hierarchy comes from size/weight, never from grey-out. Gold stays reserved for brand/rules.
    val textPrimary: Int = Color.rgb(255, 255, 255)
    val textSecondary: Int = Color.rgb(234, 240, 245)
    val textMuted: Int = Color.rgb(220, 228, 236)
    val textDim: Int = Color.rgb(201, 211, 221)

    // Functional status colors (never colour-only in UI; always paired with glyph + label)
    val info: Int = electricBlue
    val success: Int = Color.rgb(79, 209, 165)
    val warning: Int = Color.rgb(230, 185, 92)
    val danger: Int = Color.rgb(239, 106, 90)
    val critical: Int = Color.rgb(240, 75, 75)

    // Geometry
    const val RADIUS_PANEL_DP = 12
    const val RADIUS_CONTROL_DP = 8
    const val OVERSCAN_DP = 24
    const val FOCUS_STROKE_DP = 3
    const val RAIL_WIDTH_DP = 196

    // Type scale for 10-foot viewing, tuned so 1080p, 2K and 4K UI looks crisp, compact and balanced.
    // In Android TV, canonical coordinate space is 960x540 dp (sw540dp).
    const val TEXT_DISPLAY_SP = 28f
    const val TEXT_SCORE_SP = 34f
    const val TEXT_TITLE_SP = 22f
    const val TEXT_HEADING_SP = 16f
    const val TEXT_BODY_SP = 13f
    const val TEXT_LABEL_SP = 12f
    const val TEXT_CAPTION_SP = 11f
    const val TEXT_MICRO_SP = 10f

    /**
     * Display density & coordinate reference:
     * In Android TV, whether physical resolution is 720p (tvdpi/213), 1080p (xhdpi/320), or 4K
     * (xxxhdpi/640 or 1080p-scaled), the canonical viewport size is 960 x 540 dp (sw540dp).
     *
     * layoutScale provides smooth adaptive scaling only if an unusual display aspect ratio or
     * non-standard density is encountered, normalized against the 960x540 dp reference.
     */
    fun layoutScale(context: Context): Float {
        val configuration = context.resources.configuration
        val widthDp = if (configuration.screenWidthDp > 0) configuration.screenWidthDp.toFloat() else 960f
        val heightDp = if (configuration.screenHeightDp > 0) configuration.screenHeightDp.toFloat() else 540f
        val widthFactor = widthDp / 960f
        val heightFactor = heightDp / 540f
        return minOf(widthFactor, heightFactor).coerceIn(0.75f, 1.35f)
    }

    /** Width cap (in design dp) so very wide panels do not stretch single-column content. */
    fun contentMaxWidthDp(@Suppress("UNUSED_PARAMETER") context: Context): Int = 960

    /** Scaled dp value for component paddings, control heights and media sizes. */
    fun scaledDp(context: Context, value: Int): Int = dp(context, value)

    // Motion (seconds) - short, product-grade feedback, never ambient noise
    const val MOTION_FAST = 140L
    const val MOTION_STANDARD = 200L
    const val MOTION_ENTER = 220L

    /**
     * User-adjustable UI scale (Settings -> Darstellung). 1.0 = normal. Applied to dp layout sizes
     * and text sizes so the whole interface can be made more compact or larger on any TV panel.
     * Values are clamped to a readable range by the settings layer.
     */
    @Volatile
    var userScale: Float = 1f

    fun dp(context: Context, value: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            value.toFloat() * layoutScale(context) * userScale,
            context.resources.displayMetrics,
        ).toInt()

    /** Vertical brand gradient used for rail chrome and hero environments. */
    fun verticalGradient(top: Int, bottom: Int): GradientDrawable = GradientDrawable(
        GradientDrawable.Orientation.TOP_BOTTOM,
        intArrayOf(top, bottom),
    )

    fun panelBackground(radiusDp: Int = RADIUS_PANEL_DP, fill: Int = glassPanel, stroke: Int = glassStroke): GradientDrawable =
        GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radiusDp * 3f
            setColor(fill)
            setStroke(2, stroke)
        }

    /** Pixel-correct glass panel background with brand stroke. */
    fun glassPanelBackground(
        context: Context,
        fill: Int = glassPanel,
        stroke: Int = glassStroke,
        radiusDp: Int = RADIUS_PANEL_DP,
    ): GradientDrawable = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(context, radiusDp).toFloat()
        setColor(fill)
        setStroke(dp(context, 1).coerceAtLeast(1), stroke)
    }

    /**
     * Hero background: obsidian vertical gradient with a faint warm brand wash at the top. Intended
     * for the large home hero panel only - a functional brand surface, not a decorative pattern.
     */
    fun heroBackground(context: Context): GradientDrawable = GradientDrawable(
        GradientDrawable.Orientation.TOP_BOTTOM,
        intArrayOf(
            Color.rgb(20, 27, 35),
            Color.rgb(11, 16, 22),
            Color.rgb(7, 10, 14),
        ),
    ).apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(context, 24).toFloat()
        setStroke(dp(context, 1).coerceAtLeast(1), Color.argb(96, 201, 162, 75))
    }

    /** Focus ring background used by interactive controls. */
    fun focusRingBackground(
        context: Context,
        focused: Boolean,
        radiusDp: Int = RADIUS_CONTROL_DP,
    ): GradientDrawable = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(context, radiusDp).toFloat()
        setColor(if (focused) Color.argb(215, 46, 36, 16) else Color.argb(165, 18, 24, 31))
        setStroke(dp(context, if (focused) FOCUS_STROKE_DP else 1), if (focused) accent else glassStrokeCool)
    }

    fun textView(
        context: Context,
        text: CharSequence,
        sizeSp: Float = TEXT_BODY_SP,
        color: Int = textPrimary,
        bold: Boolean = false,
    ): TextView = TextView(context).apply {
        this.text = text
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp * layoutScale(context) * userScale)
        setTextColor(color)
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
        includeFontPadding = false
        gravity = Gravity.START
    }

    fun sectionLabel(context: Context, text: CharSequence): TextView = textView(context, text, TEXT_CAPTION_SP, textMuted).apply {
        letterSpacing = 0.18f
        isAllCaps = true
    }

    /** Accessibility-friendly status label with an icon glyph and explicit text. */
    fun statusLabel(context: Context, symbol: String, label: String, color: Int): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        addView(textView(context, symbol, TEXT_LABEL_SP, color, bold = true).apply {
            setPadding(0, 0, dp(context, 8), 0)
        })
        addView(textView(context, label, TEXT_LABEL_SP, color))
    }

    /** Applies consistent focus feedback: brand ring + soft scale + accent colour callback. */
    fun applyFocusFeedback(
        context: Context,
        view: View,
        radiusDp: Int = RADIUS_CONTROL_DP,
        onFocusChanged: ((Boolean) -> Unit)? = null,
    ) {
        view.isFocusable = true
        view.isFocusableInTouchMode = false
        view.setDefaultFocusHighlightEnabled(false)
        view.setOnFocusChangeListener { _, hasFocus ->
            view.background = focusRingBackground(context, hasFocus, radiusDp)
            view.animate()
                .scaleX(if (hasFocus) 1.02f else 1f)
                .scaleY(if (hasFocus) 1.02f else 1f)
                .setDuration(MOTION_FAST)
                .start()
            onFocusChanged?.invoke(hasFocus)
        }
        view.background = focusRingBackground(context, view.hasFocus(), radiusDp)
    }
}
