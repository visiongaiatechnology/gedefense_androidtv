package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.Shader
import android.graphics.Typeface
import android.view.View
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Programmatic app-initial badge for the Apps list (no icon pack, no bitmap assets).
 *
 * The tint is derived deterministically from the package name so the list stays scannable; the
 * initials come from the app label and are always accompanied by the full text next to the badge.
 */
class InitialsBadge @JvmOverloads constructor(
    context: Context,
    private val sizeDp: Int = 36,
) : View(context) {

    private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val edge = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = TvTheme.scaledDp(context, 1).coerceAtLeast(1).toFloat()
        color = Color.argb(90, 201, 162, 75)
    }
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
        color = TvTheme.textPrimary
    }

    private var initials: String = "?"
    private var tint: Int = TvTheme.accentSoft
    private val sidePx: Int get() = TvTheme.scaledDp(context, sizeDp)

    init {
        isFocusable = false
        isClickable = false
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    /** Binds the initials and a deterministic tint from the package name. */
    fun bind(label: String, packageName: String) {
        val cleaned = label.trim()
        initials = when {
            cleaned.isEmpty() -> "?"
            cleaned.length == 1 -> cleaned.uppercase()
            else -> cleaned.split(' ', '-', '_', '.')
                .filter { it.isNotBlank() }
                .take(2)
                .joinToString("") { it.first().uppercase() }
                .ifBlank { cleaned.take(2).uppercase() }
        }
        // Dark mineral tints only: white initials must stay >= 4.5:1 on the badge disc.
        val palette = intArrayOf(
            Color.rgb(126, 96, 40),   // bronze-gold
            Color.rgb(48, 110, 185),  // protection blue
            Color.rgb(44, 70, 94),    // steel blue
            Color.rgb(92, 72, 36),    // dark bronze
            Color.rgb(36, 66, 58),    // deep sage-teal
            Color.rgb(74, 56, 94),    // muted violet
        )
        var hash = 7
        for (ch in packageName) hash = hash * 31 + ch.code
        tint = palette[Math.abs(hash) % palette.size]
        contentDescription = label
        invalidate()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        setMeasuredDimension(sidePx, sidePx)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val size = width.toFloat()
        val radius = size / 2f
        // Dark center, slightly darker rim: keeps the white initials readable across the disc.
        fill.shader = RadialGradient(
            radius,
            radius,
            radius * 1.12f,
            intArrayOf(tint, darker(tint)),
            floatArrayOf(0f, 1f),
            Shader.TileMode.CLAMP,
        )
        canvas.drawCircle(radius, radius, radius - 1f, fill)
        canvas.drawCircle(radius, radius, radius - 1f, edge)
        textPaint.textSize = size * 0.34f
        val baseline = radius - (textPaint.descent() + textPaint.ascent()) / 2f
        canvas.drawText(initials, radius, baseline, textPaint)
    }

    private fun darker(color: Int): Int = Color.rgb(
        (Color.red(color) * 0.55f).toInt(),
        (Color.green(color) * 0.55f).toInt(),
        (Color.blue(color) * 0.60f).toInt(),
    )
}
