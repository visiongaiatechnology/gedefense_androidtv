package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.View
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Semantic icon set for status display. Every state in the UI is rendered as glyph + German label,
 * so status is never communicated by colour alone.
 */
enum class TvGlyph {
    DOT,
    CHECK,
    CROSS,
    ALERT,
    QUESTION,
    CLOCK,
    EYE,
    EYE_OFF,
    HALF,
    LOCK,
    SHIELD,
    INFO,
    CHEVRON,
    REFRESH,
    EXPORT,
    TRASH,
}

/**
 * Self-drawn, dependency-free glyph. Icons are simple geometric strokes in the product's restrained
 * line language - no icon font, no third-party asset, no emoji.
 */
class GlyphView @JvmOverloads constructor(
    context: Context,
    glyph: TvGlyph = TvGlyph.DOT,
    color: Int = TvTheme.textSecondary,
    sizeDp: Int = 26,
) : View(context) {

    private val stroke = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val letter = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = android.graphics.Typeface.create("sans-serif", android.graphics.Typeface.BOLD)
    }
    private val path = Path()
    private val oval = RectF()

    private val sidePx: Int = TvTheme.scaledDp(context, sizeDp)

    var glyph: TvGlyph = glyph
        set(value) {
            field = value
            invalidate()
        }

    var glyphColor: Int = color
        set(value) {
            field = value
            invalidate()
        }

    init {
        isFocusable = false
        isClickable = false
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        setMeasuredDimension(sidePx, sidePx)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val side = width.toFloat().coerceAtLeast(1f)
        stroke.color = glyphColor
        fill.color = glyphColor
        letter.color = glyphColor
        canvas.save()
        canvas.scale(side / 100f, side / 100f)
        stroke.strokeWidth = 8.5f
        drawGlyph(canvas)
        canvas.restore()
    }

    private fun drawGlyph(canvas: Canvas) {
        when (glyph) {
            TvGlyph.DOT -> canvas.drawCircle(50f, 50f, 22f, fill)

            TvGlyph.CHECK -> {
                path.reset()
                path.moveTo(20f, 54f)
                path.lineTo(42f, 76f)
                path.lineTo(80f, 26f)
                canvas.drawPath(path, stroke)
            }

            TvGlyph.CROSS -> {
                path.reset()
                path.moveTo(26f, 26f)
                path.lineTo(74f, 74f)
                path.moveTo(74f, 26f)
                path.lineTo(26f, 74f)
                canvas.drawPath(path, stroke)
            }

            TvGlyph.ALERT -> {
                path.reset()
                path.moveTo(50f, 10f)
                path.lineTo(90f, 86f)
                path.lineTo(10f, 86f)
                path.close()
                canvas.drawPath(path, stroke)
                path.reset()
                path.moveTo(50f, 38f)
                path.lineTo(50f, 64f)
                canvas.drawPath(path, stroke)
                canvas.drawCircle(50f, 76f, 5f, fill)
            }

            TvGlyph.QUESTION -> {
                canvas.drawCircle(50f, 50f, 36f, stroke)
                letter.textSize = 54f
                canvas.drawText("?", 50f, 50f + 19f, letter)
            }

            TvGlyph.CLOCK -> {
                canvas.drawCircle(50f, 52f, 34f, stroke)
                path.reset()
                path.moveTo(50f, 32f)
                path.lineTo(50f, 54f)
                path.lineTo(68f, 62f)
                canvas.drawPath(path, stroke)
            }

            TvGlyph.EYE -> {
                path.reset()
                path.moveTo(10f, 50f)
                path.cubicTo(30f, 26f, 70f, 26f, 90f, 50f)
                path.cubicTo(70f, 74f, 30f, 74f, 10f, 50f)
                path.close()
                canvas.drawPath(path, stroke)
                canvas.drawCircle(50f, 50f, 9f, fill)
            }

            TvGlyph.EYE_OFF -> {
                path.reset()
                path.moveTo(10f, 50f)
                path.cubicTo(30f, 26f, 70f, 26f, 90f, 50f)
                path.cubicTo(70f, 74f, 30f, 74f, 10f, 50f)
                path.close()
                canvas.drawPath(path, stroke)
                canvas.drawCircle(50f, 50f, 9f, fill)
                path.reset()
                path.moveTo(20f, 18f)
                path.lineTo(82f, 84f)
                canvas.drawPath(path, stroke)
            }

            TvGlyph.HALF -> {
                canvas.drawCircle(50f, 50f, 34f, stroke)
                oval.set(16f, 16f, 84f, 84f)
                canvas.drawArc(oval, 90f, 180f, true, fill)
            }

            TvGlyph.LOCK -> {
                path.reset()
                path.moveTo(30f, 48f)
                path.lineTo(70f, 48f)
                path.lineTo(70f, 84f)
                path.lineTo(30f, 84f)
                path.close()
                canvas.drawPath(path, stroke)
                path.reset()
                path.moveTo(38f, 48f)
                path.lineTo(38f, 36f)
                path.cubicTo(38f, 24f, 62f, 24f, 62f, 36f)
                path.lineTo(62f, 48f)
                canvas.drawPath(path, stroke)
                canvas.drawCircle(50f, 66f, 5f, fill)
            }

            TvGlyph.SHIELD -> {
                path.reset()
                path.moveTo(50f, 10f)
                path.lineTo(82f, 22f)
                path.lineTo(82f, 50f)
                path.cubicTo(82f, 72f, 68f, 84f, 50f, 90f)
                path.cubicTo(32f, 84f, 18f, 72f, 18f, 50f)
                path.lineTo(18f, 22f)
                path.close()
                canvas.drawPath(path, stroke)
            }

            TvGlyph.INFO -> {
                canvas.drawCircle(50f, 50f, 36f, stroke)
                path.reset()
                path.moveTo(50f, 46f)
                path.lineTo(50f, 72f)
                canvas.drawPath(path, stroke)
                canvas.drawCircle(50f, 32f, 5f, fill)
            }

            TvGlyph.CHEVRON -> {
                path.reset()
                path.moveTo(38f, 22f)
                path.lineTo(66f, 50f)
                path.lineTo(38f, 78f)
                canvas.drawPath(path, stroke)
            }

            TvGlyph.REFRESH -> {
                oval.set(16f, 16f, 84f, 84f)
                canvas.drawArc(oval, 40f, 280f, false, stroke)
                path.reset()
                path.moveTo(64f, 14f)
                path.lineTo(86f, 24f)
                path.lineTo(70f, 38f)
                canvas.drawPath(path, stroke)
            }

            TvGlyph.EXPORT -> {
                path.reset()
                path.moveTo(24f, 58f)
                path.lineTo(24f, 84f)
                path.lineTo(76f, 84f)
                path.lineTo(76f, 58f)
                canvas.drawPath(path, stroke)
                path.reset()
                path.moveTo(50f, 66f)
                path.lineTo(50f, 14f)
                path.moveTo(34f, 30f)
                path.lineTo(50f, 14f)
                path.lineTo(66f, 30f)
                canvas.drawPath(path, stroke)
            }

            TvGlyph.TRASH -> {
                path.reset()
                path.moveTo(22f, 28f)
                path.lineTo(78f, 28f)
                path.moveTo(40f, 28f)
                path.lineTo(40f, 18f)
                path.lineTo(60f, 18f)
                path.lineTo(60f, 28f)
                path.moveTo(31f, 28f)
                path.lineTo(36f, 86f)
                path.lineTo(64f, 86f)
                path.lineTo(69f, 28f)
                path.moveTo(44f, 42f)
                path.lineTo(46f, 72f)
                path.moveTo(56f, 42f)
                path.lineTo(54f, 72f)
                canvas.drawPath(path, stroke)
            }
        }
    }
}
