package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.os.SystemClock
import android.view.View
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Honest progress display.
 *
 * A determinate fill is only drawn when a real fraction is known (completed/total collectors).
 * Without a trustworthy denominator the bar renders an indeterminate travelling segment - it never
 * fakes a percentage.
 */
class TvProgressBar @JvmOverloads constructor(
    context: Context,
    trackHeightDp: Int = 10,
) : View(context) {

    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = context.getColor(R.color.tv_glass_stroke)
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = context.getColor(R.color.tv_accent)
    }
    private val segmentPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = context.getColor(R.color.tv_accent_soft)
    }
    private val rect = RectF()
    private val barHeight: Int = TvTheme.dp(context, trackHeightDp).coerceAtLeast(2)

    private var fraction: Float? = null

    fun setFraction(value: Float?) {
        fraction = value?.coerceIn(0f, 1f)
        invalidate()
        if (fraction == null && isAttachedToWindow) postInvalidateOnAnimation()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val fallbackWidth = TvTheme.dp(context, 240)
        val width = resolveSize(maxOf(suggestedMinimumWidth, fallbackWidth), widthMeasureSpec)
        setMeasuredDimension(width, barHeight)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (fraction == null) postInvalidateOnAnimation()
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
        fraction = null
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val width = width.toFloat()
        if (width <= 0f) return
        val height = height.toFloat()
        val radius = height / 2f
        rect.set(0f, 0f, width, height)
        canvas.drawRoundRect(rect, radius, radius, trackPaint)

        val known = fraction
        if (known != null) {
            if (known > 0f) {
                rect.set(0f, 0f, width * known, height)
                canvas.drawRoundRect(rect, radius, radius, fillPaint)
            }
            return
        }

        // No trustworthy denominator: a slow travelling segment communicates activity honestly.
        val segmentWidth = width * 0.28f
        val travel = (width - segmentWidth).coerceAtLeast(1f)
        val phase = (SystemClock.uptimeMillis() % 1900L) / 1900f
        val left = travel * phase
        rect.set(left, 0f, left + segmentWidth, height)
        canvas.drawRoundRect(rect, radius, radius, segmentPaint)
        if (isAttachedToWindow) postInvalidateOnAnimation()
    }
}
