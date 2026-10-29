package de.visiongaia.gedefense.tv.ui.components

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.SweepGradient
import android.graphics.Typeface
import android.view.View
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Canvas gauge used for the hero posture score and the scan progress ring.
 *
 * Both modes are drawn with anti-aliased arcs only (no bitmaps). A null score / unknown progress is
 * rendered as an honest indeterminate sweep without a fake percentage - the gauge never invents
 * precision that the model does not have.
 */
class RingGaugeView @JvmOverloads constructor(
    context: Context,
    private val diameterDp: Int = 105,
) : View(context) {

    enum class Mode { SCORE, PROGRESS }

    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = TvTheme.scaledDp(context, 7).toFloat()
        strokeCap = Paint.Cap.ROUND
        color = Color.argb(56, 120, 156, 190)
    }
    private val progressPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = TvTheme.scaledDp(context, 7).toFloat()
        strokeCap = Paint.Cap.ROUND
    }
    private val innerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = TvTheme.dp(context, 1).coerceAtLeast(1).toFloat()
        color = Color.argb(46, 244, 236, 214)
    }
    private val valuePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create("sans-serif", Typeface.BOLD)
    }
    private val unitPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
        color = TvTheme.textSecondary
    }
    private val oval = RectF()

    private var mode: Mode = Mode.SCORE
    private var valueText: String = "—"
    private var unitText: String? = null
    private var ringColor: Int = TvTheme.accent
    private var highlightColor: Int = TvTheme.goldBright
    private var indeterminate: Boolean = false
    private var targetFraction: Float = 0f
    private var displayedFraction: Float = 0f
    private var animation: ValueAnimator? = null

    private val sidePx: Int get() = TvTheme.dp(context, diameterDp)

    init {
        isFocusable = false
        isClickable = false
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    /** Score mode: numeric value or null for an honest unknown state. */
    fun setScore(value: Int?, tone: Int, highlight: Int) {
        mode = Mode.SCORE
        ringColor = tone
        highlightColor = highlight
        indeterminate = value == null
        valueText = value?.toString() ?: "—"
        unitText = if (value == null) null else context.getString(de.visiongaia.gedefense.tv.R.string.posture_score_unit)
        animateTo(if (value == null) 0.82f else value.coerceIn(0, 100) / 100f)
        invalidate()
    }

    /**
     * Progress mode: fraction 0..1 when a trustworthy denominator exists, null for an indeterminate
     * sweep. [center] and [caption] are rendered inside the ring.
     */
    fun setProgress(fraction: Float?, center: String, caption: String?, tone: Int, highlight: Int) {
        mode = Mode.PROGRESS
        ringColor = tone
        highlightColor = highlight
        indeterminate = fraction == null
        valueText = center
        unitText = caption
        animateTo(fraction ?: 0.86f)
        invalidate()
    }

    private fun animateTo(target: Float) {
        animation?.cancel()
        val start = displayedFraction
        if (indeterminate) {
            displayedFraction = target
            invalidate()
            if (isAttachedToWindow && mode == Mode.PROGRESS) postInvalidateOnAnimation()
            return
        }
        animation = ValueAnimator.ofFloat(start, target.coerceIn(0f, 1f)).apply {
            duration = TvTheme.MOTION_ENTER
            addUpdateListener { animator ->
                displayedFraction = animator.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        setMeasuredDimension(sidePx, sidePx)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (indeterminate && mode == Mode.PROGRESS) postInvalidateOnAnimation()
    }

    override fun onDetachedFromWindow() {
        animation?.cancel()
        animation = null
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val size = width.toFloat()
        val stroke = TvTheme.scaledDp(context, 7).toFloat()
        val inset = stroke / 2f + TvTheme.scaledDp(context, 2)
        oval.set(inset, inset, size - inset, size - inset)
        val cx = size / 2f
        val cy = size / 2f

        // Track
        canvas.drawArc(oval, 0f, 360f, false, trackPaint)

        // Progress / score arc
        progressPaint.shader = SweepGradient(cx, cy, intArrayOf(ringColor, highlightColor, ringColor), floatArrayOf(0f, 0.55f, 1f))
        if (indeterminate && mode == Mode.PROGRESS) {
            // Only a genuinely running scan animates; an unknown score stays a static honest arc.
            val phase = (System.currentTimeMillis() % 1600L) / 1600f
            val startAngle = -90f + 360f * phase
            canvas.drawArc(oval, startAngle, 86f, false, progressPaint)
            if (isAttachedToWindow) postInvalidateOnAnimation()
        } else if (displayedFraction > 0f) {
            canvas.drawArc(oval, -90f, 360f * displayedFraction, false, progressPaint)
        }

        // Inner hairline for material depth
        oval.set(inset + stroke, inset + stroke, size - inset - stroke, size - inset - stroke)
        canvas.drawArc(oval, 0f, 360f, false, innerPaint)

        // Center value + caption
        val hasUnit = !unitText.isNullOrBlank()
        val valueSp = if (mode == Mode.SCORE) TvTheme.TEXT_SCORE_SP else TvTheme.TEXT_TITLE_SP
        val valuePx = android.util.TypedValue.applyDimension(
            android.util.TypedValue.COMPLEX_UNIT_SP,
            valueSp * TvTheme.layoutScale(context) * TvTheme.userScale,
            context.resources.displayMetrics,
        )
        valuePaint.textSize = valuePx
        valuePaint.color = if (indeterminate && mode == Mode.SCORE) TvTheme.textSecondary else highlightColor
        val valueBaseline = cy + if (hasUnit) valuePx * 0.12f else valuePx * 0.35f
        canvas.drawText(valueText, cx, valueBaseline, valuePaint)
        if (hasUnit) {
            val unitSp = TvTheme.TEXT_MICRO_SP
            val unitPx = android.util.TypedValue.applyDimension(
                android.util.TypedValue.COMPLEX_UNIT_SP,
                unitSp * TvTheme.layoutScale(context) * TvTheme.userScale,
                context.resources.displayMetrics,
            )
            unitPaint.textSize = unitPx
            canvas.drawText(unitText!!.uppercase(), cx, valueBaseline + TvTheme.scaledDp(context, 14), unitPaint)
        }
    }
}
