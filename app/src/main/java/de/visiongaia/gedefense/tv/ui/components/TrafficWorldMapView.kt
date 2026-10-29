package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.view.View
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.model.OriginInfo
import de.visiongaia.gedefense.tv.ui.TvTheme
import kotlin.math.abs
import kotlin.math.min
import kotlin.math.sqrt

/**
 * TV traffic world map (V2): pure platform Canvas, ambient world map bitmap, animated routes from
 * the local loopback telemetry.
 *
 * All data is derived from locally observed flows; without observations the map stays in an honest
 * "waiting" state and never shows fabricated routes. Colours use the brand gold / electric-blue
 * palette only (no neon, no purple).
 */
class TrafficWorldMapView(context: Context) : View(context) {

    data class TrafficMapRoute(
        val ownerPackage: String,
        val appLabel: String,
        val countryCode: String,
        val bytes: Long,
        val flows: Int,
        val blockedFlows: Int,
        val color: Int,
    )

    private data class CachedRoute(
        val route: TrafficMapRoute,
        val path: Path?,
        val startX: Float,
        val startY: Float,
        val controlX: Float,
        val controlY: Float,
        val endX: Float,
        val endY: Float,
        val weight: Float,
        val particleOffset: Float,
    )

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val mapRect = RectF()
    private val projectionRect = RectF()
    private var surfaceShader: Shader? = null
    private var vignetteShader: Shader? = null

    private var origin: OriginInfo = OriginInfo(null, null, "")
    private var routes: List<TrafficMapRoute> = emptyList()
    private var cachedRoutes: List<CachedRoute> = emptyList()
    private var originHud: String = ""
    private var summaryHud: String = context.getString(R.string.traffic_map_waiting)

    init {
        isFocusable = false
        isClickable = false
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_YES
        contentDescription = summaryHud
    }

    /** Binds the current snapshot: approximate origin plus aggregated country routes. */
    fun setData(nextOrigin: OriginInfo, nextRoutes: List<TrafficMapRoute>) {
        origin = nextOrigin
        routes = nextRoutes
            .filter { it.bytes > 0L || it.flows > 0 }
            .sortedByDescending { it.bytes }
            .take(MAX_ROUTES)
        rebuildRouteCache()
        updateHudCache()
        invalidate()
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        if (w <= 0 || h <= 0) return
        val inset = TvTheme.dp(context, 4).toFloat()
        mapRect.set(inset, inset, w - inset, h - inset)
        val padX = TvTheme.dp(context, 8).toFloat()
        projectionRect.set(
            mapRect.left + padX,
            mapRect.top + TvTheme.dp(context, 6).toFloat(),
            mapRect.right - padX,
            mapRect.bottom - TvTheme.dp(context, 6).toFloat(),
        )
        surfaceShader = LinearGradient(
            mapRect.left,
            mapRect.top,
            mapRect.right,
            mapRect.bottom,
            intArrayOf(Color.argb(220, 10, 15, 21), Color.argb(238, 5, 8, 12)),
            null,
            Shader.TileMode.CLAMP,
        )
        vignetteShader = RadialGradient(
            mapRect.centerX(),
            mapRect.centerY(),
            (mapRect.width()).coerceAtLeast(1f) * 0.62f,
            intArrayOf(Color.argb(0, 10, 15, 21), Color.argb(0, 10, 15, 21), Color.argb(150, 4, 7, 10)),
            floatArrayOf(0f, 0.6f, 1f),
            Shader.TileMode.CLAMP,
        )
        rebuildRouteCache()
        invalidate()
    }

    override fun onDetachedFromWindow() {
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (mapRect.width() <= 0f || mapRect.height() <= 0f) return
        drawSurface(canvas)
        drawWorld(canvas)
        drawRoutes(canvas)
        drawHud(canvas)
        if (routes.isNotEmpty() && isAttachedToWindow) postInvalidateOnAnimation()
    }

    private fun drawSurface(canvas: Canvas) {
        paint.style = Paint.Style.FILL
        paint.shader = surfaceShader
        val radius = TvTheme.dp(context, TvTheme.RADIUS_PANEL_DP).toFloat()
        canvas.drawRoundRect(mapRect, radius, radius, paint)
        paint.shader = null
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = TvTheme.dp(context, 1).coerceAtLeast(1).toFloat()
        paint.color = Color.argb(90, 201, 162, 75)
        canvas.drawRoundRect(mapRect, radius, radius, paint)
    }

    private fun drawWorld(canvas: Canvas) {
        val bitmap = mapBitmap ?: return
        paint.style = Paint.Style.FILL
        paint.alpha = 190
        canvas.drawBitmap(bitmap, null, projectionRect, paint)
        paint.alpha = 255
        paint.shader = vignetteShader
        canvas.drawRoundRect(mapRect, TvTheme.dp(context, TvTheme.RADIUS_PANEL_DP).toFloat(), TvTheme.dp(context, TvTheme.RADIUS_PANEL_DP).toFloat(), paint)
        paint.shader = null
    }

    private fun drawRoutes(canvas: Canvas) {
        val phase = ((System.currentTimeMillis() % 3200L) / 3200f)
        cachedRoutes.forEach { cached ->
            cached.path?.let { drawArc(canvas, cached, phase) }
            drawDestination(canvas, cached.endX, cached.endY, cached.route.color, cached.weight)
        }
        cachedRoutes.firstOrNull { it.path != null }?.let { drawOrigin(canvas, it.startX, it.startY) }
    }

    private fun drawArc(canvas: Canvas, cached: CachedRoute, phase: Float) {
        val path = cached.path ?: return
        paint.style = Paint.Style.STROKE
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeWidth = TvTheme.dp(context, 3).toFloat()
        paint.color = withAlpha(cached.route.color, 34)
        canvas.drawPath(path, paint)
        paint.strokeWidth = (TvTheme.dp(context, 1).toFloat() + cached.weight * TvTheme.dp(context, 2).toFloat())
        paint.color = withAlpha(cached.route.color, 200)
        canvas.drawPath(path, paint)

        val t = (phase + cached.particleOffset) % 1f
        val qx = bezier(cached.startX, cached.controlX, cached.endX, t)
        val qy = bezier(cached.startY, cached.controlY, cached.endY, t)
        paint.style = Paint.Style.FILL
        paint.color = withAlpha(cached.route.color, 45)
        canvas.drawCircle(qx, qy, TvTheme.dp(context, 6).toFloat(), paint)
        paint.color = withAlpha(cached.route.color, 190)
        canvas.drawCircle(qx, qy, TvTheme.dp(context, 3).toFloat(), paint)
        paint.color = Color.WHITE
        canvas.drawCircle(qx, qy, TvTheme.dp(context, 1).coerceAtLeast(1).toFloat(), paint)
    }

    private fun drawOrigin(canvas: Canvas, x: Float, y: Float) {
        paint.style = Paint.Style.FILL
        paint.color = withAlpha(TvTheme.accent, 40)
        canvas.drawCircle(x, y, TvTheme.dp(context, 14).toFloat(), paint)
        paint.color = withAlpha(TvTheme.accent, 80)
        canvas.drawCircle(x, y, TvTheme.dp(context, 8).toFloat(), paint)
        paint.color = TvTheme.goldBright
        canvas.drawCircle(x, y, TvTheme.dp(context, 3).toFloat(), paint)
    }

    private fun drawDestination(canvas: Canvas, x: Float, y: Float, color: Int, weight: Float) {
        paint.style = Paint.Style.FILL
        paint.color = withAlpha(color, 70)
        canvas.drawCircle(x, y, TvTheme.dp(context, 5).toFloat() + weight * TvTheme.dp(context, 3).toFloat(), paint)
        paint.color = color
        canvas.drawCircle(x, y, TvTheme.dp(context, 2).toFloat(), paint)
    }

    private fun drawHud(canvas: Canvas) {
        textPaint.textSize = TvTheme.TEXT_MICRO_SP * TvTheme.layoutScale(context)
        textPaint.letterSpacing = 0.06f
        textPaint.color = TvTheme.textSecondary
        canvas.drawText(originHud, mapRect.left + TvTheme.dp(context, 10), mapRect.top + TvTheme.dp(context, 13), textPaint)

        textPaint.letterSpacing = 0f
        textPaint.textSize = TvTheme.TEXT_CAPTION_SP * TvTheme.layoutScale(context)
        textPaint.color = if (routes.isEmpty()) TvTheme.textMuted else TvTheme.textPrimary
        canvas.drawText(summaryHud, mapRect.left + TvTheme.dp(context, 10), mapRect.bottom - TvTheme.dp(context, 8), textPaint)
    }

    private fun rebuildRouteCache() {
        if (projectionRect.width() <= 0f || projectionRect.height() <= 0f || routes.isEmpty()) {
            cachedRoutes = emptyList()
            return
        }
        val maxBytes = routes.maxOfOrNull { it.bytes }?.coerceAtLeast(1L) ?: 1L
        val originPoint = origin.point?.let { project(MapAnchor(it.latitude, it.longitude)) }
        cachedRoutes = routes.mapIndexedNotNull { index, route ->
            val anchor = CountryCentroids.lookup(route.countryCode) ?: return@mapIndexedNotNull null
            val end = project(anchor)
            val weight = sqrt((route.bytes.toDouble() / maxBytes.toDouble()).coerceIn(0.0, 1.0)).toFloat()
            if (originPoint == null) {
                CachedRoute(route, null, 0f, 0f, 0f, 0f, end.first, end.second, weight, (index * 0.137f) % 1f)
            } else {
                val sx = originPoint.first
                val sy = originPoint.second
                val dx = end.first - sx
                val dy = end.second - sy
                val distance = sqrt(dx * dx + dy * dy)
                val lift = min(TvTheme.dp(context, 50).toFloat(), distance * 0.22f)
                val cx = (sx + end.first) * 0.5f
                val cy = min(sy, end.second) - lift
                val path = Path().apply {
                    moveTo(sx, sy)
                    quadTo(cx, cy, end.first, end.second)
                }
                CachedRoute(route, path, sx, sy, cx, cy, end.first, end.second, weight, (index * 0.137f) % 1f)
            }
        }
    }

    private fun updateHudCache() {
        originHud = if (origin.countryCode.isNullOrBlank()) {
            context.getString(R.string.traffic_map_origin_unknown).uppercase()
        } else {
            context.getString(R.string.traffic_map_origin, origin.label).uppercase()
        }
        val top = cachedRoutes.maxByOrNull { it.route.bytes }?.route
        summaryHud = if (top == null) {
            context.getString(R.string.traffic_map_waiting)
        } else {
            "${top.appLabel.take(18)}  →  ${top.countryCode}  ·  ${formatBytes(top.bytes)}"
        }
        contentDescription = summaryHud
    }

    private fun project(anchor: MapAnchor): Pair<Float, Float> {
        val lon = anchor.longitude.coerceIn(-180.0, 180.0)
        val lat = anchor.latitude.coerceIn(-60.0, 85.0)
        val x = projectionRect.left + (((lon + 180.0) / 360.0) * projectionRect.width()).toFloat()
        val y = projectionRect.top + (((85.0 - lat) / 145.0) * projectionRect.height()).toFloat()
        return x to y
    }

    private fun bezier(a: Float, b: Float, c: Float, t: Float): Float {
        val u = 1f - t
        return u * u * a + 2f * u * t * b + t * t * c
    }

    private fun withAlpha(color: Int, alpha: Int): Int = Color.argb(
        alpha.coerceIn(0, 255),
        Color.red(color),
        Color.green(color),
        Color.blue(color),
    )

    private companion object {
        const val MAX_ROUTES = 12

        @Volatile
        private var cachedMap: Bitmap? = null

        fun mapBitmap(context: Context): Bitmap? = cachedMap
    }

    private val mapBitmap: Bitmap? = loadMapBitmap(context)

    private fun loadMapBitmap(context: Context): Bitmap? {
        cachedMap?.let { return it }
        return try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeResource(context.resources, R.drawable.world_map_ambient, bounds)
            var sample = 1
            val target = 1280
            while (bounds.outWidth > 0 && bounds.outWidth / (sample * 2) >= target) sample *= 2
            val options = BitmapFactory.Options().apply { inSampleSize = sample }
            val bitmap = BitmapFactory.decodeResource(context.resources, R.drawable.world_map_ambient, options)
            cachedMap = bitmap
            bitmap
        } catch (t: Throwable) {
            null
        }
    }
}
