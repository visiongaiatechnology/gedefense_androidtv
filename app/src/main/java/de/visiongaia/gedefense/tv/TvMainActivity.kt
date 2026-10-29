package de.visiongaia.gedefense.tv

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import de.visiongaia.gedefense.tv.core.model.ContainmentRecord
import de.visiongaia.gedefense.tv.core.model.ContainmentState
import de.visiongaia.gedefense.tv.ui.ContainmentNotifier
import de.visiongaia.gedefense.tv.ui.NavItem
import de.visiongaia.gedefense.tv.ui.ScreenHost
import de.visiongaia.gedefense.tv.ui.ScreenRegistry
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvScreen
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.TvGlyph

/**
 * Single-activity TV shell: left D-pad navigation rail + content area with a bounded back stack.
 *
 * The activity owns all navigation and window concerns. Screens never start activities or touch
 * the back stack; they receive a [ScreenHost]. Every screen is reachable and operable with a TV
 * remote (D-pad + OK + BACK); touch/mouse are optional extras, never a requirement.
 */
class TvMainActivity : Activity(), ScreenHost {

    private lateinit var services: TvServices
    private lateinit var registry: ScreenRegistry

    private lateinit var root: FrameLayout
    private lateinit var rail: LinearLayout
    private lateinit var contentFrame: FrameLayout
    private lateinit var overlayHost: FrameLayout

    private val railItems = LinkedHashMap<TvRoute, LinearLayout>()
    private val stack = ArrayList<ScreenEntry>()

    private data class ScreenEntry(val route: TvRoute, val argument: String?, val screen: TvScreen)

    /** The first onResume belongs to onCreate; later resumes may need a data refresh. */
    private var firstResume = true

    private val current: ScreenEntry? get() = stack.lastOrNull()

    private val topLevelRoutes: Set<TvRoute> = setOf(
        TvRoute.ONBOARDING,
        TvRoute.PROTECTION,
        TvRoute.TRAFFIC,
        TvRoute.XDR,
        TvRoute.HOME,
        TvRoute.CHECK,
        TvRoute.FINDINGS,
        TvRoute.APPS,
        TvRoute.HARDENING,
        TvRoute.THREAT_INTEL,
        TvRoute.EVIDENCE,
        TvRoute.SETTINGS,
    )

    private var railVisible = true
    private var cappedContentWidthPx = 0
    private var welcomeShown = false
    private var welcomeOverlay: View? = null
    private var syncOverlay: View? = null
    private var syncOverlayText: TextView? = null
    private var syncOverlayProgress: android.widget.ProgressBar? = null
    private var containmentOverlay: View? = null
    private var containmentRecordId: String? = null
    private var containmentCountdown: TextView? = null
    private val containmentHandler = Handler(Looper.getMainLooper())
    private var containmentCountdownTick: Runnable? = null
    private val containmentListener = ContainmentNotifier.Listener { record ->
        runOnUiThread { onContainmentChanged(record) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val onCreateStartedAt = System.nanoTime()
        services = TvServices.get(this)
        registry = ScreenRegistry(services)
        ContainmentNotifier.addListener(containmentListener)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        applyImmersiveLayout()
        root = buildRoot()
        setContentView(root)
        val shellBuiltAt = System.nanoTime()
        // SECV2-11: the route extra is a QA/navigation convenience for debug builds only.
        val requestedRoute = if (BuildConfig.DEBUG) {
            intent?.getStringExtra("route")?.let { name ->
                TvRoute.values().firstOrNull { it.name.equals(name, ignoreCase = true) }
            }
        } else {
            null
        }
        val setupDone = try {
            services.settings.protectionSetupDone()
        } catch (_: Throwable) {
            true
        }
        val targetRoute = requestedRoute ?: if (setupDone) TvRoute.HOME else TvRoute.ONBOARDING
        navigate(targetRoute, null)
        val navigateDoneAt = System.nanoTime()
        // Startup instrumentation: TV cold start is a product requirement (no black screen, fast hero).
        root.post {
            val firstFrameQueuedAt = System.nanoTime()
            android.util.Log.i(
                "GeDefenseTv",
                "startup shell=${(shellBuiltAt - onCreateStartedAt) / 1_000_000}ms " +
                    "navigate=${(navigateDoneAt - shellBuiltAt) / 1_000_000}ms " +
                    "firstFrameQueued=${(firstFrameQueuedAt - navigateDoneAt) / 1_000_000}ms",
            )
            if (setupDone && targetRoute != TvRoute.ONBOARDING && !welcomeShown) {
                welcomeShown = true
                showWelcomeOverlay()
            }
            if (BuildConfig.DEBUG && intent?.getStringExtra("debugContainment") == "1") {
                Thread({
                    runCatching {
                        val applied = (services.containment as? de.visiongaia.gedefense.tv.data.TvContainmentStore)
                            ?.applyDebugTestContainment()
                        android.util.Log.i("GeDefenseTvKinetic", "debug containment result=" + (applied?.id ?: "null"))
                    }.onFailure { error -> android.util.Log.w("GeDefenseTvKinetic", "debug containment failed " + error::class.java.simpleName) }
                }, "gedefense-debug-containment").start()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        applyImmersiveLayout()
        if (firstResume) {
            firstResume = false
            return
        }
        // Returning from background or another app must never show stale scan data on the overview.
        if (current?.route == TvRoute.HOME) {
            showTop(recreate = true)
        }
    }

    override fun onNewIntent(intent: android.content.Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!BuildConfig.DEBUG) return
        val targetRoute = intent?.getStringExtra("route")?.let { name ->
            TvRoute.values().firstOrNull { it.name.equals(name, ignoreCase = true) }
        } ?: return
        navigate(targetRoute, null)
    }

    // ---------------------------------------------------------------- layout

    private fun applyImmersiveLayout() {
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
                View.SYSTEM_UI_FLAG_FULLSCREEN or
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
    }

    private fun buildRoot(): FrameLayout {
        val overscan = TvTheme.dp(this, TvTheme.OVERSCAN_DP)
        val rootView = FrameLayout(this).apply {
            setBackgroundColor(TvTheme.bgDeep)
        }

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
        }

        rail = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(TvTheme.dp(this@TvMainActivity, TvTheme.RAIL_WIDTH_DP), ViewGroup.LayoutParams.MATCH_PARENT)
            setPadding(overscan, overscan, TvTheme.dp(this@TvMainActivity, 10), overscan)
            background = TvTheme.verticalGradient(
                android.graphics.Color.rgb(13, 18, 24),
                android.graphics.Color.rgb(5, 8, 11),
            )
        }

        contentFrame = FrameLayout(this).apply {
            setPadding(TvTheme.dp(this@TvMainActivity, 16), overscan, overscan, overscan)
            isFocusable = true
            isFocusableInTouchMode = false
            setDefaultFocusHighlightEnabled(false)
        }

        // Wide TV panels: cap the usable content width and centre it instead of stretching a
        // single column across the whole panel. On the 1080p baseline the available width is the
        // limiting factor and behaviour is unchanged.
        val railWidthPx = TvTheme.dp(this, TvTheme.RAIL_WIDTH_DP)
        val availableWidthPx = (resources.displayMetrics.widthPixels - railWidthPx).coerceAtLeast(TvTheme.dp(this, 320))
        cappedContentWidthPx = minOf(availableWidthPx, TvTheme.dp(this, TvTheme.contentMaxWidthDp(this)))
        val contentHost = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f)
        }
        contentHost.addView(
            contentFrame,
            FrameLayout.LayoutParams(cappedContentWidthPx, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.CENTER_HORIZONTAL),
        )

        overlayHost = FrameLayout(this).apply {
            layoutParams = FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            isClickable = false
            isFocusable = false
        }

        buildRail()
        column.addView(rail)
        column.addView(contentHost)
        rootView.addView(column)
        rootView.addView(overlayHost)
        return rootView
    }

    private fun buildRail() {
        rail.removeAllViews()
        railItems.clear()

        // Brand lockup: original GeDefense shield asset + wordmark (VGT-owned product identity).
        val brandRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, TvTheme.dp(this@TvMainActivity, 6))
        }
        val logo = ImageView(this).apply {
            setImageBitmap(brandLogoBitmap(TvTheme.dp(this@TvMainActivity, 40)))
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = getString(R.string.brand_logo_description)
        }
        brandRow.addView(
            logo,
            LinearLayout.LayoutParams(TvTheme.dp(this, 40), TvTheme.dp(this, 40)).apply {
                rightMargin = TvTheme.dp(this@TvMainActivity, 10)
            },
        )
        val wordmark = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
        }
        wordmark.addView(
            TvTheme.textView(this, "GeDefense", TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
        )
        wordmark.addView(
            TvTheme.textView(this, "T V", TvTheme.TEXT_MICRO_SP, TvTheme.accent).apply {
                letterSpacing = 0.4f
            },
        )
        brandRow.addView(wordmark)
        rail.addView(brandRow)
        rail.addView(
            TvTheme.textView(this, getString(R.string.brand_rail_caption), TvTheme.TEXT_MICRO_SP, TvTheme.textDim).apply {
                letterSpacing = 0.02f
                setPadding(TvTheme.dp(this@TvMainActivity, 2), TvTheme.dp(this@TvMainActivity, 2), 0, 0)
            },
        )
        rail.addView(railDivider())

        // The nav rail must stay operable on short TV viewports: items live in a focusable
        // ScrollView so D-pad focus automatically scrolls the selected entry into view.
        val navScroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            isHorizontalScrollBarEnabled = false
            isFocusable = false
            isFocusableInTouchMode = false
            overScrollMode = View.OVER_SCROLL_NEVER
            setPadding(0, TvTheme.dp(this@TvMainActivity, 4), 0, 0)
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        val navColumn = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        for (item: NavItem in registry.routesForRail()) {
            val entry = buildRailItem(item)
            railItems[item.route] = entry
            navColumn.addView(entry)
            navColumn.addView(spacer(TvTheme.dp(this, 2)))
        }
        navScroll.addView(navColumn)
        rail.addView(navScroll)

        rail.addView(railDivider())
        val version = tvVersionLabel()
        rail.addView(
            TvTheme.textView(this, version, TvTheme.TEXT_MICRO_SP, TvTheme.textDim).apply {
                setPadding(TvTheme.dp(this@TvMainActivity, 14), TvTheme.dp(this@TvMainActivity, 4), 0, 0)
            },
        )
    }

    private fun railDivider(): View = View(this).apply {
        setBackgroundColor(TvTheme.glassStroke)
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 1).apply {
            topMargin = TvTheme.dp(this@TvMainActivity, 6)
            bottomMargin = TvTheme.dp(this@TvMainActivity, 4)
        }
    }

    private fun spacer(heightPx: Int): View = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(1, heightPx)
    }

    private fun buildRailItem(item: NavItem): LinearLayout {
        val label = getString(item.labelRes)
        val accentBar = View(this).apply {
            setBackgroundColor(TvTheme.accent)
            layoutParams = LinearLayout.LayoutParams(TvTheme.dp(this@TvMainActivity, 3), ViewGroup.LayoutParams.MATCH_PARENT)
            alpha = 0f
        }
        val text = TvTheme.textView(this, label, TvTheme.TEXT_LABEL_SP, TvTheme.textSecondary).apply {
            setPadding(TvTheme.dp(this@TvMainActivity, 12), TvTheme.dp(this@TvMainActivity, 7), TvTheme.dp(this@TvMainActivity, 8), TvTheme.dp(this@TvMainActivity, 7))
        }
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            isFocusable = true
            isFocusableInTouchMode = false
            isClickable = true
            setDefaultFocusHighlightEnabled(false)
            contentDescription = getString(item.descriptionRes)
            addView(accentBar)
            addView(text)
            background = railItemBackground(focused = false)
            setOnFocusChangeListener { _, hasFocus ->
                accentBar.alpha = if (hasFocus) 1f else 0f
                text.setTextColor(if (hasFocus) TvTheme.goldBright else TvTheme.textSecondary)
                background = railItemBackground(hasFocus)
                animate()
                    .scaleX(if (hasFocus) 1.03f else 1f)
                    .scaleY(if (hasFocus) 1.03f else 1f)
                    .setDuration(TvTheme.MOTION_FAST)
                    .start()
            }
            setOnClickListener {
                if (stack.lastOrNull()?.route != item.route) {
                    navigate(item.route, null)
                }
            }
        }
        return row
    }

    private fun railItemBackground(focused: Boolean) = TvTheme.glassPanelBackground(
        this,
        fill = if (focused) android.graphics.Color.argb(215, 46, 36, 16) else android.graphics.Color.TRANSPARENT,
        stroke = if (focused) TvTheme.accent else android.graphics.Color.TRANSPARENT,
        radiusDp = TvTheme.RADIUS_CONTROL_DP,
    )

    private fun tvVersionLabel(): String = "v${services.appVersionName} (${services.appVersionCode})"

    /**
     * Decodes the brand logo sampled to the rail target size.
     *
     * Decoding the full 512px asset on the startup path wastes heap and GPU upload time on TV
     * hardware; the rail shows a 54dp mark, so a power-of-two downsample is enough for a crisp
     * result while keeping cold start cheap.
     */
    private fun brandLogoBitmap(targetPx: Int): android.graphics.Bitmap? {
        return try {
            val bounds = android.graphics.BitmapFactory.Options().apply { inJustDecodeBounds = true }
            android.graphics.BitmapFactory.decodeResource(resources, R.drawable.gedefense_logo, bounds)
            var sample = 1
            val smallest = minOf(bounds.outWidth, bounds.outHeight).coerceAtLeast(1)
            while (smallest / (sample * 2) >= targetPx) sample *= 2
            val options = android.graphics.BitmapFactory.Options().apply {
                inSampleSize = sample
                inPreferredConfig = android.graphics.Bitmap.Config.ARGB_8888
            }
            android.graphics.BitmapFactory.decodeResource(resources, R.drawable.gedefense_logo, options)
        } catch (_: Throwable) {
            null
        }
    }

    // ------------------------------------------------- shell overlays / host

    override fun activity(): Activity = this

    override fun setRailVisible(visible: Boolean) {
        if (railVisible == visible) return
        railVisible = visible
        rail.visibility = if (visible) View.VISIBLE else View.GONE
        contentFrame.layoutParams = FrameLayout.LayoutParams(
            if (visible) cappedContentWidthPx else ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
            Gravity.CENTER_HORIZONTAL,
        )
    }

    /**
     * Sir Quacksec welcome animation, shown once per app start after the first frame.
     * Deliberately short and skippable: TV users must never wait for mascot theatre.
     */
    override fun showWelcomeOverlay() {
        if (welcomeOverlay != null) return
        val scrim = FrameLayout(this).apply {
            setBackgroundColor(android.graphics.Color.argb(170, 2, 4, 6))
            isClickable = true
            isFocusable = false
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(TvTheme.dp(this@TvMainActivity, 28), TvTheme.dp(this@TvMainActivity, 22), TvTheme.dp(this@TvMainActivity, 32), TvTheme.dp(this@TvMainActivity, 22))
            background = TvTheme.glassPanelBackground(this@TvMainActivity, TvTheme.glassPanel, TvTheme.accent, 18)
            alpha = 0f
            translationY = TvTheme.dp(this@TvMainActivity, 18).toFloat()
        }
        val mascot = ImageView(this).apply {
            setImageResource(R.drawable.sir_quacksec)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = getString(R.string.welcome_mascot_description)
        }
        card.addView(
            mascot,
            LinearLayout.LayoutParams(TvTheme.dp(this, 96), TvTheme.dp(this, 116)).apply {
                rightMargin = TvTheme.dp(this@TvMainActivity, 22)
            },
        )
        val textColumn = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        textColumn.addView(
            TextView(this).apply {
                text = getString(R.string.welcome_title)
                setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_HEADING_SP)
                setTextColor(TvTheme.accent)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            },
        )
        textColumn.addView(
            TextView(this).apply {
                text = getString(R.string.welcome_subtitle)
                setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_BODY_SP)
                setTextColor(TvTheme.textPrimary)
                setPadding(0, TvTheme.dp(this@TvMainActivity, 6), 0, 0)
            },
        )
        card.addView(textColumn)
        scrim.addView(
            card,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER,
            ).apply {
                leftMargin = TvTheme.dp(this@TvMainActivity, 32)
                rightMargin = TvTheme.dp(this@TvMainActivity, 32)
            },
        )
        overlayHost.addView(scrim)
        welcomeOverlay = scrim
        card.animate().alpha(1f).translationY(0f).setDuration(TvTheme.MOTION_ENTER).start()
        scrim.postDelayed({
            if (welcomeOverlay === scrim) hideWelcomeOverlay()
        }, 3200)
    }

    private fun hideWelcomeOverlay() {
        val overlay = welcomeOverlay ?: return
        welcomeOverlay = null
        overlay.animate().alpha(0f).setDuration(TvTheme.MOTION_FAST).withEndAction {
            overlayHost.removeView(overlay)
        }
    }

    override fun showSyncOverlay(title: String) {
        if (syncOverlay != null) return
        val scrim = FrameLayout(this).apply {
            setBackgroundColor(android.graphics.Color.argb(178, 2, 4, 6))
            isClickable = true
            isFocusable = false
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(TvTheme.dp(this@TvMainActivity, 36), TvTheme.dp(this@TvMainActivity, 26), TvTheme.dp(this@TvMainActivity, 36), TvTheme.dp(this@TvMainActivity, 26))
            background = TvTheme.heroBackground(this@TvMainActivity)
            alpha = 0f
        }
        card.addView(
            ImageView(this).apply {
                setImageBitmap(brandLogoBitmap(TvTheme.dp(this@TvMainActivity, 72)))
                contentDescription = getString(R.string.brand_logo_description)
            },
            LinearLayout.LayoutParams(TvTheme.dp(this, 72), TvTheme.dp(this, 72)).apply {
                bottomMargin = TvTheme.dp(this@TvMainActivity, 14)
            },
        )
        card.addView(
            TextView(this).apply {
                text = title
                setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_HEADING_SP)
                setTextColor(TvTheme.accent)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
                gravity = Gravity.CENTER
            },
        )
        val status = TextView(this).apply {
            text = getString(R.string.sync_overlay_starting)
            setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_LABEL_SP)
            setTextColor(TvTheme.textSecondary)
            setPadding(0, TvTheme.dp(this@TvMainActivity, 6), 0, TvTheme.dp(this@TvMainActivity, 12))
            gravity = Gravity.CENTER
        }
        syncOverlayText = status
        card.addView(status)
        val progress = android.widget.ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            progress = 0
            isIndeterminate = true
        }
        syncOverlayProgress = progress
        card.addView(
            progress,
            LinearLayout.LayoutParams(TvTheme.dp(this, 320), TvTheme.dp(this, 8)),
        )
        scrim.addView(
            card,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER,
            ),
        )
        overlayHost.addView(scrim)
        syncOverlay = scrim
        card.animate().alpha(1f).setDuration(TvTheme.MOTION_STANDARD).start()
    }

    override fun updateSyncOverlay(completed: Int, total: Int) {
        val text = syncOverlayText ?: return
        val progress = syncOverlayProgress ?: return
        if (total <= 0) {
            text.text = getString(R.string.sync_overlay_running)
            progress.isIndeterminate = true
        } else {
            val clamped = completed.coerceIn(0, total)
            text.text = getString(R.string.sync_overlay_progress, clamped, total)
            progress.isIndeterminate = false
            progress.max = total
            progress.progress = clamped
        }
    }

    override fun hideSyncOverlay() {
        val overlay = syncOverlay ?: return
        syncOverlay = null
        syncOverlayText = null
        syncOverlayProgress = null
        overlay.animate().alpha(0f).setDuration(TvTheme.MOTION_FAST).withEndAction {
            overlayHost.removeView(overlay)
        }
    }

    // ------------------------------------------------ containment kill popup

    override fun onDestroy() {
        ContainmentNotifier.removeListener(containmentListener)
        containmentCountdownTick?.let { containmentHandler.removeCallbacks(it) }
        super.onDestroy()
    }

    private fun onContainmentChanged(record: ContainmentRecord) {
        when {
            record.state == ContainmentState.ACTIVE -> showContainmentOverlay(record)
            containmentRecordId == record.id -> hideContainmentOverlay()
        }
    }

    /**
     * Reversible "kill" status popup: a temporary outbound containment is explained on screen and
     * can be undone with one D-pad press. The popup never blocks the data path and never auto-releases
     * by itself; the containment expires by its own TTL if the user does nothing.
     */
    private fun showContainmentOverlay(record: ContainmentRecord) {
        hideContainmentOverlay()
        val scrim = FrameLayout(this).apply {
            setBackgroundColor(Color.argb(150, 2, 4, 6))
            isClickable = false
            isFocusable = false
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                TvTheme.dp(this@TvMainActivity, 26),
                TvTheme.dp(this@TvMainActivity, 20),
                TvTheme.dp(this@TvMainActivity, 26),
                TvTheme.dp(this@TvMainActivity, 20),
            )
            background = TvTheme.heroBackground(this@TvMainActivity)
            alpha = 0f
            isFocusable = false
        }
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        header.addView(
            ImageView(this).apply {
                setImageBitmap(brandLogoBitmap(TvTheme.dp(this@TvMainActivity, 34)))
                contentDescription = getString(R.string.brand_logo_description)
            },
            LinearLayout.LayoutParams(TvTheme.dp(this, 34), TvTheme.dp(this, 34)).apply {
                rightMargin = TvTheme.dp(this@TvMainActivity, 12)
            },
        )
        header.addView(
            TextView(this).apply {
                text = getString(R.string.containment_title)
                setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_HEADING_SP)
                setTextColor(TvTheme.accent)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            },
        )
        card.addView(header)
        val appName = record.appLabel?.takeIf { it.isNotBlank() } ?: record.packageName ?: getString(R.string.traffic_app_unattributed)
        card.addView(
            TextView(this).apply {
                text = getString(R.string.containment_body, appName)
                setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_BODY_SP)
                setTextColor(TvTheme.textPrimary)
                setPadding(0, TvTheme.dp(this@TvMainActivity, 10), 0, 0)
            },
        )
        card.addView(
            TextView(this).apply {
                text = getString(R.string.containment_target, record.target.value)
                setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_LABEL_SP)
                setTextColor(TvTheme.textSecondary)
                setPadding(0, TvTheme.dp(this@TvMainActivity, 6), 0, 0)
            },
        )
        val countdown = TextView(this).apply {
            setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_CAPTION_SP)
            setTextColor(TvTheme.textSecondary)
            setPadding(0, TvTheme.dp(this@TvMainActivity, 10), 0, 0)
        }
        containmentCountdown = countdown
        card.addView(countdown)
        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
            setPadding(0, TvTheme.dp(this@TvMainActivity, 16), 0, 0)
        }
        val undo = FocusableAction.primary(this, R.string.containment_undo, TvGlyph.REFRESH).apply {
            setOnClickListener {
                val released = try {
                    services.containment.release(record.id)
                } catch (_: Throwable) {
                    false
                }
                hideContainmentOverlay()
                if (released) notifyUser(getString(R.string.containment_released)) else notifyUser(getString(R.string.containment_release_failed))
            }
        }
        val ok = FocusableAction.secondary(this, R.string.containment_ok, null).apply {
            setOnClickListener { hideContainmentOverlay() }
        }
        actions.addView(undo, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            rightMargin = TvTheme.dp(this@TvMainActivity, 10)
        })
        actions.addView(ok, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        card.addView(actions)
        scrim.addView(
            card,
            FrameLayout.LayoutParams(
                TvTheme.dp(this@TvMainActivity, 620),
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.CENTER,
            ),
        )
        overlayHost.addView(scrim)
        containmentOverlay = scrim
        containmentRecordId = record.id
        card.animate().alpha(1f).setDuration(TvTheme.MOTION_STANDARD).start()
        undo.requestFocus()
        val tick = object : Runnable {
            override fun run() {
                if (containmentOverlay == null) return
                val remaining = (record.expiresAtMillis - System.currentTimeMillis()).coerceAtLeast(0L)
                containmentCountdown?.text = getString(R.string.containment_remaining, (remaining / 60_000L) + 1L)
                if (remaining <= 0L) {
                    hideContainmentOverlay()
                } else {
                    containmentHandler.postDelayed(this, 1_000L)
                }
            }
        }
        containmentCountdownTick = tick
        containmentHandler.post(tick)
        containmentHandler.removeCallbacks(autoHideContainment)
        containmentHandler.postDelayed(autoHideContainment, 15_000L)
    }

    private val autoHideContainment = Runnable { hideContainmentOverlay() }

    private fun hideContainmentOverlay() {
        containmentHandler.removeCallbacks(autoHideContainment)
        containmentCountdownTick?.let { containmentHandler.removeCallbacks(it) }
        containmentCountdownTick = null
        containmentCountdown = null
        val overlay = containmentOverlay ?: return
        containmentOverlay = null
        containmentRecordId = null
        overlay.animate().alpha(0f).setDuration(TvTheme.MOTION_FAST).withEndAction {
            overlayHost.removeView(overlay)
        }
    }

    // ------------------------------------------------------------ navigation

    override fun navigate(route: TvRoute, argument: String?) {
        val screen = registry.create(route, argument)
        if (route in topLevelRoutes) {
            clearStack()
            stack.add(ScreenEntry(route, argument, screen))
        } else {
            stack.add(ScreenEntry(route, argument, screen))
        }
        updateRailSelection(route)
        showTop()
    }

    override fun goBack(): Boolean {
        if (stack.size > 1) {
            val removed = stack.removeAt(stack.size - 1)
            removed.screen.onHidden()
            val top = stack.last()
            updateRailSelection(top.route)
            showTop(recreate = true)
            return true
        }
        val top = current ?: return false
        if (top.route != TvRoute.HOME) {
            clearStack()
            val home = registry.create(TvRoute.HOME, null)
            stack.add(ScreenEntry(TvRoute.HOME, null, home))
            updateRailSelection(TvRoute.HOME)
            showTop()
            return true
        }
        return false
    }

    override fun notifyUser(message: String) {
        val banner = TextView(this).apply {
            text = message
            setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_LABEL_SP)
            setTextColor(TvTheme.textPrimary)
            setPadding(TvTheme.dp(this@TvMainActivity, 28), TvTheme.dp(this@TvMainActivity, 16), TvTheme.dp(this@TvMainActivity, 28), TvTheme.dp(this@TvMainActivity, 16))
            background = TvTheme.glassPanelBackground(this@TvMainActivity, TvTheme.scrimHeavy, TvTheme.glassStroke, 16)
            alpha = 0f
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL,
            ).apply { bottomMargin = TvTheme.dp(this@TvMainActivity, 64) }
            isFocusable = false
        }
        overlayHost.addView(banner)
        banner.animate().alpha(1f).setDuration(160).withEndAction {
            banner.postDelayed({
                banner.animate().alpha(0f).setDuration(220).withEndAction {
                    overlayHost.removeView(banner)
                }
            }, 2600)
        }
    }

    override fun refreshCurrent() {
        showTop(recreate = true)
    }

    private fun clearStack() {
        for (entry in stack) entry.screen.onHidden()
        stack.clear()
    }

    private fun updateRailSelection(route: TvRoute) {
        val selection = registry.railSelectionFor(route)
        for ((itemRoute, itemView) in railItems) {
            val selected = itemRoute == selection
            val text = (itemView.getChildAt(1) as? TextView)
            if (!itemView.hasFocus()) {
                text?.setTextColor(if (selected) TvTheme.accent else TvTheme.textSecondary)
            }
            val accentBar = itemView.getChildAt(0)
            if (selected && !itemView.hasFocus()) accentBar.alpha = 0.55f
        }
    }

    private fun showTop(recreate: Boolean = false) {
        val entry = current ?: return
        setRailVisible(entry.route != TvRoute.ONBOARDING)
        contentFrame.removeAllViews()
        val view = entry.screen.createView(this)
        contentFrame.addView(view)
        if (!recreate) entry.screen.onShown()
        contentFrame.post {
            val focus = entry.screen.initialFocus()
            if (focus != null) {
                focus.requestFocus()
            } else {
                contentFrame.requestFocus()
            }
            // Rebuilt screens request focus before their first layout pass; retry once measured so
            // D-pad OK always reaches the intended primary action without a TAB.
            contentFrame.postDelayed({
                val again = entry.screen.initialFocus()
                if (again != null && !again.isFocused && again.isFocusable) again.requestFocus()
            }, 140)
        }
    }

    // ------------------------------------------------------------ key handling

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        if (welcomeOverlay != null) {
            hideWelcomeOverlay()
            return true
        }
        if (syncOverlay != null) {
            if (keyCode == KeyEvent.KEYCODE_BACK) hideSyncOverlay()
            return true
        }
        val entry = current
        if (entry != null && entry.screen.onKeyEvent(event)) {
            return true
        }
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            if (entry != null && entry.screen.handleBack()) return true
            if (entry?.route == TvRoute.ONBOARDING) return true
            if (goBack()) return true
        }
        return super.onKeyDown(keyCode, event)
    }
}
