package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import de.visiongaia.gedefense.tv.ui.TvTheme

/**
 * Shared composition for every TV screen (VGT GLASS 2100 TV-native design):
 * - Header row: Left title block (eyebrow, 22sp title, subtitle, status chips) + Right action buttons
 * - Single scrollable/dashboard content zone with full vertical height (no clipped docked bars)
 * - Calibrated for canonical 960x540 dp coordinate space across 1080p, 2K and 4K TV panels
 */
class ScreenScaffold(context: Context) : LinearLayout(context) {

    private val header = LinearLayout(context)
    private val titleColumn = LinearLayout(context)
    private val eyebrowView = TvTheme.sectionLabel(context, "").apply {
        visibility = GONE
        setTextColor(TvTheme.accent)
    }
    private val titleView = TvTheme.textView(context, "", TvTheme.TEXT_TITLE_SP, TvTheme.textPrimary, bold = true).apply {
        setLineSpacing(0f, 1.03f)
        maxWidth = TvTheme.scaledDp(context, 900)
    }
    private val subtitleView = TvTheme.textView(context, "", TvTheme.TEXT_BODY_SP, TvTheme.textSecondary).apply {
        visibility = GONE
        setLineSpacing(0f, 1.14f)
        maxWidth = TvTheme.scaledDp(context, 850)
    }
    private val statusRow = horizontalRow(context).apply { visibility = GONE }

    private val actionBar = horizontalRow(context).apply {
        gravity = Gravity.END or Gravity.CENTER_VERTICAL
        isFocusable = false
    }

    private val scroll = ScrollView(context)
    private val scrollStepPx: Int = TvTheme.scaledDp(context, 100)
    private var headerSpacer: View? = null
    private var primaryView: View? = null

    /** Vertical container for screen-specific content. */
    val content: LinearLayout = verticalColumn(context)

    init {
        orientation = VERTICAL
        layoutParams = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
        )

        header.orientation = HORIZONTAL
        header.gravity = Gravity.CENTER_VERTICAL
        header.isFocusable = false

        titleColumn.orientation = VERTICAL
        titleColumn.isFocusable = false
        eyebrowView.setPadding(0, 0, 0, TvTheme.scaledDp(context, 4))
        subtitleView.setPadding(0, TvTheme.scaledDp(context, 4), 0, 0)
        statusRow.setPadding(0, TvTheme.scaledDp(context, 8), 0, 0)
        titleColumn.addView(eyebrowView)
        titleColumn.addView(titleView)
        titleColumn.addView(subtitleView)
        titleColumn.addView(statusRow)

        header.addView(
            titleColumn,
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        header.addView(
            actionBar,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                leftMargin = TvTheme.scaledDp(context, 16)
            },
        )

        val screenWidthDp = context.resources.configuration.screenWidthDp.takeIf { it > 0 } ?: 960
        val density = context.resources.displayMetrics.density
        val availableContentDp = (screenWidthDp - TvTheme.RAIL_WIDTH_DP - 48).coerceAtLeast(320)
        val maxContentDp = TvTheme.contentMaxWidthDp(context)
        val sideInset = if (availableContentDp > maxContentDp) {
            (((availableContentDp - maxContentDp) / 2f) * density).toInt()
        } else {
            0
        }
        header.setPadding(sideInset, 0, sideInset, 0)
        addView(
            header,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )

        headerSpacer = spacer(context, 8).also { addView(it) }

        scroll.isVerticalScrollBarEnabled = false
        scroll.overScrollMode = OVER_SCROLL_NEVER
        scroll.isFillViewport = true
        scroll.clipToPadding = true
        scroll.clipChildren = true
        val frameInset = TvTheme.dp(context, TvTheme.FOCUS_STROKE_DP)
        scroll.setPadding(sideInset + frameInset, frameInset, sideInset + frameInset, frameInset)
        scroll.isFocusable = true
        scroll.isFocusableInTouchMode = false
        scroll.isClickable = false
        scroll.descendantFocusability = ViewGroup.FOCUS_AFTER_DESCENDANTS
        scroll.setDefaultFocusHighlightEnabled(false)
        scroll.setOnFocusChangeListener { _, hasFocus ->
            scroll.background = if (hasFocus) readingFocusFrame() else null
        }
        scroll.setOnKeyListener { view, keyCode, event ->
            if (event.action != KeyEvent.ACTION_DOWN || !view.hasFocus()) {
                false
            } else {
                when (keyCode) {
                    KeyEvent.KEYCODE_DPAD_DOWN -> if (view.canScrollVertically(1)) {
                        view.scrollBy(0, scrollStepPx)
                        true
                    } else {
                        false
                    }

                    KeyEvent.KEYCODE_DPAD_UP -> if (view.canScrollVertically(-1)) {
                        view.scrollBy(0, -scrollStepPx)
                        true
                    } else {
                        false
                    }

                    else -> false
                }
            }
        }
        content.setPadding(0, 0, 0, TvTheme.scaledDp(context, 16))
        content.clipChildren = false
        content.clipToPadding = false
        scroll.addView(
            content,
            FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        // Full height for content: no docked bottom bars clipping scrolling cards
        addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        // Single entrance transition per created screen (no continuous motion).
        translationY = TvTheme.scaledDp(context, 10).toFloat()
        alpha = 1f
        post {
            if (isAttachedToWindow) {
                alpha = 0.94f
                animate()
                    .alpha(1f)
                    .translationY(0f)
                    .setDuration(TvTheme.MOTION_ENTER)
                    .setInterpolator(DecelerateInterpolator())
                    .start()
            } else {
                alpha = 1f
                translationY = 0f
            }
        }
    }

    /** Visible focus frame for the reading viewport (3dp bright-gold ring). */
    private fun readingFocusFrame(): GradientDrawable = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = TvTheme.dp(context, TvTheme.RADIUS_CONTROL_DP).toFloat()
        setColor(Color.TRANSPARENT)
        setStroke(TvTheme.dp(context, TvTheme.FOCUS_STROKE_DP).coerceAtLeast(1), TvTheme.goldBright)
    }

    fun setEyebrow(text: CharSequence) {
        eyebrowView.text = text
        eyebrowView.visibility = if (text.isBlank()) GONE else VISIBLE
    }

    fun setTitle(text: CharSequence) {
        titleView.text = text
    }

    fun setSubtitle(text: CharSequence?) {
        subtitleView.text = text ?: ""
        subtitleView.visibility = if (text.isNullOrBlank()) GONE else VISIBLE
    }

    /** Hero-first screens (Home) hide the standard header and compose their own hero block. */
    fun hideHeader() {
        header.visibility = GONE
        headerSpacer?.visibility = GONE
    }

    fun addStatus(view: View) {
        statusRow.visibility = VISIBLE
        statusRow.addView(
            view,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { rightMargin = TvTheme.scaledDp(context, 8) },
        )
    }

    fun addAction(action: View, primary: Boolean = false) {
        actionBar.visibility = VISIBLE
        actionBar.addView(
            action,
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply {
                if (actionBar.childCount > 1) leftMargin = TvTheme.scaledDp(context, 10)
            },
        )
        if (primary || primaryView == null) primaryView = action
    }

    fun primaryFocus(): View? = primaryView

    /** Registers a hero/screen-owned control as the initial D-pad focus without moving it. */
    fun setPrimaryFocus(view: View) {
        primaryView = view
    }

    /**
     * D-pad focus connection: DOWN from the header action enters the first list row,
     * UP from the first row returns to the header action.
     */
    fun linkFocusChain(firstRow: View?, lastRow: View?) {
        val action = primaryView ?: return
        val first = firstRow ?: return
        if (action.id == View.NO_ID) action.id = View.generateViewId()
        if (first.id == View.NO_ID) first.id = View.generateViewId()
        action.nextFocusDownId = first.id
        first.nextFocusUpId = action.id
        val last = lastRow ?: first
        if (last.id == View.NO_ID) last.id = View.generateViewId()
    }

    fun hideActions() {
        actionBar.visibility = GONE
    }

    fun addSection(title: CharSequence, meta: CharSequence? = null, topSpacingDp: Int = 16) {
        if (content.childCount > 0) content.addSpacer(topSpacingDp)
        content.addView(SectionHeader(context, title, meta))
        content.addSpacer(6)
    }

    fun addParagraph(text: CharSequence, topSpacingDp: Int = 8) {
        if (content.childCount > 0) content.addSpacer(topSpacingDp)
        content.addView(bodyText(context, text))
    }

    fun addCaption(text: CharSequence, topSpacingDp: Int = 6) {
        if (content.childCount > 0) content.addSpacer(topSpacingDp)
        content.addView(captionText(context, text))
    }

    fun addFullWidth(view: View, topSpacingDp: Int = 12) {
        if (content.childCount > 0) content.addSpacer(topSpacingDp)
        content.addView(
            view,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
    }

    fun gravityCenter(): ScreenScaffold = apply {
        content.gravity = Gravity.START
    }
}
