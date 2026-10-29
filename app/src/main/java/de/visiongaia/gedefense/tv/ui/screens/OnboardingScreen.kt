package de.visiongaia.gedefense.tv.ui.screens

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.ScanListener
import de.visiongaia.gedefense.tv.contract.ThreatIntelSyncListener
import de.visiongaia.gedefense.tv.contract.VpnStateListener
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ScanProgress
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import de.visiongaia.gedefense.tv.core.model.VpnState
import de.visiongaia.gedefense.tv.core.model.VpnStatus
import de.visiongaia.gedefense.tv.ui.ScreenHost
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvScreen
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableAction
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.GlassPanel
import de.visiongaia.gedefense.tv.ui.components.GlyphBadge
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvFormat
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvProgressBar
import de.visiongaia.gedefense.tv.ui.components.TvTone
import de.visiongaia.gedefense.tv.ui.components.bodyText
import de.visiongaia.gedefense.tv.ui.components.captionText
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.components.resolveText
import de.visiongaia.gedefense.tv.ui.components.toneColor
import de.visiongaia.gedefense.tv.ui.components.visibilityLabelRes
import de.visiongaia.gedefense.tv.ui.components.vpnReasonLabel
import de.visiongaia.gedefense.tv.ui.components.vpnStateClaimRes
import de.visiongaia.gedefense.tv.ui.components.vpnStateGlyph
import de.visiongaia.gedefense.tv.ui.components.vpnStateLabelRes
import de.visiongaia.gedefense.tv.ui.components.vpnStateTone

/**
 * First-run onboarding wizard (V2, redesigned): compact two-column TV composition with a step rail,
 * brand header, content panel and a bottom-right action bar.
 *
 * Design: fixed user tokens (no enlarged type), gold only as brand accent, white text family, glass
 * cards with 12dp radius, 12/16dp rhythm, slide/fade step transitions <=180ms, no loops.
 *
 * Functionality stays unchanged: VPN consent start, threat-intel sync with onProgress, first scan,
 * summary, `setProtectionSetupDone(true)` and navigation HOME. All states are honest.
 */
internal class OnboardingScreen(private val services: TvServices) : TvScreen {

    override val route: TvRoute = TvRoute.ONBOARDING

    private lateinit var host: ScreenHost
    private var hostingContext: Context? = null
    private val context: Context get() = hostingContext ?: services.appContext

    private var stepIndex: Int = 0
    private var stepFocus: View? = null
    private var viewRoot: View? = null
    private var scrollView: ScrollView? = null
    private var contentColumn: LinearLayout? = null

    private var tiProgressBar: TvProgressBar? = null
    private var tiProgressText: TextView? = null
    private var scanProgressBar: TvProgressBar? = null
    private var scanProgressText: TextView? = null
    private var stepProgressBar: TvProgressBar? = null

    private var tiAnimator: ValueAnimator? = null
    private var scanAnimator: ValueAnimator? = null
    private var stepAnimator: ValueAnimator? = null

    private var tiFraction: Float = 0f
    private var scanFraction: Float = 0f
    private var tiCompleted: Int = 0
    private var tiTotal: Int = 0
    private var tiLastFeed: String = ""
    private var scanCompleted: Int = 0
    private var scanTotal: Int = 0

    private var syncRunning: Boolean = false
    private var syncDone: Boolean = false
    private var syncFailed: Boolean = false
    private var scanRunning: Boolean = false
    private var scanDone: Boolean = false
    private var scanFailed: Boolean = false
    private var scannedResult: ScanResult? = null

    // ------------------------------------------------------------------ lifecycle

    override fun createView(host: ScreenHost): View {
        this.host = host
        hostingContext = host as? Context
        stepFocus = null
        return buildRoot()
    }

    override fun onShown() {
        host.setRailVisible(false)
        // The shell requests focus before the first layout pass of the rebuilt screen; retry once the
        // footer action is measured so OK always lands on the primary band action.
        val target = stepFocus
        viewRoot?.post { target?.requestFocus() }
        viewRoot?.postDelayed({ if (target != null && !target.isFocused) target.requestFocus() }, 150)
    }

    override fun onHidden() {
        host.setRailVisible(true)
    }

    override fun initialFocus(): View? = stepFocus ?: viewRoot

    override fun handleBack(): Boolean {
        if (stepIndex > 0) {
            stepIndex--
            host.refreshCurrent()
        }
        // The onboarding flow never leaves through BACK; the shell additionally blocks BACK here.
        return true
    }

    // ----------------------------------------------------------------------- root

    private fun buildRoot(): View {
        val root = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
            setPadding(dp(6), dp(2), dp(6), dp(2))
        }
        viewRoot = root

        root.addView(buildHeader())
        root.addView(brandDivider())

        val body = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f,
            )
        }
        body.addView(buildStepRail())
        body.addView(buildContentArea(), LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f))
        root.addView(body)

        root.addView(brandDivider())
        root.addView(buildFooter())

        animateEntry()
        return root
    }

    private fun buildHeader(): View {
        val header = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, dp(4))
        }
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val logo = ImageView(context).apply {
            setImageResource(R.drawable.gedefense_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = text(R.string.brand_logo_description)
        }
        row.addView(logo, LinearLayout.LayoutParams(dp(32), dp(32)).apply { rightMargin = dp(10) })
        row.addView(
            TvTheme.textView(context, text(R.string.onb_brand), TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        if (stepIndex > 0) {
            val avatar = ImageView(context).apply {
                setImageResource(R.drawable.sir_quacksec)
                scaleType = ImageView.ScaleType.FIT_CENTER
                contentDescription = text(R.string.welcome_mascot_description)
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            row.addView(avatar, LinearLayout.LayoutParams(dp(40), dp(40)))
        }
        header.addView(row)

        val bar = TvProgressBar(context, 4)
        stepProgressBar = bar
        header.addView(
            bar,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(8)
            },
        )
        return header
    }

    private fun buildStepRail(): View {
        val rail = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(dp(124), ViewGroup.LayoutParams.MATCH_PARENT)
            setPadding(0, dp(6), dp(10), 0)
        }
        val labels = intArrayOf(
            R.string.onb_step_welcome,
            R.string.onb_step_model,
            R.string.onb_step_vpn,
            R.string.onb_step_ti,
            R.string.onb_step_scan,
            R.string.onb_step_done,
        )
        for (index in labels.indices) {
            val current = index == stepIndex
            val completed = index < stepIndex
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                minimumHeight = dp(32)
            }
            val rule = View(context).apply {
                setBackgroundColor(if (current) TvTheme.accent else Color.TRANSPARENT)
            }
            row.addView(rule, LinearLayout.LayoutParams(dp(3), dp(20)).apply { rightMargin = dp(7) })
            row.addView(stepBadge(index + 1, current, completed))
            row.addView(
                TvTheme.textView(
                    context,
                    text(labels[index]),
                    TvTheme.TEXT_LABEL_SP,
                    when {
                        current -> TvTheme.accent
                        completed -> TvTheme.textPrimary
                        else -> TvTheme.textSecondary
                    },
                    bold = current,
                ).apply { maxLines = 1 },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(7) },
            )
            rail.addView(row, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                bottomMargin = dp(3)
            })
        }
        return rail
    }

    private fun stepBadge(number: Int, current: Boolean, completed: Boolean): TextView {
        val fill = when {
            current -> TvTheme.accent
            completed -> Color.parseColor("#1FDCE4EC")
            else -> Color.TRANSPARENT
        }
        val stroke = when {
            current -> TvTheme.accent
            completed -> Color.parseColor("#66DCE4EC")
            else -> Color.parseColor("#33DCE4EC")
        }
        val background = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(11).toFloat()
            setColor(fill)
            setStroke(dp(1).coerceAtLeast(1), stroke)
        }
        return TextView(context).apply {
            text = if (completed) "✓" else number.toString()
            gravity = Gravity.CENTER
            setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, TvTheme.TEXT_MICRO_SP)
            setTextColor(if (current) Color.parseColor("#0B0F14") else if (completed) TvTheme.accent else TvTheme.textSecondary)
            typeface = Typeface.DEFAULT_BOLD
            setBackground(background)
            layoutParams = LinearLayout.LayoutParams(dp(22), dp(22))
        }
    }

    private fun buildContentArea(): View {
        val scroll = ScrollView(context).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
            clipToPadding = true
            setPadding(0, dp(6), dp(2), dp(6))
            isFocusable = true
            isFocusableInTouchMode = false
            isClickable = false
            descendantFocusability = ViewGroup.FOCUS_AFTER_DESCENDANTS
            setDefaultFocusHighlightEnabled(false)
            setOnFocusChangeListener { view, focused ->
                view.background = if (focused) readingFocusFrame() else null
            }
            setOnKeyListener { view, keyCode, event ->
                if (event.action != KeyEvent.ACTION_DOWN || !view.hasFocus()) {
                    false
                } else {
                    when (keyCode) {
                        KeyEvent.KEYCODE_DPAD_DOWN -> if (view.canScrollVertically(1)) {
                            view.scrollBy(0, dp(120)); true
                        } else false

                        KeyEvent.KEYCODE_DPAD_UP -> if (view.canScrollVertically(-1)) {
                            view.scrollBy(0, -dp(120)); true
                        } else false

                        else -> false
                    }
                }
            }
            contentDescription = text(R.string.onb_brand)
        }
        scrollView = scroll
        val frame = FrameLayout(context)
        val column = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { gravity = Gravity.CENTER_VERTICAL }
        }
        contentColumn = column
        buildStepContent(column)
        frame.addView(column)
        scroll.addView(
            frame,
            ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        return scroll
    }

    private fun readingFocusFrame(): GradientDrawable = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = dp(10).toFloat()
        setColor(Color.TRANSPARENT)
        setStroke(dp(2).coerceAtLeast(1), TvTheme.goldBright)
    }

    // --------------------------------------------------------------------- footer

    private fun buildFooter(): View {
        val footer = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END or Gravity.CENTER_VERTICAL
            setPadding(0, dp(6), 0, dp(4))
        }
        if (stepIndex > 0) {
            val back = FocusableAction.secondary(context, R.string.onb_back, TvGlyph.CHEVRON)
            back.setOnClickListener {
                stepIndex--
                host.refreshCurrent()
            }
            footer.addView(back)
            footer.addView(View(context), LinearLayout.LayoutParams(dp(8), 1))
        }
        val primaryLabel = when {
            stepIndex == STEP_SUMMARY -> R.string.onb_finish
            stepIndex == STEP_TI && !isTiDone() -> R.string.onb_skip
            stepIndex == STEP_SCAN && !isScanDone() -> R.string.onb_skip
            else -> R.string.onb_next
        }
        val primaryGlyph = if (stepIndex == STEP_SUMMARY) TvGlyph.SHIELD else TvGlyph.CHEVRON
        val primary = FocusableAction.primary(context, primaryLabel, primaryGlyph)
        primary.setOnClickListener {
            if (stepIndex == STEP_SUMMARY) finishOnboarding() else goNext()
        }
        footer.addView(primary)
        // Initial focus always lands on the primary band action (never on the reading ScrollView).
        stepFocus = primary
        return footer
    }

    private fun brandDivider(): View = View(context).apply {
        setBackgroundColor(Color.parseColor("#1FDCE4EC"))
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1))
    }

    private fun animateEntry() {
        val root = viewRoot ?: return
        root.post {
            val column = contentColumn ?: return@post
            column.alpha = 0f
            column.translationX = dp(14).toFloat()
            column.animate().alpha(1f).translationX(0f).setDuration(180L).start()
            val bar = stepProgressBar
            if (bar != null) {
                bar.setFraction(0f)
                stepAnimator?.cancel()
                stepAnimator = ValueAnimator.ofFloat(0f, (stepIndex + 1).toFloat() / STEP_COUNT.toFloat()).apply {
                    duration = 180L
                    addUpdateListener { bar.setFraction(it.animatedValue as Float) }
                    start()
                }
            }
            welcomeHero?.let { hero ->
                hero.alpha = 0f
                hero.animate().alpha(1f).setDuration(180L).start()
            }
        }
    }

    // --------------------------------------------------------------- step content

    private var welcomeHero: ImageView? = null

    private fun buildStepContent(column: LinearLayout) {
        when (stepIndex) {
            STEP_WELCOME -> buildWelcome(column)
            STEP_MODEL -> buildModel(column)
            STEP_VPN -> buildVpn(column)
            STEP_TI -> buildThreatIntel(column)
            STEP_SCAN -> buildScan(column)
            STEP_SUMMARY -> buildSummary(column)
        }
    }

    private fun addStepHeader(column: LinearLayout, titleRes: Int, subtitleRes: Int) {
        val eyebrow = TvTheme.textView(
            context,
            text(R.string.onb_eyebrow_step, stepIndex + 1, STEP_COUNT),
            TvTheme.TEXT_MICRO_SP,
            TvTheme.accent,
            bold = true,
        ).apply {
            letterSpacing = 0.18f
            isAllCaps = true
            maxLines = 1
        }
        column.addView(eyebrow)
        column.addView(
            TvTheme.textView(context, text(titleRes), TvTheme.TEXT_TITLE_SP, TvTheme.textPrimary, bold = true).apply {
                maxLines = 2
            },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(3)
            },
        )
        column.addView(
            bodyText(context, text(subtitleRes), TvTheme.textSecondary).apply { maxLines = 2 },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(3)
            },
        )
    }

    private fun buildWelcome(column: LinearLayout) {
        addStepHeader(column, R.string.onb_welcome_title, R.string.onb_welcome_subtitle)
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val hero = ImageView(context).apply {
            setImageResource(R.drawable.sir_quacksec)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = text(R.string.welcome_mascot_description)
        }
        welcomeHero = hero
        row.addView(hero, LinearLayout.LayoutParams(dp(150), dp(196)).apply { rightMargin = dp(18) })
        val right = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        for (bulletRes in intArrayOf(
            R.string.onb_model_bullet1,
            R.string.onb_model_bullet2,
            R.string.onb_model_bullet3,
        )) {
            val bullet = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            bullet.addView(
                GlyphBadge(context, TvGlyph.CHECK, TvTheme.accent, 24),
                LinearLayout.LayoutParams(dp(24), dp(24)).apply { rightMargin = dp(8) },
            )
            bullet.addView(
                bodyText(context, text(bulletRes), TvTheme.textPrimary).apply { maxLines = 2 },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
            )
            right.addView(bullet, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                bottomMargin = dp(6)
            })
        }
        row.addView(right, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        column.addView(
            row,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(12)
            },
        )
    }

    private fun buildModel(column: LinearLayout) {
        addStepHeader(column, R.string.onb_model_title, R.string.onb_model_subtitle)
        val cards = listOf(
            Triple(R.string.onb_card_local_title, R.string.onb_card_local_body, TvGlyph.SHIELD),
            Triple(R.string.onb_card_no_server_title, R.string.onb_card_no_server_body, TvGlyph.EYE_OFF),
            Triple(R.string.onb_card_control_title, R.string.onb_card_control_body, TvGlyph.CHECK),
        )
        for ((titleRes, bodyRes, glyph) in cards) {
            val card = FocusableRow(context, interactive = false)
            card.setCard(true)
            card.setLeading(glyph, TvTheme.accent)
            card.setTitle(text(titleRes))
            card.setSubtitle(text(bodyRes))
            column.addView(
                card,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(8)
                },
            )
        }
    }

    private fun buildVpn(column: LinearLayout) {
        addStepHeader(column, R.string.onb_vpn_title, R.string.onb_vpn_subtitle)
        val status = readService { services.vpn.status() } ?: VpnStatus.OFF
        val panel = GlassPanel(context)
        panel.compact()
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        row.addView(
            GlyphBadge(context, vpnStateGlyph(status.state), toneColor(context, vpnStateTone(status.state)), 40),
            LinearLayout.LayoutParams(dp(40), dp(40)).apply { rightMargin = dp(12) },
        )
        val col = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        col.addView(
            TvTheme.textView(
                context,
                text(vpnStateLabelRes(status.state)),
                TvTheme.TEXT_HEADING_SP,
                TvTheme.textPrimary,
                bold = true,
            ).apply { maxLines = 1 },
        )
        col.addView(
            bodyText(context, text(vpnStateClaimRes(status.state)), TvTheme.textSecondary).apply { maxLines = 2 },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(2)
            },
        )
        val reason = resolve(status.detail) ?: status.reasonKey?.let { vpnReasonLabel(context, it) }
        if (!reason.isNullOrBlank()) {
            col.addView(
                captionText(context, reason).apply { maxLines = 2 },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(2)
                },
            )
        }
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        column.addView(
            panel,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(10)
            },
        )
        column.addView(
            captionText(context, text(R.string.onb_vpn_note)).apply { maxLines = 2 },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(8)
            },
        )
        if (!status.isProtecting) {
            val start = FocusableAction.primary(context, R.string.onb_vpn_action, TvGlyph.SHIELD)
            start.setOnClickListener { startVpnWithConsent() }
            column.addView(
                start,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(12)
                },
            )
        }
    }

    private fun isTiDone(): Boolean {
        if (syncDone) return true
        val status = readService { services.threatIntel.status() } ?: return false
        return status.availableCount > 0
    }

    private fun isScanDone(): Boolean {
        if (scanDone) return true
        return scannedResult != null || readService { services.scan.lastResult() } != null
    }

    private fun buildThreatIntel(column: LinearLayout) {
        addStepHeader(column, R.string.onb_ti_title, R.string.onb_ti_subtitle)
        val status = readService { services.threatIntel.status() } ?: ThreatIntelStatus.EMPTY
        val panel = GlassPanel(context)
        panel.compact()
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        row.addView(
            GlyphBadge(
                context,
                if (syncFailed) TvGlyph.ALERT else TvGlyph.REFRESH,
                if (syncFailed) toneColor(context, TvTone.WARNING) else TvTheme.accent,
                40,
            ),
            LinearLayout.LayoutParams(dp(40), dp(40)).apply { rightMargin = dp(12) },
        )
        val col = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        if (syncRunning) {
            col.addView(
                TvTheme.textView(context, text(R.string.onb_ti_running_title), TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
            )
            val bar = TvProgressBar(context, 6)
            tiProgressBar = bar
            bar.setFraction(tiFraction)
            col.addView(
                bar,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(8)
                },
            )
            val progress = bodyText(
                context,
                text(
                    R.string.onb_ti_running,
                    tiCompleted,
                    tiTotal.coerceAtLeast(0),
                    tiLastFeed.ifBlank { "–" },
                ),
            )
            tiProgressText = progress
            col.addView(progress)
        } else if (syncDone || status.availableCount > 0) {
            col.addView(
                TvTheme.textView(
                    context,
                    text(R.string.onb_ti_done, status.freshCount, status.feeds.size),
                    TvTheme.TEXT_HEADING_SP,
                    TvTheme.textPrimary,
                    bold = true,
                ).apply { maxLines = 1 },
            )
            col.addView(
                captionText(context, text(R.string.onb_ti_scope)).apply { maxLines = 2 },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(3)
                },
            )
            col.addView(
                StatusPill(context, text(R.string.onb_status_current), TvTone.SUCCESS, TvGlyph.CHECK),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(6)
                },
            )
        } else if (syncFailed) {
            col.addView(
                TvTheme.textView(context, text(R.string.onb_ti_failed), TvTheme.TEXT_BODY_SP, TvTheme.textPrimary).apply {
                    maxLines = 3
                },
            )
            col.addView(
                captionText(context, text(R.string.onb_ti_skip_hint)).apply { maxLines = 2 },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(3)
                },
            )
        } else {
            col.addView(
                TvTheme.textView(context, text(R.string.onb_ti_idle), TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
            )
            col.addView(
                captionText(context, text(R.string.onb_ti_skip_hint)).apply { maxLines = 2 },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(3)
                },
            )
        }
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        column.addView(
            panel,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(10)
            },
        )
        if (!syncRunning && !syncDone && !(status.availableCount > 0)) {
            val labelRes = if (syncFailed) R.string.onb_ti_retry else R.string.onb_ti_action
            val action = FocusableAction.primary(context, labelRes, TvGlyph.REFRESH)
            action.setOnClickListener { startThreatIntelSync() }
            column.addView(
                action,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(12)
                },
            )
        }
    }

    private fun buildScan(column: LinearLayout) {
        addStepHeader(column, R.string.onb_scan_title, R.string.onb_scan_subtitle)
        val panel = GlassPanel(context)
        panel.compact()
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        row.addView(
            GlyphBadge(
                context,
                if (scanFailed) TvGlyph.ALERT else TvGlyph.EYE,
                if (scanFailed) toneColor(context, TvTone.WARNING) else TvTheme.electricBlue,
                40,
            ),
            LinearLayout.LayoutParams(dp(40), dp(40)).apply { rightMargin = dp(12) },
        )
        val col = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        if (scanRunning) {
            col.addView(
                TvTheme.textView(context, text(R.string.onb_scan_running_title), TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
            )
            val bar = TvProgressBar(context, 6)
            scanProgressBar = bar
            bar.setFraction(scanFraction)
            col.addView(
                bar,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(8)
                },
            )
            val progress = bodyText(
                context,
                text(R.string.onb_scan_progress, scanCompleted, scanTotal.coerceAtLeast(0)),
            )
            scanProgressText = progress
            col.addView(progress)
        } else if (isScanDone()) {
            val result = scannedResult ?: readService { services.scan.lastResult() }
            val summary = readService { services.scan.lastSummary() }
            col.addView(
                TvTheme.textView(context, text(R.string.onb_scan_title), TvTheme.TEXT_HEADING_SP, TvTheme.textPrimary, bold = true),
            )
            val count = result?.findings?.size ?: summary?.findingsCount ?: 0
            val coverage = result?.coverage ?: summary?.coverage
            col.addView(
                captionText(
                    context,
                    text(R.string.onb_scan_done, count, coverage?.let { visibilityLabelRes(it) }?.let { text(it) } ?: "–"),
                ).apply { maxLines = 2 },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(3)
                },
            )
            col.addView(
                StatusPill(context, text(R.string.onb_status_done), TvTone.SUCCESS, TvGlyph.CHECK),
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(6)
                },
            )
        } else if (scanFailed) {
            col.addView(
                TvTheme.textView(context, text(R.string.onb_scan_skip_hint), TvTheme.TEXT_BODY_SP, TvTheme.textPrimary).apply {
                    maxLines = 3
                },
            )
        } else {
            col.addView(
                TvTheme.textView(context, text(R.string.onb_scan_idle), TvTheme.TEXT_LABEL_SP, TvTheme.textPrimary, bold = true),
            )
            col.addView(
                captionText(context, text(R.string.onb_scan_body)).apply { maxLines = 2 },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(3)
                },
            )
            col.addView(
                captionText(context, text(R.string.onb_scan_skip_hint)).apply { maxLines = 2 },
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(3)
                },
            )
        }
        row.addView(col, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        panel.addView(row)
        column.addView(
            panel,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(10)
            },
        )
        if (!scanRunning && !isScanDone()) {
            val labelRes = if (scanFailed) R.string.onb_scan_retry else R.string.onb_scan_action
            val action = FocusableAction.primary(context, labelRes, TvGlyph.REFRESH)
            action.setOnClickListener { startFirstScan() }
            column.addView(
                action,
                LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    topMargin = dp(12)
                },
            )
        }
    }

    private fun buildSummary(column: LinearLayout) {
        addStepHeader(column, R.string.onb_summary_title, R.string.onb_sum_subtitle)
        val vpn = readService { services.vpn.status() } ?: VpnStatus.OFF
        val threat = readService { services.threatIntel.status() } ?: ThreatIntelStatus.EMPTY
        val scanResult = scannedResult ?: readService { services.scan.lastResult() }
        val scanSummary = readService { services.scan.lastSummary() }
        val autoStart = readService { services.settings.vpnAutoStart() }
            ?: readService { services.vpn.autoStartEnabled() }
            ?: false

        val panel = GlassPanel(context, soft = true)
        panel.compact()
        val vpnValue: Triple<Int, TvTone, TvGlyph> = when (vpn.state) {
            VpnState.ACTIVE -> Triple(R.string.onb_status_active, TvTone.SUCCESS, TvGlyph.CHECK)
            VpnState.DEGRADED -> Triple(vpnStateLabelRes(VpnState.DEGRADED), TvTone.WARNING, TvGlyph.HALF)
            else -> Triple(R.string.onb_status_inactive, TvTone.NEUTRAL, TvGlyph.CROSS)
        }
        val tiValue: Triple<Int, TvTone, TvGlyph> = when {
            threat.availableCount > 0 && threat.staleCount == 0 -> Triple(R.string.onb_status_current, TvTone.SUCCESS, TvGlyph.CHECK)
            threat.availableCount > 0 -> Triple(R.string.onb_status_stale, TvTone.WARNING, TvGlyph.CLOCK)
            else -> Triple(R.string.onb_status_not_synced, TvTone.NEUTRAL, TvGlyph.CLOCK)
        }
        val scanValue: Triple<Int, TvTone, TvGlyph> = if (scanResult != null || scanSummary != null) {
            Triple(R.string.onb_status_done, TvTone.SUCCESS, TvGlyph.CHECK)
        } else {
            Triple(R.string.onb_status_not_done, TvTone.NEUTRAL, TvGlyph.QUESTION)
        }
        val autoValue = if (autoStart) {
            Triple(R.string.onb_status_on, TvTone.NEUTRAL, TvGlyph.CHECK)
        } else {
            Triple(R.string.onb_status_off, TvTone.NEUTRAL, TvGlyph.CROSS)
        }
        panel.addView(summaryRow(R.string.onb_sum_vpn, vpnValue))
        panel.addView(summaryRow(R.string.onb_sum_ti, tiValue))
        panel.addView(summaryRow(R.string.onb_sum_scan, scanValue))
        panel.addView(summaryRow(R.string.onb_sum_autostart, autoValue))
        column.addView(
            panel,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(10)
            },
        )
        column.addView(
            captionText(context, text(R.string.onb_summary_body)).apply { maxLines = 3 },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(8)
            },
        )
    }

    private fun summaryRow(labelRes: Int, value: Triple<Int, TvTone, TvGlyph>): View {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        row.addView(
            TvTheme.textView(context, text(labelRes), TvTheme.TEXT_LABEL_SP, TvTheme.textSecondary),
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
        )
        row.addView(StatusPill(context, text(value.first), value.second, value.third))
        return row
    }

    // ---------------------------------------------------------------- async work

    private fun startVpnWithConsent() {
        val listener = VpnStateListener { status ->
            val view = viewRoot
            view?.post {
                notify(text(vpnStateLabelRes(status.state)))
                if (view.isAttachedToWindow) host.refreshCurrent()
            }
        }
        val result = readService { services.vpn.start(host.activity(), listener) }
        if (result == null) {
            notify(text(R.string.prot_start_failed))
        } else if (result.consentRequired) {
            notify(text(R.string.prot_start_consent))
        } else if (!result.started) {
            notify(text(R.string.prot_start_failed))
        }
    }

    private fun startThreatIntelSync() {
        if (syncRunning) return
        syncRunning = true
        syncDone = false
        syncFailed = false
        tiCompleted = 0
        tiTotal = 0
        tiFraction = 0f
        val listener = object : ThreatIntelSyncListener {
            override fun onProgress(completed: Int, total: Int, lastFeedId: String) {
                tiCompleted = completed
                tiTotal = total
                tiLastFeed = lastFeedId
                val target = if (total > 0) completed.toFloat() / total.toFloat() else 0f
                tiFraction = target
                val view = viewRoot
                view?.post {
                    animateBar(tiProgressBar, target)
                    tiProgressText?.text = text(
                        R.string.onb_ti_running,
                        completed,
                        total,
                        lastFeedId.ifBlank { "–" },
                    )
                }
            }

            override fun onSyncFinished(ok: Boolean, message: MessageRef, status: ThreatIntelStatus) {
                syncRunning = false
                syncDone = ok
                syncFailed = !ok
                val view = viewRoot
                view?.post {
                    notify(resolve(message) ?: text(if (ok) R.string.onb_status_current else R.string.onb_ti_failed))
                    if (view.isAttachedToWindow && stepIndex == STEP_TI) host.refreshCurrent()
                }
            }
        }
        val started = readService { services.threatIntel.syncNow(listener) } ?: false
        if (!started) {
            syncRunning = false
            notify(text(R.string.ti_sync_already))
        } else {
            host.refreshCurrent()
        }
    }

    private fun startFirstScan() {
        if (scanRunning) return
        scanRunning = true
        scanDone = false
        scanFailed = false
        scanCompleted = 0
        scanTotal = 0
        scanFraction = 0f
        val listener = object : ScanListener {
            override fun onProgress(progress: ScanProgress) {
                scanCompleted = progress.completedCollectors
                scanTotal = progress.totalCollectors
                scanFraction = progress.fraction
                val view = viewRoot
                view?.post {
                    animateBar(scanProgressBar, progress.fraction)
                    scanProgressText?.text = text(
                        R.string.onb_scan_progress,
                        progress.completedCollectors,
                        progress.totalCollectors,
                    )
                }
            }

            override fun onCompleted(result: ScanResult) {
                scanRunning = false
                scanDone = true
                scannedResult = result
                val view = viewRoot
                view?.post {
                    scanProgressBar?.setFraction(1f)
                    if (view.isAttachedToWindow && stepIndex == STEP_SCAN) host.refreshCurrent()
                }
            }

            override fun onFailed(error: MessageRef) {
                scanRunning = false
                scanFailed = true
                val view = viewRoot
                view?.post {
                    notify(resolve(error) ?: text(R.string.onb_scan_skip_hint))
                    if (view.isAttachedToWindow && stepIndex == STEP_SCAN) host.refreshCurrent()
                }
            }
        }
        val started = readService { services.scan.start(listener) } ?: false
        if (!started) {
            scanRunning = false
            notify(text(R.string.check_already_running))
        } else {
            host.refreshCurrent()
        }
    }

    private fun animateBar(bar: TvProgressBar?, target: Float) {
        if (bar == null) return
        val isTi = bar === tiProgressBar
        val from = if (isTi) tiFraction else scanFraction
        if (isTi) tiAnimator?.cancel() else scanAnimator?.cancel()
        val animator = ValueAnimator.ofFloat(from, target.coerceIn(0f, 1f)).apply {
            duration = 180L
            addUpdateListener { bar.setFraction(it.animatedValue as Float) }
            start()
        }
        if (isTi) tiAnimator = animator else scanAnimator = animator
    }

    private fun goNext() {
        if (stepIndex < STEP_COUNT - 1) {
            stepIndex++
            host.refreshCurrent()
        }
    }

    private fun finishOnboarding() {
        val status = readService { services.vpn.status() }
        if (status == null || !status.isProtecting) {
            val result = readService {
                services.vpn.startIfPermitted { state ->
                    viewRoot?.post { notify(text(vpnStateLabelRes(state.state))) }
                }
            }
            if (result != null && result.consentRequired) {
                notify(text(R.string.prot_start_consent))
            }
        }
        readService { services.settings.setProtectionSetupDone(true) }
        readService { services.settings.setOnboardingDone(true) }
        host.navigate(TvRoute.HOME)
    }

    // -------------------------------------------------------------------- helpers

    private fun text(resId: Int): String = context.getString(resId)

    private fun text(resId: Int, vararg args: Any): String = context.getString(resId, *args)

    private fun resolve(ref: MessageRef?): String? = resolveText(services.catalog, ref)

    private fun notify(message: CharSequence) = host.notifyUser(message.toString())

    private fun dp(value: Int): Int = TvTheme.scaledDp(context, value)

    private companion object {
        const val STEP_COUNT = 6
        const val STEP_WELCOME = 0
        const val STEP_MODEL = 1
        const val STEP_VPN = 2
        const val STEP_TI = 3
        const val STEP_SCAN = 4
        const val STEP_SUMMARY = 5
    }
}
