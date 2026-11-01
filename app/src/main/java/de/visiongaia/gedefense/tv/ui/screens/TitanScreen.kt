package de.visiongaia.gedefense.tv.ui.screens

import android.view.View
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.TitanActionResultListener
import de.visiongaia.gedefense.tv.contract.TitanActivationListener
import de.visiongaia.gedefense.tv.contract.TitanScanListener
import de.visiongaia.gedefense.tv.contract.TitanWitnessListener
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.SocketObservation
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionReason
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionRequest
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionResult
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionTarget
import de.visiongaia.gedefense.tv.core.titan.model.TitanContainmentAction
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanScanOutcome
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessState
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus
import de.visiongaia.gedefense.tv.ui.TvRoute
import de.visiongaia.gedefense.tv.ui.TvTheme
import de.visiongaia.gedefense.tv.ui.components.FocusableRow
import de.visiongaia.gedefense.tv.ui.components.ScreenScaffold
import de.visiongaia.gedefense.tv.ui.components.StatusPill
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.addSpacer
import de.visiongaia.gedefense.tv.ui.components.readService
import de.visiongaia.gedefense.tv.ui.titan.TitanConfirmationOverlay
import de.visiongaia.gedefense.tv.ui.titan.TitanFimSection
import de.visiongaia.gedefense.tv.ui.titan.TitanGuardSection
import de.visiongaia.gedefense.tv.ui.titan.TitanLayout
import de.visiongaia.gedefense.tv.ui.titan.TitanSocketSection
import de.visiongaia.gedefense.tv.ui.titan.TitanStatusHero
import de.visiongaia.gedefense.tv.ui.titan.TitanText
import de.visiongaia.gedefense.tv.ui.titan.TitanVaultSection
import de.visiongaia.gedefense.tv.ui.titan.TitanWitnessSection

/**
 * TITAN LIVE — the honest surface of the Titan Engine.
 *
 * The screen renders exactly the composed [TitanStatus]: confirmed privilege level, effective
 * capabilities, the last socket provenance pass, the FIM delta, the quarantine vault, the local
 * witness checkpoints and the two guard switches. Without a confirmed channel it stays fully usable
 * at Level 1: every unavailable capability is explained, no capability is faked and no security score
 * is invented.
 *
 * Destructive or privilege-relevant controls always run through a two-step D-pad confirmation with
 * default focus on cancel; BACK closes the confirmation instead of leaving the screen.
 */
internal class TitanScreen(services: TvServices) : ScaffoldScreen(services) {

    override val route: TvRoute = TvRoute.TITAN

    private var confirmation: TitanConfirmationOverlay? = null
    private var scanRunning = false
    private var activating = false
    private var actionPending = false
    private var checkpointRunning = false

    // ------------------------------------------------------------------ composition

    override fun build(scaffold: ScreenScaffold) {
        val status = readService { services.titan.status() } ?: TitanStatus.empty(System.currentTimeMillis())
        val vault = readService { services.titan.vaultEntries() }.orEmpty()
        val witness = readService { services.titan.witnessStatus() } ?: TitanWitnessStatus.UNAVAILABLE
        val socketGuard = readService { services.settings.titanSocketGuardEnabled() } ?: false
        val fimGuard = readService { services.settings.titanFimGuardEnabled() } ?: false
        val consent = readService { services.settings.titanConsentGranted() } ?: false
        val activationAvailable = TitanText.activationAvailable(status)

        scaffold.setEyebrow(text(R.string.titan_eyebrow))
        scaffold.setTitle(text(R.string.titan_title))
        scaffold.setSubtitle(text(R.string.titan_subtitle))
        scaffold.addStatus(
            StatusPill(
                context,
                text(TitanText.outcomeLabelRes(status.lastScanOutcome)),
                TitanText.outcomeTone(status.lastScanOutcome),
                TitanText.outcomeGlyph(status.lastScanOutcome),
            ),
        )

        val overlay = TitanConfirmationOverlay(context)
        confirmation = overlay
        scaffold.content.addView(overlay, matchParams())
        scaffold.content.addSpacer(6)

        val hero = TitanStatusHero(context)
        hero.bind(status, activationAvailable, TitanText.activateLabelRes(consent)) { requestActivation() }
        scaffold.content.addView(hero, matchParams())

        val scanLabelRes = if (status.lastScanOutcome == TitanScanOutcome.NEVER) {
            R.string.titan_action_start_check
        } else {
            R.string.titan_action_rescan
        }
        val scanAction = if (activationAvailable) {
            secondaryAction(scanLabelRes, TvGlyph.REFRESH) { startScan() }
        } else {
            primaryAction(scanLabelRes, TvGlyph.REFRESH) { startScan() }
        }
        scaffold.addAction(scanAction, primary = !activationAvailable)

        val focusables = mutableListOf<View>()
        focusables += TitanSocketSection.build(
            scaffold.content,
            status,
            socketGuard,
            onScan = { startScan() },
            onFreeze = { observation -> requestFreeze(observation) },
            onIsolate = { observation -> requestIsolate(observation) },
        )
        focusables += TitanFimSection.build(
            scaffold.content,
            status,
            fimGuard,
            onScan = { startScan() },
        )
        focusables += TitanVaultSection.build(scaffold.content, status, vault)
        focusables += TitanWitnessSection.build(
            scaffold.content,
            witness,
            witness.state != TitanWitnessState.UNAVAILABLE,
        ) { createCheckpoint() }
        focusables += TitanGuardSection.build(
            scaffold.content,
            status,
            socketGuard,
            fimGuard,
            onToggleSocket = { enabled -> setSocketGuard(enabled) },
            onToggleFim = { enabled -> setFimGuard(enabled) },
        )

        if (status.notes.isNotEmpty()) {
            TitanLayout.addSection(scaffold.content, text(R.string.titan_section_notes))
            for (ref in status.notes.take(MAX_NOTES)) {
                val note = resolve(ref) ?: continue
                val row = FocusableRow(context, interactive = false)
                row.setLeading(TvGlyph.INFO, TvTheme.accent)
                row.setTitle(note)
                TitanLayout.addRow(scaffold.content, row, gapDp = 6)
                focusables += row
            }
        }

        val activate = hero.activateAction
        if (activate != null) {
            scaffold.setPrimaryFocus(activate)
            linkDown(scanAction, activate)
        }
        scaffold.linkFocusChain(focusables.firstOrNull(), focusables.lastOrNull())
    }

    override fun handleBack(): Boolean {
        val overlay = confirmation ?: return false
        if (!overlay.isOpen()) return false
        overlay.hide()
        return true
    }

    override fun onHidden() {
        confirmation?.hide()
        host.hideSyncOverlay()
    }

    // ------------------------------------------------------------------ scan

    private val scanListener = object : TitanScanListener {
        override fun onStarted() {
            scanRunning = true
        }

        override fun onProgress(step: Int, total: Int) {
            if (!scaffoldReady()) return
            scaffold.post { host.updateSyncOverlay(step, total) }
        }

        override fun onCompleted(status: TitanStatus) {
            finishScan(null)
        }

        override fun onFailed(message: MessageRef) {
            finishScan(resolve(message))
        }
    }

    private fun startScan() {
        if (scanRunning) {
            notify(text(R.string.titan_scan_already))
            return
        }
        scanRunning = true
        host.showSyncOverlay(text(R.string.titan_scan_running))
        val started = readService { services.titan.scanNow(scanListener) } ?: false
        if (!started) {
            scanRunning = false
            host.hideSyncOverlay()
            notify(text(R.string.titan_scan_already))
        }
    }

    private fun finishScan(failure: String?) {
        scanRunning = false
        if (!scaffoldReady()) {
            host.hideSyncOverlay()
            return
        }
        val view = scaffold
        view.post {
            host.hideSyncOverlay()
            if (failure != null) notify(failure)
            if (view.isAttachedToWindow) host.refreshCurrent()
        }
    }

    // ------------------------------------------------------------------ activation

    private val activationListener = object : TitanActivationListener {
        override fun onResult(snapshot: TitanPrivilegeSnapshot?, message: MessageRef) {
            activating = false
            val detail = resolve(message) ?: text(R.string.titan_activation_failed)
            if (!scaffoldReady()) {
                host.hideSyncOverlay()
                return
            }
            val view = scaffold
            view.post {
                host.hideSyncOverlay()
                notify(detail)
                if (view.isAttachedToWindow) host.refreshCurrent()
            }
        }
    }

    private fun requestActivation() {
        val overlay = confirmation ?: return
        overlay.show(
            R.string.titan_confirm_activate_title,
            R.string.titan_confirm_activate_body,
            text(R.string.titan_confirm_activate_consequence),
            R.string.titan_confirm_activate_confirm,
            scaffold.findFocus(),
        ) { performActivation() }
    }

    private fun performActivation() {
        if (activating) {
            notify(text(R.string.titan_action_in_progress))
            return
        }
        activating = true
        host.showSyncOverlay(text(R.string.titan_activation_running))
        val started = readService { services.titan.activate(activationListener) } ?: false
        if (!started) {
            activating = false
            host.hideSyncOverlay()
            notify(text(R.string.titan_activation_failed))
        }
    }

    // ------------------------------------------------------------------ containment

    private fun requestFreeze(observation: SocketObservation) {
        val packageName = observation.packageName ?: return
        val overlay = confirmation ?: return
        overlay.show(
            R.string.titan_confirm_freeze_title,
            R.string.titan_confirm_freeze_body,
            text(R.string.titan_confirm_target, packageName),
            R.string.titan_confirm_proceed,
            scaffold.findFocus(),
        ) {
            performContain(
                TitanContainmentAction.FREEZE_APP,
                TitanActionTarget(packageName = packageName, label = packageName.take(MAX_LABEL_LENGTH)),
            )
        }
    }

    private fun requestIsolate(observation: SocketObservation) {
        if (observation.uid !in 1..TitanActionTarget.MAX_UID) return
        val overlay = confirmation ?: return
        val target = observation.packageName ?: text(R.string.titan_socket_unknown_app)
        overlay.show(
            R.string.titan_confirm_isolate_title,
            R.string.titan_confirm_isolate_body,
            text(R.string.titan_confirm_target, "$target · UID ${observation.uid}"),
            R.string.titan_confirm_proceed,
            scaffold.findFocus(),
        ) {
            performContain(
                TitanContainmentAction.ISOLATE_NETWORK_UID,
                TitanActionTarget(uid = observation.uid, label = target.take(MAX_LABEL_LENGTH)),
            )
        }
    }

    private val actionResultListener = object : TitanActionResultListener {
        override fun onResult(result: TitanActionResult) {
            actionPending = false
            val failure = result.failure
            val message = when {
                result.ok -> text(
                    R.string.titan_action_done,
                    TitanText.containmentActionLabel(context, result.action),
                )

                failure != null -> text(R.string.titan_action_failed_detail, text(TitanText.failureLabelRes(failure)))
                else -> text(R.string.titan_action_failed_detail, text(R.string.titan_failure_unavailable))
            }
            if (!scaffoldReady()) return
            val view = scaffold
            view.post {
                notify(message)
                if (view.isAttachedToWindow) host.refreshCurrent()
            }
        }
    }

    private fun performContain(action: TitanContainmentAction, target: TitanActionTarget) {
        if (actionPending) {
            notify(text(R.string.titan_action_in_progress))
            return
        }
        actionPending = true
        val request = TitanActionRequest(
            action = action,
            target = target,
            reason = TitanActionReason.USER_INITIATED,
            requestedAtMillis = System.currentTimeMillis(),
        )
        val started = readService { services.titan.contain(request, actionResultListener) } ?: false
        if (!started) {
            actionPending = false
            notify(text(R.string.titan_action_in_progress))
        }
    }

    // ------------------------------------------------------------------ witness

    private val witnessListener = object : TitanWitnessListener {
        override fun onResult(ok: Boolean, status: TitanWitnessStatus, message: MessageRef) {
            checkpointRunning = false
            val detail = resolve(message) ?: text(
                if (ok) R.string.titan_witness_created else R.string.titan_witness_failed,
            )
            if (!scaffoldReady()) return
            val view = scaffold
            view.post {
                notify(detail)
                if (view.isAttachedToWindow) host.refreshCurrent()
            }
        }
    }

    private fun createCheckpoint() {
        if (checkpointRunning) return
        checkpointRunning = true
        val started = readService { services.titan.refreshWitnessCheckpoint(witnessListener) } ?: false
        if (!started) {
            checkpointRunning = false
            notify(text(R.string.titan_witness_failed))
        }
    }

    // ------------------------------------------------------------------ guards

    private fun setSocketGuard(enabled: Boolean) {
        readService { services.settings.setTitanSocketGuardEnabled(enabled) }
        notify(text(if (enabled) R.string.settings_state_enabled else R.string.settings_state_disabled))
        refreshIfVisible()
    }

    private fun setFimGuard(enabled: Boolean) {
        readService { services.settings.setTitanFimGuardEnabled(enabled) }
        notify(text(if (enabled) R.string.settings_state_enabled else R.string.settings_state_disabled))
        refreshIfVisible()
    }

    // ------------------------------------------------------------------ focus

    /** Connects the header action with the hero control so the activation button is never skipped. */
    private fun linkDown(above: View, below: View) {
        if (above.id == View.NO_ID) above.id = View.generateViewId()
        if (below.id == View.NO_ID) below.id = View.generateViewId()
        above.nextFocusDownId = below.id
        below.nextFocusUpId = above.id
    }

    private companion object {
        const val MAX_NOTES = 6
        const val MAX_LABEL_LENGTH = 96
    }
}
