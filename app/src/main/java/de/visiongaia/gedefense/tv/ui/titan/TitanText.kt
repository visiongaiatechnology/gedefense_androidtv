package de.visiongaia.gedefense.tv.ui.titan

import android.content.Context
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.titan.model.FimStatus
import de.visiongaia.gedefense.tv.core.titan.model.SocketRisk
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionFailure
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanContainmentAction
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel
import de.visiongaia.gedefense.tv.core.titan.model.TitanScanOutcome
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessState
import de.visiongaia.gedefense.tv.ui.components.TvGlyph
import de.visiongaia.gedefense.tv.ui.components.TvTone

/**
 * Deterministic mapping from Titan domain state to localized labels, glyphs and tones.
 *
 * Every status is expressed as glyph + label; colour is only reinforcement. No mapping ever claims a
 * capability, a clean state or a score that the current privilege level does not prove.
 */
internal object TitanText {

    // ------------------------------------------------------------------ privilege

    fun levelLabelRes(level: TitanPrivilegeLevel): Int = when (level) {
        TitanPrivilegeLevel.STANDARD -> R.string.titan_level_standard
        TitanPrivilegeLevel.SHIZUKU -> R.string.titan_level_shizuku
        TitanPrivilegeLevel.ROOT -> R.string.titan_level_root
    }

    fun levelGlyph(level: TitanPrivilegeLevel): TvGlyph = when (level) {
        TitanPrivilegeLevel.STANDARD -> TvGlyph.HALF
        TitanPrivilegeLevel.SHIZUKU -> TvGlyph.LOCK
        TitanPrivilegeLevel.ROOT -> TvGlyph.SHIELD
    }

    fun levelTone(level: TitanPrivilegeLevel): TvTone = when (level) {
        TitanPrivilegeLevel.STANDARD -> TvTone.NEUTRAL
        TitanPrivilegeLevel.SHIZUKU -> TvTone.WARNING
        TitanPrivilegeLevel.ROOT -> TvTone.SUCCESS
    }

    fun claimRes(level: TitanPrivilegeLevel): Int = when (level) {
        TitanPrivilegeLevel.STANDARD -> R.string.titan_claim_standard
        TitanPrivilegeLevel.SHIZUKU -> R.string.titan_claim_shizuku
        TitanPrivilegeLevel.ROOT -> R.string.titan_claim_root
    }

    /**
     * True only when the passive snapshot found a real channel marker (su binary, managed root
     * manager or a Shizuku install). A filename alone never unlocks a capability.
     */
    fun activationAvailable(status: TitanStatus): Boolean {
        val privilege = status.privilege ?: return false
        return privilege.suPaths.isNotEmpty() ||
            privilege.rootManagers.isNotEmpty() ||
            privilege.shizukuInstalled
    }

    fun activateLabelRes(consentGranted: Boolean): Int =
        if (consentGranted) R.string.titan_action_reactivate else R.string.titan_action_activate

    // ------------------------------------------------------------------ capabilities

    fun capabilityLabelRes(capability: TitanCapability): Int = when (capability) {
        TitanCapability.SOCKET_PROVENANCE -> R.string.titan_capability_socket
        TitanCapability.DEEP_INVENTORY_FIM -> R.string.titan_capability_fim
        TitanCapability.APP_FREEZE -> R.string.titan_capability_freeze
        TitanCapability.NETWORK_QUARANTINE -> R.string.titan_capability_network
        TitanCapability.ADB_LOCKDOWN -> R.string.titan_capability_adb
        TitanCapability.PROCESS_KILL -> R.string.titan_capability_kill
        TitanCapability.QUARANTINE_VAULT -> R.string.titan_capability_vault
    }

    fun capabilityGlyph(capability: TitanCapability): TvGlyph = when (capability) {
        TitanCapability.SOCKET_PROVENANCE -> TvGlyph.EYE
        TitanCapability.DEEP_INVENTORY_FIM -> TvGlyph.SHIELD
        TitanCapability.APP_FREEZE -> TvGlyph.LOCK
        TitanCapability.NETWORK_QUARANTINE -> TvGlyph.CROSS
        TitanCapability.ADB_LOCKDOWN -> TvGlyph.LOCK
        TitanCapability.PROCESS_KILL -> TvGlyph.ALERT
        TitanCapability.QUARANTINE_VAULT -> TvGlyph.TRASH
    }

    // ------------------------------------------------------------------ scan outcome

    fun outcomeLabelRes(outcome: TitanScanOutcome): Int = when (outcome) {
        TitanScanOutcome.NEVER -> R.string.titan_outcome_never
        TitanScanOutcome.RUNNING -> R.string.titan_outcome_running
        TitanScanOutcome.COMPLETED -> R.string.titan_outcome_completed
        TitanScanOutcome.PARTIAL -> R.string.titan_outcome_partial
        TitanScanOutcome.FAILED -> R.string.titan_outcome_failed
    }

    fun outcomeGlyph(outcome: TitanScanOutcome): TvGlyph = when (outcome) {
        TitanScanOutcome.NEVER -> TvGlyph.CLOCK
        TitanScanOutcome.RUNNING -> TvGlyph.REFRESH
        TitanScanOutcome.COMPLETED -> TvGlyph.CHECK
        TitanScanOutcome.PARTIAL -> TvGlyph.HALF
        TitanScanOutcome.FAILED -> TvGlyph.ALERT
    }

    fun outcomeTone(outcome: TitanScanOutcome): TvTone = when (outcome) {
        TitanScanOutcome.NEVER -> TvTone.NEUTRAL
        TitanScanOutcome.RUNNING -> TvTone.INFO
        TitanScanOutcome.COMPLETED -> TvTone.SUCCESS
        TitanScanOutcome.PARTIAL -> TvTone.WARNING
        TitanScanOutcome.FAILED -> TvTone.DANGER
    }

    // ------------------------------------------------------------------ socket risk

    fun riskLabelRes(risk: SocketRisk): Int = when (risk) {
        SocketRisk.NONE -> R.string.titan_socket_risk_none
        SocketRisk.THREAT_FEED_MATCH -> R.string.titan_socket_risk_threat
        SocketRisk.UNATTRIBUTED -> R.string.titan_socket_risk_unattributed
        SocketRisk.ADB_EXPOSED -> R.string.titan_socket_risk_adb
    }

    fun riskGlyph(risk: SocketRisk): TvGlyph = when (risk) {
        SocketRisk.NONE -> TvGlyph.DOT
        SocketRisk.THREAT_FEED_MATCH -> TvGlyph.ALERT
        SocketRisk.UNATTRIBUTED -> TvGlyph.QUESTION
        SocketRisk.ADB_EXPOSED -> TvGlyph.LOCK
    }

    fun riskTone(risk: SocketRisk): TvTone = when (risk) {
        SocketRisk.NONE -> TvTone.NEUTRAL
        SocketRisk.THREAT_FEED_MATCH -> TvTone.DANGER
        SocketRisk.UNATTRIBUTED -> TvTone.WARNING
        SocketRisk.ADB_EXPOSED -> TvTone.WARNING
    }

    // ------------------------------------------------------------------ FIM status

    fun fimStatusLabelRes(status: FimStatus): Int = when (status) {
        FimStatus.BASELINE_CREATED -> R.string.titan_fim_status_baseline
        FimStatus.MATCHES_BASELINE -> R.string.titan_fim_status_match
        FimStatus.NEW_FILE -> R.string.titan_fim_metric_new
        FimStatus.MODIFIED -> R.string.titan_fim_metric_modified
        FimStatus.UNREADABLE -> R.string.titan_fim_metric_unreadable
    }

    fun fimStatusGlyph(status: FimStatus): TvGlyph = when (status) {
        FimStatus.BASELINE_CREATED -> TvGlyph.CHECK
        FimStatus.MATCHES_BASELINE -> TvGlyph.CHECK
        FimStatus.NEW_FILE -> TvGlyph.ALERT
        FimStatus.MODIFIED -> TvGlyph.ALERT
        FimStatus.UNREADABLE -> TvGlyph.QUESTION
    }

    fun fimStatusTone(status: FimStatus): TvTone = when (status) {
        FimStatus.BASELINE_CREATED -> TvTone.INFO
        FimStatus.MATCHES_BASELINE -> TvTone.SUCCESS
        FimStatus.NEW_FILE -> TvTone.WARNING
        FimStatus.MODIFIED -> TvTone.WARNING
        FimStatus.UNREADABLE -> TvTone.NEUTRAL
    }

    // ------------------------------------------------------------------ witness

    fun witnessStateLabelRes(state: TitanWitnessState): Int = when (state) {
        TitanWitnessState.UNAVAILABLE -> R.string.titan_witness_state_unavailable
        TitanWitnessState.READY -> R.string.titan_witness_state_ready
        TitanWitnessState.PAIRED -> R.string.titan_witness_state_paired
        TitanWitnessState.DEGRADED -> R.string.titan_witness_state_degraded
    }

    fun witnessStateGlyph(state: TitanWitnessState): TvGlyph = when (state) {
        TitanWitnessState.UNAVAILABLE -> TvGlyph.EYE_OFF
        TitanWitnessState.READY -> TvGlyph.CLOCK
        TitanWitnessState.PAIRED -> TvGlyph.CHECK
        TitanWitnessState.DEGRADED -> TvGlyph.HALF
    }

    fun witnessStateTone(state: TitanWitnessState): TvTone = when (state) {
        TitanWitnessState.UNAVAILABLE -> TvTone.NEUTRAL
        TitanWitnessState.READY -> TvTone.INFO
        TitanWitnessState.PAIRED -> TvTone.SUCCESS
        TitanWitnessState.DEGRADED -> TvTone.WARNING
    }

    // ------------------------------------------------------------------ actions

    fun failureLabelRes(failure: TitanActionFailure): Int = when (failure) {
        TitanActionFailure.NOT_AUTHORIZED -> R.string.titan_failure_not_authorized
        TitanActionFailure.NOT_SUPPORTED -> R.string.titan_failure_not_supported
        TitanActionFailure.INVALID_TARGET -> R.string.titan_failure_invalid_target
        TitanActionFailure.PROTECTED_TARGET -> R.string.titan_failure_protected_target
        TitanActionFailure.RATE_LIMITED -> R.string.titan_failure_rate_limited
        TitanActionFailure.LIMIT_REACHED -> R.string.titan_failure_limit_reached
        TitanActionFailure.COMMAND_FAILED -> R.string.titan_failure_command_failed
        TitanActionFailure.VERIFICATION_FAILED -> R.string.titan_failure_verification_failed
        TitanActionFailure.UNAVAILABLE -> R.string.titan_failure_unavailable
    }

    /**
     * User-facing label of a containment action. Only the two D-pad exposed actions are localized;
     * every other enum value falls back to its stable technical name (honest, never invented copy).
     */
    fun containmentActionLabel(context: Context, action: TitanContainmentAction): String = when (action) {
        TitanContainmentAction.FREEZE_APP -> context.getString(R.string.titan_action_freeze)
        TitanContainmentAction.ISOLATE_NETWORK_UID -> context.getString(R.string.titan_action_isolate)
        else -> action.name
    }
}
