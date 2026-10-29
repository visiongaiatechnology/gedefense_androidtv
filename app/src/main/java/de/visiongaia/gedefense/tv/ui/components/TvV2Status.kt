package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.core.model.VpnState

/**
 * V2 status mapping: VPN states, privacy profiles and traffic actions to the German UI vocabulary.
 * Colour is always paired with a glyph and an explicit label; an inactive tunnel is never green.
 */

fun vpnStateLabelRes(state: VpnState): Int = when (state) {
    VpnState.OFF -> R.string.prot_state_off
    VpnState.PREPARING -> R.string.prot_state_preparing
    VpnState.ACTIVE -> R.string.prot_state_active
    VpnState.DEGRADED -> R.string.prot_state_degraded
    VpnState.FAILED -> R.string.prot_state_failed
    VpnState.UNSUPPORTED -> R.string.prot_state_unsupported
}

fun vpnStateGlyph(state: VpnState): TvGlyph = when (state) {
    VpnState.OFF -> TvGlyph.EYE_OFF
    VpnState.PREPARING -> TvGlyph.CLOCK
    VpnState.ACTIVE -> TvGlyph.SHIELD
    VpnState.DEGRADED -> TvGlyph.HALF
    VpnState.FAILED -> TvGlyph.ALERT
    VpnState.UNSUPPORTED -> TvGlyph.CROSS
}

fun vpnStateTone(state: VpnState): TvTone = when (state) {
    VpnState.ACTIVE -> TvTone.SUCCESS
    VpnState.PREPARING -> TvTone.INFO
    VpnState.DEGRADED -> TvTone.WARNING
    VpnState.FAILED -> TvTone.DANGER
    VpnState.OFF, VpnState.UNSUPPORTED -> TvTone.NEUTRAL
}

fun vpnStateClaimRes(state: VpnState): Int = when (state) {
    VpnState.OFF -> R.string.prot_claim_inactive
    VpnState.PREPARING -> R.string.prot_claim_preparing
    VpnState.ACTIVE -> R.string.prot_claim_active
    VpnState.DEGRADED -> R.string.prot_claim_degraded
    VpnState.FAILED -> R.string.prot_claim_failed
    VpnState.UNSUPPORTED -> R.string.prot_claim_unsupported
}

fun privacyProfileLabelRes(profile: TvPrivacyProfile): Int = when (profile) {
    TvPrivacyProfile.OFF -> R.string.prot_profile_off
    TvPrivacyProfile.CONSERVATIVE -> R.string.prot_profile_conservative
    TvPrivacyProfile.BALANCED -> R.string.prot_profile_balanced
    TvPrivacyProfile.STRICT -> R.string.prot_profile_strict
}

/** Map a VpnControlApi reason key to a German user-facing text; never expose technical raw keys. */
fun vpnReasonLabel(context: Context, reasonKey: String?): String {
    val key = reasonKey?.trim()?.lowercase()
    return when (key) {
        "vpn_consent_required" -> context.getString(R.string.vpn_reason_consent_required)
        "vpn_consent_denied" -> context.getString(R.string.vpn_reason_consent_denied)
        "vpn_start_failed" -> context.getString(R.string.vpn_reason_start_failed)
        "vpn_establish_failed" -> context.getString(R.string.vpn_reason_establish_failed)
        "vpn_services_unavailable" -> context.getString(R.string.vpn_reason_services_unavailable)
        "vpn_traffic_unavailable" -> context.getString(R.string.vpn_reason_traffic_unavailable)
        "vpn_helper_unavailable", "vpn_helper_failed" -> context.getString(R.string.vpn_reason_helper_unavailable)
        "vpn_anchor_missing" -> context.getString(R.string.vpn_reason_anchor_missing)
        "vpn_anchor_lost" -> context.getString(R.string.vpn_reason_anchor_lost)
        "vpn_policy_refresh", "vpn_policy_unavailable" -> context.getString(R.string.vpn_reason_policy_refresh)
        "vpn_policy_partial_ti_unavailable" -> context.getString(R.string.vpn_reason_policy_partial_ti_unavailable)
        "vpn_helper_exited" -> context.getString(R.string.vpn_reason_helper_exited)
        "vpn_telemetry_failed" -> context.getString(R.string.vpn_reason_telemetry_failed)
        "operator_stop", "vpn_stopped" -> context.getString(R.string.vpn_reason_operator_stop)
        "system_revoke" -> context.getString(R.string.vpn_reason_system_revoke)
        "vpn_self_bypass_failed" -> context.getString(R.string.vpn_reason_self_bypass_failed)
        "vpn_unsupported" -> context.getString(R.string.vpn_reason_unsupported)
        "vpn_underlying_network_missing", "vpn_network_missing" -> context.getString(R.string.vpn_reason_network_missing)
        // Dynamic helper codes (vpn_helper_<code>): prefix means "restricted", never show the code.
        else -> if (key?.startsWith("vpn_helper_") == true) {
            context.getString(R.string.vpn_reason_helper_detail)
        } else {
            context.getString(R.string.vpn_reason_unknown)
        }
    }
}

/** Localised short category label for a heuristic domain category. */
fun trafficCategoryLabelRes(category: String): Int = when (category) {
    "telemetry" -> R.string.prot_cat_telemetry
    "acr" -> R.string.prot_cat_acr
    "ads" -> R.string.prot_cat_ads
    "c2" -> R.string.prot_cat_c2
    else -> R.string.prot_categories_empty
}

/** German byte formatting with decimal comma and binary units (compact for TV HUDs). */
fun formatBytes(count: Long): String {
    if (count <= 0L) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var value = count.toDouble()
    var unit = 0
    while (value >= 1024.0 && unit < units.size - 1) {
        value /= 1024.0
        unit++
    }
    return if (unit == 0) {
        "${count} B"
    } else {
        String.format(java.util.Locale.GERMANY, "%.1f %s", value, units[unit])
    }
}



/** Stable, deterministic route colour from the VGT palette (gold / electric blue, no neon). */
fun routeColorFor(countryCode: String): Int {
    val palette = intArrayOf(
        android.graphics.Color.rgb(230, 185, 92),
        android.graphics.Color.rgb(90, 169, 230),
        android.graphics.Color.rgb(201, 162, 75),
        android.graphics.Color.rgb(120, 176, 214),
        android.graphics.Color.rgb(164, 126, 52),
        android.graphics.Color.rgb(72, 140, 198),
    )
    var hash = 7
    for (ch in countryCode) hash = hash * 31 + ch.code
    return palette[Math.abs(hash) % palette.size]
}