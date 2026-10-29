package de.visiongaia.gedefense.tv.core.model

/**
 * State of the local loopback VPN as shown to the user.
 *
 * The app must never claim protection while [OFF]/[PREPARING]/[FAILED]; [DEGRADED] means the tunnel
 * exists but parts of the data plane (telemetry/policy) are unhealthy.
 */
enum class VpnState { OFF, PREPARING, ACTIVE, DEGRADED, FAILED, UNSUPPORTED }

/** Full VPN status snapshot for the UI/report. */
data class VpnStatus(
    val state: VpnState,
    val startedAtMillis: Long,
    val reasonKey: String? = null,
    val blockedFlows: Long = 0L,
    val observedApps: Int = 0,
    val privacyProfile: String = "balanced",
    val detail: MessageRef? = null,
) {
    init {
        require(startedAtMillis >= 0L) { "invalid vpn start time" }
        require(blockedFlows >= 0L && observedApps >= 0) { "invalid vpn counters" }
        require(reasonKey == null || reasonKey.length <= 120) { "vpn reason too long" }
        require(privacyProfile.length <= 24) { "invalid privacy profile" }
    }

    /**
     * Only a fully active tunnel claims protection. DEGRADED means the tunnel exists but a policy
     * layer (e.g. TI) is missing or unhealthy; the UI must present that as restricted, never as
     * "protected".
     */
    val isProtecting: Boolean get() = state == VpnState.ACTIVE

    companion object {
        val OFF = VpnStatus(state = VpnState.OFF, startedAtMillis = 0L)
    }
}

/**
 * Portable description of a user-selectable privacy/filter profile (TV settings).
 * The concrete rule evaluation lives in the privacy policy engine.
 */
enum class TvPrivacyProfile(val storageKey: String) {
    OFF("off"),
    CONSERVATIVE("conservative"),
    BALANCED("balanced"),
    STRICT("strict"),
    ;

    companion object {
        fun fromStorage(value: String?): TvPrivacyProfile =
            entries.firstOrNull { it.storageKey == value } ?: BALANCED
    }
}
