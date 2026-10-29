package de.visiongaia.gedefense.mobile.core

// STATUS: DIAMANT VGT SUPREME
data class LanDeviceBehaviorInput(
    val observations: Int,
    val historicalRiskScore: Int,
    val currentRiskScore: Int,
    val newlyExposedPorts: Int,
    val newlyAdvertisedServices: Int,
    val lastSeenMillis: Long,
    val nowMillis: Long,
)

// STATUS: DIAMANT VGT SUPREME
data class LanNetworkBehaviorInput(
    val observations: Int,
    val historicalDeviceCount: Int,
    val currentDeviceCount: Int,
    val historicalElevatedCount: Int,
    val currentElevatedCount: Int,
)

// STATUS: DIAMANT VGT SUPREME
object LanBehaviorEvaluator {
    const val MIN_DEVICE_OBSERVATIONS = 4
    const val MIN_NETWORK_OBSERVATIONS = 4
    private const val SERVICE_BURST_THRESHOLD = 3
    private const val RISK_SPIKE_DELTA = 30
    private const val MIN_RISK_SPIKE_SCORE = 45
    private const val DEVICE_SURGE_ABSOLUTE = 5
    private const val ELEVATED_SURGE_ABSOLUTE = 3
    private const val LONG_ABSENCE_MS = 7L * 24L * 60L * 60L * 1000L

    fun deviceSignals(input: LanDeviceBehaviorInput): Set<String> {
        if (input.observations < MIN_DEVICE_OBSERVATIONS) return emptySet()
        val currentRisk = input.currentRiskScore.coerceIn(0, 100)
        val historicalRisk = input.historicalRiskScore.coerceIn(0, 100)
        val ports = input.newlyExposedPorts.coerceAtLeast(0)
        val services = input.newlyAdvertisedServices.coerceAtLeast(0)
        val surfaceDelta = saturatingAdd(ports, services)
        val out = linkedSetOf<String>()
        if (surfaceDelta >= SERVICE_BURST_THRESHOLD) out += "service_burst"
        if (currentRisk >= MIN_RISK_SPIKE_SCORE && currentRisk >= historicalRisk + RISK_SPIKE_DELTA) out += "exposure_risk_spike"
        val absence = nonNegativeDelta(input.nowMillis, input.lastSeenMillis)
        if (absence >= LONG_ABSENCE_MS && surfaceDelta > 0) out += "return_with_surface_drift"
        return out
    }

    fun networkSignals(input: LanNetworkBehaviorInput): Set<String> {
        if (input.observations < MIN_NETWORK_OBSERVATIONS) return emptySet()
        val historicalDevices = input.historicalDeviceCount.coerceAtLeast(0)
        val currentDevices = input.currentDeviceCount.coerceAtLeast(0)
        val historicalElevated = input.historicalElevatedCount.coerceAtLeast(0)
        val currentElevated = input.currentElevatedCount.coerceAtLeast(0)
        val out = linkedSetOf<String>()
        if (currentDevices >= historicalDevices + DEVICE_SURGE_ABSOLUTE && currentDevices >= saturatingMultiplyByTwo(historicalDevices)) {
            out += "device_surge"
        }
        if (currentElevated >= historicalElevated + ELEVATED_SURGE_ABSOLUTE && currentElevated >= maxOf(2, saturatingMultiplyByTwo(historicalElevated))) {
            out += "risk_surge"
        }
        return out
    }

    private fun saturatingAdd(a: Int, b: Int): Int = if (Int.MAX_VALUE - a < b) Int.MAX_VALUE else a + b
    private fun saturatingMultiplyByTwo(value: Int): Int = if (value > Int.MAX_VALUE / 2) Int.MAX_VALUE else value * 2
    private fun nonNegativeDelta(a: Long, b: Long): Long = if (a <= b) 0L else a - b
}
