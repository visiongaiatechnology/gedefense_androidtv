package de.visiongaia.gedefense.mobile.core

/**
 * Pure, local-only policy for telemetry behavior learning.
 *
 * This policy produces evidence context only. Callers must not translate any result into blocking,
 * quarantine, suspension, or other enforcement authority.
 */
object TelemetryLearningPolicy {
    const val PROMOTION_SESSIONS = 3
    const val MIN_BEACON_INTERVAL_SAMPLES = 3
    const val MIN_BEACON_INTERVAL_MILLIS = 15_000L
    const val MAX_BEACON_INTERVAL_MILLIS = 30L * 60L * 1000L
    const val MAX_BEACON_RELATIVE_DEVIATION_PERMILLE = 250L
    const val RATE_SHIFT_FACTOR = 4L
    const val MAX_EVIDENCE_RISK_POINTS = 8

    data class Promotion(val count: Int, val confirmed: Boolean)

    fun promote(previousSessionCount: Int): Promotion {
        val count = (previousSessionCount.coerceIn(0, PROMOTION_SESSIONS) + 1).coerceAtMost(PROMOTION_SESSIONS)
        return Promotion(count, count >= PROMOTION_SESSIONS)
    }

    fun isPeriodicBeacon(
        intervalSamples: Int,
        intervalEwmaMillis: Long,
        intervalDeviationEwmaMillis: Long,
    ): Boolean {
        if (intervalSamples < MIN_BEACON_INTERVAL_SAMPLES) return false
        val interval = intervalEwmaMillis.coerceAtLeast(0L)
        if (interval !in MIN_BEACON_INTERVAL_MILLIS..MAX_BEACON_INTERVAL_MILLIS) return false
        val deviation = intervalDeviationEwmaMillis.coerceAtLeast(0L)
        val relativePermille = if (interval == 0L) Long.MAX_VALUE else saturatingMultiply(deviation, 1000L) / interval
        return relativePermille <= MAX_BEACON_RELATIVE_DEVIATION_PERMILLE
    }

    fun isQueryRateShift(
        currentQueriesPerMinute: Long,
        baselineQueriesPerMinute: Long,
        baselineDeviationPerMinute: Long,
    ): Boolean {
        val current = currentQueriesPerMinute.coerceAtLeast(0L)
        val baseline = baselineQueriesPerMinute.coerceAtLeast(0L)
        if (baseline <= 0L || current < 4L) return false
        val factorThreshold = saturatingMultiply(baseline, RATE_SHIFT_FACTOR)
        val deviationThreshold = saturatingAdd(baseline, saturatingMultiply(baselineDeviationPerMinute.coerceAtLeast(0L), 4L))
        return current >= maxOf(factorThreshold, deviationThreshold)
    }

    fun evidenceRiskPoints(requested: Int): Int = requested.coerceIn(0, MAX_EVIDENCE_RISK_POINTS)

    private fun saturatingMultiply(a: Long, b: Long): Long {
        if (a <= 0L || b <= 0L) return 0L
        return if (a > Long.MAX_VALUE / b) Long.MAX_VALUE else a * b
    }

    private fun saturatingAdd(a: Long, b: Long): Long =
        if (a < 0L || b < 0L || Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b
}
