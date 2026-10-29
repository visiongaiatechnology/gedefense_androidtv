package de.visiongaia.gedefense.tv.core.model

/**
 * Read-only platform identity collected from public Android build APIs.
 *
 * None of these values is an integrity proof. A missing value must be rendered as unknown, never
 * silently replaced by an optimistic default (datasheet requirement: honest visibility).
 */
data class PlatformIdentity(
    val sdkInt: Int,
    val androidRelease: String,
    val manufacturer: String,
    val model: String,
    val device: String,
    val fingerprint: String,
    val securityPatch: String?,
    val buildTimeMillis: Long?,
    val supportedAbis: List<String>,
    val appVersionName: String,
    val appVersionCode: Long,
    val appDebuggable: Boolean,
) {
    init {
        require(sdkInt >= 1) { "invalid sdk level" }
        require(androidRelease.isNotBlank()) { "empty android release" }
        require(supportedAbis.isNotEmpty()) { "empty ABI list" }
        require(supportedAbis.size <= 8) { "unexpected ABI list size" }
        require(appVersionCode >= 0L) { "invalid app version code" }
    }

    /** "Google TV" style display label derived from the OEM build values. */
    val displayModel: String get() = listOf(manufacturer, model).filter { it.isNotBlank() }.joinToString(" ").trim()
}

/** Patch age classification. Deliberately separates "old" from "known vulnerable". */
enum class PatchStatus { CURRENT, AGING, OUTDATED, CRITICALLY_OUTDATED, UNKNOWN }

/**
 * Result of comparing the build's [PlatformIdentity.securityPatch] against the current date.
 *
 * The classification only says the patch level is old; it cannot prove (or disprove) a concrete
 * vulnerability. That distinction is mandatory for every user-facing text.
 */
data class PatchAssessment(
    val status: PatchStatus,
    val patchDateMillis: Long?,
    val ageDays: Int?,
    val summary: MessageRef,
) {
    init {
        require(ageDays == null || ageDays >= 0) { "negative patch age" }
        require((status == PatchStatus.UNKNOWN) == (patchDateMillis == null)) {
            "unknown patch status and parsed date must agree"
        }
    }
}

/** Pure patch-level policy; intentionally independent from Android APIs for JVM testability. */
object PatchPolicy {
    const val AGING_AFTER_DAYS = 90
    const val OUTDATED_AFTER_DAYS = 180
    const val CRITICALLY_OUTDATED_AFTER_DAYS = 365
    private const val MAX_FUTURE_SKEW_MILLIS = 7L * 24L * 60L * 60L * 1000L
    private const val DAY_MILLIS = 24L * 60L * 60L * 1000L

    fun assess(securityPatch: String?, nowMillis: Long): PatchAssessment {
        val parsed = parsePatchDate(securityPatch)
            ?: return PatchAssessment(
                status = PatchStatus.UNKNOWN,
                patchDateMillis = null,
                ageDays = null,
                summary = MessageRef("patch.unknown"),
            )
        if (parsed > nowMillis + MAX_FUTURE_SKEW_MILLIS) {
            return PatchAssessment(
                status = PatchStatus.UNKNOWN,
                patchDateMillis = null,
                ageDays = null,
                summary = MessageRef("patch.unknown"),
            )
        }
        val ageDays = ((nowMillis - parsed).coerceAtLeast(0L) / DAY_MILLIS).toInt()
        val status = when {
            ageDays < AGING_AFTER_DAYS -> PatchStatus.CURRENT
            ageDays < OUTDATED_AFTER_DAYS -> PatchStatus.AGING
            ageDays < CRITICALLY_OUTDATED_AFTER_DAYS -> PatchStatus.OUTDATED
            else -> PatchStatus.CRITICALLY_OUTDATED
        }
        val key = when (status) {
            PatchStatus.CURRENT -> "patch.current"
            PatchStatus.AGING -> "patch.aging"
            PatchStatus.OUTDATED -> "patch.outdated"
            PatchStatus.CRITICALLY_OUTDATED -> "patch.critically_outdated"
            PatchStatus.UNKNOWN -> "patch.unknown"
        }
        return PatchAssessment(
            status = status,
            patchDateMillis = parsed,
            ageDays = ageDays,
            summary = MessageRef(key, listOf(ageDays.toString())),
        )
    }

    /**
     * Parses the AOSP `yyyy-MM-dd` security patch value as UTC midnight.
     *
     * Returns null for blank, malformed, or implausible values (before 2007 or after 2100) so the
     * caller can surface an honest unknown state.
     */
    fun parsePatchDate(value: String?): Long? {
        val raw = value?.trim().orEmpty()
        if (!raw.matches(Regex("\\d{4}-\\d{2}-\\d{2}"))) return null
        return try {
            val year = raw.substring(0, 4).toInt()
            val month = raw.substring(5, 7).toInt()
            val day = raw.substring(8, 10).toInt()
            if (year !in 2007..2100 || month !in 1..12 || day !in 1..31) return null
            val calendar = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"))
            calendar.clear()
            calendar.set(year, month - 1, day, 0, 0, 0)
            val millis = calendar.timeInMillis
            // Reject normalised overflow such as 2026-02-31 -> 2026-03-03.
            val check = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"))
            check.timeInMillis = millis
            if (check.get(java.util.Calendar.YEAR) != year ||
                check.get(java.util.Calendar.MONTH) != month - 1 ||
                check.get(java.util.Calendar.DAY_OF_MONTH) != day
            ) {
                null
            } else {
                millis
            }
        } catch (_: RuntimeException) {
            null
        }
    }
}
