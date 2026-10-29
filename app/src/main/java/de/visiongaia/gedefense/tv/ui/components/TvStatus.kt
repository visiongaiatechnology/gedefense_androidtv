package de.visiongaia.gedefense.tv.ui.components

import android.content.Context
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.PatchStatus
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.PostureBand
import de.visiongaia.gedefense.tv.core.model.ScanState
import de.visiongaia.gedefense.tv.core.model.Severity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Deterministic German time formatting for the TV UI.
 *
 * The app UI language is German regardless of the system locale, so patterns are pinned to
 * `Locale.GERMANY`. Formatting must never return an empty or crash-prone value: invalid timestamps
 * map to the honest "unknown" state.
 */
object TvFormat {

    private const val MINUTE = 60_000L
    private const val HOUR = 60L * MINUTE
    private const val DAY = 24L * HOUR

    fun dateTime(context: Context, millis: Long): String {
        if (millis <= 0L) return context.getString(R.string.value_unknown)
        return format(context, R.string.format_date_time_with_clock, millis)
    }

    fun date(context: Context, millis: Long): String {
        if (millis <= 0L) return context.getString(R.string.value_unknown)
        return format(context, R.string.format_date, millis)
    }

    /** Relative age for recent timestamps, absolute date for older ones. */
    fun relative(context: Context, millis: Long): String {
        if (millis <= 0L) return context.getString(R.string.value_never)
        val delta = System.currentTimeMillis() - millis
        if (delta < 0L) return dateTime(context, millis)
        return when {
            delta < MINUTE -> context.getString(R.string.age_just_now)
            delta < HOUR -> context.getString(R.string.age_minutes, (delta / MINUTE).toInt())
            delta < DAY -> context.getString(R.string.age_hours, (delta / HOUR).toInt())
            delta < 30L * DAY -> context.getString(R.string.age_days, (delta / DAY).toInt())
            else -> dateTime(context, millis)
        }
    }

    /** Scan/collector duration; unknown or implausible durations stay honest. */
    fun duration(context: Context, startMillis: Long, endMillis: Long): String {
        if (startMillis <= 0L || endMillis <= 0L || endMillis < startMillis) {
            return context.getString(R.string.value_unknown)
        }
        val millis = endMillis - startMillis
        return when {
            millis < MINUTE -> context.getString(R.string.duration_seconds, (millis / 1000L).toInt())
            millis < HOUR -> context.getString(R.string.duration_minutes, (millis / MINUTE).toInt())
            else -> context.getString(R.string.duration_hours, (millis / HOUR).toInt())
        }
    }

    /** Findings summary with correct German singular/plural. */
    fun findingsSummary(context: Context, count: Int, collectors: Int): String =
        if (count == 1) {
            context.getString(R.string.findings_summary_one, count, collectors)
        } else {
            context.getString(R.string.findings_summary, count, collectors)
        }

    fun findingsCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_findings, count, count)

    fun eventsCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_events, count, count)

    fun collectorsCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_collectors, count, count)

    fun appsCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_apps, count, count)

    fun feedsCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_feeds, count, count)

    fun evidenceRecordsCount(context: Context, count: Long): String {
        val value = if (count > Int.MAX_VALUE) Int.MAX_VALUE else count.toInt()
        return context.resources.getQuantityString(R.plurals.count_evidence_records, value, value)
    }

    fun collectorFindingsCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_collector_findings, count, count)

    fun moreFindingsCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_more_findings, count, count)

    fun removedPackagesCount(context: Context, count: Int): String =
        context.resources.getQuantityString(R.plurals.count_removed_packages, count, count)

    private fun format(context: Context, patternRes: Int, millis: Long): String {
        return try {
            // Follow the active UI locale (TV system/per-app language), never a hard-coded locale.
            SimpleDateFormat(context.getString(patternRes), Locale.getDefault()).format(Date(millis))
        } catch (t: RuntimeException) {
            context.getString(R.string.value_unknown)
        }
    }
}

/** German label for a posture band. */
fun postureBandLabelRes(band: PostureBand): Int = when (band) {
    PostureBand.STRONG -> R.string.posture_band_strong
    PostureBand.MODERATE -> R.string.posture_band_moderate
    PostureBand.WEAK -> R.string.posture_band_weak
    PostureBand.UNKNOWN -> R.string.posture_band_unknown
    PostureBand.INSUFFICIENT_COVERAGE -> R.string.posture_band_insufficient
}

/** Icon for a posture band - the status is never conveyed by colour alone. */
fun postureBandGlyph(band: PostureBand): TvGlyph = when (band) {
    PostureBand.STRONG -> TvGlyph.SHIELD
    PostureBand.MODERATE -> TvGlyph.HALF
    PostureBand.WEAK -> TvGlyph.ALERT
    PostureBand.UNKNOWN -> TvGlyph.QUESTION
    PostureBand.INSUFFICIENT_COVERAGE -> TvGlyph.EYE_OFF
}

/** Semantic tone for a posture band; the score ring uses the same colour family. */
fun postureBandTone(band: PostureBand): TvTone = when (band) {
    PostureBand.STRONG -> TvTone.SUCCESS
    PostureBand.MODERATE -> TvTone.ACCENT
    PostureBand.WEAK -> TvTone.WARNING
    PostureBand.UNKNOWN -> TvTone.NEUTRAL
    PostureBand.INSUFFICIENT_COVERAGE -> TvTone.NEUTRAL
}

fun visibilityLabelRes(visibility: DataVisibility): Int = when (visibility) {
    DataVisibility.FULL -> R.string.visibility_full
    DataVisibility.PARTIAL -> R.string.visibility_partial
    DataVisibility.STALE -> R.string.visibility_stale
    DataVisibility.NONE -> R.string.visibility_none
}

fun visibilityGlyph(visibility: DataVisibility): TvGlyph = when (visibility) {
    DataVisibility.FULL -> TvGlyph.EYE
    DataVisibility.PARTIAL -> TvGlyph.HALF
    DataVisibility.STALE -> TvGlyph.CLOCK
    DataVisibility.NONE -> TvGlyph.EYE_OFF
}

fun visibilityTone(visibility: DataVisibility): TvTone = when (visibility) {
    DataVisibility.FULL -> TvTone.SUCCESS
    DataVisibility.PARTIAL -> TvTone.WARNING
    DataVisibility.STALE -> TvTone.WARNING
    DataVisibility.NONE -> TvTone.DANGER
}

fun dataQualityLabelRes(quality: DataQuality): Int = when (quality) {
    DataQuality.FRESH -> R.string.quality_fresh
    DataQuality.PARTIAL -> R.string.quality_partial
    DataQuality.STALE -> R.string.quality_stale
    DataQuality.UNKNOWN -> R.string.quality_unknown
}

fun dataQualityGlyph(quality: DataQuality): TvGlyph = when (quality) {
    DataQuality.FRESH -> TvGlyph.CHECK
    DataQuality.PARTIAL -> TvGlyph.HALF
    DataQuality.STALE -> TvGlyph.CLOCK
    DataQuality.UNKNOWN -> TvGlyph.QUESTION
}

fun dataQualityTone(quality: DataQuality): TvTone = when (quality) {
    DataQuality.FRESH -> TvTone.SUCCESS
    DataQuality.PARTIAL -> TvTone.WARNING
    DataQuality.STALE -> TvTone.WARNING
    DataQuality.UNKNOWN -> TvTone.NEUTRAL
}

fun severityLabelRes(severity: Severity): Int = when (severity) {
    Severity.INFO -> R.string.severity_info
    Severity.LOW -> R.string.severity_low
    Severity.MEDIUM -> R.string.severity_medium
    Severity.HIGH -> R.string.severity_high
    Severity.CRITICAL -> R.string.severity_critical
}

fun severityTone(severity: Severity): TvTone = when (severity) {
    Severity.INFO -> TvTone.INFO
    Severity.LOW -> TvTone.INFO
    Severity.MEDIUM -> TvTone.WARNING
    Severity.HIGH -> TvTone.DANGER
    Severity.CRITICAL -> TvTone.DANGER
}

fun severityGlyph(severity: Severity): TvGlyph = when (severity) {
    Severity.INFO -> TvGlyph.INFO
    Severity.LOW -> TvGlyph.DOT
    Severity.MEDIUM -> TvGlyph.ALERT
    Severity.HIGH -> TvGlyph.ALERT
    Severity.CRITICAL -> TvGlyph.ALERT
}

fun confidenceLabelRes(confidence: de.visiongaia.gedefense.tv.core.model.Confidence): Int =
    when (confidence) {
        de.visiongaia.gedefense.tv.core.model.Confidence.LOW -> R.string.confidence_low
        de.visiongaia.gedefense.tv.core.model.Confidence.MEDIUM -> R.string.confidence_medium
        de.visiongaia.gedefense.tv.core.model.Confidence.HIGH -> R.string.confidence_high
    }

fun confidenceTone(confidence: de.visiongaia.gedefense.tv.core.model.Confidence): TvTone =
    when (confidence) {
        de.visiongaia.gedefense.tv.core.model.Confidence.LOW -> TvTone.NEUTRAL
        de.visiongaia.gedefense.tv.core.model.Confidence.MEDIUM -> TvTone.INFO
        de.visiongaia.gedefense.tv.core.model.Confidence.HIGH -> TvTone.SUCCESS
    }

fun scanStateLabelRes(state: ScanState): Int = when (state) {
    ScanState.COMPLETED -> R.string.scan_state_completed
    ScanState.PARTIAL -> R.string.scan_state_partial
    ScanState.CANCELLED -> R.string.scan_state_cancelled
    ScanState.FAILED -> R.string.scan_state_failed
}

fun scanStateGlyph(state: ScanState): TvGlyph = when (state) {
    ScanState.COMPLETED -> TvGlyph.CHECK
    ScanState.PARTIAL -> TvGlyph.HALF
    ScanState.CANCELLED -> TvGlyph.CROSS
    ScanState.FAILED -> TvGlyph.ALERT
}

fun scanStateTone(state: ScanState): TvTone = when (state) {
    ScanState.COMPLETED -> TvTone.SUCCESS
    ScanState.PARTIAL -> TvTone.WARNING
    ScanState.CANCELLED -> TvTone.NEUTRAL
    ScanState.FAILED -> TvTone.DANGER
}

fun patchStatusLabelRes(status: PatchStatus): Int = when (status) {
    PatchStatus.CURRENT -> R.string.patch_current
    PatchStatus.AGING -> R.string.patch_aging
    PatchStatus.OUTDATED -> R.string.patch_outdated
    PatchStatus.CRITICALLY_OUTDATED -> R.string.patch_critically_outdated
    PatchStatus.UNKNOWN -> R.string.patch_unknown
}

fun patchStatusTone(status: PatchStatus): TvTone = when (status) {
    PatchStatus.CURRENT -> TvTone.SUCCESS
    PatchStatus.AGING -> TvTone.WARNING
    PatchStatus.OUTDATED -> TvTone.WARNING
    PatchStatus.CRITICALLY_OUTDATED -> TvTone.DANGER
    PatchStatus.UNKNOWN -> TvTone.NEUTRAL
}

fun patchStatusGlyph(status: PatchStatus): TvGlyph = when (status) {
    PatchStatus.CURRENT -> TvGlyph.CHECK
    PatchStatus.AGING -> TvGlyph.CLOCK
    PatchStatus.OUTDATED -> TvGlyph.ALERT
    PatchStatus.CRITICALLY_OUTDATED -> TvGlyph.ALERT
    PatchStatus.UNKNOWN -> TvGlyph.QUESTION
}

fun policyActionLabelRes(action: PolicyAction): Int = when (action) {
    PolicyAction.NONE -> R.string.policy_none
    PolicyAction.OBSERVE -> R.string.policy_observe
    PolicyAction.RECOMMEND_MANUAL -> R.string.policy_recommend_manual
    PolicyAction.ESCALATE_TO_USER -> R.string.policy_escalate
}

fun policyActionTone(action: PolicyAction): TvTone = when (action) {
    PolicyAction.NONE -> TvTone.NEUTRAL
    PolicyAction.OBSERVE -> TvTone.INFO
    PolicyAction.RECOMMEND_MANUAL -> TvTone.INFO
    PolicyAction.ESCALATE_TO_USER -> TvTone.WARNING
}

fun categoryLabelRes(category: de.visiongaia.gedefense.tv.core.model.CollectorCategory): Int =
    when (category) {
        de.visiongaia.gedefense.tv.core.model.CollectorCategory.PLATFORM -> R.string.category_platform
        de.visiongaia.gedefense.tv.core.model.CollectorCategory.APPS -> R.string.category_apps
        de.visiongaia.gedefense.tv.core.model.CollectorCategory.HARDENING -> R.string.category_hardening
        de.visiongaia.gedefense.tv.core.model.CollectorCategory.CONNECTIVITY -> R.string.category_connectivity
        de.visiongaia.gedefense.tv.core.model.CollectorCategory.THREAT_INTEL -> R.string.category_threat_intel
        de.visiongaia.gedefense.tv.core.model.CollectorCategory.SENSOR_HEALTH -> R.string.category_sensor_health
    }

fun capabilityLabelRes(capability: de.visiongaia.gedefense.tv.core.model.CapabilityState): Int =
    when (capability) {
        de.visiongaia.gedefense.tv.core.model.CapabilityState.SUPPORTED -> R.string.capability_supported
        de.visiongaia.gedefense.tv.core.model.CapabilityState.PERMISSION_REQUIRED -> R.string.capability_permission_required
        de.visiongaia.gedefense.tv.core.model.CapabilityState.UNSUPPORTED -> R.string.capability_unsupported
        de.visiongaia.gedefense.tv.core.model.CapabilityState.FAILED -> R.string.capability_failed
    }

fun capabilityTone(capability: de.visiongaia.gedefense.tv.core.model.CapabilityState): TvTone =
    when (capability) {
        de.visiongaia.gedefense.tv.core.model.CapabilityState.SUPPORTED -> TvTone.SUCCESS
        de.visiongaia.gedefense.tv.core.model.CapabilityState.PERMISSION_REQUIRED -> TvTone.WARNING
        de.visiongaia.gedefense.tv.core.model.CapabilityState.UNSUPPORTED -> TvTone.NEUTRAL
        de.visiongaia.gedefense.tv.core.model.CapabilityState.FAILED -> TvTone.DANGER
    }

fun capabilityGlyph(capability: de.visiongaia.gedefense.tv.core.model.CapabilityState): TvGlyph =
    when (capability) {
        de.visiongaia.gedefense.tv.core.model.CapabilityState.SUPPORTED -> TvGlyph.CHECK
        de.visiongaia.gedefense.tv.core.model.CapabilityState.PERMISSION_REQUIRED -> TvGlyph.LOCK
        de.visiongaia.gedefense.tv.core.model.CapabilityState.UNSUPPORTED -> TvGlyph.CROSS
        de.visiongaia.gedefense.tv.core.model.CapabilityState.FAILED -> TvGlyph.ALERT
    }

/** German label for a known event class; unknown strings stay visible unchanged (honest fallback). */
fun eventClassLabelResOrNull(type: String): Int? = try {
    when (EventClass.valueOf(type)) {
        EventClass.TV_DEVICE_STATE -> R.string.event_class_device_state
        EventClass.TV_APP_INVENTORY -> R.string.event_class_app_inventory
        EventClass.TV_USAGE_SIGNAL -> R.string.event_class_usage_signal
        EventClass.TV_CONNECTIVITY_STATE -> R.string.event_class_connectivity_state
        EventClass.TV_TI_MATCH -> R.string.event_class_ti_match
        EventClass.TV_SENSOR_HEALTH -> R.string.event_class_sensor_health
        EventClass.TV_ENFORCEMENT -> R.string.event_class_enforcement
    }
} catch (t: IllegalArgumentException) {
    null
}

/** German label for a severity name; null when the value is not a known model severity. */
fun severityLabelResOrNull(name: String): Int? = try {
    severityLabelRes(Severity.valueOf(name))
} catch (t: IllegalArgumentException) {
    null
}
