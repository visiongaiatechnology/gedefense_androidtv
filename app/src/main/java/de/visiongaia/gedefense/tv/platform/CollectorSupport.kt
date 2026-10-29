package de.visiongaia.gedefense.tv.platform

import android.content.Context
import android.content.pm.PackageManager
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.EvidenceRef
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.TvEvent
import java.util.UUID

/**
 * Shared, defensive helpers for the Android TV collectors.
 *
 * Everything here is written for the "never crash on an unreadable platform value" rule: string
 * values are bounded and single-lined, event construction is best-effort and cannot throw into a
 * collector, and result construction keeps the model invariants explicit.
 */
object CollectorSupport {
    const val KEY_COLLECTOR_FAILED = "collector.failed"
    const val KEY_COLLECTOR_TIMEOUT = "collector.timeout"
    const val KEY_COLLECTOR_PERMISSION_REQUIRED = "collector.permission_required"
    const val KEY_COLLECTOR_UNSUPPORTED = "collector.unsupported"
    const val KEY_COLLECTOR_RESTRICTED = "collector.restricted"
    const val KEY_COLLECTOR_PARTIAL_COVERAGE = "collector.partial_coverage"
    const val KEY_COLLECTOR_STALE = "collector.stale"
    const val KEY_COVERAGE_PACKAGE_VISIBILITY = "coverage.packagevisibility"
    const val KEY_COVERAGE_PARTIAL = "coverage.partial"

    const val MAX_ATTRIBUTES = 12
    const val MAX_ATTRIBUTE_VALUE = 256
    const val MAX_SUBJECT = 160

    fun descriptor(
        id: String,
        category: CollectorCategory,
        titleKey: String,
        descriptionKey: String,
        restrictedOnSomeDevices: Boolean,
    ): CollectorDescriptor = CollectorDescriptor(
        id = id,
        category = category,
        title = MessageRef(titleKey),
        description = MessageRef(descriptionKey),
        restrictedOnSomeDevices = restrictedOnSomeDevices,
    )

    fun evidence(source: String, atMillis: Long): EvidenceRef = EvidenceRef(
        source = source,
        collectedAtMillis = atMillis.coerceAtLeast(0L),
    )

    fun supported(
        descriptor: CollectorDescriptor,
        startedAtMillis: Long,
        completedAtMillis: Long,
        visibility: DataVisibility,
        dataQuality: DataQuality,
        findings: List<Finding> = emptyList(),
        coverage: CollectorCoverage? = null,
        errorKey: MessageRef? = null,
    ): CollectorResult = CollectorResult(
        collectorId = descriptor.id,
        category = descriptor.category,
        capability = de.visiongaia.gedefense.tv.core.model.CapabilityState.SUPPORTED,
        visibility = visibility,
        dataQuality = dataQuality,
        startedAtMillis = startedAtMillis,
        completedAtMillis = completedAtMillis,
        findings = findings,
        coverage = coverage,
        errorKey = errorKey,
    )

    fun degraded(
        descriptor: CollectorDescriptor,
        startedAtMillis: Long,
        completedAtMillis: Long,
        capability: de.visiongaia.gedefense.tv.core.model.CapabilityState,
        errorKey: MessageRef,
    ): CollectorResult = CollectorResult(
        collectorId = descriptor.id,
        category = descriptor.category,
        capability = capability,
        visibility = DataVisibility.NONE,
        dataQuality = DataQuality.UNKNOWN,
        startedAtMillis = startedAtMillis,
        completedAtMillis = completedAtMillis,
        errorKey = errorKey,
    )

    fun failed(
        descriptor: CollectorDescriptor,
        startedAtMillis: Long,
        completedAtMillis: Long,
        errorKey: MessageRef = MessageRef(KEY_COLLECTOR_FAILED),
    ): CollectorResult = CollectorResult.failed(
        collectorId = descriptor.id,
        category = descriptor.category,
        startedAtMillis = startedAtMillis,
        completedAtMillis = completedAtMillis.coerceAtLeast(startedAtMillis),
        errorKey = errorKey,
    )

    fun isPermissionGranted(context: Context, permission: String): Boolean = try {
        context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    } catch (_: Throwable) {
        false
    }

    /** Bounded, single-line display/evidence string; never throws for odd platform values. */
    fun oneLine(value: String?, max: Int): String {
        val raw = value ?: return ""
        val sanitized = raw.map { character ->
            if (character == '\n' || character == '\r' || character == '\t') ' ' else character
        }.joinToString("").trim()
        return if (sanitized.length <= max) sanitized else sanitized.take(max - 1) + "\u2026"
    }

    /**
     * Builds a schema-valid [TvEvent] or returns null. Attribute keys/values are normalised so a
     * malformed platform string can never throw out of a collector; unknown fields stay null.
     */
    fun event(
        eventClass: EventClass,
        collectorId: String,
        deviceId: String,
        osApiLevel: Int,
        eventTimeMillis: Long,
        subject: String,
        dataQuality: DataQuality,
        attributes: Map<String, String> = emptyMap(),
    ): TvEvent? = try {
        val sanitizedAttributes = LinkedHashMap<String, String>()
        for ((rawKey, rawValue) in attributes) {
            if (sanitizedAttributes.size >= MAX_ATTRIBUTES) break
            val key = normaliseAttributeKey(rawKey)
            if (key == null || key in sanitizedAttributes) continue
            val value = oneLine(rawValue, MAX_ATTRIBUTE_VALUE)
            if (value.isEmpty()) continue
            sanitizedAttributes[key] = value
        }
        TvEvent(
            eventClass = eventClass,
            eventId = UUID.randomUUID().toString(),
            deviceId = deviceId,
            eventTimeMillis = eventTimeMillis.coerceAtLeast(1L),
            collectorId = collectorId,
            platform = TvEvent.PLATFORM,
            osApiLevel = osApiLevel.coerceAtLeast(1),
            subject = oneLine(subject, MAX_SUBJECT).ifBlank { "android-tv" },
            dataQuality = dataQuality,
            attributes = sanitizedAttributes,
        )
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun normaliseAttributeKey(raw: String): String? {
        val candidate = raw.lowercase().map { character ->
            if (character.isLetterOrDigit() || character == '_') character else '_'
        }.joinToString("").trim('_')
        if (candidate.length < 2 || candidate.length > 32) return null
        if (!candidate[0].isLetter()) return null
        return candidate
    }
}
