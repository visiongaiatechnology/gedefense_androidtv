package de.visiongaia.gedefense.tv.core.anomaly

/**
 * Encodes the representative destination addresses of a destination-specific anomaly signal into the
 * bounded [de.visiongaia.gedefense.tv.core.model.AnomalySignal.detail] string.
 *
 * The frozen anomaly model has no address list, but the containment policy requires at least two
 * distinct observed addresses inside the aggregated /24 or /64 before proposing a target. Keeping the
 * addresses inside the detail field keeps the model untouched while remaining deterministic and
 * testable. Only the first two canonically sorted addresses are stored; the detail stays <= 160 chars
 * as required by the model.
 */
object AnomalyDetailCodec {

    private const val ADDRESS_MARKER = "dst="
    private const val EXTRA_SEPARATOR = "|"
    private const val MAX_DETAIL_LENGTH = 160
    private const val MAX_ADDRESSES = 2

    /** Encodes up to two distinct numeric destination addresses plus an optional short annotation. */
    fun encode(destinationAddresses: Collection<String>, extra: String? = null): String {
        val addresses = destinationAddresses
            .asSequence()
            .mapNotNull { raw -> PrefixSupport.canonicalAddress(raw) }
            .distinct()
            .sorted()
            .take(MAX_ADDRESSES)
            .toList()
        val addressPart = ADDRESS_MARKER + addresses.joinToString(",")
        val safeExtra = extra
            ?.replace(EXTRA_SEPARATOR, "/")
            ?.trim()
            ?.take(60)
            ?.takeIf { it.isNotEmpty() }
        val detail = if (safeExtra == null) addressPart else "$addressPart$EXTRA_SEPARATOR$safeExtra"
        return detail.take(MAX_DETAIL_LENGTH)
    }

    /** Returns the canonical distinct destination addresses encoded in [detail] (possibly empty). */
    fun destinationAddresses(detail: String): List<String> {
        val markerIndex = detail.indexOf(ADDRESS_MARKER)
        if (markerIndex < 0) return emptyList()
        val afterMarker = detail.substring(markerIndex + ADDRESS_MARKER.length)
        val rawPart = afterMarker.substringBefore(EXTRA_SEPARATOR)
        return rawPart
            .split(',')
            .asSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .mapNotNull { PrefixSupport.canonicalAddress(it) }
            .distinct()
            .sorted()
            .toList()
    }
}
