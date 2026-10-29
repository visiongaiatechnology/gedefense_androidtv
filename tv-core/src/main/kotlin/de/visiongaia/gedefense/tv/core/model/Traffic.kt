package de.visiongaia.gedefense.tv.core.model

/** What the local protection did with an observed flow. */
enum class TrafficAction { ALLOW, ANNOTATE, CORRELATE, BLOCK }

/** A point on the imported world map (WGS84). */
data class GeoPoint(val latitude: Double, val longitude: Double) {
    init {
        require(latitude in -90.0..90.0) { "invalid latitude" }
        require(longitude in -180.0..180.0) { "invalid longitude" }
    }
}

/** Origin of the map projection (the device's approximate home country, never GPS on TV). */
data class OriginInfo(
    val countryCode: String?,
    val point: GeoPoint?,
    val label: String,
) {
    init {
        require(label.length <= 64) { "origin label too long" }
    }
}

/** Aggregated traffic of one destination country. */
data class CountryTraffic(
    val countryCode: String,
    val bytes: Long,
    val flows: Int,
    val blockedFlows: Int = 0,
) {
    init {
        require(countryCode.matches(Regex("[A-Z]{2}"))) { "invalid country code" }
        require(bytes >= 0L && flows >= 0 && blockedFlows in 0..flows) { "invalid country traffic" }
    }
}

/** Aggregated queries per destination domain (only domains actually observed locally). */
data class DomainTraffic(val domain: String, val queries: Long, val blockedQueries: Long = 0) {
    init {
        require(domain.isNotBlank() && domain.length <= 253) { "invalid domain" }
        require(queries >= 0L && blockedQueries in 0..queries) { "invalid domain traffic" }
    }
}

/** Per-app traffic record with country/domain attribution. */
data class AppTraffic(
    val packageName: String,
    val label: String,
    val txBytes: Long,
    val rxBytes: Long,
    val activeFlows: Int,
    val openedFlows: Long,
    val blockedFlows: Long,
    val correlatedFlows: Long,
    val annotatedFlows: Long,
    val topCountries: List<CountryTraffic>,
    val topDomains: List<DomainTraffic>,
) {
    init {
        require(packageName.isNotBlank() && packageName.length <= 255) { "invalid app owner" }
        require(label.length <= 120) { "app label too long" }
        require(txBytes >= 0L && rxBytes >= 0L && activeFlows >= 0) { "invalid app traffic" }
        require(blockedFlows >= 0L && correlatedFlows >= 0L && annotatedFlows >= 0L) { "invalid counters" }
        require(topCountries.size <= 12 && topDomains.size <= 12) { "too many attribution rows" }
    }

    val totalBytes: Long get() = if (Long.MAX_VALUE - txBytes < rxBytes) Long.MAX_VALUE else txBytes + rxBytes
}

/**
 * Live snapshot of the on-device loopback VPN. All values are derived from locally observed
 * telemetry; a missing tunnel must never be rendered as "protected".
 */
data class TrafficSnapshot(
    val state: String,
    val startedAtMillis: Long,
    val updatedAtMillis: Long,
    val txBytes: Long,
    val rxBytes: Long,
    val activeFlows: Int,
    val blockedFlows: Long,
    val correlatedFlows: Long,
    val annotatedFlows: Long,
    val apps: List<AppTraffic>,
    val countries: List<CountryTraffic>,
    val domains: List<DomainTraffic>,
    val transportErrors: Long,
) {
    init {
        require(state.length <= 24) { "invalid traffic state" }
        require(txBytes >= 0L && rxBytes >= 0L && activeFlows >= 0) { "invalid traffic totals" }
        require(apps.size <= 200 && countries.size <= 64 && domains.size <= 200) { "traffic snapshot too large" }
    }

    val hasObservation: Boolean get() = apps.isNotEmpty() || countries.isNotEmpty() || modulesSeen > 0
    val modulesSeen: Int = countries.size

    companion object {
        val IDLE = TrafficSnapshot(
            state = "IDLE",
            startedAtMillis = 0L,
            updatedAtMillis = 0L,
            txBytes = 0L,
            rxBytes = 0L,
            activeFlows = 0,
            blockedFlows = 0L,
            correlatedFlows = 0L,
            annotatedFlows = 0L,
            apps = emptyList(),
            countries = emptyList(),
            domains = emptyList(),
            transportErrors = 0L,
        )
    }
}

/** One observed flow history entry (bounded tail, newest first in the UI). */
data class TrafficFlow(
    val id: Long,
    val ownerPackage: String,
    val ownerLabel: String,
    val destinationAddress: String,
    val countryCode: String?,
    val destinationDomain: String?,
    val action: TrafficAction,
    val protocol: String,
    val txBytes: Long,
    val rxBytes: Long,
    val openedAtMillis: Long,
    val lastSeenMillis: Long,
) {
    init {
        require(id >= 0L) { "invalid flow id" }
        require(ownerPackage.isNotBlank()) { "invalid flow owner" }
        require(destinationAddress.isNotBlank() && destinationAddress.length <= 64) { "invalid flow destination" }
        require(protocol.length in 1..8) { "invalid flow protocol" }
        require(txBytes >= 0L && rxBytes >= 0L) { "invalid flow bytes" }
        require(openedAtMillis > 0L && lastSeenMillis >= openedAtMillis) { "invalid flow timestamps" }
    }
}
