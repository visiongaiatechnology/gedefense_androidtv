package de.visiongaia.gedefense.tv.core.geo

import de.visiongaia.gedefense.mobile.core.IpPrefix

/**
 * Pure IPv4/IPv6 -> ISO-3166 alpha-2 country lookup.
 *
 * Implementations must be honest: `null` means "country not known", not "safe country". The TV app
 * must render that as UNKNOWN instead of inventing an attribution. No implementation performs
 * network I/O; the country table is always caller-provided (offline geo data).
 */
fun interface GeoLookup {
    fun countryCode(destinationAddress: String): String?

    companion object {
        /** Reserved code used by the traffic snapshot for "country unknown". */
        const val UNKNOWN_COUNTRY = "ZZ"

        /** Explicitly unknown lookup; every address resolves to `null`. */
        val NONE: GeoLookup = GeoLookup { null }
    }
}

/** One offline geo prefix -> country assignment supplied by the app layer. */
data class GeoPrefixEntry(val prefix: IpPrefix, val countryCode: String) {
    init {
        require(countryCode.matches(Regex("[A-Z]{2}"))) { "invalid geo country code: $countryCode" }
    }

    companion object {
        /** Parses `CIDR + countryCode` and returns null for invalid input instead of guessing. */
        fun parse(cidr: String, countryCode: String): GeoPrefixEntry? {
            val prefix = IpPrefix.parse(cidr) ?: return null
            val normalized = countryCode.trim().uppercase(java.util.Locale.ROOT)
            if (!normalized.matches(Regex("[A-Z]{2}"))) return null
            return GeoPrefixEntry(prefix, normalized)
        }
    }
}

/**
 * Immutable longest-prefix-match table built from caller-provided [GeoPrefixEntry] rows.
 *
 * Lookup is exact and bounded: only the configured prefix lengths are probed, so the table never
 * performs address iteration. A missing match returns `null` (honest UNKNOWN).
 */
class PrefixTableGeoLookup private constructor(
    private val byFamily: Map<Int, Map<Int, Map<IpPrefix, String>>>,
    private val lengthsByFamily: Map<Int, List<Int>>,
) : GeoLookup {

    override fun countryCode(destinationAddress: String): String? {
        val address = IpPrefix.parseAddress(destinationAddress) ?: return null
        val table = byFamily[address.family] ?: return null
        val lengths = lengthsByFamily[address.family] ?: return null
        for (length in lengths) {
            val prefixes = table[length] ?: continue
            val key = if (address.family == 4) {
                IpPrefix(4, v4 = maskV4(address.v4, length), prefixLength = length)
            } else {
                val masked = maskV6(address.v6Hi, address.v6Lo, length)
                IpPrefix(6, v6Hi = masked.first, v6Lo = masked.second, prefixLength = length)
            }
            val code = prefixes[key]
            if (code != null) return code
        }
        return null
    }

    /** Number of configured prefixes. */
    val size: Int get() = byFamily.values.sumOf { family -> family.values.sumOf { it.size } }

    companion object {
        const val MAX_ENTRIES = 200_000

        /**
         * Builds the table. Duplicate prefixes with conflicting countries are rejected instead of
         * silently last-write-wins; exact duplicates with the same country collapse.
         */
        fun build(entries: Collection<GeoPrefixEntry>, maxEntries: Int = MAX_ENTRIES): PrefixTableGeoLookup {
            require(maxEntries in 1..MAX_ENTRIES) { "invalid geo entry bound" }
            require(entries.size <= maxEntries) { "geo entry bound exceeded: ${entries.size} > $maxEntries" }
            val mutable = LinkedHashMap<Int, LinkedHashMap<Int, LinkedHashMap<IpPrefix, String>>>()
            entries.forEach { entry ->
                val country = entry.countryCode.trim().uppercase(java.util.Locale.ROOT)
                require(country.matches(Regex("[A-Z]{2}"))) { "invalid geo country code: $country" }
                val prefix = normalize(entry.prefix)
                val family = mutable.getOrPut(prefix.family) { LinkedHashMap() }
                val byLength = family.getOrPut(prefix.prefixLength) { LinkedHashMap() }
                val previous = byLength.put(prefix, country)
                require(previous == null || previous == country) {
                    "conflicting geo country for prefix $prefix"
                }
            }
            val frozen: Map<Int, Map<Int, Map<IpPrefix, String>>> = mutable.mapValues { (_, family) ->
                family.mapValues { (_, prefixes) -> prefixes.toMap() }
            }
            val lengths: Map<Int, List<Int>> = frozen.mapValues { (_, family) -> family.keys.sortedDescending() }
            return PrefixTableGeoLookup(frozen, lengths)
        }

        private fun normalize(prefix: IpPrefix): IpPrefix = if (prefix.family == 4) {
            IpPrefix(4, v4 = maskV4(prefix.v4, prefix.prefixLength), prefixLength = prefix.prefixLength)
        } else {
            val masked = maskV6(prefix.v6Hi, prefix.v6Lo, prefix.prefixLength)
            IpPrefix(6, v6Hi = masked.first, v6Lo = masked.second, prefixLength = prefix.prefixLength)
        }

        private fun maskV4(value: Int, prefixLength: Int): Int =
            if (prefixLength <= 0) 0 else value and (-1 shl (32 - prefixLength))

        private fun maskV6(hi: Long, lo: Long, prefixLength: Int): Pair<Long, Long> = when {
            prefixLength <= 0 -> 0L to 0L
            prefixLength < 64 -> (hi and (-1L shl (64 - prefixLength))) to 0L
            prefixLength == 64 -> hi to 0L
            prefixLength < 128 -> hi to (lo and (-1L shl (128 - prefixLength)))
            else -> hi to lo
        }
    }
}

/** Resolves [destinationAddress] and maps an unknown country to [GeoLookup.UNKNOWN_COUNTRY]. */
fun GeoLookup.countryCodeOrUnknown(destinationAddress: String): String =
    countryCode(destinationAddress) ?: GeoLookup.UNKNOWN_COUNTRY
