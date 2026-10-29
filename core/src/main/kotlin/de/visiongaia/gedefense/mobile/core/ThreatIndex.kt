package de.visiongaia.gedefense.mobile.core

import java.util.Collections
import java.security.MessageDigest

data class ThreatMatch(val address: IpAddress, val feeds: List<ThreatFeed>) {
    val blockingFeeds: List<ThreatFeed> get() = feeds.filter { it.enforcement == EnforcementClass.ROUTE_BLOCK }
    val hasBlockingSignal: Boolean get() = blockingFeeds.isNotEmpty()
}

data class V6Key(val hi: Long, val lo: Long)

class ThreatIndex private constructor(
    private val v4: Map<Int, Map<Int, Long>>,
    private val v6: Map<Int, Map<V6Key, Long>>,
    private val v4Lengths: IntArray,
    private val v6Lengths: IntArray,
    val count: Int,
    val routePrefixes: List<IpPrefix>,
    val routeCandidateCount: Int,
    val routeOverflow: Boolean,
    val routePolicySha256: String,
    val fullPolicySha256: String,
) {
    fun match(raw: String): ThreatMatch? = IpPrefix.parseAddress(raw)?.let(::match)

    fun match(address: IpAddress): ThreatMatch? {
        var bits = 0L
        if (address.family == 4) {
            for (prefix in v4Lengths) {
                val map = v4[prefix] ?: continue
                bits = bits or (map[IpPrefix.maskV4(address.v4, prefix)] ?: 0L)
            }
        } else {
            for (prefix in v6Lengths) {
                val map = v6[prefix] ?: continue
                val masked = IpPrefix.maskV6(address.v6Hi, address.v6Lo, prefix)
                bits = bits or (map[V6Key(masked.first, masked.second)] ?: 0L)
            }
        }
        if (bits == 0L) return null
        val feeds = ThreatFeedCatalog.all.filterIndexed { index, _ -> bits and (1L shl index) != 0L }
        return ThreatMatch(address, feeds)
    }

    /** Streams the immutable prefix policy in deterministic family/prefix/address order. */
    fun forEachPolicyRecord(visitor: (IpPrefix, Long, EnforcementClass) -> Unit) {
        v4.keys.sorted().forEach { prefixLength ->
            val entries = v4[prefixLength].orEmpty().entries.sortedWith { a, b ->
                java.lang.Integer.compareUnsigned(a.key, b.key)
            }
            entries.forEach { (address, bits) ->
                visitor(IpPrefix(4, v4 = address, prefixLength = prefixLength), bits, enforcementForBits(bits))
            }
        }
        v6.keys.sorted().forEach { prefixLength ->
            val entries = v6[prefixLength].orEmpty().entries.sortedWith { a, b ->
                val hi = java.lang.Long.compareUnsigned(a.key.hi, b.key.hi)
                if (hi != 0) hi else java.lang.Long.compareUnsigned(a.key.lo, b.key.lo)
            }
            entries.forEach { (address, bits) ->
                visitor(IpPrefix(6, v6Hi = address.hi, v6Lo = address.lo, prefixLength = prefixLength), bits, enforcementForBits(bits))
            }
        }
    }

    private fun enforcementForBits(bits: Long): EnforcementClass {
        var best = EnforcementClass.ANNOTATE_ONLY
        ThreatFeedCatalog.all.forEachIndexed { index, feed ->
            if (bits and (1L shl index) == 0L) return@forEachIndexed
            if (feed.enforcement == EnforcementClass.ROUTE_BLOCK) return EnforcementClass.ROUTE_BLOCK
            if (feed.enforcement == EnforcementClass.CORRELATE_ONLY) best = EnforcementClass.CORRELATE_ONLY
        }
        return best
    }

    class Builder {
        private val v4 = HashMap<Int, MutableMap<Int, Long>>()
        private val v6 = HashMap<Int, MutableMap<V6Key, Long>>()
        private val routeSet = LinkedHashSet<IpPrefix>()
        private var routeOverflow = false
        private var count = 0

        fun add(record: ThreatRecord): Builder {
            val index = ThreatFeedCatalog.indexOf(record.feedId)
            require(index < 63) { "too many feeds for bitset" }
            val bit = 1L shl index
            val prefix = record.prefix
            if (prefix.family == 4) {
                val map = v4.getOrPut(prefix.prefixLength) { HashMap() }
                val previous = map[prefix.v4] ?: 0L
                if (previous == 0L) count++
                map[prefix.v4] = previous or bit
            } else {
                val map = v6.getOrPut(prefix.prefixLength) { HashMap() }
                val key = V6Key(prefix.v6Hi, prefix.v6Lo)
                val previous = map[key] ?: 0L
                if (previous == 0L) count++
                map[key] = previous or bit
            }

            if (ThreatFeedCatalog.require(record.feedId).enforcement == EnforcementClass.ROUTE_BLOCK) {
                if (prefix !in routeSet) {
                    if (routeSet.size >= MAX_ROUTE_CANDIDATES) routeOverflow = true else routeSet += prefix
                }
            }
            return this
        }

        fun addAll(records: Iterable<ThreatRecord>): Builder {
            records.forEach(::add)
            return this
        }

        fun build(): ThreatIndex {
            val compacted = if (routeOverflow) emptyList() else RouteCompactor.compact(routeSet)
            if (compacted.size > MAX_ROUTE_PREFIXES) routeOverflow = true
            val safeRoutes = if (routeOverflow) emptyList() else compacted
            val immutableV4 = v4.mapValues { Collections.unmodifiableMap(HashMap(it.value)) }
            val immutableV6 = v6.mapValues { Collections.unmodifiableMap(HashMap(it.value)) }
            return ThreatIndex(
                Collections.unmodifiableMap(immutableV4),
                Collections.unmodifiableMap(immutableV6),
                immutableV4.keys.sortedDescending().toIntArray(),
                immutableV6.keys.sortedDescending().toIntArray(),
                count,
                Collections.unmodifiableList(safeRoutes),
                routeSet.size,
                routeOverflow,
                routePolicySha256(safeRoutes),
                fullPolicySha256(immutableV4, immutableV6),
            )
        }
    }

    companion object {
        const val MAX_ROUTE_PREFIXES = 8192
        const val MAX_ROUTE_CANDIDATES = 100_000

        fun empty() = ThreatIndex(
            emptyMap(), emptyMap(), IntArray(0), IntArray(0), 0, emptyList(), 0, false,
            routePolicySha256(emptyList()), fullPolicySha256(emptyMap(), emptyMap()),
        )

        fun build(records: Collection<ThreatRecord>): ThreatIndex = Builder().addAll(records).build()

        private fun fullPolicySha256(
            v4: Map<Int, Map<Int, Long>>,
            v6: Map<Int, Map<V6Key, Long>>,
        ): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'F'.code.toByte(), 1))
            v4.keys.sorted().forEach { prefixLength ->
                v4[prefixLength].orEmpty().entries
                    .sortedWith { a, b -> java.lang.Integer.compareUnsigned(a.key, b.key) }
                    .forEach { (address, bits) ->
                        digest.update(4.toByte())
                        digest.update(prefixLength.toByte())
                        for (shift in 56 downTo 0 step 8) digest.update((bits ushr shift).toByte())
                        digest.update((address ushr 24).toByte())
                        digest.update((address ushr 16).toByte())
                        digest.update((address ushr 8).toByte())
                        digest.update(address.toByte())
                    }
            }
            v6.keys.sorted().forEach { prefixLength ->
                v6[prefixLength].orEmpty().entries
                    .sortedWith { a, b ->
                        val hi = java.lang.Long.compareUnsigned(a.key.hi, b.key.hi)
                        if (hi != 0) hi else java.lang.Long.compareUnsigned(a.key.lo, b.key.lo)
                    }
                    .forEach { (address, bits) ->
                        digest.update(6.toByte())
                        digest.update(prefixLength.toByte())
                        for (shift in 56 downTo 0 step 8) digest.update((bits ushr shift).toByte())
                        for (shift in 56 downTo 0 step 8) digest.update((address.hi ushr shift).toByte())
                        for (shift in 56 downTo 0 step 8) digest.update((address.lo ushr shift).toByte())
                    }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        private fun routePolicySha256(routes: List<IpPrefix>): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'R'.code.toByte(), 1))
            routes.forEach { route ->
                digest.update(route.family.toByte())
                digest.update(route.prefixLength.toByte())
                if (route.family == 4) {
                    digest.update((route.v4 ushr 24).toByte())
                    digest.update((route.v4 ushr 16).toByte())
                    digest.update((route.v4 ushr 8).toByte())
                    digest.update(route.v4.toByte())
                } else {
                    for (shift in 56 downTo 0 step 8) digest.update((route.v6Hi ushr shift).toByte())
                    for (shift in 56 downTo 0 step 8) digest.update((route.v6Lo ushr shift).toByte())
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
