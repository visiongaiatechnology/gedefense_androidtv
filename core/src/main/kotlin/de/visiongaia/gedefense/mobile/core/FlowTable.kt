package de.visiongaia.gedefense.mobile.core

import java.util.LinkedHashMap

data class FlowKey(
    val protocol: Int,
    val src: IpAddress,
    val srcPort: Int,
    val dst: IpAddress,
    val dstPort: Int,
)

data class FlowState(
    var packets: Long,
    var bytes: Long,
    var firstSeenMillis: Long,
    var lastSeenMillis: Long,
)

class FlowTable(
    private val capacity: Int = 8192,
    private val ttlMillis: Long = 5 * 60_000L,
) {
    init {
        require(capacity in 128..65_536)
        require(ttlMillis in 10_000L..3_600_000L)
    }

    /** Access-order map: expired entries can be removed from the eldest edge without scanning the full table. */
    private val map = object : LinkedHashMap<FlowKey, FlowState>(capacity, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<FlowKey, FlowState>?): Boolean = size > capacity
    }

    @Synchronized
    fun observe(packet: ParsedPacket, now: Long = System.currentTimeMillis()): FlowState {
        purgeExpiredEldest(now)
        val key = FlowKey(
            packet.protocol,
            packet.source,
            packet.sourcePort ?: 0,
            packet.destination,
            packet.destinationPort ?: 0,
        )
        val existing = map[key]
        if (existing != null) {
            existing.packets++
            existing.bytes += packet.length
            existing.lastSeenMillis = now
            return existing
        }
        return FlowState(1, packet.length.toLong(), now, now).also { map[key] = it }
    }

    @Synchronized
    fun size(): Int = map.size

    @Synchronized
    fun clear() = map.clear()

    private fun purgeExpiredEldest(now: Long) {
        val iterator = map.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastSeenMillis <= ttlMillis) break
            iterator.remove()
        }
    }
}
