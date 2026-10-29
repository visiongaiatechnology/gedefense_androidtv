package de.visiongaia.gedefense.tv.core.anomaly

import de.visiongaia.gedefense.mobile.core.IpAddress
import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.tv.core.model.TrafficFlow
import java.security.MessageDigest

/**
 * Small, dependency-free network helpers shared by the TV anomaly/containment domain.
 *
 * Destination aggregation is deliberately coarse: IPv4 is observed at /24, IPv6 at /64. Containment
 * therefore never targets a single CDN host and never produces prefixes broader than the model allows.
 */
internal object PrefixSupport {

    fun parseAddress(raw: String): IpAddress? = IpPrefix.parseAddress(raw)

    fun parsePrefix(cidr: String): IpPrefix? = IpPrefix.parse(cidr)

    /** Canonical /24 (IPv4) or /64 (IPv6) aggregation of an address string, or null when invalid. */
    fun aggregationPrefix(address: String): String? {
        val parsed = parseAddress(address) ?: return null
        return canonicalPrefix(aggregationPrefix(parsed))
    }

    fun aggregationPrefix(address: IpAddress): IpPrefix = if (address.family == 4) {
        IpPrefix(4, v4 = maskV4(address.v4, 24), prefixLength = 24)
    } else {
        val masked = maskV6(address.v6Hi, address.v6Lo, 64)
        IpPrefix(6, v6Hi = masked.first, v6Lo = masked.second, prefixLength = 64)
    }

    /** Canonical CIDR string: dotted /24 for IPv4, RFC 5952 compressed /64 for IPv6. */
    fun canonicalPrefix(prefix: IpPrefix): String = if (prefix.family == 4) {
        val value = prefix.v4
        "${(value ushr 24) and 0xff}.${(value ushr 16) and 0xff}.${(value ushr 8) and 0xff}.${value and 0xff}/${prefix.prefixLength}"
    } else {
        "${compressV6(prefix.v6Hi, prefix.v6Lo)}/${prefix.prefixLength}"
    }

    /** Forces a /24 (IPv4) or /64 (IPv6) target prefix from any parsed prefix. */
    fun forceAggregation(prefix: IpPrefix): IpPrefix = if (prefix.family == 4) {
        IpPrefix(4, v4 = maskV4(prefix.v4, 24), prefixLength = 24)
    } else {
        val masked = maskV6(prefix.v6Hi, prefix.v6Lo, 64)
        IpPrefix(6, v6Hi = masked.first, v6Lo = masked.second, prefixLength = 64)
    }

    /** True when two prefixes of the same family overlap in either direction. */
    fun overlaps(first: IpPrefix, second: IpPrefix): Boolean {
        if (first.family != second.family) return false
        val startFirst = IpAddress(first.family, first.v4, first.v6Hi, first.v6Lo)
        val startSecond = IpAddress(second.family, second.v4, second.v6Hi, second.v6Lo)
        return first.contains(startSecond) || second.contains(startFirst)
    }

    fun contains(prefix: IpPrefix, address: IpAddress): Boolean = prefix.contains(address)

    /** Canonical textual form of an address, or null when not a numeric address. */
    fun canonicalAddress(raw: String): String? = parseAddress(raw)?.toString()

    fun bytesOf(flow: TrafficFlow): Long = saturatingAdd(flow.txBytes, flow.rxBytes)

    fun saturatingAdd(left: Long, right: Long): Long {
        if (right <= 0L) return left
        return if (Long.MAX_VALUE - left < right) Long.MAX_VALUE else left + right
    }

    fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        val chars = CharArray(digest.size * 2)
        val alphabet = "0123456789abcdef"
        digest.forEachIndexed { index, byte ->
            val unsigned = byte.toInt() and 0xff
            chars[index * 2] = alphabet[unsigned ushr 4]
            chars[index * 2 + 1] = alphabet[unsigned and 0x0f]
        }
        return String(chars)
    }

    private fun maskV4(value: Int, prefixLength: Int): Int =
        if (prefixLength <= 0) 0 else value and (-1 shl (32 - prefixLength))

    /** RFC 5952 style IPv6 compression (longest zero run, lowercase hex, no leading zeros). */
    private fun compressV6(hi: Long, lo: Long): String {
        val groups = IntArray(8)
        for (index in 0 until 4) {
            groups[index] = ((hi ushr (48 - index * 16)) and 0xffff).toInt()
            groups[4 + index] = ((lo ushr (48 - index * 16)) and 0xffff).toInt()
        }
        var bestStart = -1
        var bestLength = 0
        var cursor = 0
        while (cursor < groups.size) {
            if (groups[cursor] != 0) {
                cursor += 1
                continue
            }
            var end = cursor
            while (end < groups.size && groups[end] == 0) end += 1
            val length = end - cursor
            if (length > bestLength) {
                bestLength = length
                bestStart = cursor
            }
            cursor = end
        }
        val out = StringBuilder(39)
        if (bestLength >= 2) {
            for (index in 0 until bestStart) {
                if (index > 0) out.append(':')
                out.append(groups[index].toString(16))
            }
            out.append("::")
            var index = bestStart + bestLength
            var first = true
            while (index < groups.size) {
                if (!first) out.append(':')
                out.append(groups[index].toString(16))
                first = false
                index += 1
            }
        } else {
            for (index in 0 until groups.size) {
                if (index > 0) out.append(':')
                out.append(groups[index].toString(16))
            }
        }
        return out.toString()
    }

    private fun maskV6(hi: Long, lo: Long, prefixLength: Int): Pair<Long, Long> = when {
        prefixLength <= 0 -> 0L to 0L
        prefixLength < 64 -> (hi and (-1L shl (64 - prefixLength))) to 0L
        prefixLength == 64 -> hi to 0L
        prefixLength < 128 -> hi to (lo and (-1L shl (128 - prefixLength)))
        else -> hi to lo
    }
}
