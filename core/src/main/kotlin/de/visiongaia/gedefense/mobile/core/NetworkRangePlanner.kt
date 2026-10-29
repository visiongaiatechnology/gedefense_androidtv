package de.visiongaia.gedefense.mobile.core

/**
 * Pure IPv4 LAN scan planner. It deliberately refuses public address space and caps an active
 * discovery sweep to one /24-equivalent (254 hosts) even when the attached LAN is broader.
 */
data class Ipv4ScanPlan(
    val localAddress: String,
    val requestedPrefixLength: Int,
    val effectivePrefixLength: Int,
    val scopeClamped: Boolean,
    val targets: List<String>,
)

object NetworkRangePlanner {
    const val MAX_ACTIVE_HOSTS = 254

    fun plan(localAddress: ByteArray, prefixLength: Int, maxHosts: Int = MAX_ACTIVE_HOSTS): Ipv4ScanPlan? {
        require(maxHosts in 1..MAX_ACTIVE_HOSTS)
        if (localAddress.size != 4 || prefixLength !in 0..32 || !isPrivateIpv4(localAddress)) return null
        val local = bytesToLong(localAddress)
        val effectivePrefix = when {
            prefixLength < 24 -> 24
            prefixLength <= 30 -> prefixLength
            else -> prefixLength
        }
        if (effectivePrefix > 30) {
            return Ipv4ScanPlan(toIpv4(local), prefixLength, effectivePrefix, false, emptyList())
        }

        val hostMaskBits = 32 - effectivePrefix
        val mask = (0xffff_ffffL shl hostMaskBits) and 0xffff_ffffL
        val network = local and mask
        val broadcast = network or (mask.inv() and 0xffff_ffffL)
        val candidates = ArrayList<String>(minOf(maxHosts, MAX_ACTIVE_HOSTS))
        var current = network + 1L
        while (current < broadcast && candidates.size < maxHosts) {
            if (current != local) candidates += toIpv4(current)
            current++
        }
        return Ipv4ScanPlan(
            localAddress = toIpv4(local),
            requestedPrefixLength = prefixLength,
            effectivePrefixLength = effectivePrefix,
            scopeClamped = effectivePrefix != prefixLength || current < broadcast,
            targets = candidates,
        )
    }

    fun isPrivateIpv4(address: ByteArray): Boolean {
        if (address.size != 4) return false
        val a = address[0].toInt() and 0xff
        val b = address[1].toInt() and 0xff
        return a == 10 ||
            (a == 172 && b in 16..31) ||
            (a == 192 && b == 168) ||
            (a == 169 && b == 254)
    }

    private fun bytesToLong(address: ByteArray): Long =
        ((address[0].toLong() and 0xffL) shl 24) or
            ((address[1].toLong() and 0xffL) shl 16) or
            ((address[2].toLong() and 0xffL) shl 8) or
            (address[3].toLong() and 0xffL)

    private fun toIpv4(value: Long): String = buildString(15) {
        append((value ushr 24) and 0xffL).append('.')
        append((value ushr 16) and 0xffL).append('.')
        append((value ushr 8) and 0xffL).append('.')
        append(value and 0xffL)
    }
}
