package de.visiongaia.gedefense.mobile.core

import java.net.InetAddress

/** Numeric-only IP/CIDR value. Hostnames are rejected before InetAddress parsing. */
data class IpPrefix(
    val family: Int,
    val v4: Int = 0,
    val v6Hi: Long = 0,
    val v6Lo: Long = 0,
    val prefixLength: Int,
) {
    init {
        require(family == 4 || family == 6)
        require(prefixLength in if (family == 4) 0..32 else 0..128)
    }

    fun contains(address: IpAddress): Boolean {
        if (family != address.family) return false
        return if (family == 4) maskV4(address.v4, prefixLength) == v4
        else maskV6(address.v6Hi, address.v6Lo, prefixLength).let { it.first == v6Hi && it.second == v6Lo }
    }

    fun toInetAddress(): InetAddress {
        return if (family == 4) {
            val b = byteArrayOf((v4 ushr 24).toByte(), (v4 ushr 16).toByte(), (v4 ushr 8).toByte(), v4.toByte())
            InetAddress.getByAddress(b)
        } else {
            val b = ByteArray(16)
            writeLong(b, 0, v6Hi); writeLong(b, 8, v6Lo)
            InetAddress.getByAddress(b)
        }
    }

    override fun toString(): String = "${toInetAddress().hostAddress}/$prefixLength"

    companion object {
        fun parse(raw: String): IpPrefix? {
            val token = raw.trim().trimEnd(';', ',')
            if (token.isEmpty()) return null
            val slash = token.lastIndexOf('/')
            val ipText = if (slash >= 0) token.substring(0, slash) else token
            if (!isNumericCandidate(ipText)) return null
            val addr = parseNumeric(ipText) ?: return null
            val max = if (addr.family == 4) 32 else 128
            val prefix = if (slash >= 0) token.substring(slash + 1).toIntOrNull() ?: return null else max
            if (prefix !in 0..max) return null
            return if (addr.family == 4) IpPrefix(4, v4 = maskV4(addr.v4, prefix), prefixLength = prefix)
            else maskV6(addr.v6Hi, addr.v6Lo, prefix).let { IpPrefix(6, v6Hi = it.first, v6Lo = it.second, prefixLength = prefix) }
        }

        fun parseAddress(raw: String): IpAddress? = if (isNumericCandidate(raw)) parseNumeric(raw) else null

        private fun isNumericCandidate(raw: String): Boolean {
            if (raw.isEmpty() || raw.length > 64 || '%' in raw) return false
            return raw.all { it.isDigit() || it == '.' || it == ':' || it in 'a'..'f' || it in 'A'..'F' }
        }

        private fun parseNumeric(raw: String): IpAddress? {
            if (':' !in raw) {
                val parts = raw.split('.')
                if (parts.size != 4) return null
                var value = 0
                for (part in parts) {
                    if (part.isEmpty() || part.length > 3 || !part.all(Char::isDigit)) return null
                    val octet = part.toIntOrNull() ?: return null
                    if (octet !in 0..255) return null
                    value = (value shl 8) or octet
                }
                return IpAddress(4, v4 = value)
            }
            // A colon-bearing token cannot be a DNS hostname under isNumericCandidate(); use the
            // platform's numeric IPv6 parser only after the character whitelist has succeeded.
            return try {
                val bytes = InetAddress.getByName(raw).address
                when (bytes.size) {
                    4 -> IpAddress(4, v4 = readInt(bytes, 0)) // IPv4-mapped IPv6 canonicalization
                    16 -> IpAddress(6, v6Hi = readLong(bytes, 0), v6Lo = readLong(bytes, 8))
                    else -> null
                }
            } catch (_: Exception) { null }
        }

        fun isPublic(prefix: IpPrefix): Boolean {
            return if (prefix.family == 4) isPublicV4(prefix.v4, prefix.prefixLength) else isPublicV6(prefix.v6Hi, prefix.v6Lo, prefix.prefixLength)
        }

        /** Returns true only for globally routable unicast destinations. */
        fun isPublic(address: IpAddress): Boolean {
            return if (address.family == 4) isPublicV4(address.v4, 32) else isPublicV6(address.v6Hi, address.v6Lo, 128)
        }

        private fun isPublicV4(ip: Int, prefix: Int): Boolean {
            // Reject if this prefix overlaps any non-public range in either direction. This prevents broad hostile routes.
            return BLOCKED_V4.none { rangesOverlapV4(ip, prefix, it.v4, it.prefixLength) }
        }

        private fun isPublicV6(hi: Long, lo: Long, prefix: Int): Boolean =
            BLOCKED_V6.none { rangesOverlapV6(hi, lo, prefix, it.v6Hi, it.v6Lo, it.prefixLength) }

        private fun rangesOverlapV4(a: Int, ap: Int, b: Int, bp: Int): Boolean {
            val p = minOf(ap, bp)
            return maskV4(a, p) == maskV4(b, p)
        }
        private fun rangesOverlapV6(ahi: Long, alo: Long, ap: Int, bhi: Long, blo: Long, bp: Int): Boolean {
            val p = minOf(ap, bp)
            val am = maskV6(ahi, alo, p); val bm = maskV6(bhi, blo, p)
            return am == bm
        }
        private fun cidr4(a:Int,b:Int,c:Int,d:Int,p:Int): IpPrefix {
            val ip = (a shl 24) or (b shl 16) or (c shl 8) or d
            return IpPrefix(4, v4 = maskV4(ip,p), prefixLength=p)
        }

        private val BLOCKED_V4 = arrayOf(
            cidr4(0,0,0,0,8), cidr4(10,0,0,0,8), cidr4(100,64,0,0,10), cidr4(127,0,0,0,8),
            cidr4(169,254,0,0,16), cidr4(172,16,0,0,12), cidr4(192,0,0,0,24), cidr4(192,0,2,0,24),
            cidr4(192,88,99,0,24), cidr4(192,168,0,0,16), cidr4(198,18,0,0,15), cidr4(198,51,100,0,24),
            cidr4(203,0,113,0,24), cidr4(224,0,0,0,4), cidr4(240,0,0,0,4),
        )
        private val BLOCKED_V6 = listOf(
            requireNotNull(parse("::/128")),
            requireNotNull(parse("::1/128")),
            requireNotNull(parse("64:ff9b::/96")),        // well-known NAT64
            requireNotNull(parse("64:ff9b:1::/48")),      // local-use NAT64
            requireNotNull(parse("100::/64")),            // discard-only
            requireNotNull(parse("2001:db8::/32")),       // documentation
            requireNotNull(parse("2001:10::/28")),        // ORCHIDv1
            requireNotNull(parse("2001:20::/28")),        // ORCHIDv2
            requireNotNull(parse("fc00::/7")),            // unique local
            requireNotNull(parse("fe80::/10")),           // link-local
            requireNotNull(parse("ff00::/8")),            // multicast
        )

        internal fun maskV4(v: Int, prefix: Int): Int {
            if (prefix == 0) return 0
            val mask = -1 shl (32 - prefix)
            return v and mask
        }
        internal fun maskV6(hi: Long, lo: Long, prefix: Int): Pair<Long,Long> = when {
            prefix <= 0 -> 0L to 0L
            prefix < 64 -> (hi and (-1L shl (64-prefix))) to 0L
            prefix == 64 -> hi to 0L
            prefix < 128 -> hi to (lo and (-1L shl (128-prefix)))
            else -> hi to lo
        }
        private fun readInt(b: ByteArray, o: Int): Int =
            ((b[o].toInt() and 255) shl 24) or ((b[o+1].toInt() and 255) shl 16) or ((b[o+2].toInt() and 255) shl 8) or (b[o+3].toInt() and 255)
        private fun readLong(b: ByteArray, o: Int): Long {
            var v=0L; for (i in 0 until 8) v = (v shl 8) or (b[o+i].toLong() and 255L); return v
        }
        private fun writeLong(b: ByteArray, o: Int, v: Long) { for (i in 0 until 8) b[o+i] = (v ushr (56-i*8)).toByte() }
    }
}

data class IpAddress(val family: Int, val v4: Int = 0, val v6Hi: Long = 0, val v6Lo: Long = 0) {
    init { require(family == 4 || family == 6) }

    fun isPublic(): Boolean = IpPrefix.isPublic(this)

    fun toInetAddress(): InetAddress = if (family == 4) {
        val b = byteArrayOf((v4 ushr 24).toByte(), (v4 ushr 16).toByte(), (v4 ushr 8).toByte(), v4.toByte())
        InetAddress.getByAddress(b)
    } else {
        val b = ByteArray(16)
        for (i in 0 until 8) b[i] = (v6Hi ushr (56 - i * 8)).toByte()
        for (i in 0 until 8) b[8 + i] = (v6Lo ushr (56 - i * 8)).toByte()
        InetAddress.getByAddress(b)
    }

    override fun toString(): String = if (family == 4) {
        listOf(v4 ushr 24, v4 ushr 16, v4 ushr 8, v4).joinToString(".") { (it and 255).toString() }
    } else {
        val b=ByteArray(16); for(i in 0 until 8) b[i]=(v6Hi ushr (56-i*8)).toByte(); for(i in 0 until 8) b[8+i]=(v6Lo ushr (56-i*8)).toByte();
        InetAddress.getByAddress(b).hostAddress
    }
}
