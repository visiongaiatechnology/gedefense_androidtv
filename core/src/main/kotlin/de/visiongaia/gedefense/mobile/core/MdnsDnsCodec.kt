package de.visiongaia.gedefense.mobile.core

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * Bounded mDNS/DNS-SD codec. It parses only the record types required by local service discovery
 * and rejects malformed compression graphs, oversized labels, truncated RDATA and record floods.
 */
data class MdnsDnsRecord(
    val name: String,
    val type: Int,
    val ttlSeconds: Long,
    val textValue: String? = null,
    val port: Int? = null,
    val txtEntries: List<String> = emptyList(),
)

data class MdnsDnsMessage(val records: List<MdnsDnsRecord>)

object MdnsDnsCodec {
    const val TYPE_A = 1
    const val TYPE_PTR = 12
    const val TYPE_TXT = 16
    const val TYPE_SRV = 33
    const val MAX_PACKET_BYTES = 9_000
    const val MAX_RECORDS = 128

    fun buildPtrQuery(names: List<String>): ByteArray? {
        val normalized = names.asSequence()
            .mapNotNull(::normalizeQueryName)
            .distinct()
            .take(MAX_QUESTIONS)
            .toList()
        if (normalized.isEmpty()) return null
        val out = ByteArrayOutputStream(512)
        writeU16(out, 0) // Transaction ID is always zero for mDNS.
        writeU16(out, 0)
        writeU16(out, normalized.size)
        writeU16(out, 0)
        writeU16(out, 0)
        writeU16(out, 0)
        normalized.forEach { name ->
            encodeName(out, name)
            writeU16(out, TYPE_PTR)
            writeU16(out, CLASS_IN)
        }
        return out.toByteArray().takeIf { it.size <= MAX_QUERY_BYTES }
    }

    fun parse(packet: ByteArray, length: Int = packet.size): MdnsDnsMessage? {
        if (length !in DNS_HEADER_BYTES..minOf(packet.size, MAX_PACKET_BYTES)) return null
        return try {
            val qd = u16(packet, 4, length) ?: return null
            val an = u16(packet, 6, length) ?: return null
            val ns = u16(packet, 8, length) ?: return null
            val ar = u16(packet, 10, length) ?: return null
            val totalRecords = an + ns + ar
            if (qd > MAX_QUESTIONS || totalRecords > MAX_RECORDS) return null
            var offset = DNS_HEADER_BYTES
            repeat(qd) {
                val qname = readName(packet, length, offset) ?: return null
                offset = qname.nextOffset
                if (offset + 4 > length) return null
                offset += 4
            }

            val records = ArrayList<MdnsDnsRecord>(totalRecords)
            repeat(totalRecords) {
                val owner = readName(packet, length, offset) ?: return null
                offset = owner.nextOffset
                if (offset + 10 > length) return null
                val type = u16(packet, offset, length) ?: return null
                val ttl = u32(packet, offset + 4, length) ?: return null
                val rdLength = u16(packet, offset + 8, length) ?: return null
                val rdataStart = offset + 10
                val rdataEnd = rdataStart + rdLength
                if (rdLength > MAX_RDATA_BYTES || rdataEnd > length) return null

                val record = when (type) {
                    TYPE_A -> parseA(owner.value, ttl, packet, rdataStart, rdLength)
                    TYPE_PTR -> parsePtr(owner.value, ttl, packet, length, rdataStart, rdataEnd)
                    TYPE_SRV -> parseSrv(owner.value, ttl, packet, length, rdataStart, rdataEnd)
                    TYPE_TXT -> parseTxt(owner.value, ttl, packet, rdataStart, rdataEnd)
                    else -> null
                }
                if (record != null) records += record
                offset = rdataEnd
            }
            MdnsDnsMessage(records)
        } catch (_: RuntimeException) {
            null
        }
    }

    private fun parseA(owner: String, ttl: Long, packet: ByteArray, start: Int, size: Int): MdnsDnsRecord? {
        if (size != 4) return null
        val address = buildString(15) {
            for (i in 0 until 4) {
                if (i > 0) append('.')
                append(packet[start + i].toInt() and 0xff)
            }
        }
        return MdnsDnsRecord(owner, TYPE_A, ttl, textValue = address)
    }

    private fun parsePtr(owner: String, ttl: Long, packet: ByteArray, length: Int, start: Int, end: Int): MdnsDnsRecord? {
        val target = readName(packet, length, start) ?: return null
        if (target.nextOffset > end) return null
        return MdnsDnsRecord(owner, TYPE_PTR, ttl, textValue = target.value)
    }

    private fun parseSrv(owner: String, ttl: Long, packet: ByteArray, length: Int, start: Int, end: Int): MdnsDnsRecord? {
        if (start + 6 > end) return null
        val port = u16(packet, start + 4, length) ?: return null
        if (port !in 1..65535) return null
        val target = readName(packet, length, start + 6) ?: return null
        if (target.nextOffset > end) return null
        return MdnsDnsRecord(owner, TYPE_SRV, ttl, textValue = target.value, port = port)
    }

    private fun parseTxt(owner: String, ttl: Long, packet: ByteArray, start: Int, end: Int): MdnsDnsRecord? {
        val entries = ArrayList<String>(8)
        var offset = start
        while (offset < end && entries.size < MAX_TXT_ENTRIES) {
            val size = packet[offset].toInt() and 0xff
            offset++
            if (size == 0) continue
            if (size > MAX_TXT_ENTRY_BYTES || offset + size > end) return null
            val raw = String(packet, offset, size, StandardCharsets.UTF_8)
            entries += sanitizeText(raw, MAX_TXT_ENTRY_CHARS)
            offset += size
        }
        return MdnsDnsRecord(owner, TYPE_TXT, ttl, txtEntries = entries)
    }

    private data class DecodedName(val value: String, val nextOffset: Int)

    private fun readName(packet: ByteArray, length: Int, start: Int): DecodedName? {
        if (start !in 0 until length) return null
        val labels = ArrayList<String>(8)
        var cursor = start
        var nextOffset = -1
        var jumps = 0
        var expandedBytes = 0
        val visited = HashSet<Int>()
        while (true) {
            if (cursor !in 0 until length) return null
            if (!visited.add(cursor) && jumps > 0) return null
            val value = packet[cursor].toInt() and 0xff
            when {
                value == 0 -> {
                    if (nextOffset < 0) nextOffset = cursor + 1
                    break
                }
                value and 0xc0 == 0xc0 -> {
                    if (cursor + 1 >= length || ++jumps > MAX_POINTER_JUMPS) return null
                    val pointer = ((value and 0x3f) shl 8) or (packet[cursor + 1].toInt() and 0xff)
                    if (pointer >= length) return null
                    if (nextOffset < 0) nextOffset = cursor + 2
                    cursor = pointer
                }
                value and 0xc0 != 0 -> return null
                else -> {
                    if (value !in 1..63 || cursor + 1 + value > length) return null
                    expandedBytes += value + 1
                    if (expandedBytes > MAX_EXPANDED_NAME_BYTES || labels.size >= MAX_LABELS) return null
                    val label = String(packet, cursor + 1, value, StandardCharsets.UTF_8)
                    labels += sanitizeLabel(label)
                    cursor += value + 1
                }
            }
        }
        if (labels.isEmpty() || nextOffset < 0) return null
        return DecodedName(labels.joinToString(".").lowercase(), nextOffset)
    }

    private fun normalizeQueryName(value: String): String? {
        val trimmed = value.trim().trimEnd('.').lowercase()
        if (trimmed.isBlank() || trimmed.length > 253) return null
        val labels = trimmed.split('.')
        if (labels.isEmpty() || labels.size > MAX_LABELS) return null
        if (labels.any { label -> label.isEmpty() || label.toByteArray(StandardCharsets.UTF_8).size !in 1..63 || label.any { it.code < 0x21 || it.code == 0x7f } }) return null
        return trimmed
    }

    private fun encodeName(out: ByteArrayOutputStream, name: String) {
        name.split('.').forEach { label ->
            val bytes = label.toByteArray(StandardCharsets.UTF_8)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
    }

    private fun sanitizeLabel(value: String): String = sanitizeText(value, 63).replace('.', '_')

    private fun sanitizeText(value: String, maxChars: Int): String = buildString(minOf(value.length, maxChars)) {
        value.asSequence().take(maxChars).forEach { ch ->
            append(if (ch.code in 0x20..0x7e || ch.code >= 0xa0) ch else '?')
        }
    }

    private fun u16(packet: ByteArray, offset: Int, length: Int): Int? {
        if (offset < 0 || offset + 2 > length) return null
        return ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)
    }

    private fun u32(packet: ByteArray, offset: Int, length: Int): Long? {
        if (offset < 0 || offset + 4 > length) return null
        return ((packet[offset].toLong() and 0xffL) shl 24) or
            ((packet[offset + 1].toLong() and 0xffL) shl 16) or
            ((packet[offset + 2].toLong() and 0xffL) shl 8) or
            (packet[offset + 3].toLong() and 0xffL)
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xff)
        out.write(value and 0xff)
    }

    private const val DNS_HEADER_BYTES = 12
    private const val CLASS_IN = 1
    private const val MAX_QUESTIONS = 24
    private const val MAX_QUERY_BYTES = 1_400
    private const val MAX_RDATA_BYTES = 4_096
    private const val MAX_TXT_ENTRIES = 32
    private const val MAX_TXT_ENTRY_BYTES = 255
    private const val MAX_TXT_ENTRY_CHARS = 255
    private const val MAX_POINTER_JUMPS = 16
    private const val MAX_EXPANDED_NAME_BYTES = 255
    private const val MAX_LABELS = 32
}
