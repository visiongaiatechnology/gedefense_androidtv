package de.visiongaia.gedefense.mobile.core

import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.util.LinkedHashMap

/**
 * STATUS: DIAMANT VGT SUPREME
 *
 * Compact offline IP -> ASN index used only to enrich local evidence. The index never performs
 * network I/O and has no policy/enforcement API by design.
 */
data class AsnEvidence(
    val asn: Long,
    val organization: String,
)

data class AsnLiteBuildResult(
    val v4Records: Int,
    val v6Records: Int,
    val organizations: Int,
)

object AsnLiteCompiler {
    private data class ParsedRow(
        val start: IpAddress,
        val end: IpAddress,
        val asn: Long,
        val organization: String,
    )

    fun compile(
        v4Csv: File,
        v6Csv: File,
        v4Out: File,
        v6Out: File,
        organizationsOut: File,
        maxRecordsPerFamily: Int = MAX_RECORDS_PER_FAMILY,
        maxOrganizations: Int = MAX_ORGANIZATIONS,
    ): AsnLiteBuildResult {
        require(maxRecordsPerFamily in 1..MAX_RECORDS_PER_FAMILY)
        require(maxOrganizations in 1..MAX_ORGANIZATIONS)
        val organizations = LinkedHashMap<String, Int>()
        val v4Records = compileFamily(v4Csv, v4Out, 4, organizations, maxRecordsPerFamily, maxOrganizations)
        val v6Records = compileFamily(v6Csv, v6Out, 6, organizations, maxRecordsPerFamily, maxOrganizations)
        writeOrganizations(organizations.keys.toList(), organizationsOut)
        return AsnLiteBuildResult(v4Records, v6Records, organizations.size)
    }

    private fun compileFamily(
        csv: File,
        outFile: File,
        family: Int,
        organizations: LinkedHashMap<String, Int>,
        maxRecords: Int,
        maxOrganizations: Int,
    ): Int {
        var records = 0
        var sourceRows = 0
        var previousV4End = -1L
        var previousV6Hi = 0L
        var previousV6Lo = 0L
        var hasPreviousV6 = false

        outFile.parentFile?.let { require(it.mkdirs() || it.isDirectory) }
        FileOutputStream(outFile).use { raw ->
            DataOutputStream(raw).use { out ->
                out.writeInt(if (family == 4) MAGIC_V4 else MAGIC_V6)
                out.writeInt(FORMAT_VERSION)
                out.writeInt(0)
                BufferedReader(InputStreamReader(FileInputStream(csv), Charsets.UTF_8), 64 * 1024).use { reader ->
                    while (true) {
                        if (Thread.currentThread().isInterrupted) throw InterruptedException("ASN compile interrupted")
                        val line = reader.readLine() ?: break
                        if (line.length > MAX_CSV_LINE_CHARS) error("ASN CSV line exceeds bound")
                        if (line.isBlank()) continue
                        val fields = parseCsvLine(line)
                        if (sourceRows == 0 && isHeader(fields)) continue
                        if (fields.size != 4) error("ASN CSV shape invalid")
                        sourceRows++
                        val row = parseRow(fields, family)

                        if (family == 4) {
                            val start = row.start.v4.toLong() and 0xffff_ffffL
                            val end = row.end.v4.toLong() and 0xffff_ffffL
                            if (start > end || (sourceRows > 1 && start <= previousV4End)) {
                                error("ASN IPv4 ranges unsorted or overlapping")
                            }
                            previousV4End = end
                        } else {
                            if (compare128(row.start.v6Hi, row.start.v6Lo, row.end.v6Hi, row.end.v6Lo) > 0) {
                                error("ASN IPv6 range reversed")
                            }
                            if (hasPreviousV6 && compare128(row.start.v6Hi, row.start.v6Lo, previousV6Hi, previousV6Lo) <= 0) {
                                error("ASN IPv6 ranges unsorted or overlapping")
                            }
                            previousV6Hi = row.end.v6Hi
                            previousV6Lo = row.end.v6Lo
                            hasPreviousV6 = true
                        }

                        // IPtoASN uses ASN 0 for unannounced/non-attributed ranges. Those rows carry
                        // no useful ASN evidence, so omit them from the compact local index while
                        // still validating their ordering above.
                        if (row.asn == 0L) continue

                        val orgId = organizations[row.organization] ?: run {
                            if (organizations.size >= maxOrganizations) error("ASN organization bound exceeded")
                            organizations.size.also { organizations[row.organization] = it }
                        }
                        if (family == 4) {
                            out.writeInt(row.start.v4)
                            out.writeInt(row.end.v4)
                            out.writeLong(row.asn)
                            out.writeInt(orgId)
                            out.writeInt(0)
                        } else {
                            out.writeLong(row.start.v6Hi)
                            out.writeLong(row.start.v6Lo)
                            out.writeLong(row.end.v6Hi)
                            out.writeLong(row.end.v6Lo)
                            out.writeLong(row.asn)
                            out.writeInt(orgId)
                            out.writeInt(0)
                        }
                        records++
                        if (records > maxRecords) error("ASN record bound exceeded")
                    }
                }
                out.flush()
                raw.fd.sync()
            }
        }
        if (sourceRows == 0 || records == 0) error("ASN dataset empty")
        java.io.RandomAccessFile(outFile, "rw").use { raf ->
            raf.seek(8L)
            raf.writeInt(records)
            raf.fd.sync()
        }
        return records
    }

    private fun parseRow(fields: List<String>, family: Int): ParsedRow {
        val start = IpPrefix.parseAddress(fields[0].trim()) ?: error("ASN range start invalid")
        val end = IpPrefix.parseAddress(fields[1].trim()) ?: error("ASN range end invalid")
        if (start.family != family || end.family != family) error("ASN address family mismatch")
        val asn = fields[2].trim().toLongOrNull()?.takeIf { it in 0L..MAX_ASN } ?: error("ASN number invalid")
        val organization = sanitizeOrganization(fields[3])
        return ParsedRow(start, end, asn, organization)
    }

    private fun isHeader(fields: List<String>): Boolean = fields.size == 4 &&
        fields[0].trim().equals("ip_range_start", ignoreCase = true) &&
        fields[1].trim().equals("ip_range_end", ignoreCase = true)

    internal fun parseCsvLine(line: String): List<String> {
        val fields = ArrayList<String>(4)
        val current = StringBuilder()
        var quoted = false
        var i = 0
        while (i < line.length) {
            val ch = line[i]
            when {
                quoted && ch == '"' -> {
                    if (i + 1 < line.length && line[i + 1] == '"') {
                        current.append('"')
                        i++
                    } else {
                        quoted = false
                    }
                }
                !quoted && ch == '"' -> {
                    if (current.isNotEmpty()) error("ASN CSV quote placement invalid")
                    quoted = true
                }
                !quoted && ch == ',' -> {
                    fields.add(current.toString())
                    current.setLength(0)
                }
                else -> current.append(ch)
            }
            i++
        }
        if (quoted) error("ASN CSV quote unterminated")
        fields.add(current.toString())
        return fields
    }

    private fun sanitizeOrganization(raw: String): String {
        val compact = raw.trim().replace(Regex("\\s+"), " ")
        if (compact.isEmpty()) return "unknown"
        if (compact.any { Character.isISOControl(it) }) error("ASN organization contains control character")
        val bytes = compact.toByteArray(Charsets.UTF_8)
        if (bytes.size <= MAX_ORG_BYTES) return compact

        val out = StringBuilder()
        var used = 0
        for (ch in compact) {
            val encoded = ch.toString().toByteArray(Charsets.UTF_8)
            if (used + encoded.size > MAX_ORG_BYTES) break
            out.append(ch)
            used += encoded.size
        }
        return out.toString().trimEnd().ifEmpty { "unknown" }
    }

    private fun writeOrganizations(organizations: List<String>, outFile: File) {
        FileOutputStream(outFile).use { raw ->
            DataOutputStream(raw).use { out ->
                out.writeInt(MAGIC_ORG)
                out.writeInt(FORMAT_VERSION)
                out.writeInt(organizations.size)
                organizations.forEach { organization ->
                    val bytes = organization.toByteArray(Charsets.UTF_8)
                    require(bytes.size in 1..MAX_ORG_BYTES)
                    out.writeShort(bytes.size)
                    out.write(bytes)
                }
                out.flush()
                raw.fd.sync()
            }
        }
    }

    private fun compare128(ahi: Long, alo: Long, bhi: Long, blo: Long): Int {
        val high = java.lang.Long.compareUnsigned(ahi, bhi)
        return if (high != 0) high else java.lang.Long.compareUnsigned(alo, blo)
    }

    internal const val FORMAT_VERSION = 1
    internal const val MAGIC_V4 = 0x47444134 // GDA4
    internal const val MAGIC_V6 = 0x47444136 // GDA6
    internal const val MAGIC_ORG = 0x4744414f // GDAO
    internal const val HEADER_BYTES = 12
    internal const val V4_RECORD_BYTES = 24
    internal const val V6_RECORD_BYTES = 48
    internal const val MAX_ORG_BYTES = 192
    private const val MAX_CSV_LINE_CHARS = 2048
    private const val MAX_RECORDS_PER_FAMILY = 2_000_000
    private const val MAX_ORGANIZATIONS = 500_000
    private const val MAX_ASN = 0xffff_ffffL
}

class AsnLiteIndex private constructor(
    private val v4: ByteBuffer,
    private val v6: ByteBuffer,
    private val organizations: ByteBuffer,
    private val organizationOffsets: IntArray,
    val v4Records: Int,
    val v6Records: Int,
    val organizationCount: Int,
) : AutoCloseable {
    fun lookup(address: IpAddress): AsnEvidence? = if (address.family == 4) lookupV4(address) else lookupV6(address)

    private fun lookupV4(address: IpAddress): AsnEvidence? {
        val needle = address.v4.toLong() and 0xffff_ffffL
        var low = 0
        var high = v4Records - 1
        while (low <= high) {
            val mid = (low + high) ushr 1
            val offset = AsnLiteCompiler.HEADER_BYTES + mid * AsnLiteCompiler.V4_RECORD_BYTES
            val start = v4.getInt(offset).toLong() and 0xffff_ffffL
            val end = v4.getInt(offset + 4).toLong() and 0xffff_ffffL
            when {
                needle < start -> high = mid - 1
                needle > end -> low = mid + 1
                else -> return evidence(v4.getLong(offset + 8), v4.getInt(offset + 16))
            }
        }
        return null
    }

    private fun lookupV6(address: IpAddress): AsnEvidence? {
        var low = 0
        var high = v6Records - 1
        while (low <= high) {
            val mid = (low + high) ushr 1
            val offset = AsnLiteCompiler.HEADER_BYTES + mid * AsnLiteCompiler.V6_RECORD_BYTES
            val startHi = v6.getLong(offset)
            val startLo = v6.getLong(offset + 8)
            val endHi = v6.getLong(offset + 16)
            val endLo = v6.getLong(offset + 24)
            when {
                compare128(address.v6Hi, address.v6Lo, startHi, startLo) < 0 -> high = mid - 1
                compare128(address.v6Hi, address.v6Lo, endHi, endLo) > 0 -> low = mid + 1
                else -> return evidence(v6.getLong(offset + 32), v6.getInt(offset + 40))
            }
        }
        return null
    }

    private fun evidence(asn: Long, organizationId: Int): AsnEvidence? {
        if (asn !in 1L..0xffff_ffffL || organizationId !in organizationOffsets.indices) return null
        val offset = organizationOffsets[organizationId]
        if (offset < AsnLiteCompiler.HEADER_BYTES || offset + 2 > organizations.capacity()) return null
        val length = organizations.getShort(offset).toInt() and 0xffff
        if (length !in 1..AsnLiteCompiler.MAX_ORG_BYTES || offset + 2 + length > organizations.capacity()) return null
        val bytes = ByteArray(length)
        val duplicate = organizations.duplicate().order(ByteOrder.BIG_ENDIAN)
        duplicate.position(offset + 2)
        duplicate.get(bytes)
        return AsnEvidence(asn, bytes.toString(Charsets.UTF_8))
    }

    override fun close() {
        // MappedByteBuffer unmapping is intentionally left to the JVM/ART. Reflection-based forced
        // unmapping would add hidden-API and portability risk for no security benefit here.
    }

    companion object {
        fun open(
            v4File: File,
            v6File: File,
            organizationsFile: File,
            expectedV4Records: Int,
            expectedV6Records: Int,
            expectedOrganizations: Int,
        ): AsnLiteIndex {
            require(expectedV4Records > 0 && expectedV6Records > 0 && expectedOrganizations > 0)
            val v4 = map(v4File)
            val v6 = map(v6File)
            val organizations = map(organizationsFile)
            require(v4.capacity().toLong() == AsnLiteCompiler.HEADER_BYTES + expectedV4Records.toLong() * AsnLiteCompiler.V4_RECORD_BYTES) {
                "ASN IPv4 index size mismatch"
            }
            require(v6.capacity().toLong() == AsnLiteCompiler.HEADER_BYTES + expectedV6Records.toLong() * AsnLiteCompiler.V6_RECORD_BYTES) {
                "ASN IPv6 index size mismatch"
            }
            require(v4.getInt(0) == AsnLiteCompiler.MAGIC_V4 && v4.getInt(4) == AsnLiteCompiler.FORMAT_VERSION && v4.getInt(8) == expectedV4Records) {
                "ASN IPv4 index header invalid"
            }
            require(v6.getInt(0) == AsnLiteCompiler.MAGIC_V6 && v6.getInt(4) == AsnLiteCompiler.FORMAT_VERSION && v6.getInt(8) == expectedV6Records) {
                "ASN IPv6 index header invalid"
            }
            require(
                organizations.capacity() >= AsnLiteCompiler.HEADER_BYTES &&
                    organizations.getInt(0) == AsnLiteCompiler.MAGIC_ORG &&
                    organizations.getInt(4) == AsnLiteCompiler.FORMAT_VERSION &&
                    organizations.getInt(8) == expectedOrganizations,
            ) { "ASN organization index header invalid" }

            val offsets = IntArray(expectedOrganizations)
            var cursor = AsnLiteCompiler.HEADER_BYTES
            repeat(expectedOrganizations) { index ->
                require(cursor + 2 <= organizations.capacity()) { "ASN organization table truncated" }
                val length = organizations.getShort(cursor).toInt() and 0xffff
                require(length in 1..AsnLiteCompiler.MAX_ORG_BYTES && cursor + 2 + length <= organizations.capacity()) {
                    "ASN organization entry invalid"
                }
                offsets[index] = cursor
                cursor += 2 + length
            }
            require(cursor == organizations.capacity()) { "ASN organization table trailing bytes" }
            return AsnLiteIndex(v4, v6, organizations, offsets, expectedV4Records, expectedV6Records, expectedOrganizations)
        }

        private fun map(file: File): ByteBuffer = FileInputStream(file).channel.use { channel ->
            require(channel.size() in AsnLiteCompiler.HEADER_BYTES.toLong()..MAX_INDEX_BYTES) { "ASN index size out of bounds" }
            channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size()).order(ByteOrder.BIG_ENDIAN)
        }

        private fun compare128(ahi: Long, alo: Long, bhi: Long, blo: Long): Int {
            val high = java.lang.Long.compareUnsigned(ahi, bhi)
            return if (high != 0) high else java.lang.Long.compareUnsigned(alo, blo)
        }

        private const val MAX_INDEX_BYTES = 256L * 1024L * 1024L
    }
}
