package de.visiongaia.gedefense.tv.core.titan.proc

import de.visiongaia.gedefense.tv.core.titan.model.RawSocket
import de.visiongaia.gedefense.tv.core.titan.model.SocketProtocol
import de.visiongaia.gedefense.tv.core.titan.model.SocketState

/**
 * Parser for the Linux kernel socket tables (`/proc/net/tcp|tcp6|udp|udp6`).
 *
 * The parser is pure: it never touches the filesystem, never throws on malformed content and never
 * invents fields. Every row is validated field by field; a row that does not decode is skipped. The
 * line scan, the emitted row count and the returned collection are hard-bounded, so truncated or
 * hostile table content can never trigger unbounded work.
 *
 * Kernel row layout (`/proc/net/tcp`, values hex unless noted):
 *
 * ```
 *  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
 *   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1
 * ```
 *
 * Columns used: `sl` (0), `local_address` (1), `rem_address` (2), `st` (3), `uid` (7), `inode` (9).
 * Addresses are stored as little-endian 32-bit words: IPv4 `0100007F` is `127.0.0.1`, IPv6 is four
 * little-endian 32-bit words in 32 hex characters.
 */
class ProcNetParser {

    /**
     * Parses one kernel socket table.
     *
     * @param protocol table the content was read from; selects the IPv4/IPv6 address width.
     * @param content raw table text including the kernel header line (may use tabs, spaces or CRLF).
     * @param cap hard upper bound of emitted rows; a cap of `0` returns an empty list.
     * @return decoded rows in table order; malformed rows are skipped, never thrown.
     */
    fun parse(protocol: SocketProtocol, content: String, cap: Int = DEFAULT_ROW_CAP): List<RawSocket> {
        require(cap in 0..MAX_ROW_CAP) { "invalid socket row cap" }
        if (cap == 0 || content.isEmpty()) return emptyList()
        val rows = ArrayList<RawSocket>(minOf(cap, INITIAL_CAPACITY))
        var scannedLines = 0
        for (line in content.lineSequence()) {
            if (scannedLines >= MAX_SCAN_LINES || rows.size >= cap) break
            scannedLines += 1
            val socket = parseRow(protocol, line) ?: continue
            rows += socket
        }
        return rows
    }

    /**
     * Parses several tables in the fixed, deterministic order TCP, TCP6, UDP, UDP6.
     *
     * The cap applies per table; a missing table is treated as empty. The result order is stable and
     * independent of the map implementation that carried the content.
     */
    fun parseAll(tables: Map<SocketProtocol, String>, cap: Int = DEFAULT_ROW_CAP): List<RawSocket> {
        require(cap in 0..MAX_ROW_CAP) { "invalid socket row cap" }
        val total = ArrayList<RawSocket>()
        for (protocol in PROTOCOL_ORDER) {
            val content = tables[protocol] ?: continue
            total += parse(protocol, content, cap)
        }
        return total
    }

    /**
     * Decodes one kernel hex address for [protocol].
     *
     * Returns `null` for a wrong width, a non-hex character or an empty token; the caller treats that
     * as a malformed row. IPv4 is rendered as a dotted quad, IPv6 in RFC 5952 compressed form
     * (lowercase, longest zero run compressed, no IPv4-mapped dotted suffix).
     */
    fun decodeAddress(protocol: SocketProtocol, hex: String): String? {
        val expectedLength = if (protocol.isV6) V6_HEX_LENGTH else V4_HEX_LENGTH
        if (hex.length != expectedLength) return null
        if (!hex.all { isHexDigit(it) }) return null
        return if (protocol.isV6) decodeV6(hex) else decodeV4(hex)
    }

    /**
     * Decodes the two-hex-digit kernel `st` column.
     *
     * `01`..`0B` map to the documented TCP states; every other value (including the reserved
     * `0C`..`FF` range, a non-hex token and an empty column) is [SocketState.UNKNOWN] - the parser
     * never claims a state it cannot prove.
     */
    fun decodeState(hex: String): SocketState {
        if (hex.isEmpty() || hex.length > 2 || !hex.all { isHexDigit(it) }) return SocketState.UNKNOWN
        val code = hex.toInt(16)
        return when (code) {
            0x01 -> SocketState.ESTABLISHED
            0x02 -> SocketState.SYN_SENT
            0x03 -> SocketState.SYN_RECV
            0x04 -> SocketState.FIN_WAIT1
            0x05 -> SocketState.FIN_WAIT2
            0x06 -> SocketState.TIME_WAIT
            0x07 -> SocketState.CLOSE
            0x08 -> SocketState.CLOSE_WAIT
            0x09 -> SocketState.LAST_ACK
            0x0A -> SocketState.LISTEN
            0x0B -> SocketState.CLOSING
            else -> SocketState.UNKNOWN
        }
    }

    // -------------------------------------------------------------------------------- row decoding

    private fun parseRow(protocol: SocketProtocol, line: String): RawSocket? {
        val fields = line.trim().split(WHITESPACE)
        if (fields.size < MIN_FIELDS) return null
        val local = decodeEndpoint(protocol, fields[LOCAL_COLUMN]) ?: return null
        val remote = decodeEndpoint(protocol, fields[REMOTE_COLUMN]) ?: return null
        val state = decodeState(fields[STATE_COLUMN])
        val uid = parseInt(fields[UID_COLUMN], RawSocket.MAX_UID) ?: return null
        val inode = parseLong(fields[INODE_COLUMN]) ?: return null
        // Every field is range-checked above; the residual catch keeps future model tightening from
        // turning a hostile /proc row into a crash. Malformed rows are data, not program errors.
        return try {
            RawSocket(
                protocol = protocol,
                localAddress = local.address,
                localPort = local.port,
                remoteAddress = remote.address,
                remotePort = remote.port,
                state = state,
                uid = uid,
                inode = inode,
            )
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun decodeEndpoint(protocol: SocketProtocol, token: String): Endpoint? {
        val separator = token.lastIndexOf(':')
        if (separator <= 0 || separator == token.length - 1) return null
        val address = decodeAddress(protocol, token.substring(0, separator)) ?: return null
        val portHex = token.substring(separator + 1)
        if (portHex.length > 4 || !portHex.all { isHexDigit(it) }) return null
        val port = portHex.toInt(16)
        if (port !in 0..RawSocket.MAX_PORT) return null
        return Endpoint(address, port)
    }

    /** Little-endian 32-bit word: the hex pairs are memory order, the address is network order. */
    private fun decodeV4(hex: String): String {
        val first = hex.substring(6, 8).toInt(16)
        val second = hex.substring(4, 6).toInt(16)
        val third = hex.substring(2, 4).toInt(16)
        val fourth = hex.substring(0, 2).toInt(16)
        return "$first.$second.$third.$fourth"
    }

    /** Four little-endian 32-bit words -> 16 network-order bytes -> RFC 5952 canonical text. */
    private fun decodeV6(hex: String): String {
        val bytes = IntArray(V6_BYTE_LENGTH)
        for (word in 0 until V6_ADDRESS_WORDS) {
            val base = word * 8
            // Each word occupies 4 bytes in memory order; network order reverses them.
            bytes[word * 4] = hex.substring(base + 6, base + 8).toInt(16)
            bytes[word * 4 + 1] = hex.substring(base + 4, base + 6).toInt(16)
            bytes[word * 4 + 2] = hex.substring(base + 2, base + 4).toInt(16)
            bytes[word * 4 + 3] = hex.substring(base, base + 2).toInt(16)
        }
        return formatV6(bytes)
    }

    private fun formatV6(bytes: IntArray): String {
        val groups = IntArray(V6_GROUPS) { index -> (bytes[index * 2] shl 8) or bytes[index * 2 + 1] }
        var bestStart = -1
        var bestLength = 0
        var index = 0
        while (index < V6_GROUPS) {
            if (groups[index] != 0) {
                index += 1
                continue
            }
            var runEnd = index
            while (runEnd < V6_GROUPS && groups[runEnd] == 0) runEnd += 1
            if (runEnd - index > bestLength) {
                bestLength = runEnd - index
                bestStart = index
            }
            index = runEnd
        }
        if (bestLength < MIN_COMPRESSED_RUN) bestStart = -1
        val text = StringBuilder(MAX_V6_TEXT_LENGTH)
        var group = 0
        while (group < V6_GROUPS) {
            if (group == bestStart) {
                text.append("::")
                group += bestLength
                continue
            }
            if (text.isNotEmpty() && !text.endsWith("::")) text.append(':')
            text.append(Integer.toHexString(groups[group]))
            group += 1
        }
        return if (text.isEmpty()) "::" else text.toString()
    }

    private fun parseInt(token: String, max: Int): Int? {
        if (token.isEmpty() || token.length > 10 || !token.all { it.isDigit() }) return null
        val value = token.toLongOrNull() ?: return null
        return if (value in 0..max.toLong()) value.toInt() else null
    }

    private fun parseLong(token: String): Long? {
        if (token.isEmpty() || token.length > 19 || !token.all { it.isDigit() }) return null
        val value = token.toLongOrNull() ?: return null
        return if (value >= 0L) value else null
    }

    private fun isHexDigit(character: Char): Boolean =
        character in '0'..'9' || character in 'a'..'f' || character in 'A'..'F'

    private data class Endpoint(val address: String, val port: Int)

    companion object {
        /** Default per-table row cap. */
        const val DEFAULT_ROW_CAP = 4_096

        /** Hard upper bound of the caller-supplied row cap. */
        const val MAX_ROW_CAP = 65_536

        /** Hard bound of table lines inspected per [parse] call, including header/junk lines. */
        const val MAX_SCAN_LINES = 65_536

        /** Fixed table order of [parseAll]. */
        val PROTOCOL_ORDER: List<SocketProtocol> = listOf(
            SocketProtocol.TCP,
            SocketProtocol.TCP6,
            SocketProtocol.UDP,
            SocketProtocol.UDP6,
        )

        private const val INITIAL_CAPACITY = 512
        private const val V4_HEX_LENGTH = 8
        private const val V6_HEX_LENGTH = 32
        private const val V6_ADDRESS_WORDS = 4
        private const val V6_GROUPS = 8
        private const val V6_BYTE_LENGTH = 16
        private const val MIN_COMPRESSED_RUN = 2
        private const val MAX_V6_TEXT_LENGTH = 39
        private const val MIN_FIELDS = 10
        private const val LOCAL_COLUMN = 1
        private const val REMOTE_COLUMN = 2
        private const val STATE_COLUMN = 3
        private const val UID_COLUMN = 7
        private const val INODE_COLUMN = 9
        private val WHITESPACE = Regex("\\s+")
    }
}
