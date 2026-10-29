package de.visiongaia.gedefense.tv.data

import de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto
import de.visiongaia.gedefense.mobile.core.EvidenceEvent
import de.visiongaia.gedefense.mobile.core.EvidencePayloadProtector
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Bounded reader for the newest records of a v3 evidence ledger.
 *
 * The vendored [de.visiongaia.gedefense.mobile.core.EvidenceLedger] is append/verify-only, so the
 * evidence screen needs a read path. This reader deliberately re-verifies the HMAC of every line it
 * returns and decrypts the payload with the same protector the ledger uses; lines that do not
 * authenticate are skipped instead of being displayed as if they were trusted evidence.
 *
 * Memory and time are bounded: only the last [MAX_TAIL_BYTES] of the ledger are read, at most
 * [MAX_LINES] lines are parsed, and every line is capped by the ledger's own line limit.
 */
internal object EvidenceTailReader {
    private const val MAX_TAIL_BYTES = 512 * 1024
    private const val MAX_LINES = 500
    private const val MAX_LINE_CHARS = 24 * 1024
    private const val RECORD_VERSION = "3"
    private val HEX_64 = Regex("[0-9a-f]{64}")
    private val EVENT_MAGIC = "VGTEVT01".toByteArray(StandardCharsets.US_ASCII)
    private const val MAX_TYPE_BYTES = 320
    private const val MAX_SEVERITY_BYTES = 96
    private const val MAX_SUBJECT_BYTES = 1024
    private const val MAX_DETAIL_BYTES = 8192

    fun readLast(
        file: File,
        limit: Int,
        hmacKey: SecretKey,
        protector: EvidencePayloadProtector,
    ): List<EvidenceEvent> {
        val boundedLimit = limit.coerceIn(1, MAX_LINES)
        val text = readTailText(file) ?: return emptyList()
        val lines = text.split('\n').filter { it.isNotBlank() }
        if (lines.isEmpty()) return emptyList()
        val events = ArrayList<EvidenceEvent>(boundedLimit)
        for (index in lines.indices.reversed()) {
            if (events.size >= boundedLimit) break
            val event = parseLine(lines[index], hmacKey, protector) ?: continue
            events.add(event)
        }
        events.reverse()
        return events
    }

    private fun readTailText(file: File): String? {
        val size = file.length()
        if (size <= 0L) return null
        val start = maxOf(0L, size - MAX_TAIL_BYTES)
        val length = (size - start).toInt()
        if (length <= 0) return null
        return try {
            RandomAccessFile(file, "r").use { handle ->
                val data = ByteArray(length)
                handle.seek(start)
                handle.readFully(data)
                val text = String(data, StandardCharsets.UTF_8)
                // When the read started inside the file, drop the partially captured first line.
                if (start > 0L) text.substringAfter('\n', "") else text
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun parseLine(
        line: String,
        hmacKey: SecretKey,
        protector: EvidencePayloadProtector,
    ): EvidenceEvent? {
        if (line.length > MAX_LINE_CHARS) return null
        val fields = line.split('|')
        if (fields.size != 6 || fields[0] != RECORD_VERSION) return null
        val sequence = fields[1].toLongOrNull() ?: return null
        if (sequence < 1L) return null
        val atMillis = fields[2].toLongOrNull() ?: return null
        if (atMillis < 1L) return null
        val mac = fields[5]
        if (!mac.matches(HEX_64)) return null
        val body = fields.subList(0, 5).joinToString("|")
        val expectedMac = try {
            hmacSha256(hmacKey, body)
        } catch (_: Exception) {
            return null
        }
        if (!MessageDigest.isEqual(expectedMac.toByteArray(), mac.toByteArray())) return null
        val protectedBytes = try {
            java.util.Base64.getUrlDecoder().decode(fields[3])
        } catch (_: IllegalArgumentException) {
            return null
        }
        val plaintext = try {
            protector.unprotect(sequence, atMillis, protectedBytes)
        } catch (_: Exception) {
            protectedBytes.fill(0)
            return null
        } finally {
            protectedBytes.fill(0)
        }
        return try {
            decodeEvent(plaintext, atMillis)
        } catch (_: Exception) {
            null
        } finally {
            plaintext.fill(0)
        }
    }

    private fun decodeEvent(payload: ByteArray, expectedAtMillis: Long): EvidenceEvent? {
        if (payload.size < EVENT_MAGIC.size + 8 + 16) return null
        DataInputStream(ByteArrayInputStream(payload)).use { input ->
            val magic = ByteArray(EVENT_MAGIC.size).also(input::readFully)
            if (!MessageDigest.isEqual(magic, EVENT_MAGIC)) return null
            val atMillis = input.readLong()
            if (atMillis != expectedAtMillis) return null
            val type = readString(input, MAX_TYPE_BYTES) ?: return null
            val severity = readString(input, MAX_SEVERITY_BYTES) ?: return null
            val subject = readString(input, MAX_SUBJECT_BYTES) ?: return null
            val detail = readString(input, MAX_DETAIL_BYTES) ?: return null
            if (input.read() != -1) return null
            if (type.isEmpty() || severity.isEmpty()) return null
            return EvidenceEvent(type = type, severity = severity, subject = subject, detail = detail, atMillis = atMillis)
        }
    }

    private fun readString(input: DataInputStream, maxBytes: Int): String? {
        return try {
            val length = input.readInt()
            if (length !in 0..maxBytes) return null
            val bytes = ByteArray(length)
            input.readFully(bytes)
            String(bytes, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun hmacSha256(key: SecretKey, body: String): String {
        val bytes = BoundedSecretKeyCrypto.execute(key) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(key)
            mac.doFinal(body.toByteArray(StandardCharsets.UTF_8))
        }
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
